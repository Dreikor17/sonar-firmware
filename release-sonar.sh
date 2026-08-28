#!/usr/bin/env bash
# Build a releasable Sonar firmware + its OTA manifest.
#
# Sonar is rflab.io's MeshCore observer build: an observer that doubles as a remote
# probe Echo can task over MQTT. The name is the behaviour -- sonar works by echo, and
# its passive and active modes are exactly this node's observer and probe modes.
#
#   ./release-sonar.sh <build-number> [env ...]
#
# e.g.  ./release-sonar.sh 3 Heltec_v3_repeater_observer_mqtt
#
# Why this wrapper exists rather than calling build.sh directly: the OTA behaviour is
# decided entirely by environment variables that are easy to forget, and forgetting one
# does not fail the build -- it produces firmware that either cannot update or offers an
# update forever. All of it is pinned here.
set -euo pipefail

# --- release channel ---------------------------------------------------------
# The manifest URL IS the channel: a device only ever sees updates published under the
# base it was built with. Point this at our host, and stock observers never see our
# builds (nor we theirs).
#
# NOTE: `ota check` deliberately fetches this over PLAIN HTTP (no TLS handshake, so the
# check runs with the MQTT bridge still up on non-PSRAM boards). The host must therefore
# serve /v/*.json over http:// as well as https:// -- a forced HTTPS redirect breaks
# `ota check` while leaving `ota update` working, which is a confusing way to fail.
: "${OTA_MANIFEST_BASE_URL:=https://rflab.io/v}"

# Where the .bin itself is published. MUST be HTTPS with a publicly-trusted certificate:
# the download is verified against the firmware's embedded Mozilla root bundle, so a
# self-signed cert fails at the moment of flashing. GitHub Releases satisfies this.
#
# Defaults to this build's release tag on the public firmware repo. Derived rather than
# hand-set because the tag has to agree with the version the firmware reports, and a
# mismatch here does not fail the build -- it publishes a manifest pointing at a URL
# that 404s, which only shows up when a node tries to update.
: "${SONAR_RELEASE_REPO:=Dreikor17/sonar-firmware}"

# Identifies our fork in `ver`, the MQTT firmware_version and SNMP, while keeping
# upstream's version number so we can see how far behind upstream we are:
#   v1.17.1.3-observer-sonar-a1b2c3d
#
# Must contain no DOT. ota_parseVersion() scans for the THIRD dot to split base from
# build number, so a dotted tag in a build with no build number supplies that third dot
# and the version parses as a truncated base with build 0. "sonar" cannot do that.
export OTA_CHANNEL_TAG="sonar"
# Carried in the ARTIFACT NAME too, so a .bin sitting in a downloads folder still says
# what it is. Same no-dot rule as the version tag -- every filename parser downstream
# (web flasher, release listing) splits on "-" and takes the trailing token as the hash.
export FILENAME_CHANNEL_TAG="-sonar"

# --- build number ------------------------------------------------------------
# REQUIRED, and must increase with every published build. The firmware compares build
# numbers only when both its own version and the manifest expose a 4th component; without
# one it compares its whole version string to the manifest's baseVersion, never matches,
# and reports "update available" on every single check.
BUILD_NUMBER="${1:?usage: release-sonar.sh <build-number> [env ...]}"
shift || true
export FIRMWARE_BUILD_NUMBER="$BUILD_NUMBER"

: "${FIRMWARE_VERSION:=$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)}"
export FIRMWARE_VERSION

RELEASE_TAG="${FIRMWARE_VERSION}.${FIRMWARE_BUILD_NUMBER}"
: "${SONAR_RELEASE_BASE:=https://github.com/${SONAR_RELEASE_REPO}/releases/download/${RELEASE_TAG}}"

# build.sh invokes `python3`. On Windows/Git Bash the interpreter is usually just
# `python`, and build.sh guards that call with `|| true` -- so a missing python3 does
# NOT fail the build, it silently produces an EMPTY partition signature and a manifest
# that cannot check partition compatibility. Resolve one interpreter here and use it
# for the steps we own.
PY="$(command -v python3 || command -v python || true)"
if [ -z "$PY" ]; then
  echo "ERROR: no python interpreter on PATH" >&2
  exit 1
fi

ENVS=("$@")
if [ ${#ENVS[@]} -eq 0 ]; then
  ENVS=(Heltec_v3_repeater_observer_mqtt)
fi

# build.sh does `rm -rf out` on EVERY invocation, and we call it once per env -- so out/
# only ever holds the last board built. Accumulate finished artifacts somewhere it cannot
# reach, or a multi-board release silently ships with only one board in it.
DIST="dist"
rm -rf "$DIST"
mkdir -p "$DIST/manifests"

echo "channel : $OTA_MANIFEST_BASE_URL   (tag: $OTA_CHANNEL_TAG)"
echo "version : ${FIRMWARE_VERSION}.${FIRMWARE_BUILD_NUMBER}"
echo "binaries: $SONAR_RELEASE_BASE"
echo "tag     : $RELEASE_TAG"
echo

for env in "${ENVS[@]}"; do
  echo "=== building $env ==="
  OTA_MANIFEST_BASE_URL="$OTA_MANIFEST_BASE_URL" sh build.sh build-firmware "$env"

  # Re-emit the partition signature ourselves: build.sh's attempt is best-effort and
  # may have produced nothing (see the python3 note above). Not optional -- the device
  # refuses an update whose partition layout differs from its flashed table, and it can
  # only do that if the manifest carries the signature.
  if [ -f ".pio/build/$env/partitions.bin" ]; then
    "$PY" scripts/partition_signature.py ".pio/build/$env/partitions.bin" > "out/$env.partsig"
  fi

  # Full-flash image for a BLANK board. The release .bin is app-only (0x10000); a
  # factory-fresh device also needs bootloader, partition table and boot_app0, or it
  # will not boot at all. PlatformIO's own mergebin target reports SUCCESS and writes
  # nothing, so a release built on it ships with nothing a new probe can be flashed
  # from -- which is exactly what happened the first time.
  STEM="${env}-${FIRMWARE_VERSION}.${FIRMWARE_BUILD_NUMBER}${FILENAME_CHANNEL_TAG}-$(git rev-parse --short HEAD)"
  MERGED="out/${STEM}-merged.bin"
  "$PY" scripts/merge_sonar_image.py --env "$env" --out "$MERGED"

  # --filename-tag uses the `=` form, not a space: the tag starts with "-", and argparse
  # would otherwise read it as another option rather than as this one's value.
  "$PY" scripts/gen_sonar_manifest.py \
    --filename-tag="$FILENAME_CHANNEL_TAG" \
    --env "$env" \
    --version "$FIRMWARE_VERSION" \
    --build "$FIRMWARE_BUILD_NUMBER" \
    --file-base "$SONAR_RELEASE_BASE"

  # Move this board's results out of build.sh's reach before the next env wipes out/.
  cp "out/${STEM}.bin" "out/${STEM}-merged.bin" "$DIST/"
  cp "out/manifests/${env}.json" "$DIST/manifests/"
done

echo
echo "Artifacts in $DIST/, manifests in $DIST/manifests/."
ls -1 "$DIST"/*.bin "$DIST"/manifests/*.json
echo "Publish: upload $DIST/*.bin to the release at $SONAR_RELEASE_BASE,"
echo "         and copy $DIST/manifests/*.json to the host serving $OTA_MANIFEST_BASE_URL."
