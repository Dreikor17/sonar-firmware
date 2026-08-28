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

# --- controller identity -----------------------------------------------------
# The controller PUBLIC key, compiled in so a node flashed from our release already
# trusts our Echo and needs no 64-hex paste during provisioning. Public by definition:
# without the private half it cannot sign a command, and a node still has to be on our
# broker and approved in Echo before anything reaches it. Nothing secret ships here.
#
# A node that has already been given a key keeps it; this only seeds an unset one. After
# approval Echo moves each node onto a key issued just for it, and from then on this key
# is accepted by that node for one thing only: issuing it another.
#
# The default below is not a constant -- it is one specific Echo installation's key, and
# its private half exists in exactly one file on one machine (that install's
# instance/secrets.json). Every published Sonar image already carries it, so:
#   * lose that file and every node in the field is unmanageable except over a cable;
#   * stand up a second Echo without it and that Echo mints a DIFFERENT key, after which
#     those nodes ignore it completely -- silently, because a node that distrusts a key
#     does not answer at all.
# SONAR_CHECK_ECHO_INSTANCE below turns the second case into a build error instead.
: "${SONAR_CONTROLLER_PUBKEY:=092167A1C4089D4B5D43E4C9B9EEDCB536649E46B32DFCF644AAB51CC5679CC5}"
case "$SONAR_CONTROLLER_PUBKEY" in
  # Refuse a malformed or all-zero key here rather than shipping images that silently
  # refuse every command -- the symptom on the bench is indistinguishable from a broken
  # broker, and by then the firmware is already flashed.
  *[!0-9A-Fa-f]* | "")
    echo "ERROR: SONAR_CONTROLLER_PUBKEY must be hex" >&2; exit 1 ;;
esac
if [ "${#SONAR_CONTROLLER_PUBKEY}" -ne 64 ]; then
  echo "ERROR: SONAR_CONTROLLER_PUBKEY must be 64 hex chars (got ${#SONAR_CONTROLLER_PUBKEY})" >&2
  exit 1
fi
if [ -z "$(printf '%s' "$SONAR_CONTROLLER_PUBKEY" | tr -d '0')" ]; then
  echo "ERROR: SONAR_CONTROLLER_PUBKEY is all zeros, which means 'trust nobody'" >&2
  exit 1
fi
# --- shipped-ready defaults -------------------------------------------------
# The upstream defaults are EU (869.618 / SF8) and leave probing off, so every node would
# otherwise need re-regioning and three probe settings by hand before it could be adopted.
# US/CAN radio, matching what the mesh actually runs.
: "${SONAR_LORA_FREQ:=910.525}"
: "${SONAR_LORA_BW:=62.5}"
: "${SONAR_LORA_SF:=7}"
: "${SONAR_LORA_CR:=5}"

export PLATFORMIO_BUILD_FLAGS="${PLATFORMIO_BUILD_FLAGS:-} -DPROBE_CONTROLLER_PUBKEY='\"${SONAR_CONTROLLER_PUBKEY}\"' -DSONAR_PROBE_DEFAULTS=1 -DLORA_FREQ=${SONAR_LORA_FREQ} -DLORA_BW=${SONAR_LORA_BW} -DLORA_SF=${SONAR_LORA_SF} -DLORA_CR=${SONAR_LORA_CR}"

# Verify the baked key against the Echo that will actually task these nodes. Building an
# image against the wrong controller is not recoverable over the air: the node accepts
# nothing the new Echo signs, and answers nothing, so it reads as a dead radio. Catch it
# here, where the fix is one env var, rather than in a field enclosure.
#
# Skipped silently when the instance cannot be found (a CI box has no Echo). Point
# SONAR_CHECK_ECHO_INSTANCE at an instance dir to force it, or set it to "off" to skip.
: "${SONAR_CHECK_ECHO_INSTANCE:=../echo/backend/instance}"
if [ "$SONAR_CHECK_ECHO_INSTANCE" != "off" ] && [ -f "$SONAR_CHECK_ECHO_INSTANCE/secrets.json" ]; then
  echo_pub="$(
    SECRETS="$SONAR_CHECK_ECHO_INSTANCE/secrets.json" "$(command -v python3 || command -v python)" - <<'PY' 2>/dev/null || true
import json, os
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization
d = json.load(open(os.environ["SECRETS"], encoding="utf-8"))
tok, fk = d.get("probe_controller_prv_enc"), d.get("fernet_key")
if tok and fk:
    raw = bytes.fromhex(Fernet(fk.encode()).decrypt(tok.encode()).decode())
    pub = Ed25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(
        encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
    print(pub.hex().upper())
PY
  )"
  if [ -n "$echo_pub" ] && [ "$echo_pub" != "$SONAR_CONTROLLER_PUBKEY" ]; then
    echo "ERROR: this build would trust a controller that Echo does not hold." >&2
    echo "       baking : $SONAR_CONTROLLER_PUBKEY" >&2
    echo "       Echo at $SONAR_CHECK_ECHO_INSTANCE holds: $echo_pub" >&2
    echo "       Nodes flashed with this image would ignore that Echo entirely, and would" >&2
    echo "       not report an error -- they simply never answer. Set" >&2
    echo "       SONAR_CONTROLLER_PUBKEY to the key above, or SONAR_CHECK_ECHO_INSTANCE=off" >&2
    echo "       if you are deliberately building for a different install." >&2
    exit 1
  fi
  [ -n "$echo_pub" ] && echo "ctrl key: verified against $SONAR_CHECK_ECHO_INSTANCE"
fi

# --- manifest signing key -----------------------------------------------------
# The manifest names the URL every node fetches its firmware from, so an unsigned one makes
# write access to the manifest host equivalent to running code on every node in the field.
# Signed with the SAME controller key the nodes already hold and already verify for tasking,
# so OTA authority becomes "holds the controller private key" rather than "can write /v".
#
# Written to a temp file rather than passed as an argument: a command line is visible to
# every process on the machine.
SIGN_KEY_FILE=""
if [ "$SONAR_CHECK_ECHO_INSTANCE" != "off" ] && [ -f "$SONAR_CHECK_ECHO_INSTANCE/secrets.json" ]; then
  SIGN_KEY_FILE="$(mktemp)"
  chmod 600 "$SIGN_KEY_FILE" 2>/dev/null || true
  trap 'rm -f "$SIGN_KEY_FILE"' EXIT INT TERM
  SECRETS="$SONAR_CHECK_ECHO_INSTANCE/secrets.json"     "$(command -v python3 || command -v python)" - > "$SIGN_KEY_FILE" <<'PYKEY'
import json, os
from cryptography.fernet import Fernet
d = json.load(open(os.environ["SECRETS"], encoding="utf-8"))
tok, fk = d.get("probe_controller_prv_enc"), d.get("fernet_key")
if tok and fk:
    print(Fernet(fk.encode()).decrypt(tok.encode()).decode().strip())
PYKEY
  if [ ! -s "$SIGN_KEY_FILE" ]; then
    echo "ERROR: could not read the controller private key from $SONAR_CHECK_ECHO_INSTANCE/secrets.json." >&2
    echo "       Manifests must be signed -- an unsigned one lets whoever can write the" >&2
    echo "       manifest host choose the firmware every node runs. Point" >&2
    echo "       SONAR_CHECK_ECHO_INSTANCE at the right instance dir." >&2
    exit 1
  fi
  echo "signing : manifests signed with the controller key from $SONAR_CHECK_ECHO_INSTANCE"
else
  echo "ERROR: no Echo instance to sign manifests with (SONAR_CHECK_ECHO_INSTANCE is off or missing)." >&2
  echo "       A published manifest MUST be signed. Set SONAR_CHECK_ECHO_INSTANCE to the" >&2
  echo "       instance dir holding the controller key." >&2
  exit 1
fi

# --- build number ------------------------------------------------------------
# REQUIRED, and must increase with every published build. The firmware compares build
# numbers only when both its own version and the manifest expose a 4th component; without
# one it compares its whole version string to the manifest's baseVersion, never matches,
# and reports "update available" on every single check.
BUILD_NUMBER="${1:?usage: release-sonar.sh <build-number> [env ...]}"
shift || true
export FIRMWARE_BUILD_NUMBER="$BUILD_NUMBER"

# The base version. `git describe` is a LAST resort and usually the wrong answer: this
# tree carries upstream tags like `mbedtls-4k`, and the nearest one has nothing to do with
# the MeshCore release we are based on. Taking it silently produced a real build named
# `mbedtls-4k.6` whose version string the device cannot even parse.
: "${FIRMWARE_VERSION:=$(git describe --tags --abbrev=0 2>/dev/null || echo v0.0.0)}"

# So: validate rather than trust. ota_parseVersion() finds the build number by scanning
# for the THIRD dot, which means the base must be exactly v<major>.<minor>.<patch> -- with
# anything else the device compares whole strings, never matches, and offers the same
# update on every check forever.
case "$FIRMWARE_VERSION" in
  v[0-9]*.[0-9]*.[0-9]*) ;;
  *)
    echo "ERROR: FIRMWARE_VERSION is '$FIRMWARE_VERSION', which is not v<major>.<minor>.<patch>." >&2
    echo "       It is the base a device compares against, so a malformed one ships a build" >&2
    echo "       that reports an update available forever. Pass it explicitly:" >&2
    echo "         FIRMWARE_VERSION=v1.17.1 $0 $BUILD_NUMBER [env ...]" >&2
    exit 1
    ;;
esac
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
echo "ctrl key: ${SONAR_CONTROLLER_PUBKEY:0:16}… (public; compiled in)"
echo "radio   : ${SONAR_LORA_FREQ} / ${SONAR_LORA_BW} / SF${SONAR_LORA_SF} / CR${SONAR_LORA_CR}"
echo "defaults: probe on (slot 1), repeat off, 3-byte hash  --  'set probe.v1 on' still needed per node"
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
    --file-base "$SONAR_RELEASE_BASE"     --signing-key "$SIGN_KEY_FILE"

  # Move this board's results out of build.sh's reach before the next env wipes out/.
  cp "out/${STEM}.bin" "out/${STEM}-merged.bin" "$DIST/"
  cp "out/manifests/${env}.json" "$DIST/manifests/"
done

echo
echo "Artifacts in $DIST/, manifests in $DIST/manifests/."
ls -1 "$DIST"/*.bin "$DIST"/manifests/*.json
echo "Publish: upload $DIST/*.bin to the release at $SONAR_RELEASE_BASE,"
echo "         and copy $DIST/manifests/*.json to the host serving $OTA_MANIFEST_BASE_URL."
