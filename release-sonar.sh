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
: "${OTA_MANIFEST_BASE_URL:=https://echo1.rflab.io/v}"   # dev channel — main uses rflab.io/v

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
# "sonar-dev" on this branch, "sonar" on main, so a build says which channel it came
# from in `ver`, in its MQTT firmware_version and in its filename. Two populations that
# cannot cross-update should not be told apart only by a URL nobody can see from the node.
#
# Still no DOT: ota_parseVersion() finds the build number by scanning for the THIRD dot,
# and a dotted tag would supply that dot itself and parse the version as a truncated base
# with build 0. A hyphen is safe.
#
# And it still CONTAINS "-sonar-", which is what the controller matches on to recognise a
# probe-capable build -- "v1.17.1.7-observer-sonar-dev-<hash>" satisfies that substring, so
# widening the tag does not quietly drop these nodes out of discovery.
export OTA_CHANNEL_TAG="sonar-dev"
# Carried in the ARTIFACT NAME too, so a .bin sitting in a downloads folder still says
# what it is. Same no-dot rule as the version tag -- every filename parser downstream
# (web flasher, release listing) splits on "-" and takes the trailing token as the hash.
export FILENAME_CHANNEL_TAG="-sonar-dev"

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
# Probe settings still ship on (SONAR_PROBE_DEFAULTS): upstream leaves probing off, so a
# node would otherwise need three settings by hand before the controller could adopt it.
#
# THE RADIO IS DELIBERATELY NOT PRESET ANY MORE.
#
# This used to bake the mesh's own parameters -- 910.525 / 62.5 / SF7 / CR5 -- in as the
# COMPILED-IN default, on the reasoning that a node should arrive ready to join. The cost
# of that was not obvious until a node was wiped: `erase` formats the filesystem
# (src/helpers/CommonCLI.cpp:932-935) and /prefs.json goes with it, which leaves the
# compiled defaults in charge. The node then transmits a zero-hop advert 16 s after boot
# (examples/simple_repeater/main.cpp:127-129 -- upstream behaviour, ENABLE_ADVERT_ON_BOOT)
# carrying the compiled ADVERT_NAME. So a bench node being re-provisioned announced itself
# to the REAL mesh as "MQTT Observer", and would keep flood-advertising that name
# mesh-wide every 47 h (MyMesh.cpp:1131, which the SONAR block below does not zero).
#
# Preset radio parameters make the UNCONFIGURED state indistinguishable on air from a
# configured one, and that is not a trade worth making for saving one setting during
# provisioning. Left unset, an image inherits the board's own default from
# platformio.ini:29-31 -- which is not this mesh -- so a wiped node cannot reach the mesh
# no matter what it decides to transmit.
#
# ALREADY-DEPLOYED NODES ARE UNAFFECTED. /prefs.json stores freq/bw/sf/cr
# (src/helpers/CommonCLI.h:112-115, written unconditionally), and begin() loads it
# (MyMesh.cpp:1255) before the radio is ever programmed from prefs (MyMesh.cpp:1367).
# Only a node with NO prefs file uses a compiled default. Verified against the shipped
# images: the v1.17.1.8 release .bin contains the float 910.525 and not 869.618, while a
# plain `pio run` build is the reverse -- so this flag really was the only thing deciding
# it, and the #ifndef LORA_FREQ 915.0 in MyMesh.cpp:11-13 is dead code either way.
#
# The knob survives, opt-in: export any of SONAR_LORA_FREQ/BW/SF/CR to bake a radio into a
# particular build. Setting them is choosing the trade-off above deliberately, and the
# summary at the end of this script says which way the image went.
#
# NOTE on the inherited default: platformio.ini ships EU 869.618, which is outside the US
# 902-928 ISM band. That is upstream's value and what every plain `pio run` image and CI
# artifact already carries, but if these nodes are provisioned somewhere that matters,
# park them instead by exporting SONAR_LORA_FREQ to a quiet in-band frequency the mesh
# does not use -- rather than to the one it does.
SONAR_LORA_FLAGS=""
if [ -n "${SONAR_LORA_FREQ:-}" ]; then SONAR_LORA_FLAGS="$SONAR_LORA_FLAGS -DLORA_FREQ=${SONAR_LORA_FREQ}"; fi
if [ -n "${SONAR_LORA_BW:-}" ];   then SONAR_LORA_FLAGS="$SONAR_LORA_FLAGS -DLORA_BW=${SONAR_LORA_BW}"; fi
if [ -n "${SONAR_LORA_SF:-}" ];   then SONAR_LORA_FLAGS="$SONAR_LORA_FLAGS -DLORA_SF=${SONAR_LORA_SF}"; fi
if [ -n "${SONAR_LORA_CR:-}" ];   then SONAR_LORA_FLAGS="$SONAR_LORA_FLAGS -DLORA_CR=${SONAR_LORA_CR}"; fi

export PLATFORMIO_BUILD_FLAGS="${PLATFORMIO_BUILD_FLAGS:-} -DPROBE_CONTROLLER_PUBKEY='\"${SONAR_CONTROLLER_PUBKEY}\"' -DSONAR_PROBE_DEFAULTS=1${SONAR_LORA_FLAGS}"

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
# Say which way this image went, because the difference is invisible once it is flashed:
# an image with a compiled-in radio joins the mesh the moment it is powered on, wiped or
# not, and an image without one is inert until somebody sets it.
if [ -n "$SONAR_LORA_FLAGS" ]; then
  echo "radio   : COMPILED IN ->${SONAR_LORA_FLAGS}"
  echo "          a WIPED node comes up on this and will advertise there"
else
  echo "radio   : not preset — inherits the board default (platformio.ini)"
  echo "          a wiped node cannot reach the mesh until its radio is set"
fi
echo "defaults: probe on (slot 1), probe/v1 on, relay-TX on, flood on, repeat off, 3-byte hash"
echo "          relay-TX needs a broker that serves relay/v1 -- an older one force-closes the socket"
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

  # VERIFY THE MANIFEST AGAINST THE KEY THE IMAGE WILL ACTUALLY CHECK IT WITH.
  #
  # Signing and verifying are done by different halves of this system, and they drifted:
  # manifests are signed with the Echo instance's controller private key, while the node
  # used to verify with _prefs.probe_controller_pubkey -- which Echo ROTATES to a per-node
  # key the moment it adopts a node. Every adopted node therefore rejected every manifest
  # with "manifest signature does not match this node's controller", while an un-adopted
  # one accepted it, so the failure looked like a node problem rather than a signing one.
  #
  # The firmware now verifies with the COMPILED-IN key, so that is what this checks. A
  # mismatch fails the build here, where the fix is one variable, instead of after a cable
  # flash of every node in the field.
  SONAR_CONTROLLER_PUBKEY="$SONAR_CONTROLLER_PUBKEY"   MANIFEST="out/manifests/${env}.json" "$PY" - <<'PYVERIFY' || exit 1
import json, os, sys
try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    from cryptography.exceptions import InvalidSignature
except ImportError:
    print("WARN: python 'cryptography' not available; manifest signature NOT verified",
          file=sys.stderr)
    raise SystemExit(0)
m = json.load(open(os.environ["MANIFEST"], encoding="utf-8"))
# Byte-for-byte what ESP32Board::otaFromManifestImpl builds before verifying.
signing_input = "sonar-manifest-v1
%s
%s
%s
%d
%s
%s" % (
    m["version"], m["file"], m["baseVersion"], m["build"], m["partSig"], m["sha256"])
try:
    Ed25519PublicKey.from_public_bytes(
        bytes.fromhex(os.environ["SONAR_CONTROLLER_PUBKEY"])
    ).verify(bytes.fromhex(m["sig"]), signing_input.encode())
except InvalidSignature:
    print("ERROR: the manifest signature does not verify against SONAR_CONTROLLER_PUBKEY,",
          file=sys.stderr)
    print("       which is the key compiled into this image. Every node built from it would",
          file=sys.stderr)
    print("       refuse the update. The signing Echo instance and the baked key disagree.",
          file=sys.stderr)
    raise SystemExit(1)
print("manifest signature verifies against the compiled-in controller key")
PYVERIFY

  # Move this board's results out of build.sh's reach before the next env wipes out/.
  cp "out/${STEM}.bin" "out/${STEM}-merged.bin" "$DIST/"
  cp "out/manifests/${env}.json" "$DIST/manifests/"
done

echo
echo "Artifacts in $DIST/, manifests in $DIST/manifests/."
ls -1 "$DIST"/*.bin "$DIST"/manifests/*.json
# THE MANIFESTS ARE RELEASE ASSETS, not a separate web upload.
#
# This used to say "copy the manifests to the host serving $OTA_MANIFEST_BASE_URL", which
# describes a second copy nobody keeps. Echo's mirror (backend/app/routers/sonar_manifest.py)
# fetches releases/latest/download/<variant>.json and serves THAT over plain http, so the
# release is the only place they belong. Uploading the .bin files alone -- which the old
# wording invited -- leaves every node's `ota check` reporting "ERR: manifest HTTP 502",
# because the mirror's upstream 404s and it correctly refuses to invent an answer.
echo "Publish: upload the images AND the manifests as assets on ONE release."
echo "         Echo's /v mirror reads releases/latest/download/<variant>.json, so a"
echo "         manifest left out of the release makes every node report"
echo "         'ERR: manifest HTTP 502' on its next check."
echo
echo "  gh release create $RELEASE_TAG \\"
echo "    $DIST/*.bin $DIST/manifests/*.json \\"
echo "    --repo <owner>/<repo> --target \$(git rev-parse HEAD) \\"
echo "    --title \"Sonar $RELEASE_TAG (dev)\""
echo
echo "         Nothing needs copying to $OTA_MANIFEST_BASE_URL -- that host mirrors the release."
