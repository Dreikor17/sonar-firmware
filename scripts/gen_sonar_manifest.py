#!/usr/bin/env python3
"""Generate the slim per-variant OTA manifest the observer pull-OTA fetches.

The firmware reads <OTA_MANIFEST_BASE>/<OTA_VARIANT>.json and compares it against its
own embedded version. Upstream's generator lives in their release pipeline, not in this
repo, so this is our equivalent -- deliberately small, and driven by what build.sh has
already produced in out/.

Usage (after build.sh has run for the env):

    python3 scripts/gen_sonar_manifest.py \\
        --env Heltec_v3_repeater_observer_mqtt \\
        --version v1.17.1 --build 3 \\
        --file-base https://github.com/<owner>/<repo>/releases/download/v1.17.1.3 \\
        --out out/manifests

Writes out/manifests/<env>.json.

Two things this gets right that are easy to get wrong:

* `build` MUST be present and monotonic. The firmware only compares build numbers when
  BOTH sides parse a 4th version component; without one it falls back to comparing the
  whole version string against the manifest's baseVersion, which never matches -- so
  every `ota check` would report an update forever.
* `partSig` comes from the actual built partition table (build.sh writes out/<env>.partsig).
  The device computes the same signature from its flashed table and refuses a mismatch,
  because OTA cannot rewrite a partition table.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import subprocess
import sys

# Must match build.sh and release-sonar.sh:
#   v<VERSION>.<BUILD>-observer-<CHANNEL>-<HASH>
# No dot in the tag -- see the note in release-sonar.sh.
CHANNEL_TAG = "sonar"


def git_hash() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:  # noqa: BLE001
        return ""


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True, help="PlatformIO env name (== OTA_VARIANT)")
    ap.add_argument("--version", required=True, help="base version, e.g. v1.17.1")
    ap.add_argument("--build", required=True, type=int, help="monotonic build number")
    ap.add_argument("--file-base", required=True,
                    help="URL prefix the .bin is published under (must be HTTPS)")
    ap.add_argument("--hash", default="", help="commit hash; defaults to git HEAD")
    ap.add_argument("--out", default="out/manifests")
    ap.add_argument("--bin-dir", default="out")
    ap.add_argument("--filename-tag", default="-sonar",
                    help="channel tag build.sh put in the ARTIFACT NAME "
                         "(FILENAME_CHANNEL_TAG); must match or the file is not found")
    ap.add_argument("--allow-missing-partsig", action="store_true",
                    help="publish without a partition signature (weakens the OTA safety check)")
    args = ap.parse_args()

    commit = args.hash or git_hash()
    if not commit:
        print("ERROR: no commit hash (pass --hash)", file=sys.stderr)
        return 2

    if not args.file_base.startswith("https://"):
        # `ota update` verifies the download against the embedded Mozilla root bundle.
        # A plain-HTTP or self-signed host fails the handshake, and it fails at the point
        # where the device is about to flash -- so refuse here instead.
        print("ERROR: --file-base must be https:// (the firmware verifies the cert)",
              file=sys.stderr)
        return 2

    # build.sh names artifacts <env>-<version>[.<build>][<channel>]-<hash>.bin
    # Must reproduce build.sh's FIRMWARE_FILENAME exactly. Derived rather than globbed so a
    # mismatch is caught here, at build time, instead of becoming a manifest that points at
    # a URL which 404s only once a node tries to update.
    stem = f"{args.env}-{args.version}.{args.build}{args.filename_tag}-{commit}"
    binname = f"{stem}.bin"
    binpath = os.path.join(args.bin_dir, binname)
    if not os.path.exists(binpath):
        print(f"ERROR: {binpath} not found -- run build.sh for {args.env} first",
              file=sys.stderr)
        return 2

    partsig = ""
    sigpath = os.path.join(args.bin_dir, f"{args.env}.partsig")
    if os.path.exists(sigpath):
        with open(sigpath, encoding="utf-8") as f:
            partsig = f.read().strip()
    if not partsig and not args.allow_missing_partsig:
        # A hard error, not a warning. Without partSig the device cannot check that the
        # update's partition layout matches its flashed table, and OTA cannot rewrite a
        # partition table -- so the failure surfaces as a remote node that took an image
        # it cannot boot. A warning here is something you notice afterwards.
        print(f"ERROR: {sigpath} missing or empty -- refusing to publish a manifest that"
              " cannot verify partition compatibility."
              " Re-run the build, or pass --allow-missing-partsig if you truly mean it.",
              file=sys.stderr)
        return 2

    with open(binpath, "rb") as f:
        sha = hashlib.sha256(f.read()).hexdigest()

    manifest = {
        "file": f"{args.file_base.rstrip('/')}/{binname}",
        # The full embedded-style version, so `ota check` can print something that matches
        # what `ver` reports on the device.
        "version": f"{args.version}.{args.build}-observer-{CHANNEL_TAG}-{commit}",
        "baseVersion": args.version,
        "hash": commit,
        "build": args.build,
        "partitionChange": False,
        "partSig": partsig,
        # Not read by the firmware; here so a human (or a mirror) can verify the artifact.
        "sha256": sha,
    }

    os.makedirs(args.out, exist_ok=True)
    dest = os.path.join(args.out, f"{args.env}.json")
    with open(dest, "w", encoding="utf-8") as f:
        json.dump(manifest, f, indent=1)
        f.write("\n")
    print(f"wrote {dest}")
    print(json.dumps(manifest, indent=1))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
