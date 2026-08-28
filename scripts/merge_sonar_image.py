#!/usr/bin/env python3
"""Build the full-flash image a BLANK board needs, for one PlatformIO env.

The release .bin is app-only and lives at 0x10000. A factory-fresh device also needs the
bootloader, the partition table, and boot_app0 (which resets the OTA selector so the newly
written app is the one that boots). Without those it will not come up at all.

PlatformIO's own `mergebin` target is unreliable here -- it reports SUCCESS and produces
no file -- so this drives esptool directly, with the offsets PlatformIO itself uses.

Flash mode/frequency/size are passed as `keep`: the bootloader built for this env already
carries the right header, and rewriting it from a guess is how you get an image that
flashes cleanly and then does not boot.

    python3 scripts/merge_sonar_image.py --env <env> --out out/<name>-merged.bin
"""
from __future__ import annotations

import argparse
import glob
import os
import subprocess
import sys

# Standard ESP32 layout, matching what `pio run -t upload` writes (verified against its
# own output: 0x0 bootloader, 0x8000 partitions, 0xe000 boot_app0, 0x10000 app).
BOOTLOADER_OFFSET = "0x0"
PARTITIONS_OFFSET = "0x8000"
BOOT_APP0_OFFSET = "0xe000"
APP_OFFSET = "0x10000"


def find_one(pattern: str, what: str) -> str:
    hits = sorted(glob.glob(pattern))
    if not hits:
        print(f"ERROR: {what} not found ({pattern})", file=sys.stderr)
        raise SystemExit(2)
    return hits[0]


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--env", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--chip", default="esp32s3")
    args = ap.parse_args()

    build = os.path.join(".pio", "build", args.env)
    for name in ("bootloader.bin", "partitions.bin", "firmware.bin"):
        if not os.path.exists(os.path.join(build, name)):
            print(f"ERROR: {build}/{name} missing -- build the env first", file=sys.stderr)
            return 2

    home = os.path.expanduser("~")
    esptool = find_one(os.path.join(home, ".platformio", "packages", "tool-esptoolpy",
                                    "esptool.py"), "esptool.py")
    boot_app0 = find_one(os.path.join(home, ".platformio", "packages",
                                      "framework-arduinoespressif32", "tools", "partitions",
                                      "boot_app0.bin"), "boot_app0.bin")

    os.makedirs(os.path.dirname(args.out) or ".", exist_ok=True)
    cmd = [
        sys.executable, esptool, "--chip", args.chip, "merge_bin", "-o", args.out,
        "--flash_mode", "keep", "--flash_freq", "keep", "--flash_size", "keep",
        BOOTLOADER_OFFSET, os.path.join(build, "bootloader.bin"),
        PARTITIONS_OFFSET, os.path.join(build, "partitions.bin"),
        BOOT_APP0_OFFSET, boot_app0,
        APP_OFFSET, os.path.join(build, "firmware.bin"),
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    if res.returncode != 0 or not os.path.exists(args.out):
        # Loud. A silently missing merged image is how a release ships with nothing a new
        # board can be flashed from -- which is exactly what PlatformIO's own target did.
        print(res.stdout, file=sys.stderr)
        print(res.stderr, file=sys.stderr)
        print("ERROR: merge failed", file=sys.stderr)
        return 2

    size = os.path.getsize(args.out)
    print(f"wrote {args.out} ({size} bytes, flash at {BOOTLOADER_OFFSET})")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
