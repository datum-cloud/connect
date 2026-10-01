#!/usr/bin/env python3
"""Stage the official signed Wintun DLL and license for Windows packaging/tests.

The archive digest is published at https://www.wintun.net/. This script never
installs a driver, changes the network, or loads the DLL. Runtime loading also
requires the architecture-matched DLL beside the daemon executable.
"""
import argparse
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile

URL = "https://www.wintun.net/builds/wintun-0.14.1.zip"
SHA256 = "07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--arch", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    with urllib.request.urlopen(URL, timeout=30) as response:
        data = response.read(16 * 1024 * 1024 + 1)
    if hashlib.sha256(data).hexdigest() != SHA256:
        raise SystemExit("Wintun archive checksum does not match the pinned official release")
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        files = {
            "wintun.dll": archive.read(f"wintun/bin/{args.arch}/wintun.dll"),
            "WINTUN-LICENSE.txt": archive.read("wintun/LICENSE.txt"),
        }
    args.destination.mkdir(parents=True, exist_ok=True)
    for name, content in files.items():
        path = args.destination / name
        if path.is_symlink():
            raise SystemExit(f"Refusing to follow symlink: {path}")
        if path.exists():
            if path.read_bytes() != content:
                raise SystemExit(f"Refusing to overwrite different existing file: {path}")
        else:
            with path.open("xb") as output:
                output.write(content)
        print(f"Staged {path}: sha256={hashlib.sha256(content).hexdigest()}")


if __name__ == "__main__":
    main()
