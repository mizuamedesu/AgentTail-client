#!/usr/bin/env python3
"""Download the official signed Wintun DLLs and bundled redistribution license.
Source and pinned digest: https://www.wintun.net/ (checked 2026-09-28).
"""
import argparse
import hashlib
import io
from pathlib import Path
import urllib.request
import zipfile

URL = 'https://www.wintun.net/builds/wintun-0.14.1.zip'
DIGEST = '07c256185d6ee3652e09fa55c0b673e2624b565e02c4b9091c79ca7d2f24ef51'


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--dir', type=Path, required=True)
    a = p.parse_args()
    with urllib.request.urlopen(URL, timeout=60) as response:
        if response.url != URL:
            raise RuntimeError('unexpected Wintun redirect')
        data = response.read(16 * 1024 * 1024)
    if hashlib.sha256(data).hexdigest() != DIGEST:
        raise RuntimeError('Wintun archive digest mismatch')
    a.dir.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(io.BytesIO(data)) as archive:
        license_text = archive.read('wintun/LICENSE.txt')
        for arch in ('amd64', 'arm64'):
            (a.dir / f'wintun-windows-{arch}.dll').write_bytes(archive.read(f'wintun/bin/{arch}/wintun.dll'))
            (a.dir / f'wintun-license-{arch}.txt').write_bytes(license_text)
    print('Official Wintun 0.14.1 checksum verified; DLLs and redistribution license extracted.')


if __name__ == '__main__':
    main()
