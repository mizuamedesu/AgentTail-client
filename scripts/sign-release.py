#!/usr/bin/env python3
"""Sign existing native build outputs. Private key stays on the signing host.
Usage: python3 scripts/sign-release.py --version 0.1.0 --sequence 1 --dir build/release
Native macOS outputs MUST be built with CGO_ENABLED=1 on macOS.
"""
import argparse
import hashlib
import os
from pathlib import Path
import re
import subprocess
import time


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--version', required=True)
    p.add_argument('--sequence', required=True, type=int)
    p.add_argument('--dir', required=True, type=Path)
    p.add_argument('--key', type=Path, default=Path('.secrets/release-signing.key'))
    p.add_argument('--valid-days', type=int, default=90)
    a = p.parse_args()
    if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?', a.version) or a.sequence < 1 or not 1 <= a.valid_days <= 366:
        p.error('invalid release metadata')
    if os.name != 'nt' and a.key.stat().st_mode & 0o077:
        p.error('private signing key must have mode 0600 or stricter')
    # Compare the public key itself; Windows OpenSSL may emit CRLF PEM.
    expected = subprocess.check_output(['openssl', 'pkey', '-pubin', '-in', 'internal/distribution/trusted.pub', '-outform', 'DER'])
    public = subprocess.check_output(['openssl', 'pkey', '-in', str(a.key), '-pubout', '-outform', 'DER'])
    if public != expected:
        p.error('signing key does not match pinned trust key')
    now = int(time.time())
    lines = ['agenttail-manifest-v1', f'version {a.version}', f'sequence {a.sequence}', f'created {now}', f'expires {now + a.valid_days * 86400}']
    count = 0
    for system in ('linux', 'darwin', 'windows'):
        for arch in (('amd64', 'arm64', 'riscv64') if system == 'linux' else ('amd64', 'arm64')):
            name = f'agenttail-{system}-{arch}' + ('.exe' if system == 'windows' else '')
            if not (a.dir / name).exists():
                continue
            files = [('vpn', name)]
            if system == 'windows':
                files += [('wintun', f'wintun-windows-{arch}.dll'), ('license', f'wintun-license-{arch}.txt')]
            for role, filename in files:
                data = (a.dir / filename).read_bytes()
                if not 0 < len(data) <= 64 * 1024 * 1024:
                    p.error('artifact exceeds supported size')
                lines.append(f'file {system} {arch} {role} {filename} {len(data)} {hashlib.sha256(data).hexdigest()} -')
            count += 1
    if not count:
        p.error('no native artifacts found')
    manifest = a.dir / 'manifest.txt'
    manifest.write_text('\n'.join(lines) + '\n', encoding='ascii', newline='\n')
    subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(a.key), '-out', str(a.dir / 'manifest.sig'), str(manifest)], check=True)
    print(f'Signed {count} platform(s), version {a.version}, sequence {a.sequence}; publish only after native verification.')


if __name__ == '__main__':
    main()
