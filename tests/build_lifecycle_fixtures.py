#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""CI-only fixture binaries with an ephemeral test trust key. Never published.
Production native artifacts must be built/uploaded BEFORE this test step.
"""
import argparse
import os
import platform
from pathlib import Path
import subprocess
import tempfile

if os.environ.get('GITHUB_ACTIONS') != 'true':
    raise SystemExit('CI fixture builder refuses to replace the trust key outside GitHub Actions')
trust=Path('internal/distribution/trusted.pub')
original=trust.read_bytes()
system={'Linux':'linux','Darwin':'darwin','Windows':'windows'}[platform.system()]
parser=argparse.ArgumentParser()
parser.add_argument('--arch', choices=['amd64','arm64','riscv64'])
arch=parser.parse_args().arch or {'arm64':'arm64','aarch64':'arm64','riscv64':'riscv64','x86_64':'amd64','amd64':'amd64'}[platform.machine().lower()]
try:
    with tempfile.TemporaryDirectory(prefix='agenttail-ci-signing-') as tmp:
        key=Path(tmp)/'fixture.key'
        subprocess.run(['openssl','genpkey','-algorithm','RSA','-pkeyopt','rsa_keygen_bits:3072','-out',str(key)],check=True,stderr=subprocess.DEVNULL)
        key.chmod(0o600)
        subprocess.run(['openssl','pkey','-in',str(key),'-pubout','-out',str(trust)],check=True)
        # Separate versions for the checksum cycle: Windows can retain a loaded
        # executable until reboot after uninstall, while removing its DLLs now.
        for sequence in (1,2,3,4):
            directory=f'build/lifecycle-v{sequence}'
            version=f'0.0.0-ci.{sequence}'
            subprocess.run(['python3','scripts/build-native.py','--dir',directory,'--version',version,'--os',system,'--arch',arch,'--acceptance-fixture'],check=True)
            subprocess.run(['python3','scripts/sign-release.py','--dir',directory,'--version',version,'--sequence',str(sequence),'--key',str(key)],check=True)
finally:
    trust.write_bytes(original)
