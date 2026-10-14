#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Embed the pinned PUBLIC release key into portable bootstrap installers."""
import base64
from pathlib import Path
import re
import subprocess

root = Path(__file__).resolve().parents[1]
key = root / 'internal/distribution/trusted.pub'
modulus = subprocess.check_output(['openssl', 'rsa', '-pubin', '-in', str(key), '-modulus', '-noout'], text=True).strip().split('=', 1)[1]
detail = subprocess.check_output(['openssl', 'pkey', '-pubin', '-in', str(key), '-text', '-noout'], text=True)
exponent = int(re.search(r'Exponent: (\d+)', detail).group(1))
encoded_e = base64.b64encode(exponent.to_bytes((exponent.bit_length()+7)//8, 'big')).decode()
xml = '<RSAKeyValue><Modulus>'+base64.b64encode(bytes.fromhex(modulus)).decode()+'</Modulus><Exponent>'+encoded_e+'</Exponent></RSAKeyValue>'
for name in ('install.sh', 'install.ps1'):
    template = (root/'install'/f'{name}.in').read_text()
    (root/'install'/name).write_text(template.replace('@PUBLIC_PEM@', key.read_text().strip()).replace('@PUBLIC_XML@', xml))
print('Bootstrap installers generated with pinned public key.')
