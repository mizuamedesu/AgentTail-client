#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Render portable HTTPS/checksum bootstrap installers."""
from pathlib import Path

root = Path(__file__).resolve().parents[1]
for name in ('install.sh', 'install.ps1'):
    template = (root/'install'/f'{name}.in').read_text()
    (root/'install'/name).write_text(template, newline='\n')
print('HTTPS/checksum bootstrap installers generated.')
