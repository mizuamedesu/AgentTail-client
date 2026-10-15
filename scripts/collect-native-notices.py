#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Preserve notices for packages compiled into the native CLI on each OS."""
import json
import os
from pathlib import Path
import subprocess


def values(raw):
    decoder = json.JSONDecoder()
    while raw.strip():
        raw = raw.lstrip()
        value, end = decoder.raw_decode(raw)
        yield value
        raw = raw[end:]


notices = {}
adapter = Path('internal/netstack/LICENSE')
notices['WireGuard netstack adapter / internal/netstack/LICENSE'] = (
    'Copyright (C) 2017-2025 WireGuard LLC. All Rights Reserved.\n\n'
    + adapter.read_text(encoding='utf-8')
)
goroot = Path(subprocess.check_output(['go', 'env', 'GOROOT'], text=True).strip()).resolve()
for system in ('linux', 'darwin', 'windows'):
    environment = dict(os.environ, GOOS=system, GOARCH='amd64', CGO_ENABLED='0')
    packages = subprocess.check_output(['go', 'list', '-deps', '-json', './cmd/agenttail'], env=environment, text=True)
    for package in values(packages):
        module = package.get('Module')
        if module and module.get('Main'):
            continue
        if not package.get('Dir'):
            continue
        root = Path(module['Dir']).resolve() if module else goroot
        label = module['Path'] + '@' + module['Version'] if module else 'Go standard library'
        directory = Path(package['Dir']).resolve()
        while directory.is_relative_to(root):
            for path in sorted(directory.iterdir()):
                if path.is_file() and path.name.upper().startswith(('LICENSE', 'COPYING', 'NOTICE')):
                    name = label + ' / ' + path.relative_to(root).as_posix()
                    notices[name] = path.read_text(encoding='utf-8')
            if directory == root:
                break
            directory = directory.parent

target = Path('internal/notices/native.txt')
target.parent.mkdir(parents=True, exist_ok=True)
text = ['Third-party notices for the AgentTail native CLI',
        'Generated from the compiled package dependency graph. Wintun DLL terms are distributed separately.', '']
for name, body in sorted(notices.items()):
    text += ['=' * 78, name, '=' * 78, body.rstrip(), '']
target.write_text('\n'.join(text) + '\n', encoding='utf-8')
print(f'Preserved {len(notices)} license/notice files in {target}')
