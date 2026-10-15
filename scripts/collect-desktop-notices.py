#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Preserve dependency, font and vendored C-library notices for the desktop."""
import json
from pathlib import Path
import subprocess

raw=subprocess.check_output(['go','list','-m','-json','all'],text=True)
decoder=json.JSONDecoder()
modules=[]
while raw.strip():
    raw=raw.lstrip()
    item,end=decoder.raw_decode(raw)
    modules.append(item)
    raw=raw[end:]
notices={}
goroot=Path(subprocess.check_output(['go','env','GOROOT'],text=True).strip())
notices['Go standard library / LICENSE']=(goroot/'LICENSE').read_text()
for module in modules:
    if module.get('Main') or not module.get('Dir'): continue
    root=Path(module['Dir'])
    for item in sorted(root.rglob('*')):
        if item.is_file() and item.name.upper().startswith(('LICENSE','COPYING','NOTICE','OFL','COPYRIGHT','UNLICENSE')):
            notices[module['Path']+'@'+module['Version']+' / '+item.relative_to(root).as_posix()]=item.read_text(encoding='utf-8',errors='replace')
text=['Third-party notices for the AgentTail desktop and corresponding native-client source.',
      'Includes dependency tests, font licenses and vendored graphics-library notices.','']
for name,body in sorted(notices.items()):
    text += ['='*78,name,'='*78,body.rstrip(),'']
target=Path('internal/notices/desktop.txt')
target.write_text('\n'.join(text)+'\n')
print(f'Preserved {len(notices)} desktop and source dependency notices.')
