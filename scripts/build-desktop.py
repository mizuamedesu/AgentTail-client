#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Build and package the desktop window on its native operating system."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import plistlib
import re
import shutil
import subprocess
import tarfile
import tempfile
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--dir', type=Path, required=True)
p.add_argument('--version', required=True)
p.add_argument('--window-smoke',action='store_true')
p.add_argument('--os', choices=['linux', 'darwin', 'windows'], required=True)
p.add_argument('--arch', choices=['amd64', 'arm64'], required=True)
a = p.parse_args()
native_os = {'Linux': 'linux', 'Darwin': 'darwin', 'Windows': 'windows'}.get(platform.system())
native_arch = {'arm64': 'arm64', 'aarch64': 'arm64', 'x86_64': 'amd64', 'amd64': 'amd64'}.get(platform.machine().lower())
if (a.os, a.arch) != (native_os, native_arch):
    p.error('desktop artifacts must be built and executed on their native OS and architecture')
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?', a.version):
    p.error('invalid version')
a.dir.mkdir(parents=True, exist_ok=True)
name = f'agenttail-desktop-{a.os}-{a.arch}'
archive = a.dir/(name+('.zip' if a.os == 'windows' else '.tar.gz'))
environment = dict(os.environ, GOOS=a.os, GOARCH=a.arch, CGO_ENABLED='1')
flags = '-s -w -X main.version='+a.version
if a.os == 'windows': flags += ' -H=windowsgui'
with tempfile.TemporaryDirectory(prefix='agenttail-desktop-build-') as temp:
    root = Path(temp)
    if a.os == 'darwin':
        bundle = root/'AgentTail.app'
        executable = bundle/'Contents/MacOS/agenttail-desktop'
        executable.parent.mkdir(parents=True)
        (bundle/'Contents/Info.plist').write_bytes(plistlib.dumps({
            'CFBundleName': 'AgentTail', 'CFBundleDisplayName': 'AgentTail',
            'CFBundleIdentifier': 'io.agenttail.desktop', 'CFBundleExecutable': 'agenttail-desktop',
            'CFBundlePackageType': 'APPL', 'CFBundleShortVersionString': a.version.split('-')[0],
            'CFBundleVersion': a.version.split('-')[0].rsplit('.',1)[0]+'.'+re.search(r'([0-9]+)$',a.version).group(1),
            'NSHighResolutionCapable': True, 'NSPrincipalClass': 'NSApplication',
            'LSMinimumSystemVersion': '11.0',
        }))
    else:
        executable = root/('agenttail-desktop.exe' if a.os == 'windows' else 'agenttail-desktop')
    subprocess.run(['go', 'build', '-tags', 'desktop', '-trimpath', '-ldflags', flags,
        '-o', str(executable), './cmd/agenttail-desktop'], env=environment, check=True)
    version = json.loads(subprocess.check_output([str(executable), '--version', '--json'], text=True))
    if version != {'ok': True, 'data': {'component': 'desktop', 'version': a.version}}:
        raise RuntimeError('desktop binary did not report the requested version')
    if a.os == 'darwin':
        subprocess.run(['codesign', '--force', '--sign', os.environ.get('AGENTTAIL_CODESIGN_IDENTITY', '-'),
            '--identifier', 'io.agenttail.desktop', str(bundle)], check=True)
        subprocess.run(['codesign', '--verify', '--deep', '--strict', str(bundle)], check=True)
    metadata = subprocess.check_output(['go', 'version', '-m', str(executable)], text=True)
    if 'CGO_ENABLED=1' not in metadata or 'acceptance' in metadata:
        raise RuntimeError('desktop build must use native graphics, without acceptance fixtures')
    shutil.copyfile('LICENSE', root/'GPL-3.0.txt')
    shutil.copyfile('internal/notices/desktop.txt', root/'THIRD_PARTY_NOTICES.txt')
    shutil.copyfile('cmd/agenttail-desktop/icon.svg', root/'agenttail.svg')
    if a.os == 'windows':
        with zipfile.ZipFile(archive, 'w', compression=zipfile.ZIP_DEFLATED, compresslevel=9) as packed:
            for item in sorted(root.rglob('*')):
                if item.is_file(): packed.write(item, item.relative_to(root).as_posix())
    else:
        with tarfile.open(archive, 'w:gz') as packed:
            for item in sorted(root.iterdir()): packed.add(item, arcname=item.name)
    proof = {'version': a.version, 'os': a.os, 'arch': a.arch,
        'archive': archive.name, 'bytes': archive.stat().st_size,
        'sha256': hashlib.sha256(archive.read_bytes()).hexdigest(),
        'binary_sha256': hashlib.sha256(executable.read_bytes()).hexdigest(),
        'build_metadata': metadata, 'native_version_executed': True,
        'commit': subprocess.check_output(['git', 'rev-parse', 'HEAD'], text=True).strip()}
    if proof['bytes'] > 24*1024*1024: raise RuntimeError('desktop bundle exceeds the static asset limit')
    archive.with_name(archive.name+'.build.json').write_text(json.dumps(proof, indent=2)+'\n')
    archive.with_name(archive.name+'.sha256').write_text(proof['sha256']+'  '+archive.name+'\n', encoding='ascii', newline='\n')
if a.window_smoke:
    if os.environ.get('GITHUB_ACTIONS')!='true': p.error('window smoke fixtures are CI-only')
    with tempfile.TemporaryDirectory(prefix='agenttail-desktop-window-') as temp:
        fixture=Path(temp)/('desktop-window.exe' if a.os=='windows' else 'desktop-window')
        subprocess.run(['go','build','-tags','desktop,acceptance','-trimpath','-ldflags',flags,'-o',str(fixture),'./cmd/agenttail-desktop'],env=environment,check=True)
        proof_path=a.dir.resolve()/'native-window.json'
        command=[str(fixture),'--acceptance-ui-proof',str(proof_path)]
        if a.os=='linux':command=['xvfb-run','-a',*command]
        subprocess.run(command,env=dict(environment,LIBGL_ALWAYS_SOFTWARE='1'),check=True,timeout=60)
        window_proof=json.loads(proof_path.read_text())
        if not all(window_proof.get(key) for key in ('native_window_started','selection_scope','other_vpn_preserved','state_refreshed')):raise RuntimeError('native window controls failed')
print(f'Built native desktop bundle {archive.name} ({proof["bytes"]} bytes)')
