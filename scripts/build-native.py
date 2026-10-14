#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Produce native release artifacts. Never release a non-CGO macOS binary."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import subprocess

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--dir',type=Path,required=True)
p.add_argument('--version',required=True)
p.add_argument('--os',choices=['linux','darwin','windows'],required=True)
p.add_argument('--arch',choices=['amd64','arm64','riscv64'],required=True)
p.add_argument('--acceptance-fixture',action='store_true',help='CI-only binary, never distribute')
a=p.parse_args()
if not re.fullmatch(r'[0-9]+\.[0-9]+\.[0-9]+(?:-[a-z0-9]+(?:[.-][a-z0-9]+)*)?',a.version):
    p.error('invalid version')
if a.arch=='riscv64' and a.os!='linux':
    p.error('riscv64 is supported only on Linux')
if a.os=='darwin' and platform.system()!='Darwin':
    p.error('native macOS SDK and CGO are required; cross-built stubs are not releasable')
a.dir.mkdir(parents=True,exist_ok=True)
name=f'agenttail-{a.os}-{a.arch}'+('.exe' if a.os=='windows' else '')
env=dict(os.environ,GOOS=a.os,GOARCH=a.arch,CGO_ENABLED='1' if a.os=='darwin' else '0')
if a.arch=='riscv64': env['GORISCV64']='rva20u64' # SG2002/C906 baseline; no newer vector ISA
tags=[]
if a.acceptance_fixture:
    if os.environ.get('GITHUB_ACTIONS')!='true': p.error('acceptance fixtures are CI-only')
    tags=['-tags','acceptance']
subprocess.run(['go','build',*tags,'-trimpath','-ldflags',f'-s -w -X main.version={a.version}','-o',str(a.dir/name),'./cmd/agenttail'],env=env,check=True)
if a.os=='darwin':
    # A stable Developer ID identity may be supplied by the release operator.
    # Ad-hoc builds rely on explicit per-version Keychain ACL migration.
    identity=os.environ.get('AGENTTAIL_CODESIGN_IDENTITY','-')
    subprocess.run(['codesign','--force','--sign',identity,'--identifier','io.agenttail.vpn',str(a.dir/name)],check=True)
    subprocess.run(['codesign','--verify','--strict',str(a.dir/name)],check=True)
if a.os=='windows':
    subprocess.run(['python3','scripts/fetch-wintun.py','--dir',str(a.dir)],check=True)
native_os={'Linux':'linux','Darwin':'darwin','Windows':'windows'}.get(platform.system())
native_arch={'arm64':'arm64','aarch64':'arm64','x86_64':'amd64','amd64':'amd64','riscv64':'riscv64'}.get(platform.machine().lower())
version_executed=False
if (a.os,a.arch)==(native_os,native_arch):
    actual=json.loads(subprocess.check_output([str((a.dir/name).resolve()),'version','--json'],text=True))
    if not actual['ok'] or actual['data']['version']!=a.version:
        raise RuntimeError('compiled executable reports a different release version')
    version_executed=True
(a.dir/(name+'.build.json')).write_text(json.dumps({
    'version':a.version,'os':a.os,'arch':a.arch,'acceptance_fixture':a.acceptance_fixture,
    'native_version_executed':version_executed,
    'sha256':hashlib.sha256((a.dir/name).read_bytes()).hexdigest(),
    'trust_sha256':hashlib.sha256(Path('internal/distribution/trusted.pub').read_bytes()).hexdigest(),
},indent=2)+'\n')
print(f'Built {name}; version {a.version}')
