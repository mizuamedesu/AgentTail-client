#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Require successful native checks and collect the matching desktop bundles."""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import tarfile
import zipfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--run', type=int, required=True)
p.add_argument('--version', required=True)
p.add_argument('--sequence', type=int, required=True)
p.add_argument('--dir', type=Path, required=True)
a = p.parse_args()
run = json.loads(subprocess.check_output(['gh','run','view',str(a.run),'--json','conclusion,headSha,url,jobs'], text=True))
if run['conclusion'] != 'success' or any(j['conclusion'] != 'success' for j in run['jobs']):
    p.error('all native verification jobs must pass')
a.dir.mkdir(parents=True, exist_ok=True)
manifest = {'schema':1, 'version':a.version, 'sequence':a.sequence, 'commit':run['headSha'], 'bundles':[]}
with tempfile.TemporaryDirectory(prefix='agenttail-desktop-assemble-') as temp:
    subprocess.run(['gh','run','download',str(a.run),'--pattern','desktop-native-*','--dir',temp],check=True)
    for system, arch in [('linux','amd64'),('darwin','amd64'),('darwin','arm64'),('windows','amd64')]:
        name=f'agenttail-desktop-{system}-{arch}'+('.zip' if system=='windows' else '.tar.gz')
        candidates=list(Path(temp).rglob(name))
        if len(candidates)!=1 or candidates[0].is_symlink(): p.error('missing or duplicated desktop bundle: '+name)
        payload=candidates[0].read_bytes()
        proof=json.loads(candidates[0].with_name(name+'.build.json').read_text())
        if any(proof[k]!=v for k,v in {'version':a.version,'os':system,'arch':arch,'archive':name,'bytes':len(payload),'sha256':hashlib.sha256(payload).hexdigest(),'native_version_executed':True,'commit':run['headSha']}.items()):
            p.error('desktop bundle provenance mismatch: '+name)
        member='AgentTail.app/Contents/MacOS/agenttail-desktop' if system=='darwin' else 'agenttail-desktop.exe' if system=='windows' else 'agenttail-desktop'
        if system=='windows':
            with zipfile.ZipFile(candidates[0]) as packed: binary=packed.read(member)
        else:
            with tarfile.open(candidates[0]) as packed: binary=packed.extractfile(member).read()
        if hashlib.sha256(binary).hexdigest()!=proof['binary_sha256']:p.error('desktop executable hash mismatch: '+name)
        executable=Path(temp)/('inspect-'+system+'-'+arch)
        executable.write_bytes(binary)
        metadata=subprocess.check_output(['go','version','-m',str(executable)],text=True)

        if any(v not in metadata for v in ['GOOS='+system,'GOARCH='+arch,'CGO_ENABLED=1','vcs.revision='+run['headSha'],'vcs.modified=false']) or 'acceptance' in metadata:
            p.error('desktop bundle was built from another or modified revision: '+name)
        shutil.copyfile(candidates[0],a.dir/name)
        (a.dir/(name+'.sha256')).write_text(proof['sha256']+'  '+name+'\n',encoding='ascii',newline='\n')
        manifest['bundles'].append({k:proof[k] for k in ('os','arch','archive','bytes','sha256')})
raw=(json.dumps(manifest,indent=2)+'\n').encode()
(a.dir/'desktop.json').write_bytes(raw)
(a.dir/'desktop.json.sha256').write_text(hashlib.sha256(raw).hexdigest()+'  desktop.json\n',encoding='ascii',newline='\n')
print('Assembled four natively verified desktop bundles.')
