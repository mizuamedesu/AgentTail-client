#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Package an exact public client revision and all vendored Go dependencies."""
import argparse
import gzip
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import tarfile
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--ref', required=True)
p.add_argument('--version', required=True)
p.add_argument('--output', required=True, type=Path)
a = p.parse_args()
if not re.fullmatch(r'[A-Za-z0-9_.-]+', a.version):
    p.error('invalid source version')
commit = subprocess.check_output(['git', 'rev-parse', '--verify', a.ref+'^{commit}'], text=True).strip()
timestamp = int(subprocess.check_output(['git', 'show', '-s', '--format=%ct', commit], text=True))
archive = subprocess.check_output(['git', 'archive', '--format=tar', commit])
prefix = 'agenttail-client-'+a.version
with tempfile.TemporaryDirectory(prefix='agenttail-source-') as temporary:
    root = Path(temporary)
    with tarfile.open(fileobj=io.BytesIO(archive)) as exported:
        exported.extractall(root, filter='data')
    if (root/'apps/worker').exists() or (root/'wrangler.jsonc').exists():
        p.error('source archive contains backend implementation')
    subprocess.run(['go', 'mod', 'vendor'], cwd=root, check=True)
    (root/'SOURCE.json').write_text(json.dumps({
        'version': a.version, 'commit': commit,
        'repository': 'https://github.com/mizuamedesu/AgentTail-client',
        'license': 'GPL-3.0-or-later', 'go_dependencies': 'vendor/',
    }, indent=2)+'\n')
    a.output.parent.mkdir(parents=True, exist_ok=True)
    with a.output.open('wb') as raw, gzip.GzipFile(filename='', fileobj=raw, mode='wb', mtime=0) as compressed, tarfile.open(fileobj=compressed, mode='w') as packed:
        for path in sorted(root.rglob('*')):
            info = packed.gettarinfo(str(path), arcname=prefix+'/'+path.relative_to(root).as_posix())
            info.uid = info.gid = 0
            info.uname = info.gname = ''
            info.mtime = timestamp
            if path.is_file():
                with path.open('rb') as stream:
                    packed.addfile(info, stream)
            else:
                packed.addfile(info)
digest = hashlib.sha256(a.output.read_bytes()).hexdigest()
a.output.with_suffix(a.output.suffix+'.sha256').write_text(digest+'  '+a.output.name+'\n')
print(json.dumps({'version': a.version, 'commit': commit, 'archive': a.output.name, 'sha256': digest, 'bytes': a.output.stat().st_size}))
