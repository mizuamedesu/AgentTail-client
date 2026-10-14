#!/usr/bin/env python3
"""Assemble a desktop or NanoKVM release from a successful CI run, then sign.
Never accepts the ephemeral acceptance-fixture artifacts or a failed run.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import subprocess
import tempfile

p = argparse.ArgumentParser(description=__doc__)
p.add_argument('--profile', choices=['desktop', 'nanokvm'], default='desktop')
p.add_argument('--run', required=True, type=int)
p.add_argument('--version', required=True)
p.add_argument('--sequence', required=True, type=int)
p.add_argument('--dir', required=True, type=Path)
a = p.parse_args()
run = json.loads(subprocess.check_output(['gh', 'run', 'view', str(a.run), '--json', 'conclusion,headSha,url,jobs'], text=True))
if run['conclusion'] != 'success' or any(j['conclusion'] != 'success' for j in run['jobs']):
    p.error('all verification jobs must succeed before assembling a release')
if a.dir.exists() and any(a.dir.iterdir()):
    p.error('output directory must be empty')
a.dir.mkdir(parents=True, exist_ok=True)
trust = Path('internal/distribution/trusted.pub').read_bytes()
trust = trust.replace(b'\r\n', b'\n')
trust_variants = (trust, trust.replace(b'\n', b'\r\n'))
files = {}
with tempfile.TemporaryDirectory(prefix='agenttail-release-') as tmp:
    subprocess.run(['gh', 'run', 'download', str(a.run), '--pattern', 'native-*', '--dir', tmp], check=True)
    required = ['agenttail-linux-riscv64'] if a.profile == 'nanokvm' else [
        f'agenttail-{system}-{arch}' + ('.exe' if system == 'windows' else '')
        for system in ('linux', 'darwin', 'windows') for arch in ('amd64', 'arm64')]
    if a.profile == 'desktop':
        required += [name for arch in ('amd64', 'arm64') for name in
                     (f'wintun-windows-{arch}.dll', f'wintun-license-{arch}.txt')]
    for name in required:
        candidates = list(Path(tmp).rglob(name))
        if not candidates or any(f.is_symlink() or not f.is_file() for f in candidates):
            p.error(f'missing or invalid native artifact: {name}')
        raw = candidates[0].read_bytes()
        if any(f.read_bytes() != raw for f in candidates[1:]):
            p.error(f'conflicting native artifacts: {name}')
        if name.startswith('agenttail-'):
            metadata = subprocess.check_output(['go', 'version', '-m', str(candidates[0])], text=True)
            build = json.loads(candidates[0].with_name(name+'.build.json').read_text())
            _, system, arch = name.removesuffix('.exe').split('-')
            if build['os'] != system or build['arch'] != arch or 'GOOS='+system not in metadata or 'GOARCH='+arch not in metadata:
                p.error(f'artifact platform does not match its name: {name}')
            # Git's Windows checkout can embed CRLF PEM. Its RSA key is
            # identical; require one exact known encoding and its recorded hash.
            matching_trust = any(t in raw and build['trust_sha256'] == hashlib.sha256(t).hexdigest() for t in trust_variants)
            if build['version'] != a.version or build['acceptance_fixture'] or build['sha256'] != hashlib.sha256(raw).hexdigest() or not matching_trust or 'acceptance' in metadata:
                p.error(f'wrong version, fixture or trust key: {name}')
            if 'vcs.revision='+run['headSha'] not in metadata or 'vcs.modified=false' not in metadata:
                p.error(f'binary was built from a different or modified commit: {name}')
            if arch == 'riscv64' and ('GORISCV64=rva20u64' not in metadata or 'CGO_ENABLED=0' not in metadata):
                p.error('NanoKVM requires a static baseline RV64GC build')
            if 'darwin' in name and 'CGO_ENABLED=1' not in metadata:
                p.error('macOS release must use native Keychain support')
            if 'darwin' in name and not build['native_version_executed']:
                p.error('macOS artifact must have executed on its native builder')
        target = a.dir / name
        target.write_bytes(raw)
        target.chmod(0o755 if name.startswith('agenttail-') and not name.endswith('.exe') else 0o644)
        files[name] = {'bytes': len(raw), 'sha256': hashlib.sha256(raw).hexdigest()}
subprocess.run(['python3', 'scripts/sign-release.py', '--dir', str(a.dir), '--version', a.version, '--sequence', str(a.sequence)], check=True)
for name in ('install.sh', 'install.ps1'):
    shutil.copyfile(Path('install') / name, a.dir / name)
shutil.copyfile('internal/notices/native.txt', a.dir / 'THIRD_PARTY_NOTICES.txt')
(a.dir / 'provenance.json').write_text(json.dumps({'version': a.version, 'commit': run['headSha'], 'workflow': run['url'], 'files': files}, indent=2) + '\n')
print(f'Assembled and signed {a.profile} release at {a.dir}; source {run["headSha"]}')
