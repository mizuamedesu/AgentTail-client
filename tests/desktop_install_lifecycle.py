#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Install a native GUI bundle, exercise its scoped helper, then remove it.
Uses an empty state and refuses to replace an existing AgentTail installation.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import socket
import subprocess
import tempfile
import time
import urllib.error
import urllib.request

p=argparse.ArgumentParser(description=__doc__)
p.add_argument('--native',type=Path,required=True)
p.add_argument('--desktop',type=Path,required=True)
p.add_argument('--report',type=Path,required=True)
a=p.parse_args()
system={'Linux':'linux','Darwin':'darwin','Windows':'windows'}[platform.system()]
arch={'arm64':'arm64','aarch64':'arm64','x86_64':'amd64','amd64':'amd64'}[platform.machine().lower()]
root=Path('/Library/AgentTail' if system=='darwin' else '/usr/local/lib/agenttail')
if system=='windows':
    root=Path(subprocess.check_output(['powershell','-NoProfile','-NonInteractive','-Command',"[Environment]::GetFolderPath('ProgramFiles')"],text=True).strip())/'AgentTail'
if (root/'installation.json').exists() or (root/'desktop/installation.json').exists():
    raise RuntimeError('An existing installation must not be replaced by GUI verification')
native=a.native.resolve()/f'agenttail-{system}-{arch}'
if system=='windows':native=native.with_suffix('.exe')
version=json.loads(subprocess.check_output([str(native),'version','--json'],text=True))['data']['version']
metadata=next(a.desktop.resolve().glob(f'agenttail-desktop-{system}-{arch}.*.build.json'))
proof=json.loads(metadata.read_text())
assert proof['version']==version and proof['native_version_executed']
helper=None
installed=False
report={'version':version,'os':system,'arch':arch,'empty_client_state':True,'live_account_or_device_registration':False}
with tempfile.TemporaryDirectory(prefix='agenttail-desktop-acceptance-') as temporary:
    temp=Path(temporary)
    state=temp/'state';state.mkdir(mode=0o700)
    bundle=temp/'bundle';bundle.mkdir()
    shutil.copyfile(native,bundle/native.name)
    if system=='windows':
        for name in (f'wintun-windows-{arch}.dll',f'wintun-license-{arch}.txt'):
            shutil.copyfile(a.native/name,bundle/name)
    subprocess.run(['python3','scripts/sign-release.py','--dir',str(bundle),'--version',version,'--sequence','2026101591','--checksums'],check=True)
    archive=a.desktop.resolve()/proof['archive']
    assert hashlib.sha256(archive.read_bytes()).hexdigest()==proof['sha256']
    shutil.copyfile(archive,bundle/archive.name)
    manifest={'schema':1,'version':version,'sequence':2026101591,'commit':proof['commit'],'bundles':[{k:proof[k] for k in ('os','arch','archive','bytes','sha256')}]}
    raw=(json.dumps(manifest,indent=2)+'\n').encode()
    (bundle/'desktop.json').write_bytes(raw)
    (bundle/'desktop.json.sha256').write_text(hashlib.sha256(raw).hexdigest()+'  desktop.json\n',encoding='ascii',newline='\n')
    permissions={} if system=='windows' else {'umask':0o077}
    def run(*args,ok=True):
        result=subprocess.run([str(native),'--state-dir',str(state),'--json',*map(str,args)],capture_output=True,text=True,timeout=120,**permissions)
        assert (result.returncode==0)==ok,(args,result.returncode,result.stderr[:1500])
        return json.loads(result.stdout if ok else result.stderr)
    try:
        install_args=('install','--bundle',bundle,'--source','https://agenttail.mizuame.app/downloads/current','--https-checksums','--no-service','--gui=true')
        run(*install_args);installed=True
        gui=json.loads((root/'desktop/installation.json').read_text())
        assert gui['version']==version
        executable=root/'desktop/releases'/gui['release_id']/('agenttail-desktop.exe' if system=='windows' else 'agenttail-desktop')
        if system=='darwin':executable=executable.parent/'AgentTail.app/Contents/MacOS/agenttail-desktop'
        actual=json.loads(subprocess.check_output([str(executable),'--version','--json'],text=True))
        assert actual['data']['version']==version
        if system in ('linux','darwin') and os.geteuid()==0:
            prefix=['runuser','-u','nobody','--'] if system=='linux' else ['sudo','-n','-u','nobody','--']
            ordinary=json.loads(subprocess.check_output([*prefix,str(executable),'--version','--json'],text=True))
            assert ordinary['data']['version']==version
            report['ordinary_user_can_execute']=True
        run(*install_args)
        assert json.loads((root/'desktop/installation.json').read_text())==gui
        report.update({'gui_install':True,'private_bootstrap_umask':True,'same_release_reinstall':True})
        with socket.socket() as reserved:
            reserved.bind(('127.0.0.1',0));port=reserved.getsockname()[1]
        secret=secrets.token_urlsafe(32)
        session=temp/'session.json'
        session.write_text(json.dumps({'port':port,'secret':secret,'created':int(time.time()),'version':version}))
        if system!='windows':session.chmod(0o600)
        helper=subprocess.Popen([str(native),'--state-dir',str(state),'desktop-helper','--session-file',str(session)],stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        def request(path,body=None,authorized=True):
            data=None if body is None else json.dumps(body).encode()
            headers={'Content-Type':'application/json'}
            if authorized:headers['Authorization']='Bearer '+secret
            query=urllib.request.Request(f'http://127.0.0.1:{port}'+path,data=data,headers=headers)
            opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
            with opener.open(query,timeout=5) as response:return json.load(response)
        deadline=time.monotonic()+20
        while True:
            try:snapshot=request('/v1/status');break
            except (urllib.error.URLError,ConnectionError):
                if time.monotonic()>deadline:raise
                time.sleep(0.1)
        assert snapshot=={'version':version,'running':False,'vpns':[]},snapshot
        try:request('/v1/status',authorized=False);raise AssertionError('unauthorized helper request accepted')
        except urllib.error.HTTPError as error:assert error.code==403
        request('/v1/close',{})
        helper.wait(timeout=10)
        assert helper.returncode==0,helper.stderr.read().decode()[:1500]
        report.update({'real_helper':True,'capability_required':True,'no_credentials_exported':True,'helper_clean_exit':True})
    finally:
        if helper is not None and helper.poll() is None:
            helper.terminate();helper.wait(timeout=10)
        if installed:
            removed=run('uninstall','--yes','--offline','--purge')['data']
            assert removed['uninstalled'] and not (root/'installation.json').exists()
            assert not (root/'desktop/installation.json').exists()
            report['gui_and_cli_uninstalled']=True
a.report.parent.mkdir(parents=True,exist_ok=True)
a.report.write_text(json.dumps(report,indent=2)+'\n')
print(json.dumps(report,indent=2))
