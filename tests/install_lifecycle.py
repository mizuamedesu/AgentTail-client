#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Native install/update/uninstall acceptance. Uses isolated empty client state.
Refuses to replace any existing installation. Needs an elevated terminal and
two signed bundles with increasing sequence numbers. --with-service requires
a live native service manager; reboot and account/device login are separate.
"""
import argparse
from contextlib import contextmanager
import json
import os
from pathlib import Path
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
import time


@contextmanager
def delayed_launchd_agent(state):
    """Replace only this test's already stopped service with a slow-stop fixture."""
    if os.environ.get('GITHUB_ACTIONS') != 'true' or sys.platform != 'darwin':
        raise RuntimeError('Delayed launchd fixture is CI-only')
    import fcntl
    # The fixture itself must not race the real daemon being replaced.
    deadline = time.monotonic()+30
    with (state/'agent.lock').open('a') as lock:
        while True:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except BlockingIOError:
                if time.monotonic() > deadline:
                    raise AssertionError('Previous test agent did not stop')
                time.sleep(.1)
    path = Path('/Library/LaunchDaemons/io.agenttail.vpn.plist')
    original = path.read_bytes()
    job = plistlib.loads(original)
    assert job['ProgramArguments'][2] == str(state)
    job['ProgramArguments'] = [sys.executable, str(Path(__file__).with_name('delayed_launchd_agent.py').resolve()), str(state)]
    for name in ('fixture-ready','shutdown-started','shutdown-finished'):
        (state/name).unlink(missing_ok=True)
    (state/'launchd-fixture-enabled').touch()
    try:
        path.write_bytes(plistlib.dumps(job))
        subprocess.run(['/bin/launchctl','bootstrap','system',str(path)],check=True,timeout=30)
        deadline = time.monotonic()+10
        while not (state/'fixture-ready').exists():
            if time.monotonic() > deadline:
                raise AssertionError('Delayed launchd fixture did not acquire agent lock')
            time.sleep(.1)
        yield
        assert (state/'shutdown-started').exists() and (state/'shutdown-finished').exists()
    finally:
        # If the test failed, remove the fixture before restoring the real plist.
        subprocess.run(['/bin/launchctl','bootout','system/io.agenttail.vpn'],capture_output=True,timeout=30)
        path.write_bytes(original)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument('--arch', choices=['amd64','arm64','riscv64'])
    p.add_argument('--emulated', action='store_true')
    p.add_argument('--first', type=Path, required=True)
    p.add_argument('--second', type=Path, required=True)
    p.add_argument('--with-service', action='store_true')
    p.add_argument('--credentials', action='store_true', help='exercise CI-only native credential fixtures across versions')
    p.add_argument('--report', type=Path)
    p.add_argument('--https-checksums', action='store_true', help='exercise HTTPS/checksum install and recorded updates')
    a = p.parse_args()
    system = {'Linux':'linux', 'Darwin':'darwin', 'Windows':'windows'}[platform.system()]
    arch = a.arch or {'arm64':'arm64','aarch64':'arm64','riscv64':'riscv64','x86_64':'amd64','amd64':'amd64'}[platform.machine().lower()]
    exe = 'agenttail-'+system+'-'+arch+('.exe' if system=='windows' else '')
    legacy_first = not (a.first/exe).exists()
    if legacy_first: exe = 'vpn-'+system+'-'+arch+('.exe' if system=='windows' else '')
    bootstrap = (a.first/exe).resolve()
    root = Path(os.environ.get('ProgramFiles', r'C:\Program Files'))/'AgentTail' if system=='windows' else Path('/usr/local/lib/agenttail')
    if system=='darwin': root=Path('/Library/AgentTail')
    record = root/'installation.json'
    if record.exists():
        raise RuntimeError('Existing installation found; acceptance test will not replace it')
    state = Path(tempfile.mkdtemp(prefix='agenttail-install-state-'))

    def run(binary, *args, ok=True):
        if args and args[0]=='install':
            args=(args[0], '--gui=false', *args[1:])
        if a.https_checksums and args[0]=='install':
            args=(*args,'--https-checksums')
        # Match install.sh, including its restrictive umask after elevation.
        permissions = {} if system=='windows' else {'umask':0o077}
        result = subprocess.run([str(binary),'--state-dir',str(state),'--json',*map(str,args)],capture_output=True,text=True,timeout=90,**permissions)
        if (result.returncode==0) != ok:
            raise AssertionError(f'{args[0]} unexpected exit {result.returncode}: {result.stderr[:800]}')
        return json.loads(result.stdout if ok else result.stderr)

    def installed():
        r = json.loads(record.read_text())
        return root/'releases'/r['release_id']/('vpn.exe' if system=='windows' else 'vpn')

    launcher = root/('agenttail.cmd' if system=='windows' else 'agenttail')
    legacy = root/('vpn.cmd' if system=='windows' else 'vpn')

    def unprivileged_cli(version):
        if system=='windows':
            return
        import pwd
        uid = int(os.environ.get('SUDO_UID','0'))
        user = pwd.getpwuid(uid) if uid else pwd.getpwnam('nobody')
        assert user.pw_uid != 0
        env = dict(os.environ, HOME=user.pw_dir, PATH=str(root)+':/usr/bin:/bin:/usr/sbin:/sbin')
        options = dict(user=user.pw_uid,group=user.pw_gid,extra_groups=[],env=env,cwd='/',capture_output=True,text=True,timeout=30)
        # A root-only check misses the failure: the service starts, but the
        # user's shell cannot even find agenttail before sudo can be invoked.
        result = subprocess.run(['/bin/sh','-c','command -v agenttail && agenttail version --json'],**options)
        assert result.returncode==0, f'Ordinary user cannot run the CLI: {result.stderr[:800]}'
        found, output = result.stdout.strip().split('\n',1)
        assert found==str(launcher) and json.loads(output)['data']['version']==version
        assert state.stat().st_mode & 0o777 == 0o700
        if system=='darwin':
            # Verify the actual fresh-login PATH setup as well as an explicit
            # PATH, without relying on the elevated installer's environment.
            options['env']=dict(env, PATH='/usr/bin:/bin:/usr/sbin:/sbin')
            login = subprocess.run(['/bin/zsh','-lc','command -v agenttail'],**options)
            assert login.returncode==0 and login.stdout.strip()==str(launcher), login.stderr[:800]

    startup_diagnostics_tested = system=='linux' and arch=='riscv64' and a.with_service
    if startup_diagnostics_tested:
        # A real child startup failure must survive rollback and reach the CLI,
        # rather than disappearing behind the health-check timeout.
        occupied = state/'agent.sock'
        occupied.write_text('occupied by the lifecycle fixture')
        failed = run(bootstrap,'install','--bundle',a.first.resolve(),ok=False)
        assert 'agent socket path is occupied by a non-socket file' in failed['error']['message']
        assert not record.exists() and not launcher.exists() and not (root/'pending.json').exists()
        log = Path('/var/run/agenttail-service/last-error.txt')
        assert 'agent socket path is occupied by a non-socket file' in log.read_text()
        assert log.stat().st_size <= 4097 and log.stat().st_mode & 0o777 == 0o600
        occupied.unlink()
    first = run(bootstrap,'install','--bundle',a.first.resolve(),*(() if a.with_service else ('--no-service',)))['data']
    assert first.get('verification','signature')==('https-sha256' if a.https_checksums else 'signature')
    if startup_diagnostics_tested:
        assert not Path('/var/run/agenttail-service/last-error.txt').exists()
    old = installed()
    assert (legacy.exists() and not launcher.exists()) if legacy_first else (launcher.exists() and not legacy.exists())
    assert run(old,'version')['data']['version']==first['version']
    assert run(old,'service','status')['data']['running']==a.with_service
    assert json.loads((state/'config.json').read_text())['keys']==[]
    if a.credentials:
        run(old,'_seed-acceptance')
        assert run(old,'_check-secrets')['data']['native_credentials_readable']
    permissions_repaired = system!='windows' and not legacy_first
    if permissions_repaired:
        unprivileged_cli(first['version'])
        # Reproduce dev.9: an intact launcher inside root-only directories.
        # Same-release reinstall must repair access without touching secrets.
        root.chmod(0o700)
        (root/'releases').chmod(0o700)
        repeated = run(bootstrap,'install','--bundle',a.first.resolve())['data']
        assert repeated==first
        unprivileged_cli(first['version'])
        if a.credentials:
            assert run(old,'_check-secrets')['data']['native_credentials_readable']
    # Simulate the public launcher left by an old updater. Reinstalling the
    # same signed release migrates only our alias and preserves credentials.
    if not legacy_first:
        if system=='windows': shutil.copyfile(launcher, legacy)
        else: legacy.symlink_to(old)
        launcher.unlink()
        repeated = run(bootstrap,'install','--bundle',a.first.resolve())['data']
        assert repeated['sequence']==first['sequence'] and launcher.exists() and not legacy.exists()
        assert run(old,'_check-secrets')['data']['native_credentials_readable']
    # A changed signed manifest cannot select an arbitrary replacement.
    tampered = Path(tempfile.mkdtemp(prefix='agenttail-tamper-'))
    proof='manifest.sha256' if a.https_checksums else 'manifest.sig'
    shutil.copy(a.second/proof,tampered/proof)
    (tampered/'manifest.txt').write_bytes((a.second/'manifest.txt').read_bytes()+b'\n')
    run(old,'update','--bundle',tampered,ok=False)
    assert json.loads(record.read_text())['sequence']==first['sequence']
    shutil.rmtree(tampered)
    delayed_shutdown_tested = system=='darwin' and a.with_service and os.environ.get('GITHUB_ACTIONS')=='true'
    if delayed_shutdown_tested:
        # Reproduce the retained journal on retry after launchd has received a
        # stop but the old process still holds agent.lock. Secrets stay native.
        run(old,'service','stop')
        run(old,'service','stop')  # An already unloaded job is a successful stop.
        with delayed_launchd_agent(state):
            (root/'pending.json').write_text(json.dumps({'Old':first,'New':first}))
            subprocess.run(['/bin/launchctl','bootout','system/io.agenttail.vpn'],check=True,timeout=30)
            recovered = run(bootstrap,'install','--bundle',a.first.resolve())['data']
            assert recovered == first and not (root/'pending.json').exists()
            assert run(old,'_check-secrets')['data']['native_credentials_readable']
        # The context cleanup unloaded the restored service. Check the direct
        # activation path too, using the freshly downloaded installer binary.
        run(old,'service','stop')
        with delayed_launchd_agent(state):
            new_bootstrap = a.second/('agenttail-'+system+'-'+arch)
            second = run(new_bootstrap.resolve(),'install','--bundle',a.second.resolve())['data']
        run(installed(),'service','stop')
        run(installed(),'service','start')
    elif legacy_first:
        new_bootstrap = a.second/('agenttail-'+system+'-'+arch+('.exe' if system=='windows' else ''))
        second = run(new_bootstrap.resolve(),'install','--bundle',a.second.resolve())['data']
    else:
        second = run(old,'update','--bundle',a.second.resolve())['data']
    current = installed()
    assert second['sequence']>first['sequence']
    assert run(current,'version')['data']['version']==second['version']
    assert run(current,'_check-secrets')['data']['native_credentials_readable']
    # A valid signature on an older release does not permit rollback.
    run(current,'update','--bundle',a.first.resolve(),ok=False)
    assert json.loads(record.read_text())['sequence']==second['sequence']
    assert run(current,'service','status')['data']['running']==a.with_service
    assert launcher.exists() and not legacy.exists()
    unprivileged_cli(second['version'])
    removed = run(current,'uninstall','--yes','--purge',*(('--offline',) if a.credentials else ()))['data']
    assert removed['uninstalled'] and not record.exists() and not (state/'config.json').exists()
    assert not launcher.exists()
    # Lock files have no secrets. Remove this test's own isolated directory.
    shutil.rmtree(state)
    report={'time':time.strftime('%Y-%m-%dT%H:%M:%SZ',time.gmtime()),'os':system,'arch':arch,'install':True,'update':True,'tamper_rejected':True,'rollback_rejected':True,'uninstall':True,'native_service_tested':a.with_service and not a.emulated,'service_tested':a.with_service,'cpu_emulated':a.emulated,'reboot_tested':False,'empty_client_state':True,'file_removal_requires_reboot':removed['file_removal_requires_reboot']}
    report['empty_client_state']=not a.credentials
    report['native_credentials_survived_update']=a.credentials
    report['legacy_launcher_migrated']=True
    report['legacy_release_updated']=legacy_first
    report['startup_failure_diagnostics_tested']=startup_diagnostics_tested
    report['delayed_launchd_shutdown_tested']=delayed_shutdown_tested
    report['pending_journal_recovery_tested']=delayed_shutdown_tested
    report['idempotent_service_stop_tested']=delayed_shutdown_tested
    report['restrictive_umask_tested']=system!='windows'
    report['unprivileged_cli_tested']=system!='windows'
    report['private_install_directories_repaired']=permissions_repaired
    report['macos_login_shell_path_tested']=system=='darwin'
    report['verification']='https-sha256' if a.https_checksums else 'signature'
    if a.report:
        a.report.parent.mkdir(parents=True,exist_ok=True)
        a.report.write_text(json.dumps(report,indent=2)+'\n')
    print(json.dumps(report,indent=2))


if __name__=='__main__':
    main()
