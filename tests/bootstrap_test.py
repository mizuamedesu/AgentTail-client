#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-3.0-or-later
"""Exercise the streamed BusyBox installer using signed local fixtures only."""
import hashlib
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]


class BootstrapTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        if os.geteuid() != 0:
            raise unittest.SkipTest('NanoKVM bootstrap runs as root')
        cls.temporary = tempfile.TemporaryDirectory(prefix='agenttail-bootstrap-')
        cls.root = Path(cls.temporary.name)
        cls.key = cls.root / 'fixture.key'
        subprocess.run(['openssl', 'genpkey', '-algorithm', 'RSA', '-pkeyopt', 'rsa_keygen_bits:3072', '-out', str(cls.key)], check=True, stderr=subprocess.DEVNULL)
        cls.public = subprocess.check_output(['openssl', 'pkey', '-in', str(cls.key), '-pubout'], text=True)

    @classmethod
    def tearDownClass(cls):
        cls.temporary.cleanup()

    def attempt(self, cpu, arch, *, source=None, tamper=None, system='Linux', options=(), systemd=True):
        with tempfile.TemporaryDirectory(dir=self.root) as directory:
            base = Path(directory)
            binaries = base / 'bin'
            binaries.mkdir()
            artifact = base / f'agenttail-linux-{arch}'
            artifact.write_text('#!/bin/sh\nprintf "%s\\n" "$@" >> "$BOOT_EXEC"\n')
            raw = artifact.read_bytes()
            now = int(time.time())
            manifest = base / 'manifest.txt'
            manifest.write_text(f'agenttail-manifest-v1\nversion 0.0.0-test\nsequence 1\ncreated {now}\nexpires {now+3600}\nfile linux {arch} vpn {artifact.name} {len(raw)} {hashlib.sha256(raw).hexdigest()} -\n')
            subprocess.run(['openssl', 'dgst', '-sha256', '-sign', str(self.key), '-out', str(base/'manifest.sig'), str(manifest)], check=True)
            if tamper == 'manifest':
                manifest.write_text(manifest.read_text()+'\n')
            if tamper == 'binary':
                artifact.write_text(artifact.read_text()+'echo tampered\n')
            stubs = {
                'ip': '#!/bin/sh\nexit 0\n',
                'systemd-creds': '#!/bin/sh\nexit 0\n',
                'curl': '#!'+sys.executable+'\nimport os, pathlib, shutil, sys\na=sys.argv[1:]\nname=a[-1].rsplit("/",1)[1]\nshutil.copyfile(pathlib.Path(os.environ["BOOT_FILES"])/name, a[a.index("--output")+1])\nwith open(os.environ["BOOT_FETCH"],"a") as f: f.write(a[-1]+"\\n")\n',
            }
            for name, script in stubs.items():
                if name == 'systemd-creds' and not systemd:
                    continue
                path = binaries/name
                path.write_text(script)
                path.chmod(0o755)
            for name in ['awk', 'openssl', 'date', 'mktemp', 'rm', 'chmod', 'wc', 'tr', 'cat', 'id']:
                (binaries/name).symlink_to(shutil.which(name))
            env = dict(os.environ, PATH=str(binaries), BOOT_OS=system, BOOT_CPU=cpu, BOOT_FILES=str(base), BOOT_EXEC=str(base/'executed'), BOOT_FETCH=str(base/'fetched'))
            script = (ROOT/'install/install.sh.in').read_text().replace('@PUBLIC_PEM@', self.public.strip())
            # Standalone BusyBox ash resolves its uname applet before PATH.
            # A shell function supplies the simulated kernel CPU in both shells.
            script = 'uname() { case "$1" in -s) echo "$BOOT_OS";; -m) echo "$BOOT_CPU";; esac; }\n' + script
            command = [shutil.which('busybox'), 'sh', '-s', '--', '--no-service']
            if source:
                command += ['--source', source]
            command += list(options)
            result = subprocess.run(command, input=script, text=True, capture_output=True, env=env)
            executed = (base/'executed').read_text() if (base/'executed').exists() else ''
            fetched = (base/'fetched').read_text() if (base/'fetched').exists() else ''
            return result, executed, fetched

    def test_signed_cpu_selection_and_update_source(self):
        for cpu, arch, channel in [('x86_64','amd64','stable'),('aarch64','arm64','stable'),('riscv64','riscv64','nanokvm')]:
            with self.subTest(cpu=cpu):
                result, executed, fetched = self.attempt(cpu, arch)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('install\n--bundle\n', executed)
                self.assertIn('skills\ninstall\n', executed)
                self.assertIn('https://agenttail.mizuame.app/downloads/'+channel, executed)
                self.assertIn(f'/agenttail-linux-{arch}', fetched)
        result, executed, fetched = self.attempt('riscv64','riscv64',source='https://fixture.example.invalid/custom')
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn('https://fixture.example.invalid/custom', executed)
        self.assertNotIn('mizuame.app', fetched)

    def test_tampered_release_is_never_executed(self):
        for tamper in ['manifest', 'binary']:
            with self.subTest(tamper=tamper):
                result, executed, _ = self.attempt('riscv64','riscv64',tamper=tamper)
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(executed, '')

    def test_linux_without_systemd_creds_executes_verified_installer(self):
        for cpu, arch in [('x86_64', 'amd64'), ('aarch64', 'arm64')]:
            with self.subTest(cpu=cpu):
                result, executed, fetched = self.attempt(cpu, arch, systemd=False)
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertIn('using encrypted root-only host credentials', result.stdout)
                self.assertIn('install\n--bundle\n', executed)
                self.assertIn(f'/agenttail-linux-{arch}', fetched)

    def test_private_key_needs_only_its_name(self):
        result, executed, _ = self.attempt('x86_64', 'amd64', options=['--ssh-private-key', 'work laptop'])
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(executed.splitlines(), ['--server', 'https://agenttail-api.mizuame.app', 'ssh', 'install-private', '--key', 'work laptop'])

    def test_unsupported_cpu_has_diagnostic_and_no_download(self):
        result, executed, fetched = self.attempt('armv7l','arm64')
        self.assertEqual(result.returncode, 2)
        self.assertIn('Unsupported CPU: armv7l', result.stderr)
        self.assertEqual(executed+fetched, '')


if __name__ == '__main__':
    unittest.main()
