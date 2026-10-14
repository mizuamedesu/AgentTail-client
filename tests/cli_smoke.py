#!/usr/bin/env python3
"""Native CLI + local Wrangler smoke test. Requires a PTY and native root/admin.

Run against a development Worker only; all passwords are public test fixtures.
No process arguments/environment contain the password, A, E or a private key.
"""
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import tempfile
import time
import uuid
from urllib.parse import parse_qs, urlsplit

import pexpect

parser = argparse.ArgumentParser()
parser.add_argument("--binary", default="build/agenttail")
parser.add_argument("--server", default="http://localhost:8787")
parser.add_argument("--web-origin", help="local Web origin when distinct from the API")
parser.add_argument("--admin-smoke", action="store_true", help="promote only the new fixture user in local D1")
args = parser.parse_args()
assert args.server in ("http://localhost:8787", "http://127.0.0.1:8787"), "local development server only"
assert args.web_origin is None or args.web_origin in ("http://localhost:8788", "http://127.0.0.1:8788"), "local development Web only"
binary = str(Path(args.binary).resolve())
password = "PUBLIC-test-native-cli-password-2026!"
email = f"native-{uuid.uuid4().hex}@example.invalid"


def spawn(directory, command):
    return pexpect.spawn(binary, ["--json", "--state-dir", str(directory), *command], encoding="utf-8", timeout=35, echo=False)


def finish(child, expected=0, all_responses=False):
    # Retain output only in memory; errors deliberately omit the PTY transcript
    # because registration displays a generated recovery key once.
    child.expect(pexpect.EOF)
    transcript = child.before
    child.close()
    assert child.exitstatus == expected, f"unexpected CLI exit: {child.exitstatus}, expected {expected}"
    responses = []
    for line in transcript.splitlines():
        if line.startswith('{'):
            value = json.loads(line)
            if "ok" in value:
                responses.append(value)
    return responses if all_responses else responses[-1] if responses else None


def run(directory, command, prompts=(), expected=0):
    child = spawn(directory, command)
    try:
        for label, value in prompts:
            child.expect_exact(label + ": ")
            child.sendline(value)
        return finish(child, expected)
    finally:
        if child.isalive():
            child.close(force=True)


def local_sql(sql):
    result = subprocess.run(["wrangler", "d1", "execute", "agenttail", "--local", "--command", sql, "--json"], capture_output=True, text=True)
    assert result.returncode == 0, "local fixture SQL failed"
    return json.loads(result.stdout)[0]["results"]


with tempfile.TemporaryDirectory(prefix="agenttail-cli-test-") as temp:
    owner = Path(temp) / "owner"
    endpoint = Path(temp) / "endpoint"
    configure = ["configure", "--server", args.server, "--allow-local-http"]
    if args.web_origin:
        configure += ["--web-origin", args.web_origin]
    run(owner, configure)
    run(owner, ["account", "register"], [("Email", email), ("Display name", "Native CLI fixture"), ("Password (12+ UTF-8 bytes)", password)])
    assert run(owner, ["account", "status"])["data"]["role"] == "user"
    run(owner, ["admin", "login"], [("Email", email), ("Password (12+ UTF-8 bytes)", password)], expected=4)
    vpn = run(owner, ["vpn", "create", "--name", "native-fixture"])["data"]
    assert any(v["vpn_id"] == vpn["vpn_id"] for v in run(owner, ["vpn", "list"])["data"])
    run(endpoint, configure)
    daemon = subprocess.Popen([binary, "--state-dir", str(endpoint), "agent", "run"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            status = run(endpoint, ["vpn", "status"])["data"]
            if status["agent"] == "running":
                break
            time.sleep(0.2)
        else:
            raise AssertionError("agent startup timeout")
        login = spawn(endpoint, ["vpn", "join", "--name", vpn["vpn_id"]])
        login.expect(r'(\{[^\r\n]+\})')
        authorization = json.loads(login.match.group(1))["data"]
        assert authorization["event"] == "device_authorization"
        approval = urlsplit(authorization["verification_uri"])
        assert approval.scheme + "://" + approval.netloc == (args.web_origin or args.server)
        assert approval.path == "/device" and parse_qs(approval.query)["code"] == [authorization["user_code"]]
        fingerprint = authorization["recipient_fingerprint"]
        assert parse_qs(approval.fragment)["recipient"] == [fingerprint] and "recipient" not in parse_qs(approval.query)
        code_hash = hashlib.sha256(authorization["user_code"].replace("-", "").encode()).hexdigest()
        request = local_sql(f"SELECT request_id,ephemeral_public_key FROM device_requests WHERE user_code_hash='{code_hash}'")[0]
        context = f"agenttail/v1/device-recipient/{request['request_id']}/{request['ephemeral_public_key']}"
        assert fingerprint == "SHA256:" + base64.urlsafe_b64encode(hashlib.sha256(context.encode()).digest()).decode().rstrip("=")
        # Simulate a compromised API substituting the requesting CLI's public key.
        attacker = subprocess.check_output(["node", "-e", "process.stdout.write(require('crypto').generateKeyPairSync('x25519').publicKey.export({format:'jwk'}).x)"], text=True)
        local_sql(f"UPDATE device_requests SET ephemeral_public_key='{attacker}' WHERE request_id='{request['request_id']}'")
        try:
            rejected = run(owner, ["device", "approve", "--code", authorization["user_code"], "--recipient-fingerprint", fingerprint], [("Account password", password)], expected=4)
            assert rejected["error"]["code"] == "FORBIDDEN"
            state = local_sql(f"SELECT status,encrypted_transfer IS NULL AS no_transfer FROM device_requests WHERE request_id='{request['request_id']}'")[0]
            assert state["status"] == "pending" and state["no_transfer"] == 1
        finally:
            local_sql(f"UPDATE device_requests SET ephemeral_public_key='{request['ephemeral_public_key']}' WHERE request_id='{request['request_id']}'")
        run(owner, ["device", "approve", "--code", authorization["user_code"]], [("Account password", password), ("Recipient fingerprint from the requesting CLI", fingerprint), ("Add this device to this VPN? Type yes", "yes")])
        login_results = finish(login, all_responses=True)
        assert login_results[-1]["data"]["state"] == "up"
        result = login_results[-2]["data"]
        assert result["vpn_id"] == vpn["vpn_id"]
        key = result
        # A device-only installation has no account or administrator session.
        run(endpoint, ["account", "status"], expected=3)
        run(endpoint, ["admin", "status"], expected=3)
        metadata = (endpoint / "config.json").read_text()
        assert "atk_" not in metadata and "private_key" not in metadata and password not in metadata
        if args.admin_smoke:
            sql = f"UPDATE user SET role='admin' WHERE email='{email}'"
            result = subprocess.run(["wrangler", "d1", "execute", "agenttail", "--local", "--command", sql], capture_output=True, text=True)
            assert result.returncode == 0, "local fixture role promotion failed"
            run(owner, ["admin", "login"], [("Email", email), ("Password (12+ UTF-8 bytes)", password)])
            assert run(owner, ["admin", "status"])["data"]["role"] == "admin"
            run(owner, ["admin", "metrics"])
            run(owner, ["admin", "logout"])
            run(owner, ["admin", "status"], expected=3)
        active = run(endpoint, ["vpn", "up", "--name", "native-fixture"])["data"]
        assert active["state"] == "up" and active["interface"]
        command = run(owner, ["devices", "command", "--key-id", key["key_id"], "--action", "down"])["data"]
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            result = run(owner, ["devices", "result", "--command-id", command["command_id"]])["data"]
            if result["status"] == "done":
                break
            time.sleep(0.2)
        else:
            raise AssertionError("remote down command timeout")
        assert run(endpoint, ["vpn", "status", "--name", "native-fixture"])["data"]["keys"][0]["state"] == "down"
        run(endpoint, ["vpn", "up", "--name", "native-fixture"])
        run(endpoint, ["vpn", "down", "--name", "native-fixture"])
        run(endpoint, ["vpn", "leave", "--name", "native-fixture"])
        assert not json.loads((endpoint / "config.json").read_text())["keys"]
    finally:
        daemon.send_signal(signal.SIGINT)
        try:
            daemon.wait(timeout=10)
        except subprocess.TimeoutExpired:
            daemon.kill()
            daemon.wait()
    run(owner, ["account", "logout"])
    print(json.dumps({"ok": True, "scope": "native CLI and TUN + local Wrangler/D1", "recipient_substitution_rejected": True, "device_login": True, "named_vpn_join": True, "admin_login": args.admin_smoke, "up_down_status": True, "remote_down": True, "logout": True}))
