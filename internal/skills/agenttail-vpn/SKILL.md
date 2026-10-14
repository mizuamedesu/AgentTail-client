---
name: agenttail-vpn
description: Manage named AgentTail VPNs and independent SSH keys using the agenttail CLI. Use for VPN membership, device operations, SSH public/private key registration, and account administration.
---

Start with `agenttail version --json` and `agenttail vpn status --json`.
Use `agenttail <command> --help`. Check both the exit status and JSON `ok`.

A VPN is a named network. Run `agenttail vpn join --name <vpn-name-or-id>`
on each computer. Each join gets its own WireGuard identity; do not copy VPN
credentials between machines. Join connects after browser approval by default.
For a foreground agent use `--up=false`, start `agenttail agent run`, then
`agenttail vpn up --name <vpn-name>`.
Use `agenttail vpn down/status/sync --name <vpn-name>` for local operations and
`agenttail vpn leave --name <vpn-name>` to revoke and remove this computer's membership.
Different VPNs cannot communicate even with an ACL allow rule.

SSH keys are independent Ed25519 identities, not WireGuard keys:
- Run the SSH key's **public-key command on the connection destination** as
  the OS user to log in to: `agenttail ssh install-public --public-key 'ssh-ed25519 ...'`.
- Run its **private-key command on the connection origin** as the OS user running
  SSH: `agenttail ssh install-private --key '<ssh-key-name-or-id>'` (CLI dev.15 or later).
  The CLI obtains the approved public key automatically and verifies it against
  the received private key. Do not require the user to enter a public key here.
  Do not run private-key registration with sudo. It does not need VPN enrollment.
- After approval, the CLI reports an `identity_file` path, never the private key.
  Use `ssh -i <identity_file> <user>@<reachable-host-or-vpn-ip>`.

For approval, show the CLI's complete URL, including the `#recipient=...`
fragment, user code, and public recipient fingerprint. The person checks the
VPN or SSH key and requesting computer before approving. Never obtain the
expected recipient fingerprint from the API. Account-owner CLI approval for
VPN joins is `agenttail device approve --code <code> --recipient-fingerprint <value>`.

Private SSH files are OpenSSH keys with OS access restrictions and no passphrase.
Never read a private key, machine credential store, account password, recovery
key or vault key into agent context. Never print or place them in shell arguments,
environment variables or logs. Installed SSH keys remain usable until removed
from those computers; stopping distribution does not remotely erase them.

Account/admin sessions are separate from device credentials. Interactive
`agenttail account login` and `agenttail admin login` accept passwords only in the
person's terminal. Account management uses `agenttail vpn list/create/show/rename/delete`,
`agenttail ssh list/create/show/rename/revoke`, `agenttail devices`, `agenttail acl`,
`agenttail billing`, and `agenttail admin`. These do not grant extra authority.
Remote connect/disconnect/sync requires an online agent. Report pending commands
as pending, not executed.

`agenttail update` verifies signed releases. Do not bypass verification failures.
`agenttail uninstall --yes` removes the VPN service and its credentials only;
independently registered SSH keys are not removed. Use uninstall only when requested.
