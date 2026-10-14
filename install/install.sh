#!/bin/sh
# SPDX-License-Identifier: GPL-3.0-or-later
set -eu
umask 077
source_url='https://agenttail.mizuame.app/downloads/stable'
custom_source=''
server='https://agenttail-api.mizuame.app'
vpn=''
ssh_public=''
ssh_private=''
ssh_expected=''
no_service=''
while [ "$#" -gt 0 ]; do
  case "$1" in
    --source) source_url=$2; custom_source=1; shift 2 ;;
    --server) server=$2; shift 2 ;;
    --vpn) vpn=$2; shift 2 ;;
    --ssh-public-key) ssh_public=$2; shift 2 ;;
    --ssh-private-key) ssh_private=$2; shift 2 ;;
    --ssh-expected-public-key) ssh_expected=$2; shift 2 ;;
    --no-service) no_service='--no-service'; shift ;;
    *) printf '%s\n' "Unknown installer option: $1" >&2; exit 2 ;;
  esac
done
modes=0
[ -z "$vpn" ] || modes=$((modes+1))
[ -z "$ssh_public" ] || modes=$((modes+1))
[ -z "$ssh_private" ] || modes=$((modes+1))
[ "$modes" -le 1 ] || { printf '%s\n' 'Choose only one installation role' >&2; exit 2; }
case "$source_url" in https://*) ;; *) printf '%s\n' 'Release source must use HTTPS' >&2; exit 2 ;; esac
host_system=$(uname -s)
host_cpu=$(uname -m)
case "$host_system" in Linux) system=linux ;; Darwin) system=darwin ;; *) printf 'Unsupported OS: %s (supported: Linux, macOS)\n' "$host_system" >&2; exit 2 ;; esac
case "$host_cpu" in x86_64|amd64) arch=amd64 ;; aarch64|arm64) arch=arm64 ;; riscv64) arch=riscv64 ;; *) printf 'Unsupported CPU: %s (supported: amd64, arm64, Linux riscv64)\n' "$host_cpu" >&2; exit 2 ;; esac
if [ "$arch" = riscv64 ]; then
  [ "$system" = linux ] || { printf '%s\n' 'RISC-V builds require Linux' >&2; exit 2; }
  # Existing desktop updaters reject manifests containing an unknown CPU.
  [ -n "$custom_source" ] || source_url='https://agenttail.mizuame.app/downloads/nanokvm'
fi
for dependency in curl openssl awk; do command -v "$dependency" >/dev/null 2>&1 || { printf 'Required command: %s\n' "$dependency" >&2; exit 2; }; done
if [ "$system" = linux ] && [ -z "$ssh_public$ssh_private" ]; then
  command -v ip >/dev/null 2>&1 || { printf '%s\n' 'Required command: ip' >&2; exit 2; }
  if [ "$arch" = riscv64 ]; then
    if [ -z "$no_service" ]; then
      [ -x /bin/busybox ] && [ -f /etc/init.d/rcS ] || { printf '%s\n' 'NanoKVM builds require BusyBox init; use --no-service for a foreground agent' >&2; exit 2; }
    fi
    [ "$(id -u)" = 0 ] || { printf '%s\n' 'Run the NanoKVM installer as root' >&2; exit 2; }
    export GOMEMLIMIT="${GOMEMLIMIT:-64MiB}"
  fi
  if [ "$arch" != riscv64 ] && ! command -v systemd-creds >/dev/null 2>&1; then
    printf '%s\n' 'systemd-creds is unavailable; using encrypted root-only host credentials.'
  fi
  if [ "$arch" != riscv64 ] && [ -z "$no_service" ] && [ ! -d /run/systemd/system ]; then
    printf '%s\n' 'systemd is not running; using the Linux supervisor. After a container restart, run agenttail service start from its entrypoint.'
  fi
fi
release_dir=$(mktemp -d "${TMPDIR:-/tmp}/agenttail-install.XXXXXXXX")
trap 'rm -rf "$release_dir"' EXIT HUP INT TERM
cat > "$release_dir/trusted.pub" <<'AGENTTAIL_PUBLIC_KEY'
-----BEGIN PUBLIC KEY-----
MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAzzxw79cAiFFruFRAB881
cEHhBcsIEMZMgXEhmHVC8mFZpqmL18czZ/4otOA8E4n42PsYsB8WiRpxiIx1/lR6
KKjeWI4IFdSyW13MANkMe4hDC3eERK9UfXRjT4zIQVU4T+4rnLm9Hq7tIv93lrkL
MYkbmcLYCQXKjdNSO3/yz/n/XxnVogedWQa7SvPba71XolfDmQc3j5H87k0/HWdY
bvoWKA1ILYts6fpW+l+yDih8r0XzsW+mqU9DuaiKvmY+7YvQjmHTmmdhASPN8hxW
JhzCeRC16euJY2zMGVX80o9ov3fTRN+03cCiRFHPQ5h/I+p6DOLwQXNsePj7aNL3
cL+sK+nomS5QbY6CEx8hVBOKGU2ONKLHc4ED1RlQKDpS7yi/0RvB/p6v+HvBAi0J
Z3T2uggZ4FgyQNWpPpRhkbgVy9yLpUMsMHXfXGywFIUO18Cm+19Gee7Thv5yUiNX
e/nWxBVpnG1H1BGBKRkM11HkOUTwQHXcXsUjkIMsd/VTAgMBAAE=
-----END PUBLIC KEY-----
AGENTTAIL_PUBLIC_KEY
fetch() { curl --proto '=https' --tlsv1.2 --fail --silent --show-error --max-time 120 --max-filesize 67108864 --output "$release_dir/$1" "${source_url%/}/$1"; }
fetch manifest.txt
fetch manifest.sig
[ "$(wc -c < "$release_dir/manifest.txt" | tr -d ' ')" -le 65536 ] || { printf '%s\n' 'Manifest too large' >&2; exit 2; }
openssl dgst -sha256 -verify "$release_dir/trusted.pub" -signature "$release_dir/manifest.sig" "$release_dir/manifest.txt" >/dev/null || { printf '%s\n' 'Release signature verification failed' >&2; exit 2; }
now=$(date +%s)
# Check expiry before executing any signed binary; the binary repeats all checks.
awk -v now="$now" 'NR==1 {if($0!="agenttail-manifest-v1")exit 1} $1=="created" {if(NF!=2||$2!~/^[0-9]+$/||++c!=1)exit 1;created=$2} $1=="expires" {if(NF!=2||$2!~/^[0-9]+$/||++e!=1)exit 1;expires=$2} END {if(c!=1||e!=1||created>now+300||expires<=now||expires<=created||expires-created>31622400)exit 1}' "$release_dir/manifest.txt" || { printf '%s\n' 'Release manifest expired or invalid' >&2; exit 2; }
artifact=$(awk -v os="$system" -v arch="$arch" '$1=="file"&&$2==os&&$3==arch&&$4=="vpn" {if(NF!=8||$5!~/^[a-zA-Z0-9][a-zA-Z0-9_.-]*$/||$6!~/^[0-9]+$/||$6<1||$6>67108864||$7!~/^[0-9a-f]+$/||length($7)!=64||$8!="-"||++n!=1)exit 1;name=$5} END{if(n!=1)exit 1;print name}' "$release_dir/manifest.txt") || { printf '%s\n' 'No valid native artifact for this OS/CPU' >&2; exit 2; }
fetch "$artifact"
expected_size=$(awk -v name="$artifact" '$1=="file"&&$5==name{print $6}' "$release_dir/manifest.txt")
expected_hash=$(awk -v name="$artifact" '$1=="file"&&$5==name{print $7}' "$release_dir/manifest.txt")
actual_hash=$(openssl dgst -sha256 "$release_dir/$artifact" | awk '{print $NF}')
[ "$(wc -c < "$release_dir/$artifact" | tr -d ' ')" = "$expected_size" ] && [ "$actual_hash" = "$expected_hash" ] || { printf '%s\n' 'Artifact verification failed' >&2; exit 2; }
chmod 755 "$release_dir/$artifact"
# SSH-only registration runs as the invoking user, without a VPN daemon or
# privilege elevation. Its files remain after this temporary CLI is removed.
if [ -n "$ssh_public" ]; then
  "$release_dir/$artifact" --server "$server" ssh install-public --public-key "$ssh_public"
  exit 0
fi
if [ -n "$ssh_private" ]; then
  set -- --server "$server" ssh install-private --key "$ssh_private"
  [ -z "$ssh_expected" ] || set -- "$@" --public-key "$ssh_expected"
  "$release_dir/$artifact" "$@"
  exit 0
fi
"$release_dir/$artifact" install --bundle "$release_dir" --source "$source_url" --server "$server" ${no_service:+"$no_service"}
"$release_dir/$artifact" skills install
printf '%s\n' 'AgentTail installed. Open a new shell to use the agenttail command.'
if [ -n "$vpn" ]; then
  if [ "$system" = darwin ]; then installed_cli='/Library/AgentTail/agenttail'; else installed_cli='/usr/local/lib/agenttail/agenttail'; fi
  printf '%s\n' 'Joining the VPN. If approval is needed, open the link printed below.'
  if [ -n "$no_service" ]; then
    "$installed_cli" --server "$server" vpn join --name "$vpn" --up=false
    printf '%s\n' 'Authorized. Start agenttail agent run, then agenttail vpn up --name <vpn-name>.'
  else
    "$installed_cli" --server "$server" vpn join --name "$vpn"
  fi
else
  printf '%s\n' 'Run agenttail vpn join --name <vpn-name> to connect this computer.'
fi
