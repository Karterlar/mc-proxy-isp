#!/usr/bin/env bash
set -euo pipefail
umask 077

# Run only after reviewing this script and the adjacent sing-box.json.
# Fresh installation only: existing installations are deliberately not overwritten.
# Supported target: Debian 12 / Ubuntu 24.04 with systemd, amd64 or arm64.
[[ ${EUID} -eq 0 ]] || { echo 'Run with sudo bash ./install.sh' >&2; exit 1; }
command -v systemctl >/dev/null
command -v curl >/dev/null
command -v sha256sum >/dev/null
command -v tar >/dev/null
command -v python3 >/dev/null
command -v ss >/dev/null
command -v flock >/dev/null
command -v awk >/dev/null
exec 9>/run/proxypilot-install.lock
flock -n 9 || { echo 'Another ProxyPilot installer is running' >&2; exit 1; }
base=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
[[ -f "$base/sing-box.json" && -f "$base/proxypilot.service" ]] || { echo 'Bundle is incomplete' >&2; exit 1; }
for target in /etc/proxypilot /usr/local/lib/proxypilot /etc/systemd/system/proxypilot.service; do
  [[ ! -e "$target" && ! -L "$target" ]] || { echo 'Existing ProxyPilot installation found; no files changed. Follow the documented manual update procedure.' >&2; exit 1; }
done
if getent passwd proxypilot >/dev/null || getent group proxypilot >/dev/null; then
  echo 'Existing proxypilot account/group found; review ownership before installing' >&2; exit 1
fi
port=$(python3 - "$base/sing-box.json" 2>/dev/null <<'PY'
import json, sys
with open(sys.argv[1], encoding='utf-8') as f:
    config = json.load(f)
inbounds = config['inbounds']
assert len(inbounds) == 1
assert inbounds[0]['type'] == 'http'
assert inbounds[0]['listen'] == '127.0.0.1'
port = inbounds[0]['listen_port']
assert type(port) is int and 1024 <= port <= 65535
print(port)
PY
) || { echo 'Invalid loopback-only listener configuration' >&2; exit 1; }
[[ -z "$(ss -H -ltn "sport = :$port")" ]] || { echo 'Requested listener port is already occupied' >&2; exit 1; }
case "$(uname -m)" in
  x86_64) arch=amd64; digest=a684484d7477d1437282ee411f4d131d0340aaad60a7868841ebd5d87dd8a0c6 ;;
  aarch64|arm64) arch=arm64; digest=b43a1fb1bda131c6653576741ce527eb2bdeab7c9308ca90ee8b972abb7e4a7f ;;
  *) echo 'Unsupported CPU architecture' >&2; exit 1 ;;
esac
version=1.14.2
tmp=$(mktemp -d)
created_user=0
created_group=0
created_bin_dir=0
created_config_dir=0
created_unit=0
installed=0
cleanup() {
  status=$?
  trap - EXIT INT TERM
  set +e
  if [[ $installed -eq 0 ]]; then
    if [[ $created_unit -eq 1 ]]; then
      systemctl disable --now proxypilot.service >/dev/null 2>&1
      rm -f -- /etc/systemd/system/proxypilot.service
      systemctl daemon-reload
      systemctl reset-failed proxypilot.service >/dev/null 2>&1
    fi
    if [[ $created_config_dir -eq 1 ]]; then
      rm -f -- /etc/proxypilot/sing-box.json
      rmdir -- /etc/proxypilot
    fi
    if [[ $created_bin_dir -eq 1 ]]; then
      rm -f -- /usr/local/lib/proxypilot/sing-box
      rmdir -- /usr/local/lib/proxypilot
    fi
    [[ $created_user -eq 0 ]] || userdel proxypilot
    [[ $created_group -eq 0 ]] || groupdel proxypilot
    echo 'Installation did not complete; rollback attempted only for resources created by this run. Review any cleanup errors above.' >&2
  fi
  rm -rf -- "$tmp"
  exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
asset="sing-box-${version}-linux-${arch}"
curl --fail --show-error --location --proto '=https' --tlsv1.2 --retry 2 --output "$tmp/core.tar.gz" "https://github.com/SagerNet/sing-box/releases/download/v${version}/${asset}.tar.gz"
echo "$digest  $tmp/core.tar.gz" | sha256sum --check --status || { echo 'Core checksum mismatch; installation stopped' >&2; exit 1; }
tar --extract --gzip --file "$tmp/core.tar.gz" --directory "$tmp" "$asset/sing-box"
# Validate before installing any configuration or service. Output is withheld because
# parser errors can include configuration fragments containing provider credentials.
"$tmp/$asset/sing-box" check -c "$base/sing-box.json" >/dev/null 2>&1 || { echo 'sing-box configuration check failed; do not share the credential-bearing file' >&2; exit 1; }
groupadd --system proxypilot
created_group=1
useradd --system --gid proxypilot --no-create-home --shell /usr/sbin/nologin proxypilot
created_user=1
mkdir -m 0755 /usr/local/lib/proxypilot
created_bin_dir=1
install -m 0755 -o root -g root "$tmp/$asset/sing-box" /usr/local/lib/proxypilot/sing-box
mkdir -m 0750 /etc/proxypilot
created_config_dir=1
chown root:proxypilot /etc/proxypilot
install -m 0640 -o root -g proxypilot "$base/sing-box.json" /etc/proxypilot/sing-box.json
created_unit=1
install -m 0644 -o root -g root "$base/proxypilot.service" /etc/systemd/system/proxypilot.service
systemctl daemon-reload
systemctl enable --now proxypilot.service
ready=0
for attempt in {1..30}; do
  pid=$(systemctl show -p MainPID --value proxypilot.service)
  if [[ "$pid" =~ ^[1-9][0-9]*$ ]] && systemctl is-active --quiet proxypilot.service &&
    ss -H -ltnp "sport = :$port" | awk -v wanted="127.0.0.1:$port" -v pidtoken="pid=$pid," '$4 == wanted && index($0, pidtoken) { found=1 } END { exit !found }'; then
    ready=1
    break
  fi
  sleep 0.2
done
[[ $ready -eq 1 ]] || { echo 'Service did not own the expected loopback listener within 6 seconds' >&2; exit 1; }
installed=1
echo 'Service owns the expected loopback listener. Next run the Windows probe through SSH; upstream access has not yet been verified.'
