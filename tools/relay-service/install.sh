#!/bin/bash
# Install/upgrade on the existing owned Ubuntu relay host. No SSH/firewall edits.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
. /etc/os-release
[[ $ID == ubuntu && $VERSION_ID == 24.04 ]] || { echo 'Ubuntu 24.04 required.' >&2; exit 1; }
SOURCE=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
ROOT=/opt/mc-proxy-relay
STATE=/var/lib/mc-proxy-relay
ADMIN=/var/lib/mc-proxy-relay-admin
CERTS=/etc/proxypilot-relay-health
UNIT=/etc/systemd/system/mc-proxy-relay.service
ACCOUNT=proxypilot-relay
OWNER=mc-proxy-relay-v1
for command in python3 systemctl install flock sha256sum ss cmp; do command -v "$command" >/dev/null; done
for path in /opt /var /var/lib /etc /etc/systemd /etc/systemd/system "$CERTS"; do
  [[ -d $path && ! -L $path && $(stat -c %u "$path") == 0 ]] || { echo 'Unsafe base directory.' >&2; exit 1; }
done
[[ -f $CERTS/owner && $(cat "$CERTS/owner") == proxypilot-relay-health-bootstrap-v1 ]] || { echo 'Existing owned health installation required.' >&2; exit 1; }
getent passwd "$ACCOUNT" >/dev/null
for file in server-key.pem server-cert.pem; do [[ -f $CERTS/$file && ! -L $CERTS/$file ]]; done
for file in relay.py manage.py mc-proxy-relay.service rollback.sh; do [[ -f $SOURCE/$file && ! -L $SOURCE/$file ]]; done
python3 -I - "$SOURCE/relay.py" "$SOURCE/manage.py" <<'PY'
import ast, pathlib, sys
for source in sys.argv[1:]:
    ast.parse(pathlib.Path(source).read_text(encoding='utf-8'))
PY

if [[ -e $ADMIN || -L $ADMIN ]]; then
  [[ -d $ADMIN && ! -L $ADMIN && $(stat -c %u "$ADMIN") == 0 && -f $ADMIN/owner && $(cat "$ADMIN/owner") == "$OWNER" ]] || { echo 'Unowned admin state; refusing adoption.' >&2; exit 1; }
else
  for path in "$ROOT" "$STATE" "$UNIT"; do [[ ! -e $path && ! -L $path ]] || { echo 'Foreign installation; refusing overwrite.' >&2; exit 1; }; done
  install -d -m 0700 -o root -g root "$ADMIN"
  printf '%s\n' "$OWNER" > "$ADMIN/owner"
fi
[[ ! -L $ADMIN/install.lock ]]
exec 9>"$ADMIN/install.lock"
flock -n 9 || { echo 'Another installation is active.' >&2; exit 1; }
for path in "$ROOT" "$STATE" "$UNIT" "$ADMIN/latest"; do [[ ! -L $path ]] || { echo 'Symlink refused.' >&2; exit 1; }; done
if [[ -e $ROOT ]]; then [[ -d $ROOT && $(stat -c %u "$ROOT") == 0 ]]; fi
if [[ -e $STATE ]]; then [[ -d $STATE && $(stat -c %U "$STATE") == "$ACCOUNT" ]]; fi
if [[ -f $ADMIN/manifest.sha256 ]]; then
  sha256sum --status --check "$ADMIN/manifest.sha256" || { echo 'Installed files were modified; review before upgrading.' >&2; exit 1; }
  identical=1
  for file in relay.py manage.py rollback.sh; do cmp -s "$SOURCE/$file" "$ROOT/$file" || identical=0; done
  cmp -s "$SOURCE/mc-proxy-relay.service" "$UNIT" || identical=0
  if [[ $identical == 1 ]] && systemctl is-active --quiet mc-proxy-relay; then
    echo 'Identical MC Proxy relay is already active; no files or services changed.'
    exit 0
  fi
fi
if [[ ! -f $UNIT ]] && ! systemctl is-active --quiet proxypilot-relay-health && [[ -n $(ss -H -ltn 'sport = :443') ]]; then
  echo 'TCP 443 is held by another service; no services changed.' >&2; exit 1
fi

SNAPSHOT=$ADMIN/snapshot-$(date -u +%Y%m%dT%H%M%SZ)-$$
install -d -m 0700 "$SNAPSHOT"
for service in proxypilot-relay-health mc-proxy-relay; do
  systemctl is-active "$service" > "$SNAPSHOT/$service.active" 2>/dev/null || true
  systemctl is-enabled "$service" > "$SNAPSHOT/$service.enabled" 2>/dev/null || true
done
for file in relay.py manage.py rollback.sh; do
  if [[ -f $ROOT/$file ]]; then cp --preserve=mode,ownership "$ROOT/$file" "$SNAPSHOT/$file"; fi
done
if [[ -f $UNIT ]]; then cp --preserve=mode,ownership "$UNIT" "$SNAPSHOT/mc-proxy-relay.service"; fi
if [[ -f $ADMIN/manifest.sha256 ]]; then cp "$ADMIN/manifest.sha256" "$SNAPSHOT/manifest.sha256"; fi
printf '%s\n' "$SNAPSHOT" > "$ADMIN/latest"
changed=0
recover() {
  status=$?
  trap - ERR
  if [[ $changed == 1 ]]; then
    echo 'Installation failed; restoring prior service files and activation state.' >&2
    MC_PROXY_RELAY_INSTALL_LOCK=1 /bin/bash "$SOURCE/rollback.sh" "$SNAPSHOT" || echo 'Automatic rollback failed; inspect systemd journal locally.' >&2
  fi
  exit "$status"
}
trap recover ERR
install -d -m 0755 -o root -g root "$ROOT"
install -d -m 0700 -o "$ACCOUNT" -g "$ACCOUNT" "$STATE"
if [[ ! -e $STATE/accounts.json ]]; then
  printf '{"version":1,"accounts":{}}\n' > "$STATE/accounts.json"
  chown "$ACCOUNT:$ACCOUNT" "$STATE/accounts.json"
  chmod 0600 "$STATE/accounts.json"
fi
[[ -f $STATE/accounts.json && ! -L $STATE/accounts.json ]]
if [[ ! -e $STATE/accounts.lock ]]; then install -m 0600 -o "$ACCOUNT" -g "$ACCOUNT" /dev/null "$STATE/accounts.lock"; fi
[[ -f $STATE/accounts.lock && ! -L $STATE/accounts.lock ]]
changed=1
for file in relay.py manage.py rollback.sh; do install -m 0644 -o root -g root "$SOURCE/$file" "$ROOT/$file"; done
install -m 0644 -o root -g root "$SOURCE/mc-proxy-relay.service" "$UNIT"
systemctl daemon-reload
systemctl disable --now proxypilot-relay-health
systemctl enable mc-proxy-relay
systemctl restart mc-proxy-relay
python3 -I - "$CERTS/server-cert.pem" <<'PY'
import json, socket, ssl, sys, time
ctx = ssl.create_default_context(cafile=sys.argv[1])
last = None
for attempt in range(12):
    try:
        with socket.create_connection(('127.0.0.1', 443), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname='proxypilot-relay-test.local') as connection:
                connection.sendall(b'GET /healthz HTTP/1.1\r\nHost: proxypilot-relay-test.local\r\nConnection: close\r\n\r\n')
                data = b''
                while True:
                    chunk = connection.recv(4096)
                    if not chunk: break
                    data += chunk
                headers, body = data.split(b'\r\n\r\n', 1)
                assert headers.startswith(b'HTTP/1.1 200 ')
                assert json.loads(body)['service'] == 'mc-proxy-relay'
                break
    except Exception as error:
        last = type(error).__name__
        time.sleep(.5)
else:
    raise SystemExit('Relay health validation failed: ' + str(last))
PY
systemctl is-active --quiet mc-proxy-relay
sha256sum "$ROOT/relay.py" "$ROOT/manage.py" "$ROOT/rollback.sh" "$UNIT" > "$ADMIN/manifest.sha256"
trap - ERR
printf 'MC Proxy relay installed and TLS health verified. Accounts and certificate preserved. Rollback snapshot: %s\n' "$SNAPSHOT"
