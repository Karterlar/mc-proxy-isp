#!/bin/bash
# Restore service code/state from the installer snapshot; never revert accounts.
set -Eeuo pipefail
umask 077
[[ $EUID -eq 0 ]] || { echo 'Run as root.' >&2; exit 1; }
ADMIN=/var/lib/mc-proxy-relay-admin
ROOT=/opt/mc-proxy-relay
UNIT=/etc/systemd/system/mc-proxy-relay.service
[[ -d $ADMIN && ! -L $ADMIN && $(stat -c %u "$ADMIN") == 0 && $(cat "$ADMIN/owner") == mc-proxy-relay-v1 ]]
if [[ ${MC_PROXY_RELAY_INSTALL_LOCK:-} != 1 ]]; then
  [[ ! -L $ADMIN/install.lock ]]
  exec 9>"$ADMIN/install.lock"
  flock -n 9 || { echo 'Another installation or rollback is active.' >&2; exit 1; }
fi
snapshot=${1:-$(cat "$ADMIN/latest")}
[[ $snapshot == "$ADMIN"/snapshot-* && -d $snapshot && ! -L $snapshot && $(stat -c %u "$snapshot") == 0 ]]
[[ $(realpath -e "$snapshot") == "$snapshot" ]]
for file in relay.py manage.py rollback.sh mc-proxy-relay.service manifest.sha256; do [[ ! -L $snapshot/$file ]]; done
for path in "$ROOT" "$UNIT" "$ADMIN/manifest.sha256"; do [[ ! -L $path ]]; done
systemctl stop mc-proxy-relay || true
if [[ -f $snapshot/mc-proxy-relay.service ]]; then
  for file in relay.py manage.py rollback.sh; do install -m 0644 -o root -g root "$snapshot/$file" "$ROOT/$file"; done
  install -m 0644 -o root -g root "$snapshot/mc-proxy-relay.service" "$UNIT"
else
  systemctl disable mc-proxy-relay || true
  [[ ! -e $UNIT || -f $UNIT ]]
  rm -f -- "$UNIT"
fi
if [[ -f $snapshot/manifest.sha256 ]]; then cp "$snapshot/manifest.sha256" "$ADMIN/manifest.sha256"; else rm -f -- "$ADMIN/manifest.sha256"; fi
systemctl daemon-reload
for service in proxypilot-relay-health mc-proxy-relay; do
  enabled=$(cat "$snapshot/$service.enabled")
  active=$(cat "$snapshot/$service.active")
  if [[ $enabled == enabled ]]; then systemctl enable "$service"; else systemctl disable "$service" 2>/dev/null || true; fi
  if [[ $active == active ]]; then systemctl start "$service"; else systemctl stop "$service" 2>/dev/null || true; fi
done
echo 'Prior service files and activation restored. Current accounts and TLS key preserved.'
