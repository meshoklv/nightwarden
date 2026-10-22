#!/usr/bin/env bash
# nightwarden uninstaller. Stops and removes units and scripts.
# Keeps /etc/malware-watch.env, state and logs unless --purge is given.
#   sudo ./uninstall.sh [--dry-run] [--purge]
set -euo pipefail
DRY=0; PURGE=0
for a in "$@"; do case "$a" in --dry-run) DRY=1;; --purge) PURGE=1;; -h|--help) sed -n '2,5p' "$0"; exit 0;; *) echo "unknown option: $a" >&2; exit 2;; esac; done
run(){ if [ "$DRY" = 1 ]; then printf '[dry-run] %s\n' "$*"; else "$@" || true; fi; }
[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run as root (or use --dry-run)"; exit 1; }
# NB: stopping the guard is itself an alarm-worthy event: announce maintenance first if you use the dead-man.
run systemctl disable --now malware-watch.timer malware-watch-hb.timer mw-digest.timer audit-bridge.timer bait-watch.service
for u in malware-watch.service malware-watch.timer malware-watch-hb.service malware-watch-hb.timer mw-digest.service mw-digest.timer audit-bridge.service audit-bridge.timer bait-watch.service; do run rm -f "/etc/systemd/system/$u"; done
run rm -f /etc/cron.d/malware-watch-guard /etc/audit/rules.d/60-nightwarden.rules
for f in malware-watch.sh malware-watch-hb.sh malware-watch-guard.sh bait-watch.py audit-bridge.py mw-digest.py mw-buttons.py bait-seed.sh; do run rm -f "/usr/local/sbin/$f"; done
run systemctl daemon-reload
if [ "$PURGE" = 1 ]; then
  echo "purging config, state and logs (honeytoken files are NOT deleted; see /etc/bait-watch/baits.list)"
  run rm -rf /etc/malware-watch.env /var/lib/malware-watch /var/log/malware-watch /var/lib/bait-watch /var/log/bait-watch /etc/bait-watch /var/lib/audit-bridge
else echo "kept: /etc/malware-watch.env, /var/lib/*, /var/log/* (use --purge to remove)"; fi
echo "triage (if installed): sudo ./triage/uninstall.sh"
