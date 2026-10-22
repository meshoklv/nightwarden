#!/usr/bin/env bash
# nightwarden installer.
#   sudo ./install.sh [--dry-run] [--with-audit] [--with-bait] [--with-triage] [--enable] [--prefix DIR]
#
#   --dry-run       print every action, change nothing (no root needed)
#   --with-audit    also install auditd rules (only for paths that exist)
#   --with-bait     also create honeytoken files (bin/bait-seed.sh) and the bait-watch service
#   --with-triage   also install the AI alert triage (triage/install.sh, stays DISABLED)
#   --enable        start timers/services at the end (default: install only)
# Kits that touch the network or need extra packages (falco/, feeds/, offbox/) are
# never installed automatically — see their READMEs.
set -euo pipefail

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SBIN=/usr/local/sbin; UNITS=/etc/systemd/system; ENVF=/etc/malware-watch.env
DRY=0; AUDIT=0; BAIT=0; TRIAGE=0; ENABLE=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1;; --with-audit) AUDIT=1;; --with-bait) BAIT=1;;
    --with-triage) TRIAGE=1;; --enable) ENABLE=1;;
    --prefix) SBIN="${2:?}/usr/local/sbin"; UNITS="$2/etc/systemd/system"; ENVF="$2/etc/malware-watch.env"; shift;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) echo "unknown option: $1 (try --help)" >&2; exit 2;;
  esac; shift
done

run(){ if [ "$DRY" = 1 ]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi; }
say(){ printf '\n== %s\n' "$*"; }

say "Checking environment"
miss=0
for c in bash jq curl python3 systemctl; do
  if command -v "$c" >/dev/null 2>&1; then echo "  ok   $c"; else echo "  MISSING $c"; miss=1; fi
done
for c in iptables ss nsenter; do command -v "$c" >/dev/null 2>&1 && echo "  ok   $c" || echo "  note: $c not found (some detectors degrade)"; done
if [ "$miss" = 1 ] && [ "$DRY" != 1 ]; then echo "install the missing packages first (e.g. apt install jq curl python3)"; exit 1; fi
if [ "$DRY" != 1 ] && [ "$(id -u)" != 0 ]; then echo "run as root (or use --dry-run)"; exit 1; fi

say "Scripts -> $SBIN"
run install -d -m 0755 "$SBIN"
for f in malware-watch.sh malware-watch-hb.sh malware-watch-guard.sh bait-watch.py audit-bridge.py mw-digest.py mw-buttons.py bait-seed.sh; do
  run install -m 0750 -o root -g root "$SRC/bin/$f" "$SBIN/$f"
done

say "State and log directories"
run install -d -m 0750 /var/lib/malware-watch /var/log/malware-watch
[ "$BAIT" = 1 ] && run install -d -m 0750 /var/lib/bait-watch /var/log/bait-watch /etc/bait-watch
run install -d -m 0750 /var/lib/audit-bridge

say "Configuration -> $ENVF"
if [ -e "$ENVF" ]; then echo "  $ENVF exists, not touching it"
else run install -m 0600 -o root -g root "$SRC/etc/malware-watch.env.example" "$ENVF"
     echo "  created from example — EDIT IT (alert channel!)"; fi

say "systemd units -> $UNITS"
for u in malware-watch.service malware-watch.timer malware-watch-hb.service malware-watch-hb.timer \
         mw-digest.service mw-digest.timer audit-bridge.service audit-bridge.timer; do
  run install -m 0644 "$SRC/systemd/$u" "$UNITS/$u"
done
[ "$BAIT" = 1 ] && run install -m 0644 "$SRC/systemd/bait-watch.service" "$UNITS/bait-watch.service"
run install -m 0644 "$SRC/systemd/cron.d/malware-watch-guard" "${UNITS%/etc/systemd/system}/etc/cron.d/malware-watch-guard"
run systemctl daemon-reload

if [ "$AUDIT" = 1 ]; then
  say "auditd rules (paths that do not exist are dropped)"
  tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
  while IFS= read -r l; do
    if [[ "$l" =~ ^-w[[:space:]]+([^[:space:]]+) ]] && [ ! -e "${BASH_REMATCH[1]}" ]; then echo "  skip (missing path): $l"; continue; fi
    echo "$l" >>"$tmp"
  done <"$SRC/audit/nightwarden.rules"
  run install -m 0640 "$tmp" /etc/audit/rules.d/60-nightwarden.rules
  run augenrules --load
fi

if [ "$BAIT" = 1 ]; then
  say "Honeytokens"
  if [ "$DRY" = 1 ]; then bash "$SRC/bin/bait-seed.sh" --dry-run; else bash "$SRC/bin/bait-seed.sh"; fi
fi

if [ "$TRIAGE" = 1 ]; then
  say "AI triage (installed disabled)"
  if [ "$DRY" = 1 ]; then bash "$SRC/triage/install.sh" --dry-run; else bash "$SRC/triage/install.sh"; fi
fi

if [ "$ENABLE" = 1 ]; then
  say "Starting"
  run "$SBIN/malware-watch.sh" dryrun
  run "$SBIN/malware-watch.sh" baseline
  run systemctl enable --now malware-watch.timer malware-watch-hb.timer mw-digest.timer audit-bridge.timer
  [ "$BAIT" = 1 ] && run systemctl enable --now bait-watch.service
fi

cat <<'MSG'

Next steps (installer did NOT start anything unless you passed --enable):
  1. edit /etc/malware-watch.env   (TG_TOKEN/TG_CHAT or ALERT_WEBHOOK_URL)
  2. sudo malware-watch.sh dryrun   -> must show 0 WOULD-KILL on a clean host
  3. sudo malware-watch.sh baseline -> accept the current state as normal
  4. sudo systemctl enable --now malware-watch.timer malware-watch-hb.timer
Uninstall: ./uninstall.sh
MSG
