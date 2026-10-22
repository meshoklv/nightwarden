#!/bin/bash
# Removes the alert triage. Does NOT touch the guard at all.
# Logs and case files REMAIN by default -- they are traces of past analyses and
# may be needed to double-check earlier conclusions. To wipe them too:
#   PURGE=1 bash uninstall.sh
#
# Usage:  sudo bash uninstall.sh [--dry-run] [--help]
#   --dry-run   print what would be removed; change nothing, no root needed
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sudo [PURGE=1] bash uninstall.sh [--dry-run] [--help]

Stops and removes the alert triage service and programs. Logs, case files,
/etc/alert-triage.env and the mwtriage user stay unless PURGE=1 is set.

  --dry-run   print what would be removed and change nothing (no root needed)
  --help      this text
USAGE
}

DRY=0
for a in "$@"; do
  case "$a" in
    --dry-run) DRY=1 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $a" >&2; usage >&2; exit 2 ;;
  esac
done

# x: run a command (errors ignored where the original ignored them), or only
# print it in --dry-run mode.
x() {
  if [ "$DRY" = 1 ]; then
    printf '   [dry-run] would run:'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

if [ "$DRY" = 1 ]; then
  echo "DRY RUN: nothing will be changed."
elif [ "$(id -u)" != 0 ]; then
  echo "must be run as root (or use --dry-run)"; exit 1
fi

echo "-> stopping the service"
x systemctl disable --now alert-triage.service 2>/dev/null || true
x rm -f /etc/systemd/system/alert-triage.service
x systemctl daemon-reload

echo "-> removing programs"
x rm -rf /usr/local/lib/alert-triage
x rm -rf /run/alert-triage

if [ "${PURGE:-0}" = "1" ]; then
  echo "-> wiping logs, case files and settings (PURGE=1)"
  x rm -rf /var/log/alert-triage /var/lib/alert-triage
  x rm -f /etc/alert-triage.env
  x userdel mwtriage 2>/dev/null || true
else
  echo "-> logs and case files KEPT: /var/log/alert-triage, /var/lib/alert-triage"
  echo "   settings kept: /etc/alert-triage.env (it may hold a key)"
  echo "   user mwtriage kept (log files reference it)"
fi

if [ "$DRY" = 1 ]; then
  echo "DRY RUN finished: nothing was changed."
else
  echo "Triage removed. The guard keeps working as before -- it never depended on it."
fi
