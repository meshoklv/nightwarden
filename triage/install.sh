#!/bin/bash
# Lays the alert triage out in place. DOES NOT ENABLE IT.
# After installation the service sits with TRIAGE_ENABLED=0 and TRIAGE_SINK=file,
# i.e. it analyses nothing and writes to nobody. Enabling is a separate step,
# see the README, section "How to enable".
#
# Usage:  sudo bash install.sh [--dry-run] [--help]
#   --dry-run   print what would be created/installed/copied; change nothing,
#               does not need root
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: sudo bash install.sh [--dry-run] [--help]

Installs the alert triage (user, directories, programs, config, systemd unit).
It does NOT enable or start the service.

  --dry-run   print what would be created/installed/copied and change nothing
              (does not need root)
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

SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
LIB=/usr/local/lib/alert-triage
ENVF=/etc/alert-triage.env
USER_NAME=mwtriage

# x: run a command, or only print it in --dry-run mode.
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

echo "-> user $USER_NAME (no login, no home under /home)"
if id -u "$USER_NAME" >/dev/null 2>&1; then
  echo "   user $USER_NAME already exists"
else
  x useradd --system --no-create-home --home-dir /var/lib/alert-triage/home \
            --shell /usr/sbin/nologin "$USER_NAME"
fi

echo "-> directories"
x install -d -m 0750 -o root -g "$USER_NAME" "$LIB"
x install -d -m 0750 -o root -g root /var/lib/alert-triage
x install -d -m 0700 -o "$USER_NAME" -g "$USER_NAME" /var/lib/alert-triage/home
x install -d -m 0750 -o root -g "$USER_NAME" /var/log/alert-triage
x install -d -m 0750 -o root -g "$USER_NAME" /var/log/alert-triage/cases

echo "-> programs"
x install -m 0750 -o root -g "$USER_NAME" "$SRC/bin/triage-daemon.py" "$LIB/"
x install -m 0640 -o root -g root        "$SRC/bin/probelib.py"       "$LIB/"
x install -m 0640 -o root -g root        "$SRC/bin/notify.py"         "$LIB/"
x install -m 0755 -o root -g root        "$SRC/bin/probe"             "$LIB/"
x install -d -m 0755 "$LIB/prompt"
x install -m 0644 -o root -g root "$SRC/prompt/system.md" "$LIB/prompt/"
x install -m 0644 -o root -g root "$SRC/etc/claude-settings.json" "$LIB/"

echo "-> settings"
if [ -f "$ENVF" ]; then
  echo "   $ENVF already exists -- NOT touching it (it may hold a key)"
else
  x install -m 0600 -o root -g root "$SRC/etc/alert-triage.env.example" "$ENVF"
  echo "   $ENVF to be created (triage OFF, delivery to a file)"
fi

echo "-> service"
x install -m 0644 "$SRC/systemd/alert-triage.service" \
        /etc/systemd/system/alert-triage.service
x systemctl daemon-reload

if [ "$DRY" = 1 ]; then
  echo
  echo "DRY RUN finished: nothing was changed."
  exit 0
fi

cat <<'EOT'

Done. The service is NOT enabled and NOT started -- that is correct.

Next (step by step, each one a separate decision):
  1) put in the access key:   nano /etc/alert-triage.env   -> ANTHROPIC_API_KEY=
  2) dry-run self-check:      bash <path-to-sources>/test/selftest.sh
  3) enable triage, but WITHOUT delivery to a human:
       sed -i 's/^TRIAGE_ENABLED=0/TRIAGE_ENABLED=1/' /etc/alert-triage.env
       systemctl enable --now alert-triage
     Messages pile up in /var/log/alert-triage/outbox.jsonl -- read them with
     your own eyes and make sure the analysis talks sense.
  4) and only then real delivery:
       sed -i 's/^TRIAGE_SINK=file/TRIAGE_SINK=telegram/' /etc/alert-triage.env
       (or TRIAGE_SINK=webhook plus TRIAGE_WEBHOOK_URL=...)
       systemctl restart alert-triage

Switch off at any moment:  systemctl disable --now alert-triage
Remove completely:         bash <path-to-sources>/uninstall.sh
EOT
