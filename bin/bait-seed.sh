#!/bin/bash
# bait-seed.sh — create honeytoken (bait) files and the list bait-watch.py watches.
#
#   bait-seed.sh [--dry-run] [--home DIR]... [--list FILE]
#
# Bait files look like forgotten credentials but contain only obviously fake
# values. NOTHING legitimate should ever read them, so any read is a strong
# signal. Defaults: --home /root, --list /etc/bait-watch/baits.list
# With --dry-run it only prints what it would create.
set -euo pipefail

DRY=0; LIST=/etc/bait-watch/baits.list; HOMES=()
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY=1;;
    --home)    HOMES+=("${2:?--home needs a directory}"); shift;;
    --list)    LIST="${2:?--list needs a file}"; shift;;
    -h|--help) sed -n '2,10p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac; shift
done
[ ${#HOMES[@]} -gt 0 ] || HOMES=(/root)

# PEM markers are assembled at runtime so secret scanners do not flag this file
PEM_B="-----BEGIN OPENSSH ""PRIVATE KEY-----"; PEM_E="-----END OPENSSH ""PRIVATE KEY-----"
# relative path | file content (all values are fake)
declare -a BAITS=(
  ".aws/credentials|[default]\naws_access_key_id = AKIAEXAMPLEFAKE00000\naws_secret_access_key = ExampleFakeSecretKeyDoNotUse/0000000000000\n"
  ".ssh/id_rsa_backup|${PEM_B}\nZmFrZS1iYWl0LWtleS1ub3QtYS1yZWFsLWtleQ==\n${PEM_E}\n"
  "passwords.txt|mail: hunter2-example\nvpn: correct-horse-example\n"
  "backup/secrets.env|API_TOKEN=example-fake-token-0000\nDB_PASSWORD=example-fake-password\n"
  ".config/gcloud/credentials.db.bak|fake\n"
  ".netrc.old|machine example.invalid login bait password bait\n"
  ".env.production.bak|SECRET_KEY=example-fake-secret\n"
)

run(){ if [ "$DRY" = 1 ]; then echo "[dry-run] $*"; else "$@"; fi; }
[ "$DRY" = 1 ] || [ "$(id -u)" = 0 ] || { echo "run as root (or use --dry-run)" >&2; exit 1; }

run mkdir -p "$(dirname "$LIST")"
tmp=$(mktemp); trap 'rm -f "$tmp"' EXIT
for h in "${HOMES[@]}"; do
  for b in "${BAITS[@]}"; do
    rel=${b%%|*}; body=${b#*|}; path="$h/$rel"
    if [ -e "$path" ]; then echo "exists, skipping: $path"; echo "$path" >>"$tmp"; continue; fi
    echo "bait: $path"
    if [ "$DRY" != 1 ]; then
      mkdir -p "$(dirname "$path")"
      printf '%b' "$body" >"$path"; chmod 600 "$path"
    fi
    echo "$path" >>"$tmp"
  done
done
if [ "$DRY" = 1 ]; then echo "[dry-run] would write $(wc -l <"$tmp") paths to $LIST"
else install -m 0644 "$tmp" "$LIST"; echo "wrote $LIST ($(wc -l <"$LIST") baits)"; fi
