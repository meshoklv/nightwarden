#!/usr/bin/env bash
set -euo pipefail
systemctl disable --now falco-modern-bpf.service falcosidekick.service 2>/dev/null || true
apt-get purge -y falco || true
rm -f /etc/apt/sources.list.d/falcosecurity.list /usr/share/keyrings/falco-archive-keyring.gpg
rm -rf /etc/falco                                   # drop --if you want to keep the tuned rules for later
rm -f /usr/local/bin/falcosidekick /etc/systemd/system/falcosidekick.service
rm -rf /etc/falcosidekick /etc/systemd/system/falco-modern-bpf.service.d
userdel falcosidekick 2>/dev/null || true
systemctl daemon-reload
apt-get update -y
echo "malware-watch.sh timer/service untouched — bash watcher keeps running as the sole detector."
