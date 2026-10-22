#!/usr/bin/env bash
# Step 2 — falcosidekick (no official apt repo; binary release + own systemd unit).
set -euo pipefail

ARCH=$(dpkg --print-architecture)   # e.g. amd64
VER=$(curl -fsSL -o /dev/null -w '%{redirect_url}' https://github.com/falcosecurity/falcosidekick/releases/latest | awk -F/ '{print $NF}')
echo "Installing falcosidekick ${VER} (${ARCH})"
curl -fsSL "https://github.com/falcosecurity/falcosidekick/releases/download/${VER}/falcosidekick_${VER#v}_linux_${ARCH}.tar.gz" -o /tmp/falcosidekick.tar.gz
tar -xzf /tmp/falcosidekick.tar.gz -C /tmp falcosidekick
install -m 0755 /tmp/falcosidekick /usr/local/bin/falcosidekick
rm -f /tmp/falcosidekick.tar.gz /tmp/falcosidekick

id -u falcosidekick &>/dev/null || useradd --system --no-create-home --shell /usr/sbin/nologin falcosidekick

mkdir -p /etc/falcosidekick
chmod 750 /etc/falcosidekick
# config.yaml + falcosidekick.env are dropped in separately (see falcosidekick-config.yaml /
# falcosidekick.env.example in this same directory), then:
chown root:falcosidekick /etc/falcosidekick/falcosidekick.env
chmod 640 /etc/falcosidekick/falcosidekick.env

systemctl daemon-reload
systemctl enable --now falcosidekick.service
sleep 2
systemctl is-active falcosidekick.service
curl -fsS http://127.0.0.1:2801/ping && echo "falcosidekick OK"
