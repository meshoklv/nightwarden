#!/usr/bin/env bash
# Step 1 — install Falco with the modern eBPF driver (CO-RE, no DKMS/headers).
# Sources: falco.org/docs/setup/packages/, falco.org/blog/falco-modern-bpf-0-35-0/
set -euo pipefail

# --- pre-flight: confirm CO-RE prerequisites BEFORE touching anything ---
echo "kernel: $(uname -r)"
if [ ! -f /sys/kernel/btf/vmlinux ]; then
  echo "FATAL: /sys/kernel/btf/vmlinux missing — no BTF, modern eBPF cannot CO-RE. STOP." >&2
  exit 1
fi
echo "BTF present — modern eBPF path confirmed, no DKMS/kernel-headers needed."

# --- apt repo + signing key ---
curl -fsSL https://falco.org/repo/falcosecurity-packages.asc \
  | gpg --dearmor -o /usr/share/keyrings/falco-archive-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/falco-archive-keyring.gpg] https://download.falco.org/packages/deb stable main" \
  > /etc/apt/sources.list.d/falcosecurity.list
apt-get update -y

# --- install: force modern_ebpf, fully non-interactive, DO NOT pull dkms/make/linux-headers ---
# (those are only needed for the legacy kernel-module/legacy-eBPF driver; modern eBPF
#  is compiled-in via CO-RE and needs neither — that is the whole point of this setup)
DEBIAN_FRONTEND=noninteractive \
FALCO_FRONTEND=noninteractive \
FALCO_DRIVER_CHOICE=modern_ebpf \
FALCOCTL_ENABLED=no \
  apt-get install -y falco

systemctl daemon-reload
# Package ships one systemd unit per driver choice; enable the modern-eBPF one explicitly.
systemctl enable --now falco-modern-bpf.service

sleep 3
echo "--- health check ---"
systemctl is-active falco-modern-bpf.service
journalctl -u falco-modern-bpf -n 30 --no-pager | grep -i -E "probe|modern|bpf" || true
if lsmod | grep -qi falco; then
  echo "WARN: a falco kernel module is loaded — that means it silently fell back to kmod, investigate."
else
  echo "OK: no kernel module loaded — pure CO-RE eBPF path confirmed."
fi
falco --version
