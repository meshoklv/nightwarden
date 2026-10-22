#!/usr/bin/env bash
set -uo pipefail
echo "== falco =="
systemctl is-active falco-modern-bpf.service
journalctl -u falco-modern-bpf -n 20 --no-pager
lsmod | grep -qi falco && echo "WARN: kmod loaded (unexpected)" || echo "OK: no kmod, pure eBPF"
ls -la /sys/kernel/btf/vmlinux
systemctl show falco-modern-bpf.service -p MemoryCurrent -p CPUUsageNSec

echo "== falcosidekick =="
systemctl is-active falcosidekick.service
curl -fsS http://127.0.0.1:2801/ping || echo "falcosidekick /ping unreachable"

echo "== manual end-to-end test (run once, in a non-dev container (not matched by dev_workspace_container)) =="
echo "  cat /etc/shadow    # should trip a stock sensitive-file rule and an alert within ~2s (if the rule priority reaches your minimumpriority)"
echo "  echo x > /root/.ssh/authorized_keys   # should trip the persistence rule"
echo "== drop statistics (watch these; drops = blind spots) =="
echo "  Enable metrics in falco.yaml (metrics.enabled: true, output_rule: true) and review the"
echo "  'n_drops' counters periodically. If they climb, raise engine.modern_ebpf.buf_size_preset."
