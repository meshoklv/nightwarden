# Real-time detection with Falco + falcosidekick

> Status: experimental kit; validated by the author on one Ubuntu 24.04 host (kernel 6.8); read the "Known issues" before deploying.

Adds real-time exec/syscall detection and container attribution on top of
`malware-watch.sh`. Target: Ubuntu 24.04, kernel 6.8 with BTF (modern eBPF
CO-RE, no DKMS), a Docker host with interactive dev containers (tmux, node,
python, package managers constantly exec'ing -- the false-positive source the
tuning here targets).

Alerts go to Telegram and/or a generic webhook through falcosidekick.

## Files

| File | Deploy target |
|---|---|
| `00-install-falco.sh` | run as-is (installer) |
| `02-patch-falco-yaml.py` | run as-is (patches `/etc/falco/falco.yaml`, backup in `falco.yaml.orig`) |
| `03-install-falcosidekick.sh` | run as-is (installer) |
| `04-verify.sh` | run as-is (health check) |
| `99-rollback.sh` | run as-is (uninstall) |
| `00-host-macros.yaml` | `/etc/falco/rules.d/00-host-macros.yaml` (edit the container lists first) |
| `10-quiet-dev-noise.yaml` | `/etc/falco/rules.d/10-quiet-dev-noise.yaml` |
| `20-highvalue.yaml` | `/etc/falco/rules.d/20-highvalue.yaml` |
| `falcosidekick-config.yaml` | `/etc/falcosidekick/config.yaml` |
| `falcosidekick.env.example` | `/etc/falcosidekick/falcosidekick.env` (chmod 640 root:falcosidekick; never commit the filled-in copy) |
| `falcosidekick.service` | `/etc/systemd/system/falcosidekick.service` |
| `falco-limits.conf` | `/etc/systemd/system/falco-modern-bpf.service.d/10-limits.conf` |

## Deploy order

1. `00-install-falco.sh` -- checks BTF, adds the Falco apt repo, installs with `FALCO_DRIVER_CHOICE=modern_ebpf`.
2. `apt-get install -y python3-yaml && python3 02-patch-falco-yaml.py` -- idempotent; touches only `priority`, `json_output*`, `http_output`, `engine.modern_ebpf.*` and the container plugin.
3. Edit `00-host-macros.yaml` (list the container names/prefixes where dev work is expected), then copy the three rules files into `/etc/falco/rules.d/`.
4. Copy `falcosidekick-config.yaml`, `falcosidekick.env.example` (fill in values) and `falcosidekick.service`, then run `03-install-falcosidekick.sh`.
5. Copy `falco-limits.conf` and restart Falco.
6. `04-verify.sh`.
7. Rollback: `99-rollback.sh` (leaves the `malware-watch.sh` timer untouched).

## Priorities and paging

- Falco `priority: notice` (set by the patch script): lower events are never generated.
- falcosidekick `*_MINIMUMPRIORITY=critical`: only critical/alert/emergency page you. Lower tiers stay in `journalctl -u falco-modern-bpf` for tuning.
- Lower the threshold only after days of measured false-positive data.

## Rules posture

- `10-quiet-dev-noise.yaml` narrows four stock rules (terminal shell, package management, write below binary dir, write below etc) for containers matched by `dev_workspace_container`. Everything outside it is unchanged.
- "Launch Suspicious Network Tool in Container" (nc/ncat/socat/nmap) and "Search Private Keys or Passwords" are not exempted anywhere, and their priority is raised to CRITICAL so they actually reach the alert channel.
- `20-highvalue.yaml` adds three CRITICAL rules: outbound connections to known bot/C2 ports, exec from `/tmp` outside known toolchains, writes to `ld.so.preload`/cron/`authorized_keys`.

## Known issues

- **Stock priorities are below the paging threshold.** In stock Falco the nc/socat rule and the private-key search rule are WARNING/NOTICE-level, so with `minimumpriority=critical` they never alert. `10-quiet-dev-noise.yaml` raises them with `override: priority: replace`; the alternative is lowering `minimumpriority` (noisier).
- **`append: true` is deprecated.** Newer Falco uses `override: condition: append` (used here, needs Falco >= 0.38). On older Falco versions use `append: true` instead.
- **Watch drop statistics.** Small eBPF buffers (`buf_size_preset: 2`) bound memory but can drop events under load. Enable `metrics` in `falco.yaml` and watch `n_drops`; if it climbs, raise the preset. Drops are blind spots.
- **Expect a loud first 24-48 h.** The private-key search rule will fire on legitimate secret-hygiene greps. Narrow by exact command after watching real hits; do not blanket-exempt.
- **A webhook gets the raw Falco JSON**, not `{"text": ...}`; see comments in `falcosidekick-config.yaml`.
- Container attribution needs the Docker socket readable by Falco; adjust the `sockets` entry for containerd/podman.
- Only tested on one host; rule names refer to the stock ruleset shipped with the Falco version at the time and may change.

## Sources

- https://falco.org/docs/setup/packages/
- https://falco.org/blog/falco-modern-bpf-0-35-0/
- https://falco.org/docs/concepts/plugins/usage/
- https://github.com/falcosecurity/falcosidekick
