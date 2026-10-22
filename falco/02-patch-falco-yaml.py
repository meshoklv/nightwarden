#!/usr/bin/env python3
"""Idempotent patch of the packaged /etc/falco/falco.yaml.
Touches ONLY the keys below; everything else stays exactly as shipped by the
.deb. Original is preserved at falco.yaml.orig for diffing.
Requires: apt-get install -y python3-yaml
Sources for keys: falco.org/blog/falco-modern-bpf-0-35-0 (engine.modern_ebpf),
raw falco.yaml on github (rules_files/http_output/priority defaults),
falco.org/docs/concepts/plugins/usage (container plugin).
"""
import os, shutil
import yaml

PATH = "/etc/falco/falco.yaml"
BACKUP = PATH + ".orig"

with open(PATH) as f:
    cfg = yaml.safe_load(f) or {}

if not os.path.exists(BACKUP):
    shutil.copy2(PATH, BACKUP)

# Don't even generate info/debug events — kills the bulk of noise at the source.
cfg["priority"] = "notice"

# Structured JSON is required by falcosidekick's http input.
cfg["json_output"] = True
cfg["json_include_output_property"] = True

# Ship every generated event to falcosidekick; falcosidekick applies its OWN
# per-output minimumpriority filter (e.g. Telegram only gets >= critical, see falcosidekick.env.example).
cfg.setdefault("http_output", {})
cfg["http_output"]["enabled"] = True
cfg["http_output"]["url"] = "http://127.0.0.1:2801/"

# Engine: modern eBPF, buffers tuned to bound memory. Adjust to your CPU count.
cfg.setdefault("engine", {})
cfg["engine"]["kind"] = "modern_ebpf"
cfg["engine"].setdefault("modern_ebpf", {})
cfg["engine"]["modern_ebpf"]["cpus_for_each_buffer"] = 4  # e.g. 8 vCPU -> 2 buffers total; tune to your host
cfg["engine"]["modern_ebpf"]["buf_size_preset"] = 2       # smaller than default(4); raise if drop counters climb

# Container attribution: pid -> which docker container.
plugins = cfg.setdefault("plugins", [])
if not any(isinstance(p, dict) and p.get("name") == "container" for p in plugins):
    plugins.append({
        "name": "container",
        "library_path": "libcontainer.so",
        "init_config": {
            "label_max_len": 100,
            "with_size": False,
            "sockets": ["/var/run/docker.sock"],
        },
    })
load_plugins = cfg.setdefault("load_plugins", [])
if "container" not in load_plugins:
    load_plugins.append("container")

with open(PATH, "w") as f:
    yaml.safe_dump(cfg, f, default_flow_style=False, sort_keys=False)

print(f"Patched {PATH} (backup: {BACKUP}). Review: diff -u {BACKUP} {PATH}")
