# Why this exists

Nightwarden was written in the days after a real breach of a small development server. This is the anonymised post-mortem. No addresses, hostnames or people are named; attacker infrastructure is deliberately not published (it was never confirmed to be a public indicator).

## The setup

- A web terminal (`ttyd`) bound to `0.0.0.0` with **no password**.
- The host firewall (`ufw`) was **disabled**.
- The machine was reachable from the local network of the hosting site.
- No access logs, no auditd, no persistent journal between reboots.

## Timeline

| When | Event |
|---|---|
| t = 0 | Someone on the local network reaches the web terminal. The source was never established — there were no logs to establish it. |
| t + 21 s | A Mirai-family bot is on the machine and running. |
| Then | It renames itself to look like `irqbalance`, `atd` or `[kworker]`, deletes its own binary from disk and opens a telnet-style listener (port 23). |
| Afterwards | It collects `~/.ssh`, shell histories, and every `*.env`, `*secret*`, `*token*` file it can find — six separate passes. |
| ~2.5 days | A human notices something odd. Until then nothing alerted. |

## Why the usual instincts failed

1. **The intrusion was shorter than the monitoring interval.** 21 seconds is less than a 60-second poll. A poller can only catch what is *still there* afterwards — so persistence and leftovers must be hash-checked, and real-time sources (eBPF, fanotify, auditd) must exist alongside.
2. **The malware lied about its name.** `ps` showed `irqbalance`. Names are attacker-controlled; facts are not.
3. **Everything it stole was in plain files.** Keys, tokens and `.env` files were simply read.
4. **Nobody was watching the watcher.** Silence looked identical to "all is well".
5. **No evidence was kept**, so the honest answer to "how did they get in" is "unknown". Nightwarden's rule: if the source is not found, say *source unknown* — never a plausible story.

## Generic indicators of this class of compromise

These are behaviours, not addresses:

| Indicator | Why it is telling | Check |
|---|---|---|
| Process whose `/proc/<pid>/exe` is `(deleted)` | Binary removed after launch to hide it | `ls -l /proc/*/exe 2>/dev/null \| grep deleted` |
| `exe` is `/memfd:…` or an anonymous mapping | Fileless execution | `readlink /proc/<pid>/exe` |
| "Kernel thread" (`[kworker…]`) that has a readable `exe` | Real kernel threads have none; the `PF_KTHREAD` flag in `/proc/<pid>/stat` is the honest test | compare flag vs name |
| Shell or interpreter whose fd 0/1/2 are sockets | Reverse shell | `ls -l /proc/<pid>/fd` |
| New listener on 23 / 2323 / 7547 / 48101 / 53321 | Typical botnet ports | `ss -ltnp` |
| Outbound SYNs to 23 / 2323 / 53321 | Scanning for the next victim | `ss -tn` |
| Execution from `/tmp`, `/var/tmp`, `/dev/shm` (**also 32-bit**) | Dropper staging; Mirai is often built 32-bit and slips past `arch=b64`-only audit rules | auditd `exec_tmp` key |
| Changed `authorized_keys`, `ld.so.preload`, cron, systemd units | Persistence | hash baseline |
| One process reading many secret files | Collection | auditd `secrets_read`, honeytokens |

## What changed afterwards

- Services that give a shell must have authentication, and listen on loopback.
- Firewall on, default drop, persistent across reboots.
- Secrets out of plain files wherever possible; one key per role.
- Logging **before** the next incident: events journal, auditd, off-box audit forwarding.
- A watcher that is itself watched, by something that does not share its failure modes.
