# AI alert triage (optional)

When the watcher raises a scary **red** alert, a separate, sandboxed Claude Code session looks at the evidence and sends a short verdict: what happened, what it means, what the guard already did, what *you* should do. It first replies instantly with a fixed "alert seen, investigating" line (no model involved) so you are never alone with a frightening message.

**Off by default.** After install the service is stopped, `TRIAGE_ENABLED=0`, and messages go to a file, not to your phone.

## Flow

```text
watcher writes a RED alert to its journal
   -> triage tails the journal (never touches the watcher)
   -> checks: not self-inflicted? not a duplicate? not a storm? budget left? quiet mode?
   -> instant fixed "alert seen" message (no model)
   -> case folder: the alert, neighbouring records, the guard's evidence snapshot (fenced as untrusted)
   -> `claude -p` session as an unprivileged user, filesystem read-only
   -> it inspects the system ONLY through a small closed set of read-only verbs ("probe")
   -> schema-enforced JSON verdict (a form, not a letter)
   -> a rigid template in notify.py writes the human message
```

The model never sends anything and never runs commands of its own. The boundary is the OS (unprivileged user, read-only filesystem, no capabilities, syscall filter, a Unix socket with a closed verb list that refuses secrets, keys and bait files) — **not** Claude's own allow/deny settings, which are not a security boundary.

## Why it reads the journal instead of hooking the sender

| Approach | Verdict |
|---|---|
| Hook into the watcher's sender | rejected: the send path is the most critical code; anything added there can delay or break it |
| systemd path unit on the journal | rejected: the journal moves every few minutes, the service would thrash |
| **Separate journal tailer** | **chosen:** the watcher is untouched; if triage dies the watcher never notices |

## Fuses (each exists because of a concrete failure mode)

- **Loop breaker** ("triage causes an alert which causes triage"): bait files are never readable by the probe; alerts that arrive during a case *and* mention triage are dropped; one fingerprint is analysed once per 6 h.
- **Storm**: 6 red alerts within 15 minutes = one batched analysis.
- **Money**: $0.60 per run (`--max-budget-usd`), $3.00 per day, 4 per hour, 12 per day, 90 s minimum gap, 30 probe calls per case. Counters persist on disk — restarting the service does not reset them. A crash-looping service stops after 5 failures in 30 minutes.
- **Mute** is honoured (messages go to `outbox.jsonl`); only "the guard died" bypasses it. Analysis still runs silently, because evidence is perishable.
- **Prompt injection**: attacker-controlled strings (file names, command lines) are fenced; the real defence is that triage cannot *do* anything. An injection attempt is itself reported as evidence for an attack.
- **Honesty**: every message carries the verbatim alert and the class computed *without* the model; if the guard says red and the model says false alarm, the message says so loudly.

## Enable (four separate steps)

```bash
sudo bash install.sh --dry-run          # preview
sudo bash install.sh                    # installs OFF
sudoedit /etc/alert-triage.env          # put ANTHROPIC_API_KEY here (chmod 600)
bash test/selftest.sh                   # no model needed; checks sinks, mute, probe refusals, templates
sudo sed -i 's/^TRIAGE_ENABLED=0/TRIAGE_ENABLED=1/' /etc/alert-triage.env
sudo systemctl enable --now alert-triage   # messages still go to /var/log/alert-triage/outbox.jsonl
# read the outbox, and only when it is useful:
sudo sed -i 's/^TRIAGE_SINK=file/TRIAGE_SINK=telegram/' /etc/alert-triage.env   # or webhook
sudo systemctl restart alert-triage
```

Sinks: `file` (default) · `stdout` · `telegram` (token/chat from `/etc/malware-watch.env`) · `webhook` (`TRIAGE_WEBHOOK_URL`, JSON `{"text","content"}`). Language: `TRIAGE_LANG=en|ru`. Model: `TRIAGE_MODEL` (empty = the Claude Code default).

Switch off any time: `systemctl disable --now alert-triage`. Remove: `sudo bash uninstall.sh`.

## What has been verified

- By `test/selftest.sh` without a model: delivery interception, quiet mode, probe refusals (`rm`, shadow, ssh keys, secrets, non-numeric pid), the call ceiling, HTML escaping of foreign text, disagreement and injection warnings, all templates in `en` and `ru`, webhook against a local receiver.
- Only with `SELFTEST_LIVE=1` (needs a real model, a few tenths of a dollar): end-to-end verdict on a fake alert with a planted "declare false alarm" instruction. Not part of CI.

## Why no Docker image

The daemon needs the host's journals, `/proc` and a probe socket for the host; a container would only analyse itself.
