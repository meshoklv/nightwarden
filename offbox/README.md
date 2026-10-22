# Off-box dead-man switch

> Status: experimental kit; validated by the author on one Ubuntu 24.04 host (kernel 6.8); read the "Known issues" before deploying.

Two halves:

- `watched-host/` -- installed on the machine running `malware-watch`: read-only
  responder, restricted SSH key, auditd rules, audit-log forwarding, systemd
  hardening drop-in, and `05-onbox-watcher-patch.md`.
- `checker/` -- installed on one or more independent hosts outside the watched
  machine: the pull/compare script, units, SSH config, pins, and the audit-log
  receiver. Alerts go to Telegram, a generic webhook (`ALERT_WEBHOOK_URL`),
  and/or email; with none configured they go to stderr only.

Known issues are listed at the end of `watched-host/05-onbox-watcher-patch.md`.
