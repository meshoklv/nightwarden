# Contributing

Issues and pull requests are welcome.

- **Never run the sending scripts outside dry-run mode** while testing (`MW_TEST_SILENT=1`, `HB_DRY_RUN=1`, `malware-watch.sh dryrun`, `bait-watch.py --selftest`). A live run can page a human at night.
- Before a PR: `bash -n` on every `.sh`, `python3 -m py_compile` on every `.py`, `shellcheck` if you have it (CI runs the same).
- Detection changes must keep the principle: **wide detection, narrow killing**. A new signal should warn by default; killing needs several independent signals and the allow-list check first.
- Do not commit tokens, chat ids, hostnames or real IP addresses; use placeholders (`203.0.113.0/24`, `example.org`).
