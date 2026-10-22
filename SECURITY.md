# Security policy

Please report vulnerabilities privately via GitHub Security Advisories (the "Report a vulnerability" button on the repository's Security tab) rather than a public issue.

Scope notes:

- Nightwarden runs as root and parses attacker-controlled strings (process names, command lines, file names). Injection or escaping bugs in alert or triage paths are in scope.
- Known limits (root-level attackers, kernel rootkits, the 60 s polling gap) are documented in the README and are not vulnerabilities.
