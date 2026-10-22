# On-box tamper hints: patch notes for malware-watch.sh / malware-watch-hb.sh

> Status: experimental kit; validated by the author on one Ubuntu 24.04 host (kernel 6.8); read the "Known issues" before deploying.

These changes feed the off-box dead-man (`../checker/`): a monotonic **seq**
counter, an **append-only event ledger** (hashed off-box), and detection of a
**future-dated heartbeat** and a **cleared append-only flag**.

They are written as descriptions plus snippets, not as exact find/replace
blocks, because the watcher scripts evolve. Locate the equivalent place in your
copy of the script. Use a variable name for the ledger that does not collide
with any existing one (`EV_LEDGER` below).

## A. malware-watch.sh

1. **State paths.** Next to the other state variables (`HB=`, `SEEN=`...):
   ```bash
   SEQ=$STATE/seq                          # monotonic check-in counter
   EV_LEDGER=$LOGDIR/events-ledger.jsonl   # append-only ledger (chattr +a)
   ```
2. **Mirror every event into the ledger.** In the function that appends an event
   line to the event log, write the same line to `$EV_LEDGER` too
   (`>>` works on a `chattr +a` file).
3. **Bump the counter every run**, in the housekeeping step next to the
   heartbeat write (`date -u +%s >"$HB"`):
   ```bash
   s=$(tr -cd '0-9' <"$SEQ" 2>/dev/null); : "${s:=0}"; echo $(( s + 1 )) >"$SEQ" 2>/dev/null || true
   ```
   `$SEQ` must stay writable. Only the ledger gets `chattr +a`.
4. **Self-check, run first in each tick.** Add a function and call it at the top
   of the main `run()` (before the other modules). Replace `crit` / `esc` / `now`
   with your script's alert helpers:
   ```bash
   mod_selfcheck(){
     local n; n=$(now)
     if [ -f "$HB" ]; then local hbv; hbv=$(tr -cd '0-9' <"$HB" 2>/dev/null); : "${hbv:=0}"
       [ "$hbv" -gt $(( n + 60 )) ] && crit "dead-man forgery (heartbeat in the future)" \
         "heartbeat=$hbv > now+60: someone writes a future timestamp to look alive." "hbfuture"
     fi
     if [ -f "$SEEN" ]; then local fut
       fut=$(awk -F'\t' -v c=$(( n + 60 )) '$1>c{print $1"\t"$2}' "$SEEN" 2>/dev/null | head -3)
       [ -n "$fut" ] && crit "dedup tampering (future 'seen' entries)" "$(esc "$fut")" "seenfuture"
     fi
     if command -v lsattr >/dev/null 2>&1 && [ -f "$EV_LEDGER" ]; then
       lsattr "$EV_LEDGER" 2>/dev/null | awk '{print $1}' | grep -q 'a' || \
         crit "append-only flag removed from the evidence ledger" \
         "Restore with: chattr +a $EV_LEDGER" "ledgerattr"
     fi; }
   ```

## B. malware-watch-hb.sh (second, independent detector)

Where the heartbeat age is computed, read the value as digits only and also flag
a heartbeat that lies more than 60 s in the future:
```bash
hbv=$(tr -cd '0-9' <"$HB" 2>/dev/null); : "${hbv:=0}"
age=$(( $(now) - hbv ))
[ "$hbv" -gt $(( $(now) + 60 )) ] && add "Heartbeat is in the future ($hbv): looks like dead-man forgery."
```

## C. Install-time, once, as root: set the append-only flag

The watcher only appends; immutability is applied here, so the hardened unit does
not need CAP_LINUX_IMMUTABLE. Clearing the flag is then caught by (a) the
self-check above, (b) the off-box checker (the responder reports
`ledger_append_only:0`), (c) the auditd `mwtamper` rule.

```bash
install -o root -g root -m 0700 -d /var/log/malware-watch
: >> /var/log/malware-watch/events-ledger.jsonl        # create if absent, never clobber
chattr +a /var/log/malware-watch/events-ledger.jsonl
lsattr /var/log/malware-watch/events-ledger.jsonl      # flags must contain 'a'
```
To rotate it (rare): `chattr -a`, move, recreate, `chattr +a`. This trips the
`mwtamper` audit watch, which is expected; do it deliberately.

## Known issues

- **Do not use `LoadCredential=` for the env file** in `hardening.conf`: the unit
  fails to start if the file does not exist, and gains nothing because the
  watcher runs as root and reads the env file directly. The shipped
  `hardening.conf` omits it for that reason.
- **The checker's SSH key must be restricted on both ends.** On the watched host
  the key is forced to `command=".../mw-pull-responder",restrict`
  (`mwpull.authorized_keys.example`). If you reach the host through a jump host,
  restrict the key there too with `restrict,port-forwarding,permitopen="<watched-host>:22"`
  in that host's `authorized_keys`, so it cannot be used for anything else.
- **`-e 2` in `mw.rules` locks the audit rules until reboot.** Test the rules
  before enabling the lock; changing them later needs a reboot.
- **The responder is only as trustworthy as root on the watched host.** A root
  attacker can make it lie, but only by editing pinned files, which is visible
  off-box. Re-pin after every legitimate change.
- The seq/ledger/self-check changes above are not part of the shipped
  `bin/` scripts; apply them by hand and verify with `malware-watch.sh dryrun`.
