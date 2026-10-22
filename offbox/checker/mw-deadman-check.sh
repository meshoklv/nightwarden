#!/usr/bin/env bash
# ============================================================================
# mw-deadman-check.sh — OFF-BOX dead-man switch + integrity pin comparator.
# Deployed on one or more independent "checker" hosts OUTSIDE the watched host
# (e.g. a cheap VPS). Runs every minute (systemd timer or cron). PULL model: it
# SSHes into the watched host with a restricted, command=-forced low-priv key and
# reads the responder JSON.
#
# It ALARMS — over channels that do not depend on the watched host (Telegram
# and/or a webhook and/or email, all sent from THIS host's own internet) — when
# ANY of:
#   * the pull fails (ssh error / empty / unparseable)      -> silence = alarm
#   * heartbeat is STALE      (watched_now - hb  > HB_STALE)
#   * heartbeat is in the FUTURE (hb > watched_now + HB_FUTURE)  -> forgery
#   * watched host clock is skewed (|watched_now - local_now| > CLOCK_SKEW) -> clock tamper
#   * monotonic seq STOPS advancing (frozen > SEQ_STALL) or goes BACKWARDS
#   * any PINNED hash mismatches (script/hb/responder/units/hardening/env-hash/
#     baseline/mwpull-authorized_keys/auditd-rules/sudoers)
#   * the event ledger lost its append-only flag, or its line count regressed
#
# Every pull is also appended to an off-box ledger (forensic copy that survives
# the watched host being wiped). Root on the watched host can still make the
# responder lie, but only by editing files whose hashes are ALSO pinned here and
# whose edits trip auditd — i.e. tamper becomes noisy, never silent.
#
# Notification channels (all optional; configure at least one):
#   Telegram  TG_TOKEN + TG_CHAT
#   Webhook   ALERT_WEBHOOK_URL  (POST JSON {"text":"...","content":"..."};
#             Slack/Discord/ntfy-style proxies accept this)
#   Email     MAIL_TO (needs sendmail)
# If none is configured, alarms go to stderr (journal) only; the script never
# fails because of a missing channel.
#
# Modes:  check (default, run by timer) | pin [--yes] | test | show
# Config: /etc/mw-deadman.env   Pins: /etc/mw-deadman.pins   State: /var/lib/mw-deadman/
# ============================================================================
set -uo pipefail

CFG=/etc/mw-deadman.env
PINS=/etc/mw-deadman.pins
STATE=/var/lib/mw-deadman
LEDGER=$STATE/ledger.jsonl
DEDUP=$STATE/dedup.tsv
SEQST=$STATE/seq.state          # last_seq \t local_ts_of_last_advance
mkdir -p "$STATE"; chmod 700 "$STATE" 2>/dev/null || true

# ---- defaults (override in /etc/mw-deadman.env) ----
: "${THIS:=$(hostname -s 2>/dev/null || echo checker)}"   # label of this checker in every alert
: "${SSH_ALIAS:=watched-host-mw}"          # Host block in /root/.ssh/config (see mw-deadman.ssh.example)
: "${SSH_OPTS:=-F /root/.ssh/config -o BatchMode=yes -o ConnectTimeout=10 -o ServerAliveInterval=5 -o ServerAliveCountMax=2}"
: "${SSH_TIMEOUT:=20}"
: "${HB_STALE:=240}"                 # 4 min
: "${HB_FUTURE:=30}"
: "${CLOCK_SKEW:=300}"
: "${SEQ_STALL:=300}"
: "${DEDUP_TTL:=1800}"               # re-alert the same problem every 30 min
: "${TG_TOKEN:=}"; : "${TG_CHAT:=}"  # alert bot token/chat — lives on THIS host only
: "${ALERT_WEBHOOK_URL:=}"            # optional generic webhook
: "${MAIL_TO:=}"                     # optional; uses `sendmail -t` if set
: "${MAIL_FROM:=mw-deadman@$THIS}"
# shellcheck disable=SC1090
[ -r "$CFG" ] && . "$CFG"

now(){ date -u +%s; }
ts(){ date -u +'%F %T'; }
have(){ command -v "$1" >/dev/null 2>&1; }
have jq || { echo "FATAL: jq required (apt-get install -y jq)"; exit 3; }

# ---------------- pull ----------------
pull(){ timeout "$SSH_TIMEOUT" ssh $SSH_OPTS "$SSH_ALIAS" pull 2>/dev/null; }

# ---------------- notify (independent of the watched host) ----------------
tg(){ [ -n "$TG_TOKEN" ] || return 1
  timeout 12 curl -s -m 12 -X POST "https://api.telegram.org/bot$TG_TOKEN/sendMessage" \
    --data-urlencode "chat_id=$TG_CHAT" --data-urlencode "parse_mode=HTML" \
    --data-urlencode "disable_web_page_preview=true" --data-urlencode "text=$1" \
    2>/dev/null | grep -q '"ok":true'; }
# strip HTML tags and unescape entities for plain-text channels
plain(){ printf '%s' "$1" | sed -e 's/<[^>]*>//g' -e 's/&lt;/</g' -e 's/&gt;/>/g' -e 's/&amp;/\&/g'; }
webhook(){ [ -n "$ALERT_WEBHOOK_URL" ] || return 1
  local t body; t=$(plain "$1")
  body=$(jq -nc --arg t "$t" '{text:$t,content:$t}') || return 1
  timeout 12 curl -fsS -m 12 -X POST -H 'Content-Type: application/json' \
    --data "$body" "$ALERT_WEBHOOK_URL" >/dev/null 2>&1; }
email(){ [ -n "$MAIL_TO" ] || return 0; have sendmail || return 0
  { printf 'From: %s\nTo: %s\nSubject: [mw-deadman/%s] %s\n\n%s\n' \
      "$MAIL_FROM" "$MAIL_TO" "$THIS" "$1" "$2"; } | timeout 20 sendmail -t 2>/dev/null || true; }

# dedup identical problems for DEDUP_TTL
seen(){ local sig=$1 last
  last=$(awk -F'\t' -v s="$sig" '$2==s{print $1}' "$DEDUP" 2>/dev/null | tail -1)
  [ -n "$last" ] && [ $(( $(now) - last )) -lt "$DEDUP_TTL" ]; }
mark(){ printf '%s\t%s\n' "$(now)" "$1" >>"$DEDUP"
  [ -f "$DEDUP" ] && awk -F'\t' -v c=$(( $(now)-86400 )) '$1>=c' "$DEDUP" >"$DEDUP.t" 2>/dev/null && mv "$DEDUP.t" "$DEDUP"; }

# ALARM: sig=dedup-key  short=subject  detail=body
ALARMED=0
alarm(){ local sig=$1 short=$2 detail=$3; ALARMED=1
  seen "$sig" && return 0; mark "$sig"
  local html="🆘🔴 <b>DEAD-MAN [$THIS→watched host]: $short</b>
$detail

<i>$(ts) UTC · alarm sent from $THIS (independent of the watched host)</i>"
  # always leave a trace on stderr/journal, so a missing channel is never silent
  echo "$(ts) ALARM [$sig] $short" >&2
  tg "$html" || true
  webhook "$html" || true
  email "$short" "$detail
-- sent from $THIS at $(ts) UTC"
}

# ---------------- integrity pins ----------------
PIN_KEYS="watch hb resp svc timer hbsvc hbtimer harden env baseline mwpull_ak auditd sudoers"

capture_pins(){ # write current responder pins to $PINS (operator confirms the watched host is clean)
  local j; j=$(pull) || { echo "pull failed — cannot capture pins"; exit 2; }
  echo "$j" | jq -e . >/dev/null 2>&1 || { echo "unparseable response — aborting"; exit 2; }
  echo "== pins reported by the watched host now =="; echo "$j" | jq -r '.pins'
  if [ "${1:-}" != "--yes" ]; then
    echo; echo "Re-run with --yes to WRITE these to $PINS (only after you've verified the watched host is clean)."; exit 0; fi
  { echo "# mw-deadman pins captured $(ts) UTC from the watched host — do not hand-edit"; echo "# regenerate after any LEGITIMATE change: mw-deadman-check.sh pin --yes"
    local k; for k in $PIN_KEYS; do printf '%s\t%s\n' "$k" "$(echo "$j" | jq -r ".pins.$k")"; done
  } >"$PINS.tmp" && chmod 600 "$PINS.tmp" && mv "$PINS.tmp" "$PINS"
  echo "wrote $PINS"; }

pinned(){ awk -F'\t' -v k="$1" '$1==k{print $2}' "$PINS" 2>/dev/null; }

# ---------------- main check ----------------
check(){
  local j; j=$(pull)
  if [ -z "$j" ] || ! echo "$j" | jq -e . >/dev/null 2>&1; then
    alarm "pull-fail" "PULL FAILED — the watched host unreachable or responder gone" \
      "ssh to the watched host returned nothing / unparseable. Either the watched host is down, the network path (e.g. jump host) is broken, the responder/key was removed, or the box is being tampered with. THIS IS THE SILENCE=ALARM CASE — investigate now."
    return; fi

  local dnow hb seq evcount evtail led lnow
  dnow=$(echo "$j" | jq -r '.now'); hb=$(echo "$j" | jq -r '.hb'); seq=$(echo "$j" | jq -r '.seq')
  evcount=$(echo "$j" | jq -r '.evcount'); evtail=$(echo "$j" | jq -r '.evtail'); led=$(echo "$j" | jq -r '.ledger_append_only')
  lnow=$(now)

  # archive every pull off-box (survives the watched host wipe)
  printf '{"pull_ts":"%s","from":"%s",%s\n' "$(ts)" "$THIS" "${j#\{}" >>"$LEDGER"

  # 1. heartbeat freshness / forgery — judged against the watched host's OWN clock to avoid cross-host skew
  local age=$(( dnow - hb ))
  if [ "$hb" -gt $(( dnow + HB_FUTURE )) ]; then
    alarm "hb-future" "Heartbeat is in the FUTURE (dead-man forgery)" \
      "heartbeat=$hb > watched_now=$dnow (+${HB_FUTURE}s). Someone is writing a future timestamp to keep the watcher looking 'alive'."
  elif [ "$age" -gt "$HB_STALE" ]; then
    alarm "hb-stale" "Heartbeat STALE ${age}s (> ${HB_STALE}s)" \
      "The watcher has not run for ${age}s. It was stopped, masked, frozen (flock/kill), or the box is wedged."
  fi

  # 2. watched-host clock sanity (an attacker can push the clock forward to fake freshness)
  local skew=$(( dnow - lnow )); [ "$skew" -lt 0 ] && skew=$(( -skew ))
  [ "$skew" -gt "$CLOCK_SKEW" ] && alarm "clock-skew" "watched-host clock skew ${skew}s" \
      "watched_now=$dnow vs ${THIS}_now=$lnow differ by ${skew}s (> ${CLOCK_SKEW}s). Possible clock tampering to defeat staleness checks."

  # 3. monotonic seq (only once the on-box seq patch is live: seq>0)
  if [ "$seq" -gt 0 ] 2>/dev/null; then
    local last_seq last_adv; last_seq=$(awk -F'\t' 'END{print $1}' "$SEQST" 2>/dev/null); last_adv=$(awk -F'\t' 'END{print $2}' "$SEQST" 2>/dev/null)
    if [ -z "$last_seq" ]; then printf '%s\t%s\n' "$seq" "$lnow" >"$SEQST"
    elif [ "$seq" -lt "$last_seq" ] 2>/dev/null; then
      alarm "seq-back" "check-in seq went BACKWARDS ($last_seq -> $seq)" \
        "State rollback / restore-from-old-image. The watcher's monotonic counter decreased."
      printf '%s\t%s\n' "$seq" "$lnow" >"$SEQST"
    elif [ "$seq" -gt "$last_seq" ] 2>/dev/null; then printf '%s\t%s\n' "$seq" "$lnow" >"$SEQST"
    else # unchanged
      local stall=$(( lnow - ${last_adv:-$lnow} ))
      [ "$stall" -gt "$SEQ_STALL" ] && alarm "seq-frozen" "check-in seq FROZEN ${stall}s at $seq" \
        "heartbeat may look fresh but the monotonic counter has not advanced for ${stall}s — a naive 'touch heartbeat' forgery, or the watcher body is not actually executing."
    fi
  fi

  # 4. append-only ledger integrity
  [ "$led" = "0" ] && alarm "ledger-attr" "event ledger lost append-only flag" \
      "The append-only (chattr +a) flag on the event ledger is cleared/absent — history can now be rewritten. Someone prepared to erase tracks."
  local last_ec; last_ec=$(awk -F'\t' 'BEGIN{v=0} $1=="evcount"{v=$2} END{print v}' "$STATE/evcount.state" 2>/dev/null); : "${last_ec:=0}"
  if [ "$evcount" -lt $(( last_ec - 5 )) ] 2>/dev/null; then
    alarm "ledger-shrank" "event ledger SHRANK ($last_ec -> $evcount lines)" \
      "The append-only ledger got smaller — truncation/rollback of the evidence log."
  fi
  [ "$evcount" -ge "$last_ec" ] 2>/dev/null && printf 'evcount\t%s\n' "$evcount" >"$STATE/evcount.state"

  # 5. integrity pins
  if [ ! -s "$PINS" ]; then
    alarm "no-pins" "no integrity baseline pinned yet" \
      "$PINS is empty. Run 'mw-deadman-check.sh pin --yes' on $THIS AFTER verifying the watched host is clean."
  else
    local k cur exp bad=""
    for k in $PIN_KEYS; do
      cur=$(echo "$j" | jq -r ".pins.$k"); exp=$(pinned "$k")
      [ -z "$exp" ] && continue                      # key not pinned -> skip
      [ "$cur" = "$exp" ] || bad="$bad
• <code>$k</code>: pinned <code>${exp:0:12}…</code> now <code>${cur:0:12}…</code>"
    done
    [ -n "$bad" ] && alarm "pin-mismatch" "INTEGRITY PIN MISMATCH" \
      "A watcher/self-defense file changed vs the off-box baseline:$bad

If YOU changed it, re-pin: mw-deadman-check.sh pin --yes. Otherwise treat as tamper — cross-check auditd (key mwtamper) on the watched host and the shipped audit log."
  fi

  [ "$ALARMED" = 0 ] || true   # (per-problem dedup already handled)
}

case "${1:-check}" in
  check) check ;;
  pin)   capture_pins "${2:-}" ;;
  test)  m="✅ <b>mw-deadman test [$THIS]</b> — alert path OK · $(ts) UTC"
         tg "$m" && echo "telegram: sent" || echo "telegram: not sent (unset or failed; check TG_TOKEN/TG_CHAT/network)"
         webhook "$m" && echo "webhook: sent" || echo "webhook: not sent (unset or failed)"
         email "test" "mw-deadman email test from $THIS at $(ts) UTC"; echo "email: attempted (MAIL_TO=${MAIL_TO:-unset})" ;;
  show)  echo "== last pull =="; pull | jq . 2>/dev/null || echo "(pull failed)"; echo "== pins =="; cat "$PINS" 2>/dev/null || echo none ;;
  *) echo "usage: $0 {check|pin [--yes]|test|show}"; exit 2 ;;
esac
