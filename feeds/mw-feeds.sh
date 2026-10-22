#!/usr/bin/env bash
# ============================================================================
# mw-feeds.sh — threat-intel feed fetcher + atomic blocklist loader.
# Target: Ubuntu 24.04, kernel 6.8. Runs from mw-feeds.timer every
# 6-24h — NEVER from the 60s malware-watch job. Runs as root.
#
# WHAT IT DOES
#   1. Downloads several public IP blocklists (Feodo aggressive, FireHOL level1,
#      Spamhaus DROP) over your normal egress: curl -m + retries.
#   2. VALIDATES each download: must be non-empty AND pass a per-feed line-count
#      floor. A truncated/empty/HTML-error response is REJECTED and the previous
#      last-known-good cache is kept. We NEVER replace a live good feed with junk.
#   3. Collapses/dedups all validated CIDRs (python3 ipaddress), strips private/
#      reserved ranges, our own egress/VPN IPs, and the feed hosts themselves.
#   4. Atomically loads the aggregate into the blocklist:
#        - nft present  -> flush+refill the `feed4` set inside table `inet mw_feed`
#                          in a single `nft -f` transaction (atomic, O(1) match).
#        - nft absent   -> ping-pong rebuild of a dedicated iptables chain pair
#                          (build standby full -> repoint jump -> flush old);
#                          the referenced chain is ALWAYS fully populated.
#
# TIER RULE (important): feed-derived entries are BLOCK-ONLY. They live in the
#   feed set / feed chain and only DROP traffic. They are NEVER written to the
#   watcher's CRIT-kill path. Only the hand-curated IOC list (static4 set /
#   IOC_CIDRS, loaded by mw-blocklist.nft and the watcher's MW_BLOCK) is the
#   CRIT tier that can get a process killed. A noisy feed can at worst drop
#   packets to a bad IP — it can never trigger a kill.
#
# FAIL-SAFE: on any fetch/validate failure we fall back to the last-known-good
#   cache, never to an empty set and never to block-all. If EVERYTHING is missing
#   (first run, no cache, no network) the set is simply left empty (no drops) —
#   the curated IOC static set still protects the box.
#
# Subcommands:  run (fetch+load, default) | load-cached (reload cache, no net) |
#               status | flush | selftest
# ============================================================================
set -uo pipefail

CONF=/etc/mw-feeds.env
# shellcheck disable=SC1090
[ -r "$CONF" ] && . "$CONF"

# ---- defaults (override in /etc/mw-feeds.env) ------------------------------
: "${STATE:=/var/lib/mw-feeds}"
: "${CACHE:=$STATE/cache}"                 # last-known-good per feed
: "${LOG:=/var/log/mw-feeds.log}"
: "${CURL_MAX_TIME:=45}"                   # per-attempt hard timeout (s)
: "${CURL_RETRY:=3}"                       # curl internal retries
: "${MAX_ENTRIES:=40000}"                  # safety cap after collapse
: "${NFT_TABLE:=inet mw_feed}"             # native nft table (see mw-blocklist.nft)
: "${NFT_SET:=feed4}"                      # feed set name inside that table
# Your own public egress / VPN endpoint IPs (space-separated) — they MUST never be
# blocked. REQUIRED in practice: if empty, a feed that happens to list your own
# egress IP can cut your connectivity. Example: SELF_IPS="203.0.113.10 198.51.100.7"
: "${SELF_IPS:=}"
# Curated IOC CIDRs (space-separated; EMPTY by default). Keep in sync with
# malware-watch IOC_CIDRS + mw-blocklist.nft static4. In iptables fallback these
# are re-added on every rebuild so they are effectively permanent; in nft mode
# they live in static4 and are NOT touched here.
: "${IOC_CIDRS:=}"

# Feeds: "name|url|min_valid_lines". Floors are deliberately conservative — a
# feed that returns fewer valid IP lines than its floor is treated as FAILED.
: "${FEEDS:=}"
if [ -z "$FEEDS" ]; then
  FEEDS='feodo|https://feodotracker.abuse.ch/downloads/ipblocklist_aggressive.txt|20
firehol1|https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset|300
spamhaus|https://www.spamhaus.org/drop/drop.txt|50'
fi

mkdir -p "$STATE" "$CACHE"; chmod 700 "$STATE" 2>/dev/null || true
umask 077

log(){ printf '%s %s\n' "$(date -u +'%F %T')" "$*" >>"$LOG" 2>/dev/null; printf '%s\n' "$*" >&2; }

# single-run lock (timer overlap guard)
exec 9>"$STATE/lock"
flock -w 30 9 || { log "lock busy, another mw-feeds run active — exit"; exit 0; }

have(){ command -v "$1" >/dev/null 2>&1; }

# backend detection: prefer native nft IF the binary exists AND our table exists
# (installed by mw-blocklist.service). Otherwise iptables fallback.
BACKEND=iptables
if have nft && nft list table $NFT_TABLE >/dev/null 2>&1; then
  BACKEND=nft
elif have nft && nft list ruleset >/dev/null 2>&1; then
  # nft usable but our table not installed yet — try to (re)load the ruleset if
  # present; if that fails we fall back to iptables so we never no-op silently.
  if [ -r /etc/nftables.d/mw-blocklist.nft ] && nft -f /etc/nftables.d/mw-blocklist.nft 2>>"$LOG"; then
    BACKEND=nft
  fi
fi

# ---------------------------------------------------------------------------
# fetch one feed -> validate -> update cache. Returns 0 if cache is usable
# (fresh OR previously-good), 1 only if there is NO usable data at all.
# ---------------------------------------------------------------------------
fetch_one(){
  local name=$1 url=$2 floor=$3
  local out="$CACHE/$name.ips" tmp="$CACHE/.$name.raw.$$" cnt
  : >"$tmp"
  # curl: bounded time, internal retries w/ backoff, follow redirects.
  # --fail so an HTTP 4xx/5xx (e.g. Cloudflare error page) is NOT saved as data.
  if curl -fsSL -m "$CURL_MAX_TIME" --retry "$CURL_RETRY" --retry-delay 4 \
          --retry-connrefused -A 'mw-feeds/1.0' -o "$tmp" "$url" 2>>"$LOG"; then
    # count VALID ipv4 / cidr lines only (ignore comments, HTML, blanks)
    cnt=$(grep -oE '(^|[^0-9.])([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' "$tmp" 2>/dev/null | wc -l)
    if [ "${cnt:-0}" -ge "$floor" ]; then
      mv -f "$tmp" "$out"
      log "feed $name OK: $cnt valid lines (floor $floor)"
      rm -f "$tmp"; return 0
    fi
    log "feed $name REJECTED: only ${cnt:-0} valid lines < floor $floor — keeping last-known-good"
  else
    log "feed $name fetch FAILED (curl) — keeping last-known-good"
  fi
  rm -f "$tmp"
  [ -s "$out" ] && return 0 || return 1
}

# resolve feed hostnames so we can EXCLUDE them from the blocklist (never block
# the source of our own updates). Best-effort; failure just means no extra excl.
feed_host_ips(){
  local line url host ip
  while IFS='|' read -r _ url _; do
    [ -n "$url" ] || continue
    host=${url#*://}; host=${host%%/*}
    getent ahostsv4 "$host" 2>/dev/null | awk '{print $1}' | sort -u
  done <<<"$FEEDS"
}

# ---------------------------------------------------------------------------
# collapse + filter aggregate. Uses python3 ipaddress.collapse_addresses which
# dedups AND merges overlapping/adjacent nets => the result has NO overlaps, so
# it loads cleanly into an nft interval+timeout set (which rejects overlaps).
# Excludes private/reserved, our SELF_IPS, and the feed hosts.
# Emits one CIDR (or bare v4) per line on stdout.
# ---------------------------------------------------------------------------
collapse_filter(){
  local excl="$1"     # space-separated extra IPs/CIDRs to drop (self + feedhosts)
  if have python3; then
    EXCL="$excl" python3 - <<'PY'
import os,sys,ipaddress
excl=[]
for tok in os.environ.get("EXCL","").split():
    try: excl.append(ipaddress.ip_network(tok,strict=False))
    except Exception: pass
# always-exclude private/reserved/CGNAT/multicast/etc so we never self-block
for tok in ("0.0.0.0/8","10.0.0.0/8","100.64.0.0/10","127.0.0.0/8",
            "169.254.0.0/16","172.16.0.0/12","192.168.0.0/16","192.0.0.0/24",
            "192.0.2.0/24","198.18.0.0/15","198.51.100.0/24","203.0.113.0/24",
            "224.0.0.0/4","240.0.0.0/4","255.255.255.255/32"):
    excl.append(ipaddress.ip_network(tok))
nets=[]
for line in sys.stdin:
    line=line.strip()
    if not line or line[0] in "#;/": continue
    tok=line.split()[0].split(";")[0].strip()
    try: n=ipaddress.ip_network(tok,strict=False)
    except Exception: continue
    if n.version!=4: continue
    if any(n.subnet_of(e) or n==e or e.subnet_of(n) for e in excl): continue
    nets.append(n)
for n in ipaddress.collapse_addresses(nets):
    print(n.with_prefixlen)
PY
  else
    # crude fallback (no collapse): dedup + drop obvious private/loopback.
    log "WARN python3 missing — using crude dedup (no overlap-merge; may cause nft overlap errors)"
    grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?' \
      | grep -vE '^(10\.|127\.|169\.254\.|192\.168\.|172\.(1[6-9]|2[0-9]|3[01])\.|0\.|224\.|240\.)' \
      | sort -u
  fi
}

# ---------------------------------------------------------------------------
# LOADERS
# ---------------------------------------------------------------------------
load_nft(){
  # atomic: single transaction flushes then refills feed4. Set carries a
  # set-level timeout (see mw-blocklist.nft) so entries auto-expire if this
  # loader ever stops running — failing toward "no drop", which is safe.
  local ipfile=$1 f n=0 elems=""
  f=$(mktemp "$STATE/.nftload.XXXXXX") || return 1
  {
    echo "flush set $NFT_TABLE $NFT_SET"
    # chunk elements to keep add-lines sane
    local buf="" c=0
    while read -r ip; do
      [ -n "$ip" ] || continue
      buf+="${buf:+, }$ip"; c=$((c+1)); n=$((n+1))
      if [ "$c" -ge 500 ]; then echo "add element $NFT_TABLE $NFT_SET { $buf }"; buf=""; c=0; fi
      [ "$n" -ge "$MAX_ENTRIES" ] && break
    done <"$ipfile"
    [ -n "$buf" ] && echo "add element $NFT_TABLE $NFT_SET { $buf }"
  } >"$f"
  if nft -f "$f" 2>>"$LOG"; then
    log "nft loaded $n entries into $NFT_TABLE $NFT_SET (atomic)"
    rm -f "$f"; return 0
  fi
  log "ERROR nft -f failed — feed set left UNCHANGED (last-known-good preserved)"
  rm -f "$f"; return 1
}

# iptables ping-pong rebuild for one direction. Keeps a fully-populated chain
# referenced at ALL times: build standby -> add standby jump -> remove old jump
# -> flush old. flag = -s (inbound src) or -d (outbound dst).
ipt_rebuild_dir(){
  local flag=$1 base=$2 ipfile=$3; shift 3
  local hooks=("$@")
  local a="$base" b="${base}b" active standby h rf n=0
  iptables -nL "$a" >/dev/null 2>&1 || iptables -N "$a" 2>/dev/null || true
  iptables -nL "$b" >/dev/null 2>&1 || iptables -N "$b" 2>/dev/null || true
  active="$a"; standby="$b"
  if iptables -C "${hooks[0]}" -j "$b" 2>/dev/null; then active="$b"; standby="$a"; fi

  iptables -F "$standby" 2>/dev/null || true
  rf=$(mktemp "$STATE/.iptload.XXXXXX") || return 1
  {
    echo "*filter"
    echo ":$standby - [0:0]"
    # curated IOC first (always present in fallback mode => effectively permanent;
    # an empty IOC_CIDRS simply adds nothing)
    local n0
    for n0 in $IOC_CIDRS; do echo "-A $standby $flag $n0 -j DROP"; done
    # established/related traffic is never cut by a feed entry (protects your own
    # SSH/VPN session if SELF_IPS is incomplete). RETURN = skip the feed rules.
    echo "-A $standby -m conntrack --ctstate ESTABLISHED,RELATED -j RETURN"
    while read -r ip; do
      [ -n "$ip" ] || continue
      echo "-A $standby $flag $ip -j DROP"; n=$((n+1))
      [ "$n" -ge "$MAX_ENTRIES" ] && break
    done <"$ipfile"
    echo "COMMIT"
  } >"$rf"
  # -n = noflush: append into the (already emptied) standby chain in one txn.
  if ! iptables-restore -n <"$rf" 2>>"$LOG"; then
    log "ERROR iptables-restore failed for $standby — leaving ACTIVE chain $active in place"
    rm -f "$rf"; return 1
  fi
  rm -f "$rf"
  # repoint every hook to standby (insert first, so a populated chain is always
  # referenced), then drop the old active jump, then flush old chain.
  for h in "${hooks[@]}"; do
    iptables -nL "$h" >/dev/null 2>&1 || continue   # e.g. DOCKER-USER may be absent
    iptables -C "$h" -j "$standby" 2>/dev/null || iptables -I "$h" 1 -j "$standby" 2>/dev/null || true
  done
  for h in "${hooks[@]}"; do
    iptables -nL "$h" >/dev/null 2>&1 || continue
    iptables -D "$h" -j "$active" 2>/dev/null || true
  done
  iptables -F "$active" 2>/dev/null || true
  log "iptables rebuilt $standby ($flag): $n feed + curated IOC entries; now active"
}

load_iptables(){
  local ipfile=$1
  # inbound: match source; hooked in INPUT, DOCKER-USER, FORWARD
  ipt_rebuild_dir -s MW_FEED_IN  "$ipfile" INPUT DOCKER-USER FORWARD
  # outbound: match dest;  hooked in OUTPUT, FORWARD
  ipt_rebuild_dir -d MW_FEED_OUT "$ipfile" OUTPUT FORWARD
}

# ---------------------------------------------------------------------------
build_and_load(){
  local mode=$1   # fetch | cached
  local agg excl name url floor ok_any=0
  agg=$(mktemp "$STATE/.agg.XXXXXX") || exit 1

  if [ "$mode" = fetch ]; then
    while IFS='|' read -r name url floor; do
      [ -n "$name" ] || continue
      fetch_one "$name" "$url" "$floor" && ok_any=1
    done <<<"$FEEDS"
  fi

  # aggregate whatever cache we have (fresh or last-known-good)
  if ! ls "$CACHE"/*.ips >/dev/null 2>&1; then
    log "no cached feed data available — feed set left as-is / empty (curated IOC still enforced)"
    rm -f "$agg"; return 0
  fi
  excl="$SELF_IPS $(feed_host_ips | tr '\n' ' ')"
  cat "$CACHE"/*.ips 2>/dev/null | collapse_filter "$excl" >"$agg"
  local total; total=$(wc -l <"$agg" 2>/dev/null || echo 0)
  if [ "${total:-0}" -eq 0 ]; then
    log "aggregate empty after filtering — NOT loading empty set (keeping current)"
    rm -f "$agg"; return 0
  fi
  log "aggregate: $total unique CIDRs after collapse+filter (backend=$BACKEND)"

  case "$BACKEND" in
    nft)      load_nft "$agg" || true ;;
    iptables) load_iptables "$agg" || true ;;
  esac
  rm -f "$agg"
}

status(){
  echo "backend: $BACKEND"
  echo "cache:"; ls -l "$CACHE"/*.ips 2>/dev/null || echo "  (none)"
  if [ "$BACKEND" = nft ]; then
    echo "== nft feed set count =="
    nft list set $NFT_TABLE $NFT_SET 2>/dev/null | grep -c '/' || true
    echo "== nft static4 =="; nft list set $NFT_TABLE static4 2>/dev/null || true
  else
    echo "== iptables feed chains (pkt counts) =="
    for c in MW_FEED_IN MW_FEED_INb MW_FEED_OUT MW_FEED_OUTb; do
      echo "--- $c ---"; iptables -nvL "$c" 2>/dev/null | head -3
    done
  fi
}

case "${1:-run}" in
  run)         build_and_load fetch ;;
  load-cached) build_and_load cached ;;   # boot-time fast restore, no network
  status)      status ;;
  flush)
    if [ "$BACKEND" = nft ]; then nft flush set $NFT_TABLE $NFT_SET 2>/dev/null || true
    else for c in MW_FEED_IN MW_FEED_INb MW_FEED_OUT MW_FEED_OUTb; do iptables -F "$c" 2>/dev/null || true; done; fi
    log "feed entries flushed (curated IOC/static untouched)" ;;
  selftest)
    echo "backend=$BACKEND python3=$(have python3 && echo yes || echo no) nft=$(have nft && echo yes || echo no)"
    echo "feeds:"; printf '%s\n' "$FEEDS"
    printf '1.2.3.4\n1.2.3.0/24\n8.8.8.8\n10.0.0.5\n%s\n' "${SELF_IPS%% *}" | collapse_filter "$SELF_IPS" ;;
  *) echo "usage: $0 {run|load-cached|status|flush|selftest}"; exit 2 ;;
esac
exit 0
