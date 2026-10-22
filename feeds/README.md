# Threat-intel IP feeds + blocklist

> Status: experimental kit; validated by the author on one Ubuntu 24.04 host (kernel 6.8); read the "Known issues" before deploying.

Standalone add-on to `malware-watch`. Adds auto-updating threat-intel IP
blocklists on a slow (6–24h) timer, loaded atomically into an nftables set
(or an iptables fallback chain). **Block-only** — feed hits only DROP packets;
they never touch the watcher's CRIT kill path. Only the curated IOC list stays
CRIT.

## Files
| file | install path |
|---|---|
| `mw-feeds.sh` | `/usr/local/sbin/mw-feeds.sh` (0755, root) |
| `mw-feeds.env.example` | `/etc/mw-feeds.env` (0600, root) |
| `mw-feeds.service` / `mw-feeds.timer` | `/etc/systemd/system/` |
| `mw-blocklist.nft` | `/etc/nftables.d/mw-blocklist.nft` (nft path only) |
| `mw-blocklist.service` | `/etc/systemd/system/` (nft path only) |

## Install
```bash
# 0. FIRST verify assumptions (see below), esp. nft presence + SELF_IPS.
install -m0755 mw-feeds.sh      /usr/local/sbin/mw-feeds.sh
install -m0600 mw-feeds.env.example /etc/mw-feeds.env  # then EDIT SELF_IPS
mkdir -p /etc/nftables.d
install -m0644 mw-blocklist.nft /etc/nftables.d/mw-blocklist.nft
install -m0644 mw-feeds.service mw-feeds.timer mw-blocklist.service /etc/systemd/system/
systemctl daemon-reload

# nft path (if `nft` is installed — the normal case on Ubuntu 24.04):
systemctl enable --now mw-blocklist.service     # creates table inet mw_feed
# iptables fallback path (only if nft is absent): skip mw-blocklist.service;
# the chains are built by mw-feeds.sh on first run.

systemctl enable --now mw-feeds.timer
systemctl start mw-feeds.service                # first fetch now (optional)
```

## Verify it loaded
```bash
/usr/local/sbin/mw-feeds.sh status      # backend, cache files, entry counts
systemctl list-timers mw-feeds.timer    # next run time
journalctl -u mw-feeds.service -n40     # per-feed OK / REJECTED lines
tail -20 /var/log/mw-feeds.log

# nft path:
nft list set inet mw_feed feed4 | head          # feed entries (with timeouts)
nft list set inet mw_feed static4               # curated IOC (permanent)
nft list table inet mw_feed | grep -c drop      # hooks present

# iptables fallback:
iptables -nvL MW_FEED_IN  | head                # DROP src, with packet counts
iptables -nvL MW_FEED_OUT | head                # DROP dst
```

## See current block counts
- **nft:** `nft list set inet mw_feed feed4 | grep -c /` (entry count);
  per-rule counters aren't kept on set-lookups — add `counter` before `drop`
  in `mw-blocklist.nft` if you want hit counts.
- **iptables:** `iptables -nvL MW_FEED_IN` / `MW_FEED_OUT` — the `pkts` column
  is live drop counts per bad CIDR.

## Rollback
```bash
systemctl disable --now mw-feeds.timer mw-feeds.service
# nft path:
systemctl disable --now mw-blocklist.service    # ExecStop deletes only our table
# or manually:  nft delete table inet mw_feed
# iptables fallback:
for h in INPUT DOCKER-USER FORWARD; do iptables -D $h -j MW_FEED_IN 2>/dev/null; iptables -D $h -j MW_FEED_INb 2>/dev/null; done
for h in OUTPUT FORWARD;            do iptables -D $h -j MW_FEED_OUT 2>/dev/null; iptables -D $h -j MW_FEED_OUTb 2>/dev/null; done
for c in MW_FEED_IN MW_FEED_INb MW_FEED_OUT MW_FEED_OUTb; do iptables -F $c 2>/dev/null; iptables -X $c 2>/dev/null; done
rm -f /var/lib/mw-feeds/cache/*.ips
```
Removing these touches **only** the `inet mw_feed` table / `MW_FEED_*` chains —
the watcher's `MW_BLOCK`/`MW_BLOCK_OUT` and your own firewall rules are left intact.

## How it coexists (does NOT fight the watcher or your firewall)
- **nft path:** everything lives in a *separate* native table `inet mw_feed`.
  On Ubuntu 24.04 `iptables` = iptables-nft, so the watcher's `MW_BLOCK` and
  your own iptables rules live in the compat table `ip filter`. Two different
  tables; the kernel evaluates both; if either DROPs, the packet dies. We only
  ADD drops and never run `nft flush ruleset`, so we can't open or clobber
  anything.
- **iptables fallback:** dedicated chains `MW_FEED_IN{,b}` / `MW_FEED_OUT{,b}`,
  distinct from the watcher's `MW_BLOCK*`. The watcher re-inserts its own jump
  at the top of INPUT every 60s — harmless, our jump just sits below it and both
  are DROP-only. Rebuilds are atomic-in-effect: a fully-populated standby chain
  is referenced *before* the old jump is removed, so the hook is never empty.

## Fail-safe behaviour (by design)
- Empty/truncated/HTTP-error download → **rejected**, last-known-good cache kept
  (per-feed line-count floor + `curl --fail`).
- Aggregate empty after filtering → set left unchanged (never load empty).
- Feed loader stops entirely → nft `feed4` entries **age out** at `timeout 3d`
  and stop dropping. Failing toward *no-drop* is safe for a blocklist; we never
  fail to block-all.
- Our SELF_IPS / VPN endpoint and the feed hosts are excluded from the set, plus
  all RFC1918/reserved — so a feed can't black-hole our own egress or its own
  update path.

---

## Known issues

- **Fill in `SELF_IPS` with your own egress/VPN addresses.** Left empty, only
  private ranges are excluded, so a feed that lists your own public IP can
  block your own connectivity. Find them with `ip route get 1.1.1.1` and your
  tunnel's remote address.
- **Established connections are accepted first.** The first rule in the
  input/output/forward chains is `ct state established,related accept`
  (iptables fallback: a conntrack `RETURN` placed before the feed entries), so a
  new feed entry cannot kill a running session such as your SSH connection.
  Trade-off: an already-open connection to a newly listed IP keeps working until
  it closes; only new flows are blocked. Curated static IOC entries are dropped
  before that rule, unconditionally.
- **Firewall units must not `nft flush ruleset`.** None of the units in this kit
  do, but check yours (`grep -rn "flush ruleset" /etc/nftables.conf /etc/systemd/system`).
  The stock Ubuntu `/etc/nftables.conf` starts with `flush ruleset`: reloading
  `nftables.service` wipes the `inet mw_feed` table (`mw-blocklist.service` is
  ordered after it, but a manual `systemctl reload nftables` is not followed by
  a re-load; re-run `systemctl restart mw-blocklist.service`).
- **Static IOC list is empty by default** (`IOC_CIDRS` empty, `static4` has no
  elements). Add networks in both places and keep them in sync with the
  watcher's `IOC_CIDRS`.
- **Priority -150** assumes no other table must ACCEPT before this one. Fine for
  a pure blocklist; verify nothing relies on running earlier.
- **IPv4 only.** IPv6 egress is not covered.
- Feed hostnames must resolve (`getent ahostsv4 feodotracker.abuse.ch`) so the
  feed hosts themselves are excluded from the set.
- `nft` absent -> the script uses the iptables fallback automatically (`ipset`
  not required). Only the nft path is exercised regularly by the author.
