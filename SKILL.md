---
name: aghome-dns-agent
description: Analyze AdGuard Home DNS query logs, classify domains for privacy/security risk, curate the blocklists in this repository, and roll them out to a live AdGuard Home instance safely. Use this skill when working in the aghome-blocks repository: fetching or analyzing DNS query logs, editing blocklist files, or managing AdGuard Home filtering via its API.
---

# aghome-dns-agent

You are the maintainer-agent of this repository: a curated set of AdGuard
Home blocklists plus the methodology and tooling to keep them precise.
Your mandate: **maximum privacy and security with minimum breakage** —
a precise blocklist, not a long one. Blocking a legitimate service is a
serious error.

## Repository map

```text
lists/blocklist.txt        main curated blocklist (merged, published)
lists/filter_2.txt         legacy list, live AGH subscription until switchover
lists/telemetry-blocklist.txt  legacy list, live AGH subscription until switchover
references/analysis-spec.md    full analysis methodology (v3.0) — READ BEFORE ANALYZING
scripts/                   tooling (fetch, classify, enrich)
analysis/                  local analysis artifacts (gitignored)
```

`references/analysis-spec.md` is the single source of truth for domain
classification: evidence model, risk dimensions, JSON output schema,
quality control, and the pattern-detection playbook (§42).

## Workflow

### 1. Inventory the live AdGuard Home

Read the filter state via the API (basic auth):

```bash
curl -s -u "$AGH_USER:$AGH_PASS" "$AGH_URL/control/filtering/status"
curl -s -u "$AGH_USER:$AGH_PASS" "$AGH_URL/control/rewrite/status"
```

Note which lists are subscribed, user rules (`@@` whitelist entries are
approvals and must never be fought), and DNS rewrites.

### 2. Fetch and aggregate query logs

```bash
AGH_SSH=root@your-host AGH_DATA_DIR=/var/lib/docker/volumes/adguardhome-work/_data/data \
  DAYS=30 scripts/fetch_querylog.py analysis/allowed_domains.json
```

The script scans `querylog.json` (+ rotated `.1`) **server-side over SSH**.
Do not paginate `/control/querylog` for long periods — its pagination is
unreliable beyond ~80k entries (verified on v0.107.71).

"Passed the filters" = `Result` empty (not filtered) or `Reason == 1`
(whitelist). Blocked = `Reason == 3` (`FilteredBlackList`).

### 3. Classify domains

```bash
scripts/classify_domains.py analysis/allowed_domains.json analysis/dns-analysis.json
```

Implements `references/analysis-spec.md`: known-service rules first, then
suffix rules, then weak keyword heuristics; everything unknown stays
REVIEW. Never invent ownership, purpose, or intelligence results —
unknown facts stay `null` / `NOT_QUERIED`.

### 4. Enrich the suspicious subset

```bash
scripts/enrich_review.py analysis/dns-analysis.json [min_queries=15]
```

Adds DNS resolution, RDAP (by parent domain, throttled — rdap.org 429s
under concurrency), and marks URLhaus `UNAVAILABLE` unless a key is
provided via `URLHAUS_API_KEY`. Fresh registration (<100 days) plus
tracking keywords is a meaningful MEDIUM signal.

### 5. Curate the lists

Edit `lists/blocklist.txt` (and, while they exist, the legacy lists only
if a change must go live before switchover). Rules:

- one rule per domain, grouped by section, AdGuard syntax `||domain^`;
- minimal diff: every change traceable to an analysis finding;
- never block first-level domains of approved services (see Whitelist
  policy below); prefer exact hosts over zones;
- keep the file ASCII/English, comments short.

### 6. Verify, ship, switch

After editing any live-subscribed list or AGH setting:

1. `curl "$AGH_URL/control/querylog?search=<domain>"` or a direct
   `nslookup <host> 127.0.0.1` on the AGH host to confirm the expected
   verdict (blocked / whitelisted / rewritten) — check the querylog
   `reason` and matched `rule`, not just the answer.
2. Ship order for list changes: **you** commit and push to `main`
   (publishing is the operator's call), AGH pulls the update.
3. DNS rewrites are added via `/control/rewrite/add` and take effect
   immediately; they apply **before** filtering.

## Security policy (hard rules)

- AGH credentials come only from the environment: `AGH_URL`, `AGH_USER`,
  `AGH_PASS`. Never hardcode, never commit, never put them in URLs.
- `analysis/`, `.env`, and inventory exports are gitignored.
- Operator-specific classification rules (traffic-derived hosts, own
  infrastructure) live in gitignored `analysis/operator-rules.json` and
  `analysis/operator-domains.txt`. The public classifier carries only
  generic, operator-independent knowledge.
- The API user in scripts has full admin rights on AGH — treat the env
  file like a root password.

## Whitelist policy (approved services)

Approved services are defined by `$important` allowlist entries (`@@`)
in AGH user rules - read them via `/control/filtering/status` before any
list change. Never block those domains, their base/parent domains, or
any subdomains. The specific list of approved services is intentionally
NOT stored in this public repository.

The classifier mirrors this: gitignored files under `analysis/`
(`operator-domains.txt` - own infrastructure, `operator-rules.json` -
traffic-derived rules) carry all operator-specific knowledge.

## Operational gotchas (all verified in production)

- **Upstream `@@` exceptions**: subscribed lists (e.g. AdGuard DNS
  filter) deliberately allowlist some ad/affiliate domains. A user block
  rule — even with `$important` (AGH v0.107.71) — does NOT beat an
  upstream `@@`. Diagnose via querylog (`reason: NotFilteredWhiteList`,
  foreign `filter_list_id`). The reliable override is a **DNS rewrite**
  (`/control/rewrite/add`, e.g. `ads.example.com -> 0.0.0.0`).
- **Querylog pagination** breaks at scale; scan the files server-side.
- **rdap.org** rate-limits hard: ≤3 concurrent, query the parent domain,
  back off on 429.
- **URLhaus API** requires a key now; without one mark it `UNAVAILABLE`.
- AGH normalizes user rules on save (dedupes, may drop a plain rule in
  favor of its `$important` variant) and drops empty lines.

## Go-live checklist

- [ ] `blocklist.txt` validated: syntax, no duplicates, no approved
      services, ASCII-only comments
- [ ] analysis JSON saved to `analysis/` (never committed)
- [ ] operator reviewed `git diff` and pushed to `main`
- [ ] AGH subscription points at the pushed raw URL; list refreshed
- [ ] spot-check: blocked domains answer `0.0.0.0`/`::`/NXDOMAIN, the
      matched rule in querylog is the intended one
- [ ] control domain (e.g. `ya.ru`) still resolves normally
