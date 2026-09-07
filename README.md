# aghome-blocks

Curated AdGuard Home blocklists plus an agent skill that keeps them
precise: analyze live DNS query logs, classify domains for privacy and
security risk, edit the lists with minimal diff, and roll changes out
safely.

Mandate: **maximum privacy and security with minimum breakage** —
a precise blocklist, not a long one.

## Repository layout

```text
SKILL.md                    agent skill (Agent Skills format): the full workflow
references/analysis-spec.md analysis methodology v3.0 (evidence model, risks, JSON schema)
scripts/fetch_querylog.py   server-side querylog aggregation over SSH
scripts/classify_domains.py rule-based classifier (v3.0 schema)
scripts/enrich_review.py    DNS/RDAP/URLhaus enrichment for REVIEW domains
lists/blocklist.txt         main curated blocklist (published)
lists/                      legacy lists (live subscriptions until switchover)
analysis/                   local artifacts, gitignored
```

## Lists

| File | Purpose |
|------|---------|
| `lists/blocklist.txt` | merged curated list: ads, counters, telemetry, vendor telemetry (Xiaomi/HiHonor/360), scam suspects, torrent trackers, per-analysis findings |
| `lists/filter_2.txt`, `lists/telemetry-blocklist.txt` | legacy lists, still subscribed by the live AGH instance until switchover |

The blocklist deliberately does **not** touch approved services - they
are covered by `$important` allowlist entries in AGH user rules and must
never be blocked. The specific list of approved services is
intentionally not public (see `SKILL.md`, "Whitelist policy").

## Using the agent

Open this repository with an [Agent Skills](https://agentskills.io)
compatible assistant and follow `SKILL.md`. Short version:

```bash
# 1. aggregate query logs from the AGH host (secrets via environment)
AGH_SSH=root@dns-host AGH_DATA_DIR=/var/lib/docker/volumes/adguardhome-work/_data/data \
    DAYS=30 scripts/fetch_querylog.py analysis/allowed_domains.json

# 2. classify domains (analysis-spec.md methodology)
scripts/classify_domains.py analysis/allowed_domains.json analysis/dns-analysis.json

# 3. enrich the suspicious REVIEW subset (RDAP, DNS resolution)
scripts/enrich_review.py analysis/dns-analysis.json 15

# 4. curate lists/blocklist.txt from the findings, then commit and push;
#    AdGuard Home pulls the raw URL on its refresh interval
```

Credentials live only in the environment (`AGH_SSH`, `AGH_URL`,
`AGH_USER`, `AGH_PASS`, optional `URLHAUS_API_KEY`) and are never
committed.

## Security notes

- The repo is public: no hosts, credentials, or operator-specific
  domains belong in commits. Operator-owned domains go to the
  gitignored `analysis/operator-domains.txt`.
- Some upstream blocklists (e.g. AdGuard DNS filter) contain `@@`
  allowlist entries for certain ad/affiliate domains; user block rules
  cannot override those — use AGH DNS rewrites for the exceptions
  (see `SKILL.md`, "Operational gotchas").

## License

See [LICENSE](LICENSE).
