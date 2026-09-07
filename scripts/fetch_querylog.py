#!/usr/bin/env python3
"""Fetch and aggregate AdGuard Home query logs over SSH.

Runs a streaming aggregation of querylog.json (+ rotated .1) on the AGH
host itself - the /control/querylog API pagination is unreliable at scale
(verified on v0.107.71). Counts domains that PASSED the filters
(Result empty -> NotFilteredNotFound, Reason 1 -> whitelist).

Environment:
  AGH_SSH       ssh target of the AGH host, e.g. root@dns.example.com (required)
  AGH_DATA_DIR  querylog directory on the host
                (default: /var/lib/docker/volumes/adguardhome-work/_data/data)
  DAYS          lookback window in days (default: 30)

Usage:
  fetch_querylog.py [output.json]     # default: analysis/allowed_domains.json

Reason int mapping (verified against the API on v0.107.71):
  None -> NotFilteredNotFound, 1 -> NotFilteredWhiteList,
  3 -> FilteredBlackList, 11 -> RewriteRule
"""

import json
import os
import subprocess
import sys

DAYS = os.environ.get("DAYS", "30")
DATA_DIR = os.environ.get(
    "AGH_DATA_DIR", "/var/lib/docker/volumes/adguardhome-work/_data/data"
)
OUT = sys.argv[1] if len(sys.argv) > 1 else "analysis/allowed_domains.json"

REMOTE = f"""
import json, collections, datetime as dt, sys

BASE = {DATA_DIR!r}
FILES = [BASE + 'querylog.json.1', BASE + 'querylog.json']
cutoff_dt = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days={DAYS})
CUT = cutoff_dt.strftime('%Y-%m-%dT%H:%M:%S')

reason_hist = collections.Counter()
dom_count = collections.Counter()
dom_clients = collections.defaultdict(set)
dom_first, dom_last, dom_whitelist = {{}}, {{}}, set()
client_count, proto_count = collections.Counter(), collections.Counter()
total = 0

for PATH in FILES:
    try:
        f = open(PATH, 'r')
    except FileNotFoundError:
        continue
    with f:
        for line in f:
            i = line.find('"T":"')
            if i < 0:
                continue
            if line[i + 5:i + 24] < CUT:
                continue
            e = json.loads(line)
            total += 1
            res = e.get('Result') or {{}}
            reason = res.get('Reason')
            reason_hist[reason] += 1
            if res.get('IsFiltered') or (res and reason not in (0, 1)):
                continue
            name = (e.get('QH') or '').lower().rstrip('.')
            if not name:
                continue
            dom_count[name] += 1
            dom_clients[name].add(e.get('IP', ''))
            client_count[e.get('IP', '')] += 1
            proto_count[e.get('CP', '')] += 1
            if reason == 1:
                dom_whitelist.add(name)
            ts = e.get('T', '')
            if name not in dom_first or ts < dom_first[name]:
                dom_first[name] = ts
            if name not in dom_last or ts > dom_last[name]:
                dom_last[name] = ts

out = {{
    "meta": {{
        "source": "AdGuard Home querylog file scan over SSH",
        "period_days": {DAYS},
        "period_from_utc": cutoff_dt.isoformat(),
        "generated_at_utc": dt.datetime.now(dt.timezone.utc).isoformat(),
        "total_entries_scanned": total,
        "allowed_entries": sum(dom_count.values()),
        "unique_allowed_domains": len(dom_count),
        "reason_breakdown_raw_int": {{str(k) if k is not None else "none": v
                                     for k, v in reason_hist.most_common()}},
        "clients_breakdown": {{c: {{"queries": n}} for c, n in client_count.most_common()}},
        "client_proto_breakdown": dict(proto_count),
    }},
    "domains": [
        {{
            "domain": d,
            "queries": dom_count[d],
            "whitelisted": d in dom_whitelist,
            "clients": sorted(dom_clients[d]),
            "first_seen_utc": dom_first.get(d),
            "last_seen_utc": dom_last.get(d),
        }}
        for d, _ in dom_count.most_common()
    ],
}}
json.dump(out, sys.stdout, ensure_ascii=False)
print(f"scanned={{total}} allowed={{sum(dom_count.values())}} "
      f"unique={{len(dom_count)}}", file=sys.stderr)
"""


def main() -> None:
    ssh = os.environ.get("AGH_SSH")
    if not ssh:
        sys.exit("error: AGH_SSH is required (e.g. root@dns.example.com)")
    proc = subprocess.run(
        ["ssh", "-o", "BatchMode=yes", ssh, "python3", "-"],
        input=REMOTE, capture_output=True, text=True, timeout=900,
    )
    if proc.returncode != 0:
        sys.exit(f"remote scan failed:\n{proc.stderr}")
    with open(OUT, "w") as f:
        f.write(proc.stdout)
    print(proc.stderr.strip())
    print(f"saved: {OUT}")


if __name__ == "__main__":
    main()
