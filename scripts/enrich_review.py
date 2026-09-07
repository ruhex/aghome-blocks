#!/usr/bin/env python3
"""Enrich REVIEW-classified domains in an analysis JSON.

For REVIEW domains with queries >= threshold:
  - resolve A records and CNAME (dig);
  - RDAP lookup on the parent domain via rdap.org (registrar, creation
    date, age) - throttled, retries on 429;
  - URLhaus check if URLHAUS_API_KEY is set, otherwise marked UNAVAILABLE
    (abuse.ch API requires a key now).

Usage:
  enrich_review.py [analysis.json] [min_queries=15]
"""

import concurrent.futures as cf
import datetime as dt
import json
import os
import subprocess
import sys
import time
import urllib.parse
import urllib.request

PATH = sys.argv[1] if len(sys.argv) > 1 else "analysis/dns-analysis.json"
MIN_QUERIES = int(sys.argv[2]) if len(sys.argv) > 2 else 15
UA = {"User-Agent": "aghome-dns-agent/1.0"}

d = json.load(open(PATH))
targets = [x for x in d["domains"]
           if x["classification"] == "REVIEW" and x["queries_period"] >= MIN_QUERIES]
print(f"enriching {len(targets)} REVIEW domains (queries >= {MIN_QUERIES})", flush=True)


def dig(host, qtype):
    try:
        out = subprocess.run(["dig", "+short", qtype, host],
                             capture_output=True, text=True, timeout=8).stdout.strip()
        return [l for l in out.splitlines() if l] if out else []
    except Exception:
        return []


def get_rdap(parent):
    url = f"https://rdap.org/domain/{urllib.parse.quote(parent)}"
    for attempt in range(3):
        try:
            req = urllib.request.Request(url, headers=UA)
            with urllib.request.urlopen(req, timeout=15) as r:
                j = json.load(r)
            created = next((e.get("eventDate") for e in j.get("events", [])
                            if e.get("eventAction") == "registration"), None)
            registrar = None
            for ent in j.get("entities", []):
                if "registrar" in ent.get("roles", []):
                    vcard = ent.get("vcardArray", [None, []])[1]
                    registrar = next((i[3] for i in vcard if i[0] == "fn"), None)
            return {"status": "OK", "registrar": registrar, "created": created,
                    "domain_status": j.get("status", []), "queried_domain": parent}
        except Exception as ex:
            s = str(ex)
            if "429" in s:
                time.sleep(6 + attempt * 4)
            else:
                return {"status": "NOT_FOUND", "queried_domain": parent, "error": s[:100]}
    return {"status": "UNAVAILABLE", "queried_domain": parent, "error": "rate limited"}


def get_urlhaus(host, key):
    if not key:
        return {"status": "UNAVAILABLE",
                "reason": "abuse.ch URLhaus API requires a key; URLHAUS_API_KEY not set"}
    try:
        data = urllib.parse.urlencode({"host": host, "key": key}).encode()
        req = urllib.request.Request("https://urlhaus-api.abuse.ch/v1/host/",
                                     data=data, headers=UA)
        with urllib.request.urlopen(req, timeout=15) as r:
            j = json.load(r)
        qs = j.get("query_status")
        if qs == "ok":
            return {"status": "OK", "query_status": "ok",
                    "url_count": j.get("url_count"), "blacklists": j.get("blacklists")}
        return {"status": "OK", "query_status": qs}
    except Exception as ex:
        return {"status": "UNAVAILABLE", "error": str(ex)[:120]}


def process(x):
    host = x["domain"]
    parent = x.get("parent_domain") or host
    x["resolved_ips"] = dig(host, "A")[:6]
    cname = dig(host, "CNAME")
    x["cname"] = cname[0].rstrip(".") if cname else None
    rdap = get_rdap(parent)
    x["external_intelligence"]["rdap"] = rdap
    x["external_intelligence"]["urlhaus"] = get_urlhaus(host, os.environ.get("URLHAUS_API_KEY"))
    used, supporting, conflicting = [], [], []
    if rdap["status"] == "OK":
        used.append("rdap")
        if rdap.get("created"):
            try:
                created = dt.datetime.fromisoformat(rdap["created"].replace("Z", "+00:00"))
                rdap["age_days"] = (dt.datetime.now(dt.timezone.utc) - created).days
                if rdap["age_days"] > 365:
                    supporting.append("rdap:domain_older_than_1y")
                elif rdap["age_days"] < 100:
                    supporting.append("rdap:freshly_registered")
            except ValueError:
                pass
    if x["external_intelligence"]["urlhaus"].get("query_status") == "no_results":
        supporting.append("urlhaus:no_malware_reports")
    if x["external_intelligence"]["urlhaus"].get("query_status") == "ok":
        conflicting.append("urlhaus:malware_urls_reported")
    x["decision_basis"]["external_sources_used"] = used
    x["decision_basis"]["external_sources_supporting"] = supporting
    x["decision_basis"]["external_sources_conflicting"] = conflicting
    return x


with cf.ThreadPoolExecutor(max_workers=3) as ex:
    for i, _ in enumerate(ex.map(process, targets)):
        if (i + 1) % 40 == 0:
            print(f"  {i + 1}/{len(targets)}", flush=True)
        time.sleep(0.15)

with open(PATH, "w") as f:
    json.dump(d, f, ensure_ascii=False, indent=1)

ok_rdap = sum(1 for x in targets if x["external_intelligence"]["rdap"]["status"] == "OK")
print(f"rdap OK: {ok_rdap}/{len(targets)}")
fresh = [(x["domain"], x["external_intelligence"]["rdap"].get("age_days"))
         for x in targets
         if isinstance(x["external_intelligence"]["rdap"].get("age_days"), int)
         and x["external_intelligence"]["rdap"]["age_days"] < 100]
if fresh:
    print("freshly registered (<100d):", fresh)
print(f"updated: {PATH}")
