#!/usr/bin/env python3
"""Fit a record-shaping profile from real browsing traffic.

Record sizes and inter-record timing are the entire observable of an encrypted
tunnel, so the Padder must be fitted to measurement rather than guessed.
"""
import json, sys, statistics
from collections import Counter

path = sys.argv[1] if len(sys.argv) > 1 else "testdata/records.jsonl"
flows = []
for line in open(path):
    line = line.strip()
    if not line:
        continue
    try:
        flows.append(json.loads(line))
    except json.JSONDecodeError:
        continue

APP = 0x17
sizes = {"c": [], "s": []}
gaps = {"c": [], "s": []}
per_flow = []
handshake_only = 0

for f in flows:
    app = [r for r in f["records"] if r["t"] == APP]
    if not app:
        handshake_only += 1
        continue
    per_flow.append(len(app))
    last = {"c": None, "s": None}
    for r in app:
        d = r["d"]
        sizes[d].append(r["n"])
        if last[d] is not None:
            gaps[d].append(r["us"] - last[d])
        last[d] = r["us"]

tot = len(sizes["c"]) + len(sizes["s"])
print(f"flows: {len(flows)}   with application_data: {len(per_flow)}   handshake-only: {handshake_only}")
print(f"application_data records: {tot}  (client {len(sizes['c'])}, server {len(sizes['s'])})\n")

def pct(v, p):
    if not v: return 0
    v = sorted(v)
    return v[min(len(v)-1, int(p*len(v)))]

for d, name in (("c", "client->server"), ("s", "server->client")):
    v = sizes[d]
    if not v: continue
    print(f"=== {name}: {len(v)} records")
    print(f"    min {min(v)}  p10 {pct(v,.1)}  p25 {pct(v,.25)}  median {pct(v,.5)}  "
          f"p75 {pct(v,.75)}  p90 {pct(v,.9)}  p99 {pct(v,.99)}  max {max(v)}")
    big = sum(1 for x in v if x >= 16000)
    small = sum(1 for x in v if x <= 100)
    print(f"    >=16000 B: {100*big/len(v):.1f}%    <=100 B: {100*small/len(v):.1f}%")
    print(f"    most common sizes: {Counter(v).most_common(8)}")
    g = gaps[d]
    if g:
        print(f"    inter-record gap us: median {pct(g,.5)}  p90 {pct(g,.9)}  "
              f"(same-ms: {100*sum(1 for x in g if x < 1000)/len(g):.0f}%)")
    print()

if per_flow:
    print(f"app records per flow: median {pct(per_flow,.5)}  p90 {pct(per_flow,.9)}  max {max(per_flow)}")
    print(f"flows with <=2 app records: {100*sum(1 for x in per_flow if x<=2)/len(per_flow):.0f}%")

# The buckets a Padder would round up to: keep the real modes.
allsz = sizes["c"] + sizes["s"]
if allsz:
    print("\n=== candidate padding buckets (cover 90% of records, chosen from real modes) ===")
    c = Counter(allsz)
    common = [s for s, _ in c.most_common(40)]
    buckets, covered = [], 0
    for b in sorted(common):
        buckets.append(b)
    cum = 0
    chosen = []
    for b in sorted(set([pct(allsz, q) for q in (.1,.25,.5,.75,.9,.99)] + [max(allsz)])):
        chosen.append(b)
    print(f"    {chosen}")
