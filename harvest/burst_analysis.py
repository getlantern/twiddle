#!/usr/bin/env python3
"""Approximate Xue et al.'s Mahalanobis-over-bursts classifier and test two
questions: does session resumption evade it, and does interleaving a small
client-direction record into the server flight evade it?

Follows Algorithm 2 from the paper: train on the first Wb bursts of each TLS
flow, then for a test sample slide a Wb window and take the MINIMUM distance.
Wb = 3 for TLS 1.3.

This is an approximation, not their classifier: different training corpus, no
chi-squared stage, and our burst inputs come from socket reads rather than
packet capture. Burst aggregation sums consecutive same-direction bytes, so it
is robust to read coalescing -- but the caveat stands.
"""
import json, statistics

WB = 3

def bursts(sizes):
    out = []
    for v in sizes:
        if out and (out[-1] > 0) == (v > 0):
            out[-1] += v
        else:
            out.append(v)
    return out

def server_runs(sizes):
    runs, i = [], 0
    while i < len(sizes):
        j = i
        while j < len(sizes) and (sizes[j] < 0) == (sizes[i] < 0):
            j += 1
        if sizes[i] < 0:
            runs.append((i, j))
        i = j
    return runs

def interleave(sizes, mode, pieces=2, inject=64):
    """Split server-direction runs by injecting small client-direction records,
    the way an h2 client emits WINDOW_UPDATE during a download.

    mode "first": split only the handshake flight (the first server run).
    mode "all":   split every server run.
    """
    runs = server_runs(sizes)
    if not runs:
        return sizes[:]
    targets = runs[:1] if mode == "first" else runs
    cuts = set()
    for (a, b) in targets:
        n = b - a
        if n < 2:
            continue
        for k in range(1, pieces):
            idx = a + (n * k) // pieces
            if a <= idx < b:
                cuts.add(idx)
    out = []
    for idx, v in enumerate(sizes):
        if idx in cuts:
            out.append(inject)
        out.append(v)
    return out

recs = [json.loads(l) for l in open("testdata/burst-corpus.jsonl")]
full = [bursts(r["sizes"]) for r in recs if r["kind"] == "full"]
res  = [bursts(r["sizes"]) for r in recs if r["kind"] == "resumed" and r["resumed"]]
full = [b for b in full if len(b) >= WB]
res  = [b for b in res  if len(b) >= WB]
print(f"corpus: {len(full)} full handshakes, {len(res)} confirmed resumptions\n")

def inv3(C, ridge):
    """Inverse of a 3x3 matrix with ridge regularisation for near-singularity.
    The client-burst dimension has very low variance across real handshakes, so
    the covariance is close to singular without it."""
    C = [row[:] for row in C]
    for i in range(3):
        C[i][i] += ridge
    a,b,c = C[0]; d,e,f = C[1]; g,h,i = C[2]
    det = a*(e*i-f*h) - b*(d*i-f*g) + c*(d*h-e*g)
    if abs(det) < 1e-12:
        return None
    adj = [[ (e*i-f*h), -(b*i-c*h),  (b*f-c*e)],
           [-(d*i-f*g),  (a*i-c*g), -(a*f-c*d)],
           [ (d*h-e*g), -(a*h-b*g),  (a*e-b*d)]]
    return [[adj[r][k]/det for k in range(3)] for r in range(3)]

def fit(train):
    X = [[float(v) for v in b[:WB]] for b in train]
    n = len(X)
    M = [sum(row[j] for row in X)/n for j in range(WB)]
    C = [[sum((row[r]-M[r])*(row[k]-M[k]) for row in X)/(n-1)
          for k in range(WB)] for r in range(WB)]
    trace = sum(C[j][j] for j in range(WB))
    return M, inv3(C, ridge=max(1e-6, trace*1e-6))

def mindist(b, M, Ci):
    if Ci is None: return float("inf")
    ds = []
    for i in range(0, max(1, len(b) - WB + 1)):
        w = b[i:i+WB]
        if len(w) < WB: break
        d = [float(w[j]) - M[j] for j in range(WB)]
        q = sum(d[r]*Ci[r][k]*d[k] for r in range(WB) for k in range(WB))
        ds.append((max(0.0, q))**0.5)
    return min(ds) if ds else float("inf")

# leave-one-out for full handshakes so we never test on training data
loo = []
for k in range(len(full)):
    tr = full[:k] + full[k+1:]
    M, Ci = fit(tr)
    loo.append(mindist(full[k], M, Ci))

M, Ci = fit(full)
d_res  = [mindist(b, M, Ci) for b in res]
raw_full = [r["sizes"] for r in recs if r["kind"] == "full"]
d_il1 = [mindist(bursts(interleave(x, "first", 2)), M, Ci) for x in raw_full]
d_il2 = [mindist(bursts(interleave(x, "first", 4)), M, Ci) for x in raw_full]
d_ila = [mindist(bursts(interleave(x, "all",   2)), M, Ci) for x in raw_full]
d_il4 = [mindist(bursts(interleave(x, "all",   4)), M, Ci) for x in raw_full]

def show(name, ds):
    ds = sorted(d for d in ds if d != float("inf"))
    if not ds: print(f"  {name:34s} (none)"); return
    print(f"  {name:34s} median {statistics.median(ds):7.2f}   "
          f"p10 {ds[len(ds)//10]:7.2f}   p90 {ds[min(len(ds)-1,9*len(ds)//10)]:7.2f}")

print("Mahalanobis min-distance over sliding Wb=3 windows:")
show("full handshake (leave-one-out)", loo)
show("resumed handshake", d_res)
show("handshake flight split in 2", d_il1)
show("handshake flight split in 4", d_il2)
show("ALL server runs split in 2", d_ila)
show("ALL server runs split in 4", d_il4)

# threshold set to flag 90% of full handshakes; how much else does it catch?
gamma = sorted(loo)[min(len(loo)-1, int(0.9*len(loo)))]
print(f"\nthreshold gamma = {gamma:.2f}  (flags 90% of full handshakes)")
for name, ds in (("full (LOO)", loo), ("resumed", d_res),
                 ("flight split in 2", d_il1), ("flight split in 4", d_il2),
                 ("all runs split in 2", d_ila), ("all runs split in 4", d_il4)):
    ds = [d for d in ds if d != float("inf")]
    if not ds: continue
    hit = sum(1 for d in ds if d <= gamma)
    print(f"  {name:24s} flagged {hit:3d}/{len(ds):3d}  = {100*hit/len(ds):5.1f}%")
