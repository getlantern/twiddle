#!/usr/bin/env python3
"""Compare ClientHello structure across capture arms (headless vs headful).

Normalises everything Chrome varies per connection -- extension order, GREASE
values, random, session_id, key material, ECH padding -- and compares what must
be stable if the two arms are emitting the same fingerprint.
"""
import sys, json
from collections import Counter

def isg(i): return (i & 0x0f0f) == 0x0a0a and (i >> 8) == (i & 0xff)
def g(i):   return 'GREASE' if isg(i) else f'0x{i:04x}'

def parse(rec):
    b = rec[5:]
    out = {}
    out['legacy_version'] = f"0x{int.from_bytes(b[4:6],'big'):04x}"
    p = 4 + 2 + 32
    sid = b[p]; out['session_id_len'] = sid; p += 1 + sid
    csl = int.from_bytes(b[p:p+2],'big'); p += 2
    out['cipher_suites'] = [g(int.from_bytes(b[p+i:p+i+2],'big')) for i in range(0, csl, 2)]
    p += csl
    cml = b[p]; out['compression'] = list(b[p+1:p+1+cml]); p += 1 + cml
    end = p + 2 + int.from_bytes(b[p:p+2],'big'); p += 2
    exts = []
    while p + 4 <= end:
        i = int.from_bytes(b[p:p+2],'big'); ln = int.from_bytes(b[p+2:p+4],'big')
        exts.append((i, ln, b[p+4:p+4+ln])); p += 4 + ln
    out['ext_ids'] = sorted(g(i) for i,_,_ in exts)
    out['ext_count'] = len(exts)
    d = {i:(ln,data) for i,ln,data in exts}
    def u16list(data, off=2):
        return [g(int.from_bytes(data[k:k+2],'big')) for k in range(off, len(data), 2)]
    if 0x000a in d: out['supported_groups'] = u16list(d[0x000a][1])
    if 0x002b in d: out['supported_versions'] = [g(int.from_bytes(d[0x002b][1][k:k+2],'big')) for k in range(1, len(d[0x002b][1]), 2)]
    if 0x000d in d: out['sig_algs'] = u16list(d[0x000d][1])
    if 0x0010 in d:
        data = d[0x0010][1]; k = 2; alpn = []
        while k < len(data):
            n = data[k]; alpn.append(data[k+1:k+1+n].decode('latin1')); k += 1 + n
        out['alpn'] = alpn
    if 0x002d in d: out['psk_kex_modes'] = list(d[0x002d][1][1:])
    if 0x001b in d: out['compress_cert'] = list(d[0x001b][1][1:])
    if 0x000b in d: out['ec_point_formats'] = list(d[0x000b][1][1:])
    if 0x0033 in d:  # key_share: groups + key lengths only, never the keys
        data = d[0x0033][1]; k = 2; ks = []
        while k + 4 <= len(data):
            grp = int.from_bytes(data[k:k+2],'big'); n = int.from_bytes(data[k+2:k+4],'big')
            ks.append((g(grp), n)); k += 4 + n
        out['key_share'] = ks
    for i in (0x0005, 0x0012, 0x0017, 0x0023, 0xff01, 0x12e0, 0x4469, 0x44cd):
        if i in d: out[f'ext_{i:04x}_len'] = d[i][0]
    out['has_psk'] = 0x0029 in d
    out['has_early_data'] = 0x002a in d
    return out

def load(path):
    rows = []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith('#'): continue
        rows.append(parse(bytes.fromhex(line.split(' ',1)[1])))
    return rows

arms = {}
for path in sys.argv[1:]:
    name = path.split('/')[-1].replace('hh-','').replace('.hex','')
    rows = load(path)
    full = [r for r in rows if not r['has_psk']]
    arms[name] = (rows, full)
    sigs = {json.dumps({k:v for k,v in r.items() if k!='has_psk'}, sort_keys=True) for r in full}
    print(f"{name:16s} {len(rows):3d} hellos ({len(full)} full, {len(rows)-len(full)} resumed)  "
          f"-> {len(sigs)} distinct full-hello signature(s)")

names = list(arms)
print()
if len(names) < 2:
    sys.exit(0)
base = names[0]
for other in names[1:]:
    a = arms[base][1][0]; b = arms[other][1][0]
    print(f"=== {base}  vs  {other} ===")
    diffs = []
    for k in sorted(set(a) | set(b)):
        if k in ('has_psk','has_early_data'): continue
        va, vb = a.get(k,'<absent>'), b.get(k,'<absent>')
        if va != vb: diffs.append((k, va, vb))
    if not diffs:
        print("  NO STRUCTURAL DIFFERENCE across every compared field")
    else:
        for k, va, vb in diffs:
            print(f"  {k}:")
            print(f"     {base:16s} {va}")
            print(f"     {other:16s} {vb}")
    print(f"\n  fields compared: {len([k for k in set(a)|set(b) if k not in ('has_psk','has_early_data')])}")
