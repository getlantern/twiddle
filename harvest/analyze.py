#!/usr/bin/env python3
"""Compare Chrome's full-handshake ClientHello against its resumption hello.

Tests the claim measured for Go's stack: a resumption hello is the full hello
with pre_shared_key appended and nothing else changed.
"""
import sys, collections

NAMES = {0:"server_name",5:"status_request",10:"supported_groups",11:"ec_point_formats",
 13:"signature_algorithms",16:"ALPN",18:"SCT",21:"padding",23:"extended_master_secret",
 27:"compress_certificate",35:"session_ticket",41:"pre_shared_key",42:"early_data",
 43:"supported_versions",44:"cookie",45:"psk_key_exchange_modes",50:"signature_algorithms_cert",
 51:"key_share",17513:"application_settings",17613:"application_settings_new",
 0xfe0d:"encrypted_client_hello",0x4469:"application_settings_old",0x12e0:"ext_0x12e0"}

def name(i):
    if i in NAMES: return NAMES[i]
    if (i & 0x0f0f) == 0x0a0a and (i >> 8) == (i & 0xff): return "GREASE"
    return f"0x{i:04x}"

def parse(rec):
    b = rec[5:]
    p = 4 + 2 + 32
    sid_len = b[p]; sid = b[p+1:p+1+sid_len]; p += 1 + sid_len
    cs = int.from_bytes(b[p:p+2],'big'); p += 2 + cs
    p += 1 + b[p]
    end = p + 2 + int.from_bytes(b[p:p+2],'big'); p += 2
    exts = []
    while p + 4 <= end:
        i = int.from_bytes(b[p:p+2],'big'); ln = int.from_bytes(b[p+2:p+4],'big')
        exts.append((i, ln, b[p+4:p+4+ln])); p += 4 + ln
    return exts, sid

def load(path):
    full, resumed = [], []
    for line in open(path):
        line = line.strip()
        if not line or line.startswith('#'): continue
        _, hx = line.split(' ', 1)
        rec = bytes.fromhex(hx)
        exts, _ = parse(rec)
        (resumed if any(i == 41 for i,_,_ in exts) else full).append(rec)
    return full, resumed

def main():
    path = sys.argv[1] if len(sys.argv) > 1 else "testdata/chrome-hellos.hex"
    full, resumed = load(path)
    print(f"captured: {len(full)} full-handshake hello(s), {len(resumed)} resumption hello(s)\n")
    if not full or not resumed:
        print("!! need at least one of each -- reload the page, or the session was not cached")
        return 1
    f, r = full[0], resumed[-1]
    fe, _ = parse(f); re_, _ = parse(r)
    fmap = {i:(ln,d) for i,ln,d in fe}; rmap = {i:(ln,d) for i,ln,d in re_}

    print(f"full hello       : {len(f)} bytes, {len(fe)} extensions")
    print(f"resumption hello : {len(r)} bytes, {len(re_)} extensions")
    print(f"delta            : {len(r)-len(f):+d} bytes\n")

    added   = [i for i in rmap if i not in fmap]
    removed = [i for i in fmap if i not in rmap]
    print("extensions added  :", [name(i) for i in added] or "none")
    print("extensions removed:", [name(i) for i in removed] or "none")

    print("\nlength changes among shared extensions:")
    changed = []
    for i in fmap:
        if i in rmap and fmap[i][0] != rmap[i][0]:
            changed.append(i)
            print(f"  {name(i):28s} {fmap[i][0]:5d} -> {rmap[i][0]:5d}")
    if not changed: print("  (none)")

    print("\nextension ORDER:")
    fo, ro = [i for i,_,_ in fe], [i for i,_,_ in re_]
    print("  full      :", " ".join(name(i) for i in fo))
    print("  resumption:", " ".join(name(i) for i in ro))
    print(f"  pre_shared_key last? {ro[-1] == 41}")

    if 41 in rmap:
        psk = rmap[41][0]
        print(f"\npre_shared_key = {psk} B  (+4 header = {psk+4})")
        print(f"observed delta = {len(r)-len(f)}  ->  {'EXACT MATCH' if len(r)-len(f)==psk+4 else 'DOES NOT ACCOUNT FOR DELTA'}")
        d = rmap[41][1]
        ids_end = 2 + int.from_bytes(d[0:2],'big'); p = 2
        while p + 2 <= ids_end:
            tl = int.from_bytes(d[p:p+2],'big'); p += 2
            print(f"  ticket {tl} B, obfuscated_ticket_age 0x{int.from_bytes(d[p+tl:p+tl+4],'big'):08x}")
            p += tl + 4
        bl = d[ids_end+2]
        print(f"  binder {bl} B")
    if 42 in rmap: print("\n**early_data (0-RTT) OFFERED** — Chrome does send it here")
    else:          print("\nearly_data (0-RTT): not offered")
    return 0

sys.exit(main())
