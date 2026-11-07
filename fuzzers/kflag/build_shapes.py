#!/usr/bin/env python3
# Extract per-selector IOExternalMethodDispatch shapes for EVERY concrete UserClient in the
# symbolicated kernelcache, by decoding each externalMethod's `cmp w1,#count` + `adrp/add`
# (table base), then reading `count` 24-byte dispatch entries. Output: shapes.json + the
# input-bearing (fuzzable) target list. No ipsw per-call — pure byte decode, fast.
import struct, subprocess, re, json
KC = "/Users/dawgyg/kernelcaches_ref/kc651.img4.decompressed"
VAR = 0xffffffff
data = open(KC, "rb").read()

# --- Mach-O segment map (vaddr -> file offset) ---
ncmds, = struct.unpack_from("<I", data, 16); off = 32; segs = []
for _ in range(ncmds):
    cmd, cs = struct.unpack_from("<II", data, off)
    if cmd == 0x19:
        vm, vs, fo, fs = struct.unpack_from("<QQQQ", data, off+24); segs.append((vm, vs, fo, fs))
    off += cs
def v2o(v):
    for vm, vs, fo, fs in segs:
        if vm <= v < vm+vs and v-vm < fs: return fo+(v-vm)
    return None
def rd(v, n):
    o = v2o(v); return data[o:o+n] if o is not None else None

# --- minimal arm64 decode: cmp w1,#imm ; adrp xN,#imm ; add xN,xN,#imm ---
def decode_table(ext_vaddr):
    code = rd(ext_vaddr, 80)
    if not code: return None
    count = None; adrp = {}; table = None
    for i in range(0, len(code), 4):
        w, = struct.unpack_from("<I", code, i)
        # SUBS Wzr, Wn, #imm  (cmp w, #imm) : 0x7100001f mask 0xff80001f, Rn at [9:5]
        if (w & 0xff80001f) == 0x7100001f:
            rn = (w >> 5) & 0x1f
            imm = (w >> 10) & 0xfff
            if (w >> 22) & 1: imm <<= 12
            if rn == 1 and count is None: count = imm           # cmp w1 (the selector)
        # ADRP xN, imm
        elif (w & 0x9f000000) == 0x90000000:
            rd_ = w & 0x1f
            immlo = (w >> 29) & 3; immhi = (w >> 5) & 0x7ffff
            v = (immhi << 2) | immlo
            if v & (1 << 20): v -= (1 << 21)                    # sign extend 21-bit
            adrp[rd_] = ((ext_vaddr + i) & ~0xfff) + (v << 12)
        # ADD xN, xM, #imm (64-bit)
        elif (w & 0xff800000) == 0x91000000:
            rd_ = w & 0x1f; rn = (w >> 5) & 0x1f
            imm = (w >> 10) & 0xfff
            if (w >> 22) & 1: imm <<= 12
            if rn in adrp and table is None:
                table = adrp[rn] + imm                          # table base = adrp+add
    return (count, table)

def parse_table(table, count):
    if not table or not count or count > 512: return None
    raw = rd(table, count*24)
    if not raw: return None
    out = []
    for i in range(count):
        si, ss, so, sso = struct.unpack_from("<IIII", raw, i*24+8)
        # sanity: a real dispatch entry has small counts / VAR; bail if clearly not
        if not ((si == VAR or si < 256) and (so == VAR or so < 256)
                and (ss == VAR or ss < 0x1000000) and (sso == VAR or sso < 0x1000000)):
            break
        out.append([si, ss, so, sso])
    return out

# --- enumerate concrete UC externalMethod symbols ---
nm = subprocess.run(["nm", KC], capture_output=True, text=True).stdout
syms = []
for line in nm.splitlines():
    p = line.split()
    if len(p) >= 3 and p[2].endswith("externalMethodEjP25IOExternalMethodArgumentsP24IOExternalMethodDispatchP8OSObjectPv"):
        m = re.match(r'__ZN(\d+)(.+)', p[2])
        if m:
            n = int(m.group(1)); cls = m.group(2)[:n]
            if cls != "IOUserClient":
                syms.append((cls, int(p[0], 16)))

shapes = {}; targets = []
for cls, addr in syms:
    ct = decode_table(addr)
    if not ct: continue
    count, table = ct
    tbl = parse_table(table, count)
    if not tbl: continue
    shapes[cls] = tbl
    for sel, (si, ss, so, sso) in enumerate(tbl):
        if si not in (0,) or ss not in (0,):     # has input -> fuzzable
            targets.append((cls, sel, si, ss, so, sso))

json.dump(shapes, open("/Users/dawgyg/kflag/shapes.json", "w"))
print(f"UCs with extracted tables: {len(shapes)} / {len(syms)} classic-externalMethod UCs")
print(f"input-bearing (fuzzable) selectors: {len(targets)}")
f = lambda x: "VAR" if x == VAR else x
# show ones with VARIABLE struct input (prime OOB targets) first
targets.sort(key=lambda t: (t[3] != VAR, t[0]))
print("\n=== prime targets (VAR or large structIn = attacker controls size) ===")
shown = 0
for cls, sel, si, ss, so, sso in targets:
    if ss == VAR or (ss != 0 and ss >= 0x1000):
        print(f"  {cls:46s} sel{sel:<3} scalarIn={f(si)} structIn={f(ss)} scalarOut={f(so)} structOut={f(sso)}")
        shown += 1
        if shown >= 40: break
print(f"... ({shown} shown)")
