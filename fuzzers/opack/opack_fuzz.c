// OPACK decoder fuzz harness — Claude-written for Codex to run under Guard Malloc.
// Target: CoreUtils _OPACKDecodeBytes (shared Continuity/AirDrop/HomeKit deserializer).
// Bug class: wire length/count vs remaining-bytes bound, integer wrap (count*elemsize),
// nesting depth (recursive dict/array), extended-length prefixes (1/2/4/8-byte).
// One bug here = many remote wireless-proximity services (several root/high-priv).
//
// Build (arm64e, links CoreUtils from the dyld cache):
//   clang -arch arm64e -O0 -g opack_fuzz.c -o opack_fuzz \
//     -F/System/Library/PrivateFrameworks -framework CoreUtils
// Run under one-shot Guard Malloc (per file OR whole-process):
//   MallocGuardEdges=1 MallocScribble=1 DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./opack_fuzz seedfile
//   (or: ./opack_fuzz  -> internal mutation loop)
// A crash in OPACKDecode* = the finding. Minimize the crashing blob, confirm on stock, package w/ .ips + honest tier.
//
// _OPACKDecodeBytes prototype (CoreUtils): CFTypeRef OPACKDecodeBytes(const void *ptr, size_t len,
//   uint32_t flags, CFErrorRef *outError);  (flags 0; outError optional). Returns a retained CF object or NULL.
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <CoreFoundation/CoreFoundation.h>

// Weak-import so the harness links even if the symbol name differs; Codex: fix to the exact export.
extern CFTypeRef OPACKDecodeBytes(const void *ptr, size_t len, uint32_t flags, CFErrorRef *err) __attribute__((weak_import));

static void feed(const uint8_t *buf, size_t len) {
    CFErrorRef err = NULL;
    CFTypeRef o = OPACKDecodeBytes(buf, len, 0, &err);
    if (o) CFRelease(o);
    if (err) CFRelease(err);
}

// A few structural seeds exercising the risky OPACK encodings.
// OPACK tag bytes (from OPACKEncode observation — Codex verify exact tag map):
//   small int 0x00-0x2F; data/string with 1/2/4/8-byte extended length; array/dict with count; nesting.
static void seeds(void) {
    // EMPIRICAL OPACK tags (Claude encoder round-trip): int 0x30-33, str 0x40+/ext 0x61-64, data 0x70+/ext 0x91-94,
    // array 0xd0+, dict 0xe0+. Fuzz the EXTENDED-length decode (huge wire length vs actual remaining bytes).
    // 1. string ext-length: 0x63 = 4-byte length, claim 0xffffffff but supply 1 byte (len vs remaining check?)
    uint8_t d1[] = {0x63, 0xff,0xff,0xff,0xff, 0x41};
    feed(d1, sizeof d1);
    // 2. data ext-length: 0x94 = 8-byte length = SIZE_MAX-ish (integer wrap on len/alloc?)
    uint8_t d2[] = {0x94, 0xff,0xff,0xff,0xff,0xff,0xff,0xff,0xff};
    feed(d2, sizeof d2);
    // 3. array with large count 0xdf(=count 15) but no elements (count vs remaining?), + repeated
    uint8_t d3[] = {0xdf};
    feed(d3, sizeof d3);
    // 4. DEEP NESTING: chain of 1-pair dicts (0xe1 key ...) -> recursion depth (stack exhaustion / unbounded)?
    uint8_t d4[3000]; for (size_t i=0;i<sizeof d4;i+=2){ d4[i]=0xe1; d4[i+1]=0x40; } feed(d4, sizeof d4);
    // 5. data ext 4-byte length just past buffer end (off-by-one / len==remaining+1)
    uint8_t d5[] = {0x93, 0x05,0x00,0x00,0x00, 1,2,3,4};   // claims 5, supplies 4
    feed(d5, sizeof d5);
}

int main(int argc, char **argv) {
    if (!OPACKDecodeBytes) { fprintf(stderr, "OPACKDecodeBytes unresolved — Codex: bind exact export/addr\n"); return 2; }
    if (argc > 1) { // replay a seed file
        FILE *f = fopen(argv[1], "rb"); if (!f) return 1;
        static uint8_t b[1<<20]; size_t n = fread(b, 1, sizeof b, f); fclose(f); feed(b, n); return 0;
    }
    if (argc>1 && !strcmp(argv[1],"seeds")) { seeds(); return 0; }
    seeds();
    // Dumb mutation loop (Codex: replace with a coverage-guided runner; deterministic seed via argv for replay).
    static uint8_t b[512];
    for (long i = 0; i < 2000000; i++) {
        size_t n = 1 + (i * 2654435761u) % sizeof b;      // vary length (no Math.random per repo rule)
        for (size_t k = 0; k < n; k++) b[k] = (uint8_t)((i*131 + k*7 + (k?b[k-1]:0)) & 0xff);
        // bias byte0 toward variable-length/container tags
        b[0] = (uint8_t)(0x60 + (i % 0x40));
        feed(b, n);
    }
    return 0;
}
