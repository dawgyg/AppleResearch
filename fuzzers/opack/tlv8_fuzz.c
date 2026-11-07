// TLV8 decoder fuzz harness — Claude-written for Codex, sibling to opack_fuzz.c.
// Target: CoreUtils TLV8 parsers (HomeKit/HAP pairing TLV — remote/BLE/Wi-Fi surface).
//   _TLV8Get, _TLV8GetBytes, _TLV8GetOrCopyCoalesced, _TLV8GetUInt64.
// Coalesced-fragment reassembly (GetOrCopyCoalesced) leans bounded per Claude static (per-fragment data_end<=end +
// malloc-to-sum), BUT the integer decoders (GetUInt64 reading 1..8 bytes) + Get/GetBytes iteration on malformed
// buffers may still fault — fuzz confirms what static missed. HomeKit HAP = fan-out to homed/HomeKit accessories.
//
// Build (verified pattern from opack_fuzz):
//   clang -arch arm64e -O0 -g tlv8_fuzz.c -o tlv8_fuzz -framework CoreFoundation \
//     -F/System/Library/PrivateFrameworks -framework CoreUtils
// Run one-shot Guard Malloc (NOT while user AFK):
//   MallocGuardEdges=1 MallocScribble=1 DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./tlv8_fuzz
//
// Signatures (CoreUtils; Codex verify exact):
//   OSStatus TLV8Get(const uint8_t *inSrc, const uint8_t *inEnd, uint8_t inType,
//                    const uint8_t **outPtr, size_t *outLen, const uint8_t **outNext);
//   OSStatus TLV8GetBytes(const uint8_t *src, const uint8_t *end, uint8_t type, size_t minLen, size_t maxLen,
//                         void *buf, size_t *outLen, const uint8_t **outNext);
//   OSStatus TLV8GetOrCopyCoalesced(const uint8_t *src, const uint8_t *end, uint8_t type,
//                                   uint8_t *inlineBuf, size_t inlineLen, uint8_t **outPtr, size_t *outLen, ...);
//   uint64_t TLV8GetUInt64(const uint8_t *src, const uint8_t *end, uint8_t type, OSStatus *err, const uint8_t **next);
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

extern int  TLV8Get(const uint8_t*, const uint8_t*, uint8_t, const uint8_t**, size_t*, const uint8_t**) __attribute__((weak_import));
extern int  TLV8GetBytes(const uint8_t*, const uint8_t*, uint8_t, size_t, size_t, void*, size_t*, const uint8_t**) __attribute__((weak_import));
extern uint64_t TLV8GetUInt64(const uint8_t*, const uint8_t*, uint8_t, int*, const uint8_t**) __attribute__((weak_import));

static void feed(const uint8_t *b, size_t n) {
    const uint8_t *end = b + n, *p, *next; size_t len; int err;
    for (uint8_t ty = 0; ty < 8; ty++) {           // try several TLV types
        if (TLV8Get)      { p=NULL; len=0; next=NULL; TLV8Get(b, end, ty, &p, &len, &next); }
        if (TLV8GetUInt64){ err=0; next=NULL; TLV8GetUInt64(b, end, ty, &err, &next); }
        if (TLV8GetBytes) { uint8_t dst[64]; size_t ol=0; next=NULL; TLV8GetBytes(b, end, ty, 0, sizeof dst, dst, &ol, &next); }
    }
}

int main(int argc, char **argv) {
    if (!TLV8Get && !TLV8GetUInt64 && !TLV8GetBytes) { fprintf(stderr,"TLV8 syms unresolved — Codex bind exact\n"); return 2; }
    if (argc > 1) { FILE*f=fopen(argv[1],"rb"); if(!f)return 1; static uint8_t b[1<<20]; size_t n=fread(b,1,sizeof b,f); fclose(f); feed(b,n); return 0; }
    // structural seeds: TLV8 item = [type][len<=255][len bytes]; fuzz the len byte vs remaining + fragment coalescing.
    uint8_t s1[]={0x00,0xff,0x41};                         feed(s1,sizeof s1);   // len 255 but only 1 data byte
    uint8_t s2[512]; memset(s2,0x00,sizeof s2); s2[1]=0xff; feed(s2,sizeof s2);  // many 0x00-type fragments (coalesce sum)
    uint8_t s3[]={0x06,0x08,1,2,3,4,5,6,7,8};              feed(s3,sizeof s3);   // GetUInt64 8-byte value
    static uint8_t b[512];
    for (long i=0;i<2000000;i++){ size_t n=1+(i*2654435761u)%sizeof b; for(size_t k=0;k<n;k++) b[k]=(uint8_t)((i*131+k*7)&0xff); feed(b,n); }
    return 0;
}
