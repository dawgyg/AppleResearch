// CoreUtils HTTP/RTP header parser fuzz — Claude, sibling to opack_fuzz.c.
// Targets (less-audited than OPACK, remote-reachable string parsers):
//   _HTTPParseByteRangeRequest @0x1904db694 (HTTP Range header)
//   _HTTPParseRTPInfo          @0x1904dba74 (AirPlay RTP-Info header — remote wireless receiver)
//   _HTTPParseParameter        @0x1904db288
//   _HTTPParseCacheControlHeader @0x1904db874
// Build: clang -arch arm64e -O0 -g http_parse_fuzz.c -o http_parse_fuzz -framework CoreFoundation \
//   -F/System/Library/PrivateFrameworks -framework CoreUtils
// Run one-shot Guard Malloc: MallocGuardEdges=1 DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib ./http_parse_fuzz
// A crash = less-audited CoreUtils remote parser finding (RTP-Info = AirPlay report-grade reachability).
// Codex: VERIFY exact signatures (weak-import guesses below; the common Apple shape is
//   (const char *inSrc, const char *inEnd, ...out params...)). Fix and re-fuzz.
#include <stdio.h>
#include <string.h>
#include <stdint.h>

// Common Apple HTTP-parser shape: (src, end, ...outs). Guessed prototypes — Codex bind exact from CoreUtils SDK/RE.
extern int HTTPParseByteRangeRequest(const char*, size_t, int64_t*, int64_t*) __attribute__((weak_import)); // verified: x0=src,x1=len(-1=strlen),x2/x3=out
extern int HTTPParseRTPInfo(const char*, size_t, void*, void*, void*) __attribute__((weak_import)); // Codex: verify exact outs; x0=src x1=len likely
extern int HTTPParseParameter(const char*, size_t, const char**, size_t*, const char**, size_t*, const char**) __attribute__((weak_import)); // x1=len

static void feed(const char *b, size_t n) {
    const char *next; int64_t a=0,c=0; const char *k,*v; size_t kl,vl; char o1[64],o2[64],o3[64];
    if (HTTPParseByteRangeRequest) { HTTPParseByteRangeRequest(b, n, &a, &c); }
    if (HTTPParseRTPInfo)          { HTTPParseRTPInfo(b, n, o1, o2, o3); }
    if (HTTPParseParameter)        { next=NULL; k=v=NULL; kl=vl=0; HTTPParseParameter(b, n, &k,&kl,&v,&vl,&next); }
}

int main(int argc, char **argv) {
    if (!HTTPParseByteRangeRequest && !HTTPParseRTPInfo && !HTTPParseParameter) { fprintf(stderr,"HTTP parsers unresolved\n"); return 2; }
    if (argc > 1 && strcmp(argv[1],"seeds")) { FILE*f=fopen(argv[1],"rb"); if(!f)return 1; static char b[1<<16]; size_t n=fread(b,1,sizeof b,f); fclose(f); feed(b,n); return 0; }
    // structural seeds: malformed Range / RTP-Info headers (delimiter/offset/length edge cases).
    const char *s[] = {
        "bytes=0-", "bytes=-1", "bytes=0-99999999999999999999", "bytes=,,,,", "bytes=1-0",
        "bytes=0-1,2-3,4-5,6-7,8-9,10-", "bytes= - ", "bytes=99999999999999999999-0",
        "url=rtsp://x;seq=65535;rtptime=4294967295", "seq=;rtptime=", "url=;;;;;;;;", ";=;=;=",
        "a=b;c=d;e=", "\x00\x00\x00", "bytes=0x10-0x20",
    };
    for (size_t i=0;i<sizeof s/sizeof s[0];i++) feed(s[i], strlen(s[i]));
    if (argc>1 && !strcmp(argv[1],"seeds")) return 0;
    static char b[256];
    for (long i=0;i<2000000;i++){ size_t n=1+(i*2654435761u)%sizeof b; for(size_t k=0;k<n;k++) b[k]=(char)((i*131+k*7)&0xff); feed(b,n); }
    return 0;
}
