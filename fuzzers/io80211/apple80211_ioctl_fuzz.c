// apple80211 socket-ioctl fuzz — Claude-written for Codex to run on a KASAN VM (kernel-crash target).
// Target: IO80211SkywalkInterface::processBSDCommand @0xfffffe000a74cd94 (IO80211Family) — the apple80211 ioctl
// dispatch, reachable from uid501 via socket ioctl(SIOCGA80211/SIOCSA80211) on the wifi interface (bypasses the
// entitlement-gated IO80211APIUserClient). GET commands are NOT privilege-gated => uid501->kernel if a per-command
// handler copies/allocates by req.len without bounding it. See lead_io80211_skywalk_wifi_uc_uid501_kernel_378j.md
//
// ★ RUN ON A KASAN VM (this WILL panic the kernel on a hit). uid501, NOT root needed for the GET path.
// Build: clang apple80211_ioctl_fuzz.c -o a8f    (arm64e). Run: ./a8f en0   (or the actual wifi ifname)
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>

// apple80211req (from apple80211_ioctl.h): { ifname[16]; req_type; req_val; req_len; req_data* }
struct apple80211req {
  char      req_if_name[IFNAMSIZ]; // 16
  int       req_type;
  int       req_val;
  uint32_t  req_len;
  void     *req_data;
};
#ifndef SIOCGA80211
#define SIOCGA80211 _IOWR('i', 201, struct ifreq)
#define SIOCSA80211 _IOW ('i', 202, struct ifreq)
#endif

int main(int argc, char **argv) {
  const char *ifn = argc>1 ? argv[1] : "en0";
  int s = socket(AF_INET, SOCK_DGRAM, 0);
  if (s < 0) { perror("socket"); return 1; }
  fprintf(stderr, "[*] uid=%d fuzzing apple80211 ioctls on %s (KASAN VM). GET first (uid501, no priv).\n", getuid(), ifn);

  static uint8_t buf[0x20000];  // generous data buffer for copyout targets
  // Fuzz req_type across the known APPLE80211_IOC_* range (~0..700) x req_len edge values.
  uint32_t lens[] = { 0, 1, 2, 4, 8, 0x10, 0x40, 0x100, 0x1000, 0x10000, 0x20000,
                      0x7fffffff, 0x80000000, 0xffffffff, 0xfffffffe };
  int hits = 0;
  for (int type = 0; type < 720; type++) {
    for (unsigned li = 0; li < sizeof lens/sizeof lens[0]; li++) {
      struct apple80211req req; memset(&req, 0, sizeof req);
      strncpy(req.req_if_name, ifn, IFNAMSIZ);
      req.req_type = type; req.req_val = 0; req.req_len = lens[li];
      memset(buf, 0x41, sizeof buf); req.req_data = buf;
      struct ifreq ifr; memset(&ifr, 0, sizeof ifr);
      strncpy(ifr.ifr_name, ifn, IFNAMSIZ);
      // ifr_data carries the apple80211req pointer (Apple's convention)
      *(void **)&ifr.ifr_ifru = &req;
      // GET first (uid501-reachable, copyout => kernel info-leak/OOB-read on len>buffer)
      ioctl(s, SIOCGA80211, &ifr);
      // SET second (may need root; copyin => OOB-write). Comment out for the pure-uid501 GET run.
      // ioctl(s, SIOCSA80211, &ifr);
    }
    if ((type % 64) == 0) fprintf(stderr, "  type=%d ...\n", type);
  }
  fprintf(stderr, "[*] done. On a KASAN VM a per-command req_len OOB => panic .ips w/ the faulting IO80211 handler.\n");
  fprintf(stderr, "    Minimize to the single (type,len), confirm GET-only (uid501) => uid501->kernel finding.\n");
  fprintf(stderr, "    NOTE: verify the apple80211req/ifr_data ABI on 378n (Apple80211 framework headers) if no dispatch.\n");
  return 0;
}
