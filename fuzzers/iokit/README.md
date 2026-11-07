# iPhone dynamic Target-Flag kit (deploy when the device is in hand)

WHY: static iOS surface is hardened (same -fbounds-safety + IOCommandGate + reply-zeroing as macOS, audited).
The flag-capturable bugs are DYNAMIC + iOS-SPECIFIC: the M-series drivers (GPU/ISP/ANE/codec) reachable from the
app sandbox, and 0-click iMessage. The VM can't host those drivers; only the real device can.

## A. On-device IOKit kernel fuzzer (kernel LPE / Target Flag)
1. Pair the iPhone to this Mac, enable Developer Mode (Settings>Privacy>Developer Mode).
2. Build ios_iokit_fuzz.c into a tiny iOS app via Xcode (or `xcrun -sdk iphoneos clang -arch arm64e`), sign with
   the user's free dev cert, sideload. (App-sandboxed — exactly the attacker's position.)
3. First, on-device: `ioreg -l | grep UserClient` to get the REAL openable client names; update SVCS[].
4. Run it. A kernel panic = the bug. Capture: Settings>Privacy>Analytics & Improvements>Analytics Data
   (panic-full-*.ips), or Console.app on the Mac (device paired) live, or `idevicecrashreport` (libimobiledevice).
5. Triage the .ips: EXC_BAD_ACCESS in the kernel with an attacker-controlled fault addr = flag-tier; classify
   read vs write vs UAF. (NOT a -fbounds-safety brk trap, which is CVE-only.)

## B. 0-click iMessage (BlastDoor downstream → ImageIO/CoreText/codec)
1. From a SECOND device/account, send crafted attachments to the daughter's iPhone Apple ID:
   - the malicious .usdz at /tmp/usd/oob_mesh.usdz (RealityKit thumbnail path)
   - malformed HEIC/JPEG/PNG, malformed fonts (.ttf/.dfont), PDF.
2. 0-click: the receiving device auto-generates previews/thumbnails. Watch for MessagesBlastDoorService /
   imagent / previewd crashes in Analytics Data. A repro crash from a SENT message = 0-click, flag/high-bounty.

## C. Capture discipline (per the bounty bar)
- Real-process crash on the REAL path (no harness), attacker-controlled fault/value, reproducible = bounty/flag.
- A sanitizer-only/harness-only/assert/brk-trap crash = CVE at most. Verify the faulting instruction + register control.
