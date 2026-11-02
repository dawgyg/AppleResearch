# Broker-Kernel-UC candidates — macOS 27.0 26A5368g (m1mac, uid501)

Pattern hunted: **root daemon that itself opens a kernel IOKit UC (IOServiceOpen after
IOServiceMatching / IORegistryEntryFromPath) AND exposes an XPC/MIG method reachable by
uid501 that forwards client-controlled selector/scalars/struct into IOConnectCall***.**
Such brokered UCs were EXCLUDED from the prior direct-uid501-openable sweep, so their
external methods are UNAUDITED kernel surface reachable by uid501 through the broker.

Method: (1) all 430 /System/Library/LaunchDaemons plists, keep UserName root/absent whose
binary imports BOTH `_IOServiceOpen` and any `IOConnectCall*`. (2) gate heuristic =
does the binary even import audit_token / SecTask / entitlement / euid checks (absence =
likely-ungated XPC accept). (3) resolve the brokered UC class from the IOServiceMatching /
IORegistryEntryFromPath argument. Static only — no UC opened, no daemon contacted.

Direct-openable exclusions honored (already swept): AppleParavirt, IOGPU/AGX, IOSurface,
AppleMultitouch, IOUserSerial, CCDataPipe, ANE, media UCs, IOTimeSync (clocksyncd, closed).

## Survivors (root daemon, imports IOServiceOpen + IOConnectCall*)
26 daemons matched. Gate heuristic split:

UNGATED (no audit_token/SecTask/entitlement/euid import in binary — strongest-EV):
 accessoryd, inboxupdaterd, MobileStorageMounter, powerexperienced, online-auth-agent,
 liquiddetectiond, watchdogd, thermald, systemstats, BlueTool, IOMFB_bics_daemon,
 logd_helper, mobile_obliterator, AppleCredentialManagerDaemon

GATED (imports audit_token/SecTask/sandbox_check → broker but access-controlled, secondary):
 airportd, AssetCache(euid), bluetoothd, ctkahp, CVMServer(euid), diskarbitrationd,
 diskimagesiod, FindMyMacd, mobileactivationd, powerd, storagekitd, usermanagerd,
 biometrickitd/coreauthd(auth daemons)

## RANKED CANDIDATE TABLE (ungated + broker-only UC + client-into-IOConnectCall)

| # | daemon (root) | uid501 XPC (gate) | brokered kernel UC | broker-only? | IOConnectCall site(s) [arm64e vaddr] | dataflow evidence | prio |
|---|---|---|---|---|---|---|---|
| 1 | **MobileStorageMounter** /usr/libexec/MobileStorageMounter | com.apple.mobile.storage_mounter.xpc (NO gate imports) | **AppleMobileFileIntegrity** (matched @0x10000e564, opened @0x10000e590) | broker-only (AMFI UC direct-open needs amfi private entitlement) | IOConnectCallMethod **0x10000ea68** (sel=2, structIn=x26 from objc obj x22, size=x5), **0x10000ed1c** | sel-2 struct input is built from an objc object (retainAutorelease @0x10000ea30) — the mount request's trust-cache/CDHash blob → AMFI. Strongest shallow client→struct dataflow. | **TOP** |
| 2 | **inboxupdaterd** /usr/libexec/inboxupdaterd | com.apple.inboxupdaterd (UserName=root, NO gate imports) | **AppleKeyStore** (IOService:/IOResources/AppleKeyStore via IORegistryEntryFromPath @0x10005d114 + IOServiceMatching @0x10005d154; also string "AppleKeyStoreTest") | broker-only (AppleKeyStore UC open is entitlement/root gated) | IOConnectCallMethod many sels: **0x10005c24c**(sel 0x56), **0x10005c4ec**(0xf), **0x10005c6f0**(0x13), **0x10005c8ec**(0x14), **0x10005ca34**(0x15), **0x10005cc18**(0x10), **0x10005cdc4**(0x17), **0x10005d008**(0x12), **0x10005d1b4**(sel0) | Rich keystore keybag selector surface reachable inside one root daemon; needs XPC→sel arg trace (phase 2). | **TOP** |
| 3 | **accessoryd** /System/Library/PrivateFrameworks/CoreAccessories.framework/Support/accessoryd | com.apple.accessories.hid / .transport-server / .externalaccessory-server / .connection-info-server (NO gate imports) | **AppleKeyStore** (IOService:/IOResources/AppleKeyStore) | broker-only | IOConnectCallMethod **0x100108c98** (UC opened @0x100108c18/0x100108c5c), **0x1001896a0** | accessory transport/hid services are the classic uid501-reachable accessory surface; forwards into keystore UC. Phase-2 dataflow trace needed. | **HIGH** |
| 4 | **powerexperienced** /usr/libexec/powerexperienced | com.apple.powerexperienced.powermodes / .resourceusage / .powertargetcontroller* (NO gate imports) | **AppleCLPC** (kext); also AppleSMC | broker-only (AppleCLPC not uid501-openable) | IOConnectCallStructMethod sel=2 **0x100010434**, **0x100010c14**, **0x100010c58**; IOConnectCallScalarMethod **0x100010e1c**, **0x100010e78** | multiple ungated power-mode XPC services; struct-input sel-2 forwarding into AppleCLPC. | MED |
| 5 | **online-auth-agent** /usr/libexec/online-auth-agent | com.apple.online-auth-agent.xpc (NO gate imports) | **AppleMobileFileIntegrity** + **IOAESAccelerator** | broker-only | IOConnectCallMethod **0x100003608**; IOConnectCallStructMethod sel=1 **0x10000f56c** | AMFI UC "user client call failed" logging confirms live AMFI brokering; AESAccelerator UC also opened. | MED |
| 6 | **liquiddetectiond** /System/Library/CoreServices/liquiddetectiond.app/liquiddetectiond | com.apple.ldcm.ldcm-server (NO gate imports) | **IOPortFeatureLDCM** (IOPort family) | broker-only (niche HW UC) | IOConnectCallMethod/Scalar/Struct present | ungated ldcm-server → liquid-detection port UC; niche but unaudited. | MED-LOW |
| 7 | **watchdogd** /usr/libexec/watchdogd | com.apple.watchdogd.optin.registration / com.apple.unblock (NO gate imports) | **IOWatchdog** (IODeviceTree:/arm-io/wdt) | broker-only | IOConnectCallScalarMethod (kIOWatchdogDaemon* incl. **TestSocWatchdog=panic**), IOConnectCallStructMethod | scalar-only test methods incl. deliberate SoC-watchdog panic → **kernel DoS** tier, not mem-corruption. Low corruption EV. | LOW-MED (DoS) |

Secondary / lower-EV ungated brokers (noted, not ranked-top):
- thermald → AGPM/AppleSMC/IONVMeBlockStorageDevice mostly via IORegistryEntrySetCFProperty (not raw UC method); scalar/struct. mach com.apple.thermald.
- systemstats → IOAccelerator stats reads (scalar, read-only), AppleSMC/battery. mach com.apple.systemstats.analysis. Read-only stats = low EV.
- IOMFB_bics_daemon → AppleNVMeEAN / IOMobileFramebuffer, mach ...migration. Niche.
- mobile_obliterator → AppleSEPManager/IOMedia, mach com.apple.mobile.obliteration — destructive, almost certainly hard-gated; scalar.
- BlueTool → AppleConvergedIPCInterface/AppleOLYHAL/AppleBluetoothModule, mach com.apple.BlueTool. Likely internal tool; BT HW.
- logd_helper → IOP coproc connect (IOPropertyMatch), mach com.apple.logd_helper.
- AppleCredentialManagerDaemon → AppleCredentialManager UC, but NO MachServices in plist (dynamic registration; reachability unclear).

Gated brokers worth a later look IF their gate is weak: diskarbitrationd (AppleAPFS via
diskarb), storagekitd (AppleAPFS, com.apple.storagekitd), diskimagesiod (mount broker),
powerd (powerdxpc → power UC). All import sandbox_check/SecTask so deprioritized.

## Top-3 flagged for follow-on kernel external-method audit (like IOTimeSync)
1. **AppleMobileFileIntegrity UC** via MobileStorageMounter (sel 2 struct broker) — AND via
   online-auth-agent. AMFI UC is broker-only; two independent root brokers forward into it.
   Audit AMFI externalMethod sel 2 (+ neighbors) for struct-input OOB/type-confusion.
2. **AppleKeyStore UC** via inboxupdaterd (sels 0xf,0x10,0x12–0x15,0x17,0x56) AND accessoryd.
   Broadest brokered selector surface; audit those keystore selectors' struct-input handling.
3. **AppleCLPC UC** via powerexperienced — never uid501-openable, ungated power XPC broker.

## Caveats (no overclaim — phase 1 = reachability only)
- Gate heuristic = binary-import absence; an NSXPC listener could still set a code-signing
  requirement not visible as an import. Confirm each accept path in phase 2.
- Site-level IOConnectCall presence is proven; FULL XPC-handler→IOConnectCall-arg dataflow
  is traced only shallowly (strongest for MobileStorageMounter sel 2). Confirm per-method.
- broker-only = these UC classes require entitlement/root to open directly (so excluded from
  the uid501-direct sweep); direct-open non-reachability to be re-confirmed in phase 2.
- watchdogd path is DoS-tier (scalar panic test), not a memory-corruption flag.
