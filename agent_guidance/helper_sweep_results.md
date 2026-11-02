# Ungated-root-XPC helper sweep — macOS 27.0 26A5368g (host m1mac)
Date: 2026-07-01. Method: static RE only (r2 + otool). No privileged method invoked, no dynamic connect performed (reachability = static-only). Confirmed template = NSXPC `-listener:shouldAcceptNewConnection:` returning YES with no euid/audit-token/entitlement/AuthorizationRef/code-signing gate.

## Enumeration
- 262 root (or UserName-omitted) LaunchDaemons with a MachServices dict.
- 88 of them are NSXPC listeners (reference `shouldAcceptNewConnection`).
- Heuristic gate-string prune → 44 with no gate string; broadened prune (valueForEntitlement / effectiveUserIdentifier / auditToken) → most gate somewhere. The sweep correctly re-surfaced the already-confirmed avbdeviced, revisiond, automationmode-writer (sanity check that the heuristic finds true positives).
- Verified each surviving candidate by disassembling the accept IMP.

---

## CONFIRMED-UNGATED accept (NEW, not in prior audited set) — no peer gate in accept path

### 1. hdiejectd  — RANK 1 (ungated + a mutating/registry XPC surface)
- Binary: `/System/Library/PrivateFrameworks/DiskImages.framework/Resources/hdiejectd`
- Mach services: `com.apple.system.hdiejectd`, `com.apple.system.hdiejectd.xpc`
- Accept IMP `0x100002eac` (`EjectTracker -listener:shouldAcceptNewConnection:`): loads a fixed NSXPCInterface (DATA_CONST+0xb98) + selector, calls interfaceWithProtocol (fcn.100005840), `setExportedInterface:` (fcn.100005c20), `setExportedObject:` (fcn.100005c40), then `mov w0, 1; retab` @0x100002ef8. NO objc_msgSend of euid/entitlement/audit-token; NO cmp/cbz/tbz on any peer property. Unconditional YES.
- Exported protocol methods (reachable XPC sinks):
  - `receiveEndpoint:uuid:withReply:`
  - `sendEndpointForUUID:withReply:`
- Sink assessment: a UUID-keyed **mach-endpoint registry**. No file-write/exec/chown/path sink. `sendEndpointForUUID:` may return another client's registered endpoint (cross-client endpoint disclosure / hijack of the disk-image eject channel); `receiveEndpoint:uuid:` lets an unprivileged caller register an endpoint under an arbitrary UUID (spoof/DoS of eject tracking). Tier = confused-deputy / DoS, NOT a clean LPE. Honest label: **ungated accept confirmed; no privileged write/exec sink reached.**

### 2. systemstats — RANK 2 (ungated + cross-process info-disclosure)
- Binary: `/usr/sbin/systemstats`
- Mach service: `com.apple.systemstats.analysis` (plist also declares daemon/notification variants)
- Accept IMP `0x10001498c`: calls fcn.1000d31c0 (result NOT branched on), sets exported interface/object (fcn.1000d6680/1000d66a0/1000d5660), `mov w0, 1` @0x100014a18; NO cmp/cbz/tbz/entitlement/euid. Unconditional YES.
- Exported methods: `coalitionCount:withReply:`, `doXPCBattery:withReply:`, `doXPCBatteryWithReply:`, `energyImpactGreaterThan:withReply:`, `endTime:withReply:`, `logCoreDuetRequest:withReply:`.
- Sink assessment: read-only queries returning root-collected **system-wide** power / per-process energy-impact / coalition statistics. No write/exec. Tier = cross-process activity **info-disclosure / side-channel** (unprivileged process learns other users'/processes' energy+coalition behavior). Honest label: **ungated accept confirmed; sink = statistics disclosure, not LPE.**

### 3. CrashReporterSupportHelper — ungated, fixed-path sink only
- Binary: `/System/Library/CoreServices/CrashReporterSupportHelper`
- Mach service: `com.apple.CrashReporterSupportHelper`
- Accept IMP `0x100000ef0`: sets exported interface/object, `mov w0, 1` @0x100000f8c. No gate.
- Exported methods: `setupSystemDiagnosticReportsDirectoryWithReply:`, `createAppleInternalNetworkCacheIfRequired`, `isAppleInternalWithReply:`.
- `setupSystemDiagnosticReportsDirectoryWithReply:` (0x100000ff8): calls fcn.100002040 on a fixed singleton, then reply(YES). Operates on the FIXED path `/Library/Logs/DiagnosticReports` with no attacker path/content input. Tier = confused-deputy on a fixed-path/dir op. Honest label: **ungated accept; no attacker-controlled sink.**

### 4. MobileGestaltHelper — ungated, cache-management fixed-path sink only
- Binary: `/usr/libexec/MobileGestaltHelper`
- Mach service: `com.apple.mobilegestalt.xpc`
- Accept IMP `0x100000c98`: objc_retain(peer) → setExportedInterface/Object → `mov w0, 1` @0x100000d10. No gate. (Note: `audit_token` appears elsewhere in the binary only in `processNameForConnection:` for logging, not in accept.)
- Exported methods: `getServerAnswerForQuestion:reply:`, `getSpringboardRegionOverride:reply:`, `getAppleTVMode:`, `rebuildCache:`, `setCacheSentinel:`, `queryBootUUID`, `needsNewCachePostBoot`.
- Sinks: `getServerAnswerForQuestion:` = read; `rebuildCache:`/`setCacheSentinel:` write the MobileGestalt cache/sentinel at FIXED paths with internally-derived (non-attacker) content. Tier = MG cache DoS/poison at most. Honest label: **ungated accept; sinks are fixed-path cache management.**

---

## NEEDS-FOLLOWUP (accept possibly ungated; per-method gate unverified)

### clocksyncd — accept ambiguous, MUTATING time-sync sinks
- Binary: `/usr/libexec/clocksyncd`; services `com.apple.timesync.manager`, `com.apple.timesync.ptp.manager`, `com.apple.timesync.expositor`.
- Accept IMP `0x100023064` has `cmp x19,x24; b.ne` — appears to be a **listener-identity** discriminator (3 mach services on one delegate), NOT a peer-credential gate; no euid/entitlement/audit-token call in the accept body. Binary declares `com.apple.private.timesync.*` entitlement strings, suggesting per-method gating may exist.
- Mutating exported methods worth a per-method gate check: `addMSGClockRef:reply:`, `removeMSGClock:reply:`, `registerClient:withReply:`, `removeMockSSAMEntityWithUUID:reply:`, `removeAllMockSSAMEntriesWithReply:`.
- If those methods are not entitlement-gated internally → unprivileged manipulation of system gPTP/time-sync clock state (time-manipulation / DoS). Recommend: disassemble each mutating IMP for a `valueForEntitlement:`/audit-token check before declaring a finding.

---

## GATED (closed — do NOT re-audit; gate instruction cited)
- StorageDEHelper (`com.apple.storagede.helper`): accept `0x100000db0` calls `DEUtilsValidateConnection(peer)` @0x100000e38, `cbz w0 -> reject 0x100000ea8`.
- userfs_helper (`com.apple.filesystems.userfs_helper`): handler `sym.func.100000884` requires entitlement `com.apple.private.allow-external-storage` via `xpc_connection_copy_entitlement_value` + bool check @0x1000008c8-0x1000008f4; else reject.
- misagent (`com.apple.misagent`): per-op gate `sym.func.10000a9f4` (`xpc_connection_copy_entitlement_value` compared to expected singleton @0x10000aa40) called from install `0x100008474` and remove/query `0x10000953c`.
- mbusertrampoline (Setup Assistant): accept `0x100003640` calls validator `sym.func.10000386c`, `tbz w0,0 -> reject 0x1000037c0`.
- diskimagespawner: accept `0x100000d78` validates peer (isKindOfClass + validators fcn.10000f7f8/f784 with reject paths); imports effectiveUserIdentifier/valueForEntitlement.
- bootinstalld: accept `0x100004ec4` calls validator `fcn.100005f40` (w23), `tbz w23,0 -> reject`; imports effectiveUserIdentifier.
- Entitlement/audit-token gated (valueForEntitlement / effectiveUserIdentifier / auditToken present in binary; standard per-connection gate): accessoryd, airportd, aned, AppSSODaemon, AssetCacheManagerService, AssetCacheTetheratorService, backgroundtaskmanagementd, centaurid, coreduetd, corerepaird, countryd, devicerecoveryd, efilogin-helper, userfsd, fskit_helper, gamepolicyd, griddatad, iconservicesagent, inboxupdaterd, keybagd, mbsystemadministration, mobile_obliterator, usermanagerd, amfid, ospredictiond, powerexperienced, startupdiskhelper, tzd, teslad, wifianalyticsd, wifivelocityd, audioanalyticsd (biome.writer per-method).

## Bottom line
No NEW confirmed unprivileged->root LPE (no ungated helper reached an attacker-controlled file-write/exec/chown/trust sink). Best NEW ungated-accept surfaces: **hdiejectd** (endpoint registry, confused-deputy/DoS) and **systemstats** (cross-process stats info-disclosure). One follow-up worth a per-method gate check: **clocksyncd** mutating time-sync methods. The vast majority of root NSXPC daemons on 26A5368g gate correctly via entitlement/audit-token, unlike the kernelmanager_helper/revisiond/avbdeviced cluster.
