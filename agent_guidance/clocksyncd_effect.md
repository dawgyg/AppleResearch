# clocksyncd effect/tier audit — static RE (macOS 27.0 26A5368g, m1mac, uid501)

Binary: /usr/libexec/clocksyncd (arm64e slice -> /tmp/cs.arm64e). Static RE only; no daemon
connection, no XPC method invoked. All vaddrs are the arm64e in-file vaddrs (base 0x100000000).

## Bottom line

**CAPPED (medium) at the clocksyncd level.** No daemon-side memory corruption, no
file-write/exec confused-deputy, and **no arbitrary-Objective-C-selector call** anywhere. The
whole exported XPC surface is a *thin proxy* that forwards fully client-controlled
clientID/registryEntryID/clientType/selector/scalars/struct to ONE kernel IOKit user client that
root holds open (`IOTimeSyncDaemonService`, IOKit selectors 0/1/5 via `IOConnectCallMethod`).

The only escalation lane is that IOKit passthrough: uid501 unauthenticated -> root daemon ->
kernel `IOTimeSyncDaemonService` user client. That is a **confused-deputy into a kernel attack
surface** *iff* the kernel UC is not directly uid501-openable. The corruption/flag, if any, lives
in the **kext** (`com.apple.iokit.IOTimeSyncFamily` / `IOTimeSyncDaemonService` +
`IOUserClientClass`), NOT in clocksyncd. That kext is a separate target and must be audited
separately (recommended next step). Inside clocksyncd itself there is nothing flag-tier.

## Architecture (confirmed)

- Exported NSXPC delegate class = `TSDDaemonServiceServerExported` (methods @0x100023d1c..).
- Per-connection client identity = `processID` = ivar `[exported+8]` (getter @0x100025014
  `ldr w0,[x0,8]`; setter @0x10002501c `str w2,[x0,8]`).
- **processID is never populated from an authenticated source.** No xref sets it; the string
  `setProcessID:` (@0x10005abcd) exists only as a method name. `nm -arch arm64e` confirms ZERO
  pid/authz imports (no xpc_connection_get_pid/audit_token/geteuid/valueForEntitlement/SecTask/
  SecCode/processIdentifier). => every uid501 client is an unauthenticated, indistinguishable
  clientID (0). No per-client authentication anywhere.
- Accept gate `-[TSDDaemonServiceServer listener:shouldAcceptNewConnection:]` @0x100023064:
  returns `w21 = (arg2_listener == [self+0x10])` — a listener-IDENTITY discriminator
  (cmp x19,x24 @0x1000230ac / cset @0x1000231c8). No peer/entitlement/pid check. Confirms the
  sweep's "discriminator, not a gate" finding.
- `[TSDDaemonService+8]` = an `IODConnection` (ivar `_iokConnection` IOKConnection at its +8);
  opened at init to kernel service `IOTimeSyncDaemonService` (string @0x10004a275; `IOUserClientClass`
  @0x10004959f; `IOTimeSyncDaemonClientEntryIDMatching` @0x10004a34a). init @0x10001a550 stores the
  connection at `[self+8]`.

## Closure table (client-controlled input -> sink -> bound/gate -> vaddr)

| Exported method | Client input | Sink / effect | Bound / gate | Verdict |
|---|---|---|---|---|
| `callMethodForDaemonClient:clientMethodSelector:scalarInputs:structInput:scalarOutputCount:reply:` @0x100023f64 -> internal `TSDDaemonService callMethodForDaemonClient:...:error:` @0x10001ac48 | clientMethodSelector (int32), scalarInputs[], scalarInputCount, structInput(bytes+len) | builds scalar array `[clientID,clientMethodSelector,userScalars...]`, `memcpy(sp+0x48, scalarInputs, count*8)` @0x10001ace4, then `[[TSDDaemonService+8] callMethodWithSelector:1 scalarInputs:.. structInput:..]` = `IOConnectCallMethod(iokConn, sel=1, ...)` (IODConnection.callMethodWithSelector @0x100002fcc -> IOKConnection) | **count bounded: `cmp w5,0xe; b.hi @0x10001ac80` (<=14).** memcpy dest buffer = 112 bytes (2-scalar header @sp+0x38 + 14 zeroed quads @sp+0x48..0xb8) = exact fit, no OOB. clientMethodSelector is DATA (a scalar), NOT an ObjC selector -> **no arbitrary-call/type-confusion.** structInput passed straight to IOConnectCallMethod with its own length (no daemon buffer). | Daemon-side BOUNDED. Flag potential = kernel UC (separate). IOKit passthrough. |
| `openDaemonClientWithRegistryEntryID:clientType:reply:` @0x100023d20 -> internal `openDaemonClient:withRegistryEntryID:clientType:error:` @0x10001aa38 | registryEntryID (obj/string), clientType (int32); clientID = [exported+8]=processID(unauth,0) | converts registryEntryID -> int64 (@0x10001aae8), builds scalars `[4, clientID, registryEntryID_int, clientType]`, `IOConnectCallMethod(iokConn, sel=0, scalars, count=4)` @0x10001ab2c | fixed 4-scalar stack array, no memcpy, no client-sized buffer. Kernel resolves the registry entry + opens sub-client of clientType. No daemon-side corruption. | Daemon-side BOUNDED. **Confused-deputy candidate**: client names an arbitrary IOKit registry entry + clientType; root forwards it. Impact depends on kernel UC. |
| `closeDaemonClient:reply:` @0x100023e48 -> internal @0x10001abac | daemonClientID (int32) | scalars `[5, clientID, daemonClientID]`, IOConnectCallMethod sel path @0x10001ac04 | fixed 3-scalar array; no buffer. | BOUNDED. tamper/DoS (close another client's kernel handle if IDs guessable, unauthenticated). |
| `addMSGClockRef:reply:` @0x1000249a0 -> `TSDMSGService addMSGClockRef:forProcess:error:` @0x100009c04 | clockRef (NSXPC-decoded obj = dict key); forProcess = [exported+8]=processID | os_unfair_lock [svc+0x28]; dictionary lookup (0x100044ae0) + refcount bookkeeping; error 0x2c2 if dup | Pure NSDictionary/refcount. **No buffer, no array index, no memcpy, no client-sized alloc.** | No corruption. Clock-ref tamper/DoS. |
| `removeMSGClock:reply:` @0x100024a4c -> `removeMSGClock:forProcess:error:` @0x100009dec | clock key; processID | dictionary remove + refcount | same as above | No corruption. Tamper/DoS (unauth remove of a clock another process relies on). |
| `restoreMSGClockSession:nominalSyncDuration:refCnt:reply:` @0x100024af0 -> `restoreMSGClockSession:...:forProcess:error:` @0x100009fc0 (and `addClockSessionRef:refCnt:pid:session:` @0x1000082b4) | refCnt (int), nominalSyncDuration, session key; processID | session dict lookup ([svc+0x20], 0x100042960) then addRef; refCnt stored/added into a ClockSessionRefCounter | **refCnt is NOT used for an alloc/loop/array index** — it is stored/accumulated as an integer (str @0x100008330 path). No unchecked size. | No corruption. Refcount tamper/DoS. |
| `propertyForRegistryEntryID:signpostID:key:reply:` @0x100024144 / `propertiesForRegistryEntryID:...` @0x100024440 | registryEntryID, key | IOKit property read proxy (class `IOKRegistryEntry(daemon_iokit_get_property_proxy)`) | read-only property fetch | Info-read of arbitrary registry entry properties. Low/info tier. |

## Answers to the three tier questions

1. **Confused-deputy (forProcess):** The `forProcess:` value is NOT a per-call client argument
   and NOT the authenticated connection pid — it is `[exported+8] = processID`, which is **never
   set from an authenticated source** (no pid primitives; no setProcessID xref). So the client
   identity the daemon acts under is an unauthenticated constant (0) shared by all clients. This is
   a real *authentication gap* (any uid501 client can manipulate MSG clock/session refcounts and
   close daemon-client handles that are keyed only by this unauthenticated identity => cross-client
   time-sync tamper + DoS). It is NOT a privilege escalation to root code/file — the effect is
   confined to time-sync/clock-session state. The stronger confused-deputy is the IOKit passthrough
   (openDaemonClient/callMethodForDaemonClient), where the client names the kernel registryEntryID/
   clientType/selector and root forwards it (see below).

2. **Memory corruption in the root daemon:** NONE found. The structured `addMSGClockRef:`/session
   arguments are NSXPC-decoded objects used as dictionary keys (type-checked by the NSXPC
   interface), not raw buffers indexed by a client count. The only raw memcpy
   (callMethodForDaemonClient @0x10001ace4) is bounded by `cmp w5,0xe; b.hi @0x10001ac80` into an
   exact-fit 112-byte buffer. `refCnt` (restore/addClockSessionRef) is a stored integer, never an
   alloc/loop size. No fixed-array-indexed-by-client-count, no type-confusion, no client-length
   memcpy in the daemon.

3. **callMethodForDaemonClient (generic dispatch):** NOT an arbitrary-ObjC-selector primitive.
   The msgSend it performs is a FIXED selector (`callMethodWithSelector:...` on the IODConnection).
   `clientMethodSelector` is a 32-bit integer packed into the IOKit scalar-input array (IOKit
   external-method style), i.e. it becomes a *sub-opcode* interpreted by the kernel user client, not
   a Objective-C selector msgSend'd on a root object. So no userland arbitrary-call/type-confusion.
   It IS an unauthenticated IOKit passthrough (uid501 -> root -> `IOConnectCallMethod` on
   `IOTimeSyncDaemonService` sel 1 with client scalars<=14 + client structInput).

## Escalation lane worth a SEPARATE kernel audit (not a clocksyncd flag)

`IOTimeSyncDaemonService` kernel user client (`IOUserClientClass`), driven unauthenticated by
uid501 through this root proxy via `openDaemonClient` (sel 0) then `callMethodForDaemonClient`
(sel 1). Client fully controls: registryEntryID, clientType, sub-selector, up to 14 scalar inputs,
and a struct input of client-chosen size. If that UC is NOT directly `IOServiceOpen`-able by uid501
(likely, since the daemon exists to broker it), clocksyncd is the confused-deputy that hands uid501
a kernel attack surface. Next step: pull the IOTimeSyncFamily kext, check
`newUserClient`/`IOServiceOpen` gating on `IOTimeSyncDaemonService`, and audit sel 0/1/5 external
methods for OOB/type-confusion driven by the forwarded scalars/struct/clientType. That is where a
Target Flag could exist — not in clocksyncd.

## Confirmed vs inference

- CONFIRMED (instruction-level): count bound @0x10001ac80; memcpy @0x10001ace4; exact-fit buffer;
  processID getter/setter offsets; no setProcessID xref; zero pid/authz imports; accept =
  listener-identity compare @0x1000230ac/@0x1000231c8; passthrough to IODConnection ->
  IOConnectCallMethod; kernel service = `IOTimeSyncDaemonService`; MSG methods = dict/refcount only.
- INFERENCE: exact IOKit external-method selector numbering (open=0/call=1/close=5) and the
  kernel-side interpretation of clientMethodSelector/clientType (kernel side not disassembled here);
  whether the kernel UC is uid501-openable (requires the kext).
