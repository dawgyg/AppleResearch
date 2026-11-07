# Apple report status log

Disclosure status of my Apple Security Research reports. **Only reports in a terminal state are listed** — reports that are still open / in progress / under review are intentionally omitted, as are Apple case (OE) IDs and bounty figures.

Derived from the Apple Security Research portal (snapshot 2026-11-07).


## Fixed by Apple (Resolved) — 9

| Reported | Title | CVE | Fixed in |
|---|---|---|---|
| 4/24/26, 11:35 PM | Webkit: Container Overflow read via iterator invalidation | webkit-317231 | — |
| 5/21/26, 12:35 AM | WebKit XHTML custom-element reparent heap-use-after-free in Style::TreeResolver | — | tvOS 26.6 public beta (23L5729e), visionOS 26.6 (23O780), watchOS 26.6 public beta (23U5025e) |
| 5/21/26, 12:47 AM | WebKit async Clipboard ClipboardItemBindingsDataSource re-entrant loader clear heap-use-after-free | — | tvOS 26.6 public beta (23L5729e), visionOS 26.6 (23O780), watchOS 26.6 public beta (23U5025e) |
| 5/22/26, 12:24 PM | CacheStorageConnection cross-thread race causes Safari WebContent double-free on macOS 26.5 | — | iOS 26.6.1 and iPadOS 26.6.1 public beta (23G6082), tvOS 27 public beta (24J360), visionOS 27 (24M6372), watchOS 27 (24R6365) |
| 5/22/26, 12:38 PM | WebKit Clipboard write() use-after-free in ClipboardItemBindingsDataSource (26.5) | — | tvOS 26.6 public beta (23L5729e), visionOS 26.6 (23O780), watchOS 26.6 public beta (23U5025e) |
| 6/11/26, 11:39 PM | OOB write in root opendirectoryd parsing AuthenticationAuthority DisabledTags from a sandbox | CVE-2026-84505 | macOS Golden Gate 27 public beta (26A428) |
| 6/12/26, 9:17 PM | Unauthenticated local disclosure and control of device identity in root daemon remoted | — | macOS Tahoe 26.6 public beta (25G5028f) |
| 6/13/26, 4:18 PM | Sandboxed app escalates to root via DesktopServicesHelper RepairPermissionsForCloudItems chown | — | macOS Tahoe 26.6 public beta (25G5028f) |
| 7/21/26, 12:02 AM | Unprivileged AppleVideoToolboxParavirtualization sel-0 IOMemoryMap double-release kernel UAF | CVE-2026-84492 | iOS 27 and iPadOS 27 (24A9446), macOS Golden Gate 27 public beta (26A428), tvOS 27 public beta (24J360), visionOS 27 (24M6372), watchOS 27 (24R6365) |

## Closed by Apple as “unable to identify a security issue” (declined) — 10

These were reported and reviewed; Apple determined they did not meet their security-issue bar and closed them. Listed here for research transparency.

| Reported | Title |
|---|---|
| 5/31/26, 10:35 PM | WebGPU copyExternalImageToTexture OOB read: origin validated vs rendered not intrinsic image size |
| 5/31/26, 11:00 AM | WebKit: malformed OKP PKCS8 key import crashes WebContent in CryptoKeyOKP::importPkcs8 |
| 5/31/26, 11:03 AM | WebKit: null IPC identifier crashes NetworkProcess in performSynchronousLoad and loadPing |
| 5/31/26, 11:55 AM | WebKit: malformed OKP SPKI key import crashes WebContent in CryptoKeyOKP::importSpki |
| 5/31/26, 11:57 AM | WebKit: FileSystem IPC handle id lacks owner check → cross-origin OPFS read/modify/delete |
| 6/1/26, 9:37 PM | Font.mdimporter: FOND StyleTable 1-byte OOB read in SPFontImport_Suitcase (zero-click .dfont) |
| 6/12/26, 9:20 PM | Unprivileged persistent state injection and resource exhaustion in root daemon fskitd |
| 6/8/26, 5:00 PM | WebKit: MIMESniffer hasSignatureForWebM OOB read (sequence[iter+1]) - stock 26.5, web-reachable |
| 6/9/26, 12:28 AM | WebKit 1-byte out-of-bounds read in KanjiCode::judge (TextResourceDecoder), stock Safari 26.5 |
| 8/20/26, 11:32 PM | corestoragehelperd SynchronizeUsers: no auth + symlink race lets uid501 write root FDE metadata |
