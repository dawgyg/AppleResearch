# Gemini Onboarding — Apple Security Bounty Hunt (macOS 26.5.1) (Note during upload: this is several months old, so the information in here about vulnerabilities is likely no longer valid)

Welcome aboard. You're joining a two-agent team (Claude + Codex) hunting vulnerabilities for the **Apple Security Bounty**. This doc covers who's who, how we communicate, the infrastructure, and what we're working on right now.

---

## 1. Who the user is
- **dawgyg** (dawgyg@gmail.com) — **Head of AppSec at Braze**, professional bug-bounty hunter on the side.
- **HARD RULE: never test, probe, or touch Braze anything.** This work is exclusively Apple Security Bounty.
- He runs the show, makes the calls on what to file, and wants relentless grinding — no premature "let's stop here," no menus of options. When something's dead, move to the next target. Report findings as they land; don't narrate or pad.

## 2. The goal
Find real, reportable vulnerabilities in **Apple-owned code on macOS 26.5.1 (build 25F80), Apple Silicon (arm64e)**. In scope = anything Apple-owned: local file parsers, daemons (LPE), sandbox escapes, kernel, WebKit. Highest value: **LPE (unpriv→root), sandbox escape ($300K target flag), kernel ($1M)**. Memory corruption with a real exploit path beats DoS; DoS/OOB-read are low-tier unless they show real impact (crash w/ control, data disclosure, or protection bypass).

## 3. The team & roles
- **Claude** (me) — coordination + **dynamic validation & fuzzing**. I build PoC clients, run fuzzers in the VM, triage crashes, capture protocols dynamically (lldb), and verify reachability. I keep the memory/notes.
- **Codex** — **static RE engineer**. Deep disassembly, root-causing crashes, mapping jump tables / validation logic, finding the precise faulting instruction and the exploitability ceiling. Excellent at "is this gated, and where."
- **Gemini** (you) — extra hunting capacity. Best initial fit: parallel static/dynamic analysis on a *distinct* target so we don't dupe. Coordinate before diving so we split cleanly.

Division principle: **one agent per target lane.** Claude+Codex currently split cvmsServ (Claude) and syspolicyd/fskitd (Codex). Pick a lane that's not actively owned, or ask.

## 4. How to communicate

We use plain files in the home dir (`/Users/dawgyg/` = `~`). Polling/monitoring picks them up.

**Existing Claude↔Codex channel (for reference):**
- `~/note_to_codex.md` — Claude writes → Codex reads.
- `~/note_from_codex.md` — Codex writes → Claude reads.
- `~/codex_replied` — Codex `touch`es this after replying (signals Claude).
- `~/codex_claude_notes/` — timestamped archive notes (`codex_to_claude_YYYYMMDDTHHMMZ_topic.md`). Both monitor this dir.

**Your channels (Gemini):**
- **To send a message:** append/write to `~/note_to_claude.md` (for Claude) and/or `~/note_to_codex.md` (for Codex). For durable/threaded notes, drop a timestamped file in `~/codex_claude_notes/` named `gemini_to_<who>_<UTCstamp>_<topic>.md` — both of us monitor that folder.
- **To receive:** check `~/note_to_gemini.md` (we'll write there for you) and scan `~/codex_claude_notes/` for new files.
- After you reply, `touch ~/gemini_replied` so we get the signal.
- Keep notes concrete: exact addresses, message schemas, register values, file paths, repro commands. We pass real artifacts, not prose.

**Note:** timestamps — the runtime may not give you a live clock; use a stamp the user provides or a monotonic counter, and say "approx."

## 5. Infrastructure (the test environment)
- **VM:** a tart-managed macOS 26.5.1 VM named **`lpe-vm`** (Apple Virtualization.framework). SIP **disabled**, developerMode on — it's our disposable LPE lab.
  - Host controls: `tart list`, `tart stop lpe-vm`, `tart run --vnc-experimental lpe-vm` (PATH may need `/opt/homebrew/bin`). If it freezes, hard-stop + re-run.
  - SSH in: `sshpass -p test ssh -F /Users/dawgyg/vm_lpe/ssh_config lpevm` (user `test`, **passwordless sudo**). Use `-o ControlMaster=no -o ConnectTimeout=…` and host-side watchdogs — the VM's disk subsystem can wedge under heavy fuzzing; SSH then hangs.
  - VM is the ONLY place to run PoCs/fuzzers. Don't run attack code on the host.
- **Tools live in** `/Users/dawgyg/vm_lpe/` (host) and `/tmp/` (VM). Disassembly via `otool -tV -arch arm64e`; crash reports in `/Library/Logs/DiagnosticReports/*.ips` (sudo to read).
- **Fuzzing gotchas we've learned:** macOS has no `/usr/bin/timeout`; `libgmalloc` trips a 15MB EXC_RESOURCE watermark on some daemons (false crashes) — fuzz native, rely on SIGSEGV; sync-XPC fuzzing hangs on a hung server (use async `xpc_connection_send_message` fire-hose); always reproduce on a production build before claiming.

## 6. What we're working on RIGHT NOW (state as of this writing)

**ACTIVE — cvmsServ (Claude's lane, you can help):**
- `com.apple.cvmsServ` = the OpenGL shader-compiler **broker**, runs as **root**, **reachable from unprivileged + sandboxed processes** (system.sb mach-lookup; GPUProcess/apps/QuickLook; WebProcess denies). An unprivileged OpenGL shader compile spawns it as root.
- Working raw-libxpc client built (`/tmp/cvms_client.c`, fuzzers `/tmp/cvms_fuzz3.c`, `/tmp/cvms_esc2.c`).
- Protocol: `{message:int64, framework_name, plugin_name(path), bitcode_name, args:data, control, value}`. Handlers: msg1=ConnectionCreate, msg4=ServiceAttach, msg6=ServiceControl, + ElementBuild (the LLVM compile), ServiceGetMemory (shmem channel), ElementWriteContentToFile, etc.
- **CONFIRMED bugs (sandbox→root, both DoS-tier so far):** (1) `cvmsServerServiceControl` NULL-deref (msg1 then msg6 skips the attach-flag `[+0x218]` check → deref `[NULL+0x28]`, SIGSEGV in root). (2) `_xpc_api_misuse` SIGTRAP in reply construction.
- **Current hunt:** upgrade to *controllable* corruption — (a) Codex enumerating which msg IDs use the service object without the attach-check AND write attacker data; (b) Claude reaching `cvmsServerElementBuild` to **fuzz malformed bitcode into the root cvmsCompAgent LLVM backend** (the real memory-corruption prize — client controls the bitcode via shmem). Full memory write-up: `~/.../memory/vrp_cvmsserv_servicecontrol_dos.md` and `project_ungated_root_daemon_triage.md`.

**Codex's lane:** syspolicyd Gatekeeper path-confusion (simple user-intent + script-eval bypasses came back no-op/advisory), and fskitd EBUSY real-disk proof (bounded).

**Recently filed (don't re-derive):** remoted + fskitd unauth root-daemon method bugs; CVE-2026-43676 (AnchorScrollAdjuster). Several WebKit UAFs in review.

**Recently CLOSED (don't re-spend):** diskimagesiod ASIF root-attach — confused-deputy bridge real but parser bounds-checked across 4 candidates; definitively closed.

## 7. Good first moves for Gemini
1. Confirm you can read/write the note files + reach the VM read-only (don't disrupt running fuzzers — check `pgrep -fl cvms` first).
2. Tell us (via `~/note_to_claude.md` + `~/note_to_codex.md`) which lane you want. Strong un-owned options: the **cvmsCompAgent LLVM bitcode** surface (huge memory-corruption potential, pairs with Claude's cvmsServ work), or a **fresh root daemon** from the ungated-triage shortlist in `project_ungated_root_daemon_triage.md` (coresymbolicationd, taskgated-helper, filecoordinationd, aslmanager...).
3. Coordinate before fuzzing the VM heavily — only one heavy fuzz campaign at a time (the VM wedges).

Welcome — let's land a big one.
