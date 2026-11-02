# Apple Security Research Rules

## Rule zero: verify both sides

For every memory sink, enumerate every operand feeding the index, length,
offset, or pointer and identify the exact instruction bounding each operand.
An existing bounds check is not proof of safety. Check for sibling operands,
global-versus-record bounds, missing sibling checks, subtraction underflow,
width/sign changes, and omitted contributors to aggregate capacity.

## Physical-host hard lock

The physical Mac is for read-only static analysis by default. Do not run any
PoC, fuzzer, replay, stress loop, IOKit trigger, DTrace action, debugger action,
kernel-extension load, boot-argument change, panic test, reboot, or other live
kernel exercise on the host without the user's literal `go` for that specific
run.

Before requesting `go`, state all of the following:

1. Exact command and binary.
2. Exact target, explicitly named as the physical host.
3. Expected result and runtime.
4. Panic, reboot, data-loss, battery, and unattended-login risk.
5. Stop condition and recovery plan.

Approval for a VM never authorizes a host fallback. If SSH or VM identity
verification fails, stop. Never execute the command locally as a fallback.

Before every dynamic VM trigger, verify in the same remote command session:

1. SSH alias or IP.
2. `hostname`.
3. `sw_vers -buildVersion`.
4. `id -u`.
5. Virtualization identity from `system_profiler` or I/O Registry.

The trigger may run only when all values match the intended VM. All unattended
host-side dynamic research is prohibited.

## Coordination

Use timestamped files in `/Users/dawgyg/codex_claude_notes` for durable Claude
and Codex handoffs. Keep `note_from_codex.md` as a pointer to the latest note
and touch `/Users/dawgyg/codex_replied` after a substantive handoff.
