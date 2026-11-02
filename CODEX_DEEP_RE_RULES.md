cat CODEX_DEEP_RE_RULES.md
# CODEX DEEP-RE RULES (prepended to every lane task — obey strictly)

You are doing DEEP reverse-engineering to find NOVEL memory-corruption bugs (UAF/OOB/type-confusion/race) in macOS 27. Shallow passes find nothing. Hardened-looking code is where the bugs hide. Follow this or the result is rejected.

## RULE ZERO — "bounds != ok, verify BOTH sides" (the whole vein; obey before anything else)
**a bounds check existing does NOT mean the value is safe.** The bug lives in the GAP between what was validated and what
actually indexes/copies/frees memory. For EVERY sink (`arr[i]=`, `memcpy(d,s,len)`, `A-B`, `free(p)`,
`blraa`), you must:
1. Enumerate EVERY operand feeding the index/length/offset/pointer (A, B, index, count, stride, pad, tag).
2. For EACH operand, name the EXACT instruction (`cmp … ; b.hs/b.hi @vaddr`) that bounds it — on BOTH sides
   of the operation. A check on operand A does NOT bound operand B that feeds the same sink.
3. The bug is any of: (a) one operand checked, a sibling operand feeding the same sink unchecked;
   (b) the check uses a GLOBAL/max limit while the sink uses a PER-record/per-buffer span (two different
   bounds → the gap between them is the bug); (c) a check present on N call-sites/selectors but MISSING on a
   sibling; (d) `A - B` underflow where B can exceed A (as exploitable as overflow); (e) width/sign change
   (u64→u32 trunc, sxtw vs uxtw) between the check and the use; (f) an aggregate guard sums N-1 of N
   contributors that share one fixed-capacity buffer, while the omitted contributor has only an independent
   per-contributor check and there is no joint `sum(all contributors) <= capacity` check.
Concrete example just proven: HFS+ `hfs_swap_BTNode` checks keyLength ≤ 516 (global max) AND
keyLength+6 ≤ record-span — BOTH sides, so it's DEFENDED. If it had checked only the global max, a
keyLength that fits the global max but exceeds its record's span would underflow `recordLen` in
`GetRecordByIndex` = a live OOB. That second check is exactly what you hunt for the ABSENCE of.
Never write "bounded/hardened" for a sink until you have named the instruction bounding EVERY one of its
operands. Most of our false "defended" verdicts came from seeing ONE check and stopping.

## You may NOT answer "hardened / defended / bounded / no bug" unless you provide the CLOSURE TABLE
For EVERY attacker-reachable path, a row:
  path/window | attacker value | sink (copy/store/index/free/call) | the EXACT serializer or bound (instruction + vaddr) |
- OOB: name the `cmp/b.hs`/`b.hi` and the limit, at a vaddr. Not "the wrapper checks it."
- UAF/race: name the lock (acquire+release vaddrs) or refcount (inc+dec vaddrs) or ordering serializing the free vs EACH concurrent use. One unproven window => report it OPEN.
- type-confusion: name the type/tag/OSDynamicCast/DTYPE check and that it runs on ALL paths.
These are NOT acceptable as a closed verdict: "no candidate found", "looks bounded", "probably intentional", a pass that stopped at the entry guard.

## Depth required
1. Trace the FULL call tree to the LEAVES — every callee, the error paths, the cleanup paths. The bug is in the 2nd/3rd-level helper, not the front guard.
2. Map the object lifecycle: every alloc (zone/size), every free (+lock+state), every refcount inc/dec, every cross-thread/cached pointer.
3. Trace every attacker dword through EVERY branch: integer width/sign/trunc, off-by-one (<= vs <, 0x80 vs 0x81), sum-overflow, count*size.
4. Check CONTEXT assumptions: does it assume current_proc()/cred/task/map == caller while running in a worker/async/other context?
5. Prioritize NEW-in-27 code (diff vs kc651) but still apply the full protocol.

## Deliverable (always)
Either: a concrete BUG with function vaddr + the exact unchecked instruction/free-vs-use window + a precise userspace trigger recipe (syscall/IOConnect args, fd types, interleaving, iovcnt, heap setup).
Or: the COMPLETE closure table proving each window shut, AND the single most-promising remaining un-audited path to go deeper on next.
"I looked and didn't find one" without the table = incomplete; keep digging or hand back the open window.

## Mechanics
- Write findings to the lane's output file and touch its done-flag.
- Disasm facts only; cite vaddrs. No speculation as fact.
- This is ONE deep target. Go all the way down.
