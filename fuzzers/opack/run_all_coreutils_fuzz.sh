#!/bin/bash
# Master runner for the CoreUtils fuzz harnesses — Claude-written for Codex.
# Builds + runs all 3 sig/tag-verified fuzzers under one-shot Guard Malloc, priority-ordered, capturing crashes.
# Run in a DISPOSABLE VM (userspace fuzz, but crashes generate reports; keep it isolated). NOT while user AFK.
#
#   ./run_all_coreutils_fuzz.sh [seconds_per_fuzzer]   (default 120s each; a crash aborts that fuzzer with a report)
#
# On a crash: the offending input is the last one fed — re-run with a shrinking replay to minimize, then package.
set -u
cd "$(dirname "$0")" || exit 1
DUR="${1:-120}"
CLANG='clang -arch arm64e -O0 -g'
FW='-framework CoreFoundation -F/System/Library/PrivateFrameworks -framework CoreUtils'
GM='MallocGuardEdges=1 MallocScribble=1 DYLD_INSERT_LIBRARIES=/usr/lib/libgmalloc.dylib'
LOG=fuzz_run_$$.log; : > "$LOG"

# priority order: http_parse (less-audited, AirPlay RTP-Info) > opack (heavily-audited, obvious-bounded) > tlv8.
for tgt in http_parse_fuzz opack_fuzz tlv8_fuzz; do
  echo "==== $tgt ====" | tee -a "$LOG"
  if ! $CLANG "$tgt.c" -o "$tgt" $FW 2>>"$LOG"; then echo "  BUILD FAILED (fix signatures in $tgt.c)" | tee -a "$LOG"; continue; fi
  # seeds-only first (fast crash on the structural cases), then the timed mutation loop.
  echo "  [seeds]" | tee -a "$LOG"
  env $GM ./"$tgt" seeds >>"$LOG" 2>&1; rc=$?
  if [ $rc -ne 0 ]; then echo "  ★ SEEDS CRASH rc=$rc in $tgt — a structural input found the bug. Check the .crash/.ips + minimize." | tee -a "$LOG"; continue; fi
  echo "  [mutation loop, ${DUR}s]" | tee -a "$LOG"
  # run the 2M loop bounded by DUR (kill after timeout; no /usr/bin/timeout on macOS -> background+sleep+kill)
  env $GM ./"$tgt" >>"$LOG" 2>&1 & pid=$!
  ( sleep "$DUR"; kill -9 $pid 2>/dev/null ) & watch=$!
  wait $pid 2>/dev/null; rc=$?
  kill -9 $watch 2>/dev/null
  if [ $rc -eq 137 ] || [ $rc -eq 0 ]; then echo "  no crash in ${DUR}s (rc=$rc)" | tee -a "$LOG";
  else echo "  ★ MUTATION CRASH rc=$rc in $tgt — capture the crashing input + .ips, minimize, package." | tee -a "$LOG"; fi
done
echo "==== done. crashes marked with ★ above. log: $LOG ====" | tee -a "$LOG"
echo "NOTE mmaintenanced privesc PoC is separate (VM host-fire): ~/codex_scratch/mmaintenanced_symlink/mmaint_symlink_poc.sh"
