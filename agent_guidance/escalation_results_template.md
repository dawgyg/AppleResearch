# ESCALATION SWEEP — REPORT FORMAT TEMPLATE

## Format for Each Report (Agent + Manual)

```
### [REPORT_ID] — [SHORT_TITLE]
**Status:** [Reproduced|Reviewing|In progress]

#### PRIMITIVE (Required)
- **Instruction:** [address + opcode, e.g. "0xbd1404: str x11,[out,x14,lsl#3]"]
- **What attacker controls:** [exact description of address/value control]
- **Verification:** [how verified in 26A5425a — disassembly cite or LC_UUID match]

#### BOUNDED OR FULL-POINTER
- **Analysis:** [decision logic]
- **Conclusion:** BOUNDED (base+index) OR FULL-POINTER
- **Why:** [structural reason — if bounded, it's DEAD for ASB]

#### STILL PRESENT?
- **LC_UUID check:** [old vs current UUID, or byte-identical window proof]
- **Conclusion:** YES (unfixed) OR NO (fixed)

#### ESCALATABLE?
- **Answer:** YES / NO / UNKNOWN
- **Reasoning:** [1-2 sentences]
- **Confidence:** HIGH / MEDIUM / LOW

#### WHAT WOULD PROVE IT?
- **If YES:** [minimal experiment to confirm FAR==ASB]
- **If NO:** [structural barrier to flag-tier]
```

---

## Competing Hypotheses Template (Per Report)

For each report, agents should consider:
1. **Hypothesis A:** "Bounded index — attacker controls the offset but not the base"
   - **Evidence for:** instruction shows base+index pattern
   - **Evidence against:** [what would disprove this]
   - **Verdict:** [accept/reject + why]

2. **Hypothesis B:** "Full pointer — attacker supplies the target address"
   - **Evidence for:** pointer dereferenced directly from attacker data
   - **Evidence against:** [constraints that limit pointer range]
   - **Verdict:** [accept/reject + why]

3. **Hypothesis C:** "Already fixed — instruction is different in 26A5425a"
   - **Evidence for:** binary comparison shows changed mnemonic/operands
   - **Evidence against:** LC_UUID identical proves no kext update
   - **Verdict:** [accept/reject + why]

---

## Coverage Attestation

For any grep/scan used:
- **Scope:** [what files searched]
- **Count:** [X of Y functions/kexts examined]
- **Coverage:**  XX% of binary
- **Sampling:** [random sample for QA if <100%]

---

## Summary Shortlist (After All Reports)

### Tier-1: Already Confirmed Flags (Filed)
_(List each already-filed flag here so new escalation candidates aren't duplicated against them.)_

### Tier-2: Flag Escalation Candidates (Top 3-5)
Rank by: (1) Confidence, (2) Cheapest experiment, (3) Distinctness from filed

### Tier-3: Declined (Structural Barriers)
Why each is BOUNDED / already-fixed / userland / read-only
