Execute the OKR loop for AgentWall v1.0 release autonomously.

Read docs/V1_RELEASE_OKR.md for the full OKR list. Execute each STEP in order (STEP 1 → STEP 2 → STEP 3 → STEP 4). Do NOT stop until all STEPs are complete.

## Core Principle

**Solve the real problem.** Never suppress, hide, or relabel findings to pass metrics. If a finding is a false positive, genuinely fix the detection logic so it doesn't fire. If the FP can't be fixed statically, mark the KR as blocked with an honest explanation. The user values correct methodology over passing numbers.

## The Loop (for each KR)

```
1. PLAN
   - Read the KR description from V1_RELEASE_OKR.md
   - Read the relevant source files
   - Use superpowers:writing-plans to write a spec and plan
   - Auto-confirm the plan (no human approval needed)
   - Save plan to docs/superpowers/plans/

2. EXECUTE
   - Note current HEAD as checkpoint
   - Use superpowers:subagent-driven-development to implement
   - All subagents MUST use model: opus (Claude Opus 4.6 only)
   - TDD: tests first, then code
   - Run: python3 -m pytest tests/ -q --tb=line
   - Run: ruff check src/ tests/ --quiet
   - If tests fail → fix and retry

3. MEASURE
   - Run benchmark scan on 15+ cached projects in /tmp/agentwall-bench3k/
   - Compare old JSON results in /tmp/agentwall-results3k/ vs new scan
   - For FP-related KRs: check if the specific FP rate improved
   - For framework KRs: check if detection/finding count improved
   - Print: "BEFORE: X | AFTER: Y | Delta: Z"
   - Review the code to verify it solves the real problem, not gaming metrics

4. DECIDE
   - If GENUINELY BETTER (real problem solved, not relabeled):
     → git add + git commit + git push
     → Update docs/V1_RELEASE_OKR.md:
       - Mark KR as done with actual measured result
       - Update the "Current" column with post-fix metrics
       - Add a brief note on what was done and the evidence
     → Move to next KR
   - If WORSE, NO CHANGE, or GAMING:
     → git checkout -- . (revert)
     → Analyze root cause
     → Try different approach (max 3 attempts)
     → If blocked after 3 attempts: mark as blocked in OKR with reason, move on

5. CHECK STEP
   - After all KRs in a STEP: print "STEP N: X/Y KRs done"
   - Update docs/V1_RELEASE_OKR.md with STEP completion summary
   - If all required KRs done → next STEP
   - If blocked → report and continue to next STEP
```

## Permissions

All permissions granted. No human approval needed for:
- Planning, spec writing, plan review
- Code implementation via subagents
- Git commit and push
- Benchmark execution
- Moving between KRs and STEPs

## Anti-Gaming Rules

- Downgrading severity without reducing findings = gaming. Don't do it.
- Changing test assertions to match wrong output = gaming. Don't do it.
- Suppressing findings without proving they're safe = gaming. Don't do it.
- Every change must make the user's experience genuinely better.

## Start

Check docs/V1_RELEASE_OKR.md for current progress. Pick up from the first incomplete KR. Do not redo completed work.
