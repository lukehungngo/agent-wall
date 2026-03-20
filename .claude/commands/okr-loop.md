Execute the OKR loop for AgentWall v1.0 release.

Read docs/V1_RELEASE_OKR.md for the full OKR list. Execute each STEP in order (STEP 1 → STEP 2 → STEP 3 → STEP 4).

For each KR within a STEP, follow this loop:

## The Loop

```
1. PLAN
   - Read the KR description from V1_RELEASE_OKR.md
   - Read the relevant source files
   - Write a plan (what files to change, what tests to add)
   - Save plan to docs/superpowers/plans/

2. REVIEW PLAN
   - Dispatch a reviewer subagent to check the plan
   - Fix issues if found

3. EXECUTE
   - Create a git checkpoint: git stash or note current HEAD
   - Implement the changes (TDD: tests first, then code)
   - Run: python3 -m pytest tests/ -q --tb=line
   - Run: ruff check src/ tests/ --quiet
   - If tests fail → fix and retry

4. MEASURE
   - Run benchmark on 10-20 cached projects in /tmp/agentwall-bench3k/
   - Compare old JSON results in /tmp/agentwall-results3k/ vs new scan
   - For FP-related KRs: check if the specific FP rate improved
   - For framework KRs: check if detection/finding count improved
   - Print: "BEFORE: X findings | AFTER: Y findings | Delta: Z"

5. DECIDE
   - If BETTER (findings reduced OR FP rate reduced OR coverage increased):
     → git add + git commit with descriptive message
     → Update V1_RELEASE_OKR.md: mark KR as done, update metrics
     → Move to next KR
   - If WORSE or NO CHANGE:
     → git checkout -- . (revert all changes)
     → Analyze WHY it didn't work
     → Try a different approach (go back to step 1)
     → Max 3 attempts per KR, then skip and note blocker

6. CHECK OKR
   - After completing all KRs in a STEP, print status:
     "STEP N complete: X/Y KRs done"
   - If all required KRs in the STEP are done → move to next STEP
   - If any required KR is blocked → stop and report
```

## Rules

- Never skip the measurement step
- Never commit without measuring improvement
- Revert failed attempts cleanly (git checkout)
- Use subagents for implementation (fresh context per task)
- Use cached benchmark projects in /tmp/agentwall-bench3k/ (don't re-clone)
- Compare against old results in /tmp/agentwall-results3k/
- Update V1_RELEASE_OKR.md after each successful KR

## Start

Begin with STEP 1, KR1.1 (MEM-001 FP rate: 100% → <20%).
