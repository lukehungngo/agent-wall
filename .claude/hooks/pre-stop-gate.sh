#!/usr/bin/env bash
# Hook: pre-stop-gate
# Trigger: Stop
# Purpose: Quick quality summary before session ends.
# Non-blocking — always exits 0. Outputs JSON systemMessage.

cd /home/soh/working/agent-wall 2>/dev/null || exit 0

summary=""

# ruff
if ruff check src/ tests/ --quiet 2>/dev/null; then
  summary="ruff:ok"
else
  summary="ruff:warnings"
fi

# pytest (quick count only)
test_line=$(python3 -m pytest tests/ -q --tb=no 2>/dev/null | tail -1)
summary="$summary | $test_line"

echo "{\"systemMessage\": \"Stop gate: $summary\"}"
