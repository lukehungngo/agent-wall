#!/usr/bin/env bash
# Hook: lint
# Called by the PostToolUse prompt hook — agent runs this and sees the output.
# Scoped to src/ and tests/ only. Fast. Ruff only.

set -uo pipefail

cd /home/soh/working/agent-wall

changed=$(git diff --name-only HEAD 2>/dev/null; git diff --cached --name-only 2>/dev/null)

if echo "$changed" | grep -qE '^(src/|tests/)'; then
  ruff check src/ tests/ --quiet
else
  echo "no source changes — lint skipped"
fi
