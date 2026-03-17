#!/usr/bin/env bash
# Create GitHub labels for AgentWall
# Usage: .github/setup-labels.sh
# Requires: gh auth login

set -euo pipefail

REPO="lukehungngo/agentwall"

labels=(
  "triage|fbca04|Needs triage"
  "false-positive|d93f0b|AgentWall flagged safe code"
  "false-negative|e99695|AgentWall missed a real vulnerability"
  "adapter-request|0075ca|Request for new framework or vector store support"
  "bug|d73a4a|Something isn't working"
  "enhancement|a2eeef|New feature or improvement"
  "documentation|0075ca|Documentation improvements"
  "rule: AW-MEM|b60205|Related to memory security rules"
  "rule: AW-TOOL|e4e669|Related to tool permission rules"
  "layer: L1-L3|c5def5|AST / call graph / taint analysis"
  "layer: L4-L6|bfdadc|Config / semgrep / symbolic analysis"
  "layer: L7-L8|d4c5f9|Runtime / LLM-assisted analysis"
  "P0|b60205|Critical — blocks release"
  "P1|d93f0b|High — fix before next release"
  "P2|fbca04|Medium — fix when possible"
  "good first issue|7057ff|Good for newcomers"
  "help wanted|008672|Community contributions welcome"
)

for entry in "${labels[@]}"; do
  IFS='|' read -r name color desc <<< "$entry"
  echo "Creating label: $name"
  gh label create "$name" --color "$color" --description "$desc" --force --repo "$REPO" 2>/dev/null || true
done

echo "Done. Created ${#labels[@]} labels."
