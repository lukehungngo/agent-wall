#!/usr/bin/env bash
# Create pinned GitHub Discussions for AgentWall
# Usage: .github/setup-discussions.sh
# Requires: gh auth login + Discussions enabled on the repo

set -euo pipefail

REPO="lukehungngo/agentwall"

echo "Creating discussion: Share your scan results"
gh api graphql -f query='
mutation {
  createDiscussion(input: {
    repositoryId: "'$(gh api repos/$REPO --jq .node_id)'"
    categoryId: "'$(gh api repos/$REPO/discussions/categories --jq '.[0].node_id')'"
    title: "Share your scan results"
    body: "Run `agentwall scan` on your project and share what you found!\n\n**How to share:**\n1. Run `agentwall scan ./your-project/`\n2. Paste the output (redact any secrets)\n3. Tell us: were the findings accurate?\n\nThis helps us improve detection accuracy and prioritize rules."
  }) { discussion { url } }
}' 2>/dev/null || echo "  (skipped — may already exist or Discussions not enabled)"

echo "Creating discussion: Framework requests"
gh api graphql -f query='
mutation {
  createDiscussion(input: {
    repositoryId: "'$(gh api repos/$REPO --jq .node_id)'"
    categoryId: "'$(gh api repos/$REPO/discussions/categories --jq '.[0].node_id')'"
    title: "Framework requests — what should AgentWall support next?"
    body: "Vote and comment on which frameworks you want AgentWall to support:\n\n- **OpenAI Agents SDK** — 👍 this comment\n- **CrewAI** — 👍 this comment\n- **AutoGen** — 👍 this comment\n- **LlamaIndex** — 👍 this comment\n- **Haystack** — 👍 this comment\n\nOr add your own in the replies!"
  }) { discussion { url } }
}' 2>/dev/null || echo "  (skipped — may already exist or Discussions not enabled)"

echo "Creating discussion: Roadmap voting"
gh api graphql -f query='
mutation {
  createDiscussion(input: {
    repositoryId: "'$(gh api repos/$REPO --jq .node_id)'"
    categoryId: "'$(gh api repos/$REPO/discussions/categories --jq '.[0].node_id')'"
    title: "Roadmap voting — what matters most to you?"
    body: "Help us prioritize! React with 👍 on features you want:\n\n**Near-term:**\n- SARIF output for GitHub Advanced Security\n- `# agentwall: safe` inline suppression comments\n- ChromaDB live probe\n- GitHub Action: `agentwall/scan-action@v1`\n\n**Medium-term:**\n- OpenAI Agents SDK adapter\n- CrewAI adapter\n- Neo4j graph-aware probe\n- MCP tool permission audit\n\n**Longer-term:**\n- VS Code extension\n- Pre-commit hook\n- Custom rule DSL\n\nAdd your own ideas in the replies!"
  }) { discussion { url } }
}' 2>/dev/null || echo "  (skipped — may already exist or Discussions not enabled)"

echo "Done. Pin the discussions manually via GitHub UI."
