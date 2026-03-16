<p align="center">
  <h1 align="center">AgentWall</h1>
  <p align="center">
    <strong>Pre-deployment security scanner for AI agents</strong>
  </p>
  <p align="center">
    Finds memory leakage, memory poisoning, and unsafe tool permissions<br>in your LangChain agent — before you ship it.
  </p>
  <p align="center">
    <a href="#install">Install</a> &middot;
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#what-it-detects">Detection Rules</a> &middot;
    <a href="#ci-integration">CI Setup</a> &middot;
    <a href="#roadmap">Roadmap</a>
  </p>
</p>

<p align="center">
  <img src="https://img.shields.io/pypi/v/agentwall?style=flat-square&color=blue" alt="PyPI version">
  <img src="https://img.shields.io/pypi/pyversions/agentwall?style=flat-square" alt="Python versions">
  <img src="https://img.shields.io/github/license/soh/agentwall?style=flat-square" alt="License">
  <img src="https://img.shields.io/github/actions/workflow/status/soh/agentwall/ci.yml?style=flat-square&label=CI" alt="CI">
</p>

---

## Why AgentWall?

Your agent works. But is it **safe**?

```python
# This looks fine. It isn't.
docs = vectorstore.similarity_search(user_query)
```

That call returns the globally closest vectors — **including other users' data**. No error. No warning. Silent cross-tenant leakage.

Three attack surfaces that no existing tool covers:

| Attack | What happens | Example |
|---|---|---|
| **Memory leakage** | Agent retrieves another user's data via unfiltered similarity search | User A's medical records returned to User B |
| **Memory poisoning** | Attacker injects malicious content into long-term memory that persists across sessions | "Ignore previous instructions" planted via crafted query ([MINJA](https://arxiv.org/abs/2024.minja), NeurIPS 2025) |
| **Unsafe tool access** | Agent calls destructive tools (shell exec, file delete) without human approval | Prompt injection → `subprocess.run("rm -rf /")` |

AgentWall scans your code statically, finds these issues, and tells you exactly how to fix them — **before production**.

---

## Install

```bash
pip install agentwall
```

That's it. Zero runtime dependencies on any vector store SDK. Fully offline.

Optional extras for live vector store probing:

```bash
pip install agentwall[chroma]      # ChromaDB
pip install agentwall[pgvector]    # PostgreSQL + pgvector
pip install agentwall[pinecone]    # Pinecone
pip install agentwall[qdrant]      # Qdrant
pip install agentwall[neo4j]       # Neo4j
pip install agentwall[weaviate]    # Weaviate
```

---

## Quick Start

```bash
# Scan any LangChain project
agentwall scan ./my-agent/

# Force framework detection
agentwall scan . --framework langchain

# Export machine-readable JSON
agentwall scan . --output report.json

# CI mode — exit 1 on critical findings only
agentwall scan . --fail-on critical

# Report-only — never exit 1
agentwall scan . --fail-on none
```

### Example output

```
AgentWall v0.1.0 — Memory Security Scanner
Scanning: ./my-agent  Framework: langchain  Files: 3  Findings: 7

──────────────────────────────  CRITICAL (1)  ──────────────────────────────

  AW-MEM-001  No tenant isolation in vector store
  File: agent.py:8
  Vector store queries are executed without any user/tenant filter.
  A similarity search returns the globally closest vectors — including
  other users' data.
  Fix: Add a metadata filter on every retrieval call:
       similarity_search(query, filter={'user_id': user_id})

────────────────────────────────  HIGH (3)  ────────────────────────────────

  AW-MEM-003  Memory backend has no access control configuration
  File: agent.py:8
  ...

  AW-TOOL-001  Destructive tool accessible without approval gate
  File: agent.py:13
  ...
```

**Exit codes:** `0` clean | `1` findings at/above `--fail-on` threshold | `2` scan error

---

## What It Detects

### Memory Security Rules

| Rule | Severity | What it catches |
|---|---|---|
| **AW-MEM-001** | CRITICAL | Vector store queries with no user/tenant filter — cross-user data leakage |
| **AW-MEM-002** | HIGH | Metadata written at insert time but no matching filter at retrieval — false sense of security |
| **AW-MEM-003** | HIGH | Memory backend with zero access control configuration |
| **AW-MEM-004** | HIGH | Known injection patterns in memory retrieval path (MINJA, MemoryGraft) |
| **AW-MEM-005** | MEDIUM | Retrieved memory injected into agent context without sanitization |

### Tool Permission Rules

| Rule | Severity | What it catches |
|---|---|---|
| **AW-TOOL-001** | HIGH | Destructive tools (delete, execute, send) registered without human-in-the-loop approval gate |
| **AW-TOOL-002** | MEDIUM | Tools that accept arbitrary code, SQL, or shell commands |
| **AW-TOOL-003** | MEDIUM | High-risk tools without user-scope access verification |
| **AW-TOOL-004** | LOW | Tools with no description — blocks risk classification and degrades LLM tool selection |
| **AW-TOOL-005** | INFO | Agent with >15 tools — increases token usage and reduces selection accuracy |

Every finding includes the file, line number, description, and a concrete remediation step.

---

## How It Works

```
agentwall scan ./project/
  │
  ├─ 1. Detect framework    (pyproject.toml, imports)
  ├─ 2. AST parse            (ast.parse — never imports or runs your code)
  ├─ 3. Extract AgentSpec    (tools, vector stores, memory configs)
  ├─ 4. MemoryAnalyzer       (isolation, filters, poisoning patterns)
  ├─ 5. ToolAnalyzer         (permissions, scope, risk classification)
  └─ 6. Report               (terminal, JSON, or SARIF)
```

**Key design principles:**

- **Static only** — all analysis via Python `ast` module. Your code is never imported, executed, or modified
- **Zero network calls** — fully offline by default. Optional `--live` mode for real vector store probing
- **Fail safe** — parse errors on individual files produce a warning and skip. The scan never crashes
- **Conservative** — prefers false negatives over false positives. Findings you see are real

### Supported frameworks

| Framework | Status |
|---|---|
| LangChain / LangGraph (v0.2–0.3) | Supported |
| OpenAI Agents SDK | Planned (month 2) |
| CrewAI | Planned (month 2–3) |
| AutoGen | Planned (community) |

### Supported vector stores (static detection)

Chroma, PGVector, Pinecone, Qdrant, FAISS, Weaviate, Neo4j, Milvus, Redis, MongoDB Atlas, Elasticsearch, LanceDB

---

## CI Integration

### GitHub Actions

```yaml
name: Agent Security
on: [push, pull_request]

jobs:
  agentwall:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-python@v5
        with:
          python-version: "3.12"
      - run: pip install agentwall
      - run: agentwall scan . --fail-on high --output report.json
      - uses: actions/upload-artifact@v4
        if: always()
        with:
          name: agentwall-report
          path: report.json
```

SARIF output for GitHub Advanced Security tab is coming in v0.2.

---

## Where AgentWall Fits

```
Development         Pre-Deploy             Runtime              Post-Incident
───────────       ─────────────          ─────────────        ─────────────
Code → Build  →  ★ AgentWall scan ★  →  Galileo/Operant  →  Noma/Zenity
                 memory + tool audit     policy enforce       audit/forensics
                 "Is it safe to ship?"   "Block bad actions"  "What happened?"
```

AgentWall is the **shift-left** security tool for AI agents. Scan before you ship. Enforce at runtime with complementary tools.

We are **not** competing with:
- **Galileo Agent Control** — OSS control plane for policy governance
- **Noma / Zenity / Operant** — enterprise runtime platforms
- **Promptfoo** (now OpenAI) — prompt-level red-teaming and evals

AgentWall scans what they don't: **the stateful memory and permission surface**.

---

## Research Background

AgentWall's detection rules are grounded in published security research:

| Research | Finding | AgentWall Rule |
|---|---|---|
| **MINJA** (NeurIPS 2025) | >95% injection success rate via query-only memory manipulation | AW-MEM-001, AW-MEM-004 |
| **MemoryGraft** (Srivastava & He, 2025) | Semantic manipulation plants persistent false memories | AW-MEM-004, AW-MEM-005 |
| **Palo Alto Unit42** (2025) | Indirect prompt injection poisons long-term memory permanently | AW-MEM-004, AW-MEM-005 |
| **LangGrinch CVE** (CVSS 9.3, Dec 2025) | LangChain core secrets exposure | AW-MEM-001, AW-MEM-003 |
| **Schneider** (2025) | Persistent memory poisoning across agent architectures | AW-MEM-004, AW-MEM-005 |

---

## Roadmap

### v0.1.0 — Week 1 (current)

- [x] Project scaffold with CI (ruff, mypy strict, pytest)
- [x] Core models: AgentSpec, Finding, ScanResult, Severity
- [x] LangChain adapter: AST-based tool and vector store extraction
- [x] MemoryAnalyzer: AW-MEM-001, AW-MEM-002, AW-MEM-003
- [x] ToolAnalyzer: AW-TOOL-001 through AW-TOOL-005
- [x] Terminal reporter (Rich, colored, grouped by severity)
- [x] JSON reporter
- [x] CLI: `agentwall scan` with `--framework`, `--output`, `--fail-on`
- [x] Auto-detect framework from pyproject.toml and imports
- [x] 47 tests passing, 0 lint errors, mypy strict clean

### v0.2.0 — Week 2 (in progress)

- [ ] MemoryAnalyzer: AW-MEM-004 (injection patterns), AW-MEM-005 (no sanitization)
- [ ] ChromaDB live probe (`--live` mode)
- [ ] SARIF 2.1.0 reporter (GitHub Advanced Security integration)
- [ ] `agentwall version` subcommand
- [ ] 60%+ test coverage

### v0.3.0 — Week 3 (ship)

- [ ] PyPI publish: `pip install agentwall`
- [ ] GitHub repo public (AGPL-3.0 license)
- [ ] GitHub Actions reusable workflow
- [ ] Launch blog: "We found memory leakage in 3 popular LangChain templates"

### Future (if traction)

- [ ] OpenAI Agents SDK adapter
- [ ] CrewAI adapter
- [ ] Pinecone / pgvector live probes
- [ ] MCP tool permission audit
- [ ] GitHub Action: `agentwall/scan-action@v1`
- [ ] `# agentwall: safe` inline suppression comments

---

## Development

```bash
# Clone and install
git clone https://github.com/soh/agentwall && cd agentwall
uv sync

# Run tests
uv run pytest

# Lint + type check
uv run ruff check src/ tests/
uv run mypy src/ --strict

# Run scanner locally
uv run agentwall scan tests/fixtures/langchain_unsafe/
```

---

## Contributing

AgentWall is early-stage and contributions are welcome. The best ways to help:

1. **Try it on your agent** and file issues for false positives/negatives
2. **Add vector store probes** — each probe is a self-contained module
3. **Request framework adapters** — OpenAI, CrewAI, AutoGen

---

## License

AGPL-3.0
