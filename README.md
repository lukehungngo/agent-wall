<p align="center">
  <h1 align="center">AgentWall</h1>
  <p align="center">
    <strong>Memory security scanner for AI agents</strong>
  </p>
  <p align="center">
    Install in 10 seconds. First finding in 60 seconds.
  </p>
  <p align="center">
    <a href="#install">Install</a> &middot;
    <a href="#quick-start">Quick Start</a> &middot;
    <a href="#what-it-detects">Detection Rules</a> &middot;
    <a href="#who-is-this-for">Who Is This For</a> &middot;
    <a href="#ci-integration">CI Setup</a> &middot;
    <a href="BENCHMARK.md">Benchmark</a> &middot;
    <a href="#roadmap">Roadmap</a>
  </p>
</p>

<p align="center">
  <!-- TODO: Switch to dynamic PyPI badges after first publish: https://img.shields.io/pypi/v/agentwall -->
  <img src="https://img.shields.io/badge/pypi-v0.1.0-blue?style=flat-square" alt="PyPI version">
  <img src="https://img.shields.io/badge/python-3.10%20|%203.11%20|%203.12-blue?style=flat-square" alt="Python versions">
  <a href="https://github.com/lukehungngo/agentwall/blob/main/LICENSE"><img src="https://img.shields.io/badge/license-MIT-green?style=flat-square" alt="License"></a>
  <img src="https://img.shields.io/badge/tests-216%20passing-brightgreen?style=flat-square" alt="Tests">
  <img src="https://img.shields.io/badge/coverage-72%25-yellow?style=flat-square" alt="Coverage">
</p>

<!-- TODO: Replace with actual GIF recording of `agentwall scan examples/` -->
<p align="center">
  <img src="https://raw.githubusercontent.com/lukehungngo/agentwall/main/docs/demo.gif" alt="AgentWall demo" width="700">
</p>

---

## Install

```bash
pip install agentwall
```

That's it. Zero runtime dependencies on any vector store SDK. Fully offline.

## Quick Start

```bash
# Your first scan — finds issues in under 60 seconds
agentwall scan ./my-agent/

# Try our example (ships with the repo)
agentwall scan examples/
```

```
AgentWall v0.1.0 — Memory Security Scanner
Scanning: examples/  Framework: langchain  Files: 2  Findings: 7

──────────────────────────────  CRITICAL (1)  ──────────────────────────────

  AW-MEM-001  No tenant isolation in vector store
  File: unsafe_agent.py:24
  Vector store queries are executed without any user/tenant filter.
  A similarity search returns the globally closest vectors — including
  other users' data.
  Fix: Add a metadata filter on every retrieval call:
       similarity_search(query, filter={'user_id': user_id})

────────────────────────────────  HIGH (3)  ────────────────────────────────

  AW-TOOL-001  Destructive tool accessible without approval gate
  File: unsafe_agent.py:33
  ...
```

**Exit codes:** `0` clean | `1` findings at/above `--fail-on` threshold | `2` scan error

---

## Who Is This For?

**AgentWall is built for teams shipping LangChain and LangGraph agents to production.**

If you answer "yes" to any of these, you need AgentWall:

- Your agent uses a shared vector store (Chroma, Pinecone, PGVector, etc.) across users
- Your agent has tools that can execute code, delete files, or send messages
- Your agent has long-term memory (ConversationBufferMemory, etc.)
- You're going from prototype to production and need a security check

**Who uses AgentWall:**
- Solo AI engineers shipping side projects
- Seed/Series A startups building multi-tenant agents
- OSS contributors who want to ship safely
- Teams that can't afford $50K+ enterprise security platforms

**Not for you if:** You need runtime enforcement (see [Galileo](https://www.rungalileo.io/)), enterprise CISO dashboards (see [Noma](https://www.nomasecurity.com/)), or K8s-level guardrails (see [Operant](https://www.operant.ai/)). AgentWall is complementary — we shift-left, they enforce at runtime.

---

## The Problem

```python
# This looks fine. It isn't.
docs = vectorstore.similarity_search(user_query)
```

That call returns the globally closest vectors — **including other users' data**. No error. No warning. Silent cross-tenant leakage.

| Attack | What happens | Real-world example |
|---|---|---|
| **Memory leakage** | Agent retrieves another user's data via unfiltered similarity search | User A's medical records returned to User B |
| **Memory poisoning** | Attacker injects malicious content into long-term memory | "Ignore previous instructions" planted via crafted query ([MINJA](https://arxiv.org/abs/2024.minja), NeurIPS 2025) |
| **Unsafe tool access** | Agent calls destructive tools without human approval | Prompt injection triggers `subprocess.run("rm -rf /")` |

---

## Examples

The repo includes a side-by-side comparison:

| File | Description |
|---|---|
| [`examples/unsafe_agent.py`](examples/unsafe_agent.py) | Unfiltered vector store + shell exec tool + delete tool |
| [`examples/fixed_agent.py`](examples/fixed_agent.py) | Same features, tenant-scoped, no destructive tools |

```bash
# Scan the unsafe agent — see 5+ findings
agentwall scan examples/unsafe_agent.py

# Scan the fixed agent — clean
agentwall scan examples/fixed_agent.py
```

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

## Analysis Layers

AgentWall uses 9 analysis layers — each layer refines findings from the previous:

| Layer | Technique | What it does |
|---|---|---|
| **L0** | Regex / Import Matching | Framework detection |
| **L1** | Single-File AST | Kwarg inspection for filters, tools, permissions |
| **L2** | Inter-Procedural Call Graph | Cross-file filter resolution via call chains |
| **L3** | Taint Analysis | Tracks user identity from request entry to filter sink |
| **L4** | Config Auditing | Scans .env, docker-compose, settings.py for insecure defaults |
| **L5** | Semgrep Rules | Declarative pattern matching (requires `semgrep` binary) |
| **L6** | Symbolic Analysis | Path-sensitive: detects filters missing on some branches |
| **L7** | Runtime Instrumentation | Monkey-patches vector stores during test runs (`--dynamic`) |
| **L8** | LLM Confidence Scoring | Reduces false positives via regex/Ollama/API (`--llm-assist`) |

```bash
# Default: L0-L6 (all static layers)
agentwall scan .

# Fast mode: L0-L2 only
agentwall scan . --fast

# Pick specific layers
agentwall scan . --layers L1,L3,L6

# Enable runtime instrumentation
agentwall scan . --dynamic

# Enable LLM-assisted confidence scoring
agentwall scan . --llm-assist
```

---

## How It Works

```
agentwall scan ./project/
  │
  ├─ 1. Detect framework    (pyproject.toml, imports)
  ├─ 2. AST parse            (ast.parse — never imports or runs your code)
  ├─ 3. Extract AgentSpec    (tools, vector stores, memory configs)
  ├─ 4. Run analysis layers  (L1-L8, configurable)
  └─ 5. Report               (terminal, JSON, or SARIF)
```

**Key design principles:**

- **Static only** — all analysis via Python `ast` module. Your code is never imported, executed, or modified
- **Zero network calls** — fully offline by default. L7/L8 are opt-in
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

Optional extras for live probing:

```bash
pip install agentwall[chroma]      # ChromaDB
pip install agentwall[pgvector]    # PostgreSQL + pgvector
pip install agentwall[pinecone]    # Pinecone
pip install agentwall[qdrant]      # Qdrant
pip install agentwall[neo4j]       # Neo4j
pip install agentwall[weaviate]    # Weaviate
```

---

## Where AgentWall Fits

```
Development         Pre-Deploy             Runtime              Post-Incident
───────────       ─────────────          ─────────────        ─────────────
Code → Build  →  ★ AgentWall scan ★  →  Galileo/Operant  →  Noma/Zenity
                 memory + tool audit     policy enforce       audit/forensics
                 "Is it safe to ship?"   "Block bad actions"  "What happened?"
```

AgentWall scans what runtime tools don't: **the stateful memory and permission surface**.

---

## Benchmark: 10 Real-World Projects

We scanned 10 popular LangChain projects (3,185 files total). **6 of 10 have confirmed memory security issues.**

| Project | Stars | Findings | CRIT | HIGH | Top Rule |
|---|---|---|---|---|---|
| [Langchain-Chatchat](https://github.com/chatchat-space/Langchain-Chatchat) | ~37k | 22 | 14 | 5 | AW-MEM-001 |
| [PrivateGPT](https://github.com/zylon-ai/private-gpt) | ~54k | 0 | 0 | 0 | — |
| [Quivr](https://github.com/QuivrHQ/quivr) | ~36k | 2 | 2 | 0 | AW-MEM-001 |
| [DocsGPT](https://github.com/arc53/DocsGPT) | ~15k | 8 | 3 | 2 | AW-MEM-001 |
| [DB-GPT](https://github.com/eosphoros-ai/DB-GPT) | ~17k | 8 | 5 | 2 | AW-MEM-001 |
| [Chat-LangChain](https://github.com/langchain-ai/chat-langchain) | ~6k | 7 | 0 | 7 | AW-CFG |

**Post-fix false positive rate: ~0%.** Full results, methodology, and reproduction script: **[BENCHMARK.md](BENCHMARK.md)**

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

### v0.1.0 — Core Scanner

- [x] LangChain adapter: AST-based tool and vector store extraction
- [x] Memory rules: AW-MEM-001 through AW-MEM-005
- [x] Tool rules: AW-TOOL-001 through AW-TOOL-005
- [x] Analysis layers L0-L8 (L7/L8 opt-in)
- [x] Terminal reporter (Rich), JSON reporter
- [x] CLI with `--fail-on`, `--layers`, `--fast`, `--dynamic`, `--llm-assist`
- [x] 109 tests passing, ruff clean, mypy strict clean

### v0.2.0 — Hardening

- [ ] ChromaDB live probe (`--live` mode)
- [ ] SARIF 2.1.0 reporter (GitHub Advanced Security integration)
- [ ] `# agentwall: safe` inline suppression comments
- [ ] 80%+ test coverage

### v0.3.0 — Ecosystem

- [ ] PyPI publish: `pip install agentwall`
- [ ] GitHub Action: `agentwall/scan-action@v1`
- [ ] Launch blog: "We found memory leakage in 3 popular LangChain templates"

### Future

- [ ] OpenAI Agents SDK adapter
- [ ] CrewAI adapter
- [ ] Pinecone / pgvector / Neo4j live probes
- [ ] MCP tool permission audit

---

## Development

```bash
git clone https://github.com/lukehungngo/agentwall && cd agentwall
uv sync

uv run pytest                          # Run tests
uv run ruff check src/ tests/         # Lint
uv run mypy src/ --strict             # Type check
uv run agentwall scan examples/       # Run scanner on examples
```

---

## Contributing

AgentWall is early-stage and contributions are welcome:

1. **Try it on your agent** and [report false positives](https://github.com/lukehungngo/agentwall/issues/new?template=false_positive.yml) or [false negatives](https://github.com/lukehungngo/agentwall/issues/new?template=false_negative.yml)
2. **Add vector store probes** — each probe is a self-contained module
3. **[Request framework adapters](https://github.com/lukehungngo/agentwall/issues/new?template=adapter_request.yml)** — OpenAI, CrewAI, AutoGen

Join the [Discussions](https://github.com/lukehungngo/agentwall/discussions) to share scan results, vote on the roadmap, or request frameworks.

---

## License

MIT
