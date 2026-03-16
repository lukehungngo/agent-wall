# AgentWall — Project Context

## What This Is

**Memory security scanner for AI agents.**
Detects cross-user memory leakage, memory poisoning, and unsafe tool permissions in AI agent
applications before deployment. OSS CLI. `pip install agentwall`.

Not a runtime control plane. Not a governance dashboard. A pre-deploy scanner.

---

## Tech Stack

| Layer | Tool | Version |
|---|---|---|
| Language | Python | 3.10+ |
| CLI | Typer + Rich | 0.9+ |
| Validation | Pydantic v2 | 2.x |
| AST parsing | `ast` | stdlib |
| Testing | pytest + pytest-cov | latest |
| Linting | Ruff | latest |
| Types | mypy (strict) | latest |
| Build | Hatch + pyproject.toml | latest |
| CI | GitHub Actions | — |

No runtime LLM dependency. Fully offline by default.

---

## Directory Map

```
agentwall/
├── CLAUDE.md                   ← you are here
├── pyproject.toml              ← deps, build, tool config
├── src/agentwall/
│   ├── cli.py                  ← Typer app, `scan` command
│   ├── scanner.py              ← scan() orchestrator
│   ├── models.py               ← AgentSpec, Finding, ScanResult, ToolSpec, MemoryConfig
│   ├── detector.py             ← auto_detect_framework()
│   ├── rules.py                ← all AW-MEM-* and AW-TOOL-* rules defined here
│   ├── adapters/
│   │   ├── base.py             ← AbstractAdapter Protocol
│   │   └── langchain.py        ← LangChain/LangGraph AST adapter
│   ├── analyzers/
│   │   ├── memory.py           ← MemoryAnalyzer: leak + poison + isolation
│   │   └── tools.py            ← ToolAnalyzer: enumerate + classify + scope
│   ├── probes/                 ← per-backend memory isolation probes
│   │   ├── __init__.py         ← PROBE_REGISTRY dict
│   │   ├── base.py             ← MemoryProbe Protocol + ProbeResult
│   │   ├── chroma.py           ← ChromaProbe (priority 1)
│   │   ├── pgvector.py         ← PgVectorProbe (priority 1)
│   │   ├── pinecone.py         ← PineconeProbe (priority 2)
│   │   ├── qdrant.py           ← QdrantProbe (priority 2)
│   │   ├── neo4j.py            ← Neo4jProbe — graph-aware, unique logic
│   │   ├── weaviate.py         ← WeaviateProbe (priority 3)
│   │   ├── milvus.py           ← MilvusProbe (priority 4)
│   │   ├── redis.py            ← RedisProbe (priority 4)
│   │   ├── mongodb.py          ← MongoAtlasProbe (priority 4)
│   │   ├── elasticsearch.py    ← ElasticsearchProbe + OpenSearch (priority 5)
│   │   ├── faiss.py            ← FaissProbe — always flag, no native access control
│   │   └── lancedb.py          ← LanceDBProbe (priority 5)
│   └── reporters/
│       ├── terminal.py         ← Rich colored output
│       ├── json.py             ← JSON file output
│       └── sarif.py            ← SARIF 2.1.0 (GitHub Advanced Security)
└── tests/
    ├── fixtures/
    │   ├── langchain_unsafe/   ← agents with known vulnerabilities (test targets)
    │   ├── langchain_safe/     ← properly configured agents
    │   └── langchain_basic/    ← minimal agent
    ├── test_scanner.py
    ├── test_langchain_adapter.py
    ├── test_memory_analyzer.py
    └── test_tool_analyzer.py
```

---

## Build & Test Commands

```bash
# Install in dev mode
pip install -e ".[dev]"

# Run tests
pytest

# Run tests with coverage
pytest --cov=agentwall --cov-report=term-missing

# Lint
ruff check src/ tests/

# Type check
mypy src/

# Format
ruff format src/ tests/

# Run scanner locally
agentwall scan .
agentwall scan ./tests/fixtures/langchain_unsafe/
agentwall scan . --output report.json
agentwall scan . --fail-on high

# Build package
hatch build

# Publish to PyPI (only when releasing)
hatch publish
```

---

## Architecture

### Core Flow

```
agentwall scan ./project/
  → detector.auto_detect_framework()      # inspect pyproject.toml / imports
  → LangChainAdapter.parse()             # AST walk → AgentSpec
  → MemoryAnalyzer.analyze(agent_spec)   # leak + poison + isolation checks
  → ToolAnalyzer.analyze(agent_spec)     # enumerate + classify + scope
  → merge findings, sort by severity
  → TerminalReporter.render()
  → sys.exit(0 or 1 or 2)
```

### Key Design Rules

1. **Static by default** — never execute user code, never make network calls unless `--live`
2. **AST only** — all code analysis via Python `ast` module. No `exec()`, no `import` of user code
3. **Fail safe** — parse error on a file → warning + skip. Never crash entire scan
4. **Probe registry** — each backend is a self-contained probe module. Adding a new backend = one file + one registry entry
5. **Lazy imports** — probe SDKs only imported in `probe_live()`. Static probes have zero SDK deps
6. **No policy engine** — rules are hardcoded in `rules.py`. YAGNI. Add DSL only if users demand it

### The Memory Leakage Problem

The bug is always the same: a vector similarity search is called without a user/tenant filter.
The vector store returns the closest vectors globally — including other users' data.

Three failure modes:
- **Missing filter entirely** — `collection.query(embedding)` with no `where`
- **Metadata mismatch** — `add_texts(metadata={"user_id": x})` but `similarity_search(query)` with no filter
- **FAISS** — no native access control at all, always requires wrapper

Neo4j is special: graph traversal without `BELONGS_TO` relationship scoping can expose
entire connected subgraphs (conversations, tools, documents) across user boundaries.

---

## Rules Reference

| Rule ID | Category | Severity | What It Checks |
|---|---|---|---|
| AW-MEM-001 | Memory | CRITICAL | No tenant isolation in vector store |
| AW-MEM-002 | Memory | HIGH | Shared collection, no metadata filter |
| AW-MEM-003 | Memory | HIGH | Memory backend has no access control config |
| AW-MEM-004 | Memory | HIGH | Known injection patterns in memory retrieval path |
| AW-MEM-005 | Memory | MEDIUM | No sanitization on retrieved memory before context injection |
| AW-TOOL-001 | Tool | HIGH | Destructive tools accessible without approval gate |
| AW-TOOL-002 | Tool | MEDIUM | Tool accepts arbitrary code/SQL/shell execution |
| AW-TOOL-003 | Tool | MEDIUM | High-risk tool lacks user-scope access check |
| AW-TOOL-004 | Tool | LOW | Tool has no description (blocks risk classification) |
| AW-TOOL-005 | Tool | INFO | Agent has >15 tools (exceeds recommended limit) |

---

## Probe Build Priority

```
P1 (ship with MVP):   chroma, pgvector
P2 (week 2–3):        pinecone, qdrant
P3 (week 3–4):        neo4j, weaviate
P4 (post-launch):     milvus, redis, mongodb
P5 (community PRs):   elasticsearch, opensearch, faiss, lancedb
```

---

## Gotchas

- **LangChain breaks constantly.** Pin `langchain>=0.2,<0.4`. Test adapter against both 0.2 and 0.3.
- **LangGrinch CVE (CVSS 9.3, Dec 2025)** — LangChain core had a critical secrets exposure bug. Users are actively looking for tooling. This is our launch moment.
- **Never import user agent code.** Use `ast.parse()` only. Running user code in a security scanner is a P0 security issue.
- **Neo4j probe is graph-aware.** Don't treat it like a vector store probe. Cypher query parsing is string-based (regex + AST). The isolation check is relationship-based, not filter-based.
- **FAISS has zero access control.** `FaissProbe.detect_static()` always returns a HIGH finding. The only question is whether a wrapper exists.
- **Metadata ≠ isolation.** The most common false sense of security: `add_texts(metadata={"user_id": x})` looks safe but does nothing without a matching filter on retrieval. Detect the mismatch pattern explicitly.
- **`--live` requires SDK install.** Document this clearly. Default pip install has zero vector store SDK deps. `pip install agentwall[chroma]` for live ChromaDB probing.
- **Severity = CRITICAL only for confirmed cross-tenant access.** Everything else is HIGH or below. Don't inflate severity — it kills user trust.

---

## Competitive Context

We are NOT competing with:
- **Noma** ($132M) — enterprise platform, CISO buyer, $50K+ contracts
- **Zenity** ($55M) — enterprise, Microsoft ecosystem
- **Operant AI** (Series A) — K8s runtime enforcement
- **Galileo Agent Control** — OSS control plane (launched March 11, 2026)

We ARE serving: indie AI builders, seed/Series A startups, OSS contributors, solo engineers
who cannot afford or access enterprise platforms.

We are complementary to runtime tools (Galileo, Operant). We shift-left: scan before deploy.
They enforce at runtime. A Galileo user should also use AgentWall.

---

## Installed Claude Code Skills

### Workflow (obra/superpowers)
| Skill | Trigger |
|---|---|
| `test-driven-development` | Before writing implementation code |
| `systematic-debugging` | Any bug, test failure, unexpected behavior |
| `writing-plans` | Multi-step task, before touching code |
| `executing-plans` | Execute a written plan in a separate session |
| `requesting-code-review` | Completing features, before merging |
| `receiving-code-review` | When review feedback arrives |
| `subagent-driven-development` | Independent tasks in current session |
| `finishing-a-development-branch` | All tests pass, ready to integrate |
| `verification-before-completion` | Before claiming work is done |

### Security Auditing (trailofbits/skills)
| Skill | Trigger |
|---|---|
| `ask-questions-if-underspecified` | Spec is ambiguous before implementation |
| `differential-review` | PR review — what changed and why |
| `fp-check` | False positive triage in static analysis findings |
| `insecure-defaults` | Review default configurations for security |
| `property-based-testing` | Hypothesis/property test design |
| `semgrep` | Run/interpret semgrep static analysis |
| `sharp-edges` | Language-specific footguns and gotchas |
| `modern-python` | Python idioms, type hints, safety patterns |
| `supply-chain-risk-auditor` | Dependency risk, typosquatting, pinning |
| `variant-analysis` | Find variants of a known vulnerability pattern |

### Agents (`.claude/agents/`)
| Agent | Invoke | Role |
|---|---|---|
| `engineer` | `/agent:engineer` | Implement features via TDD. Owns clarify→plan→design→implement flow. |
| `reviewer` | `/agent:reviewer` | Security-focused code review. Produces P0-P3 verdict reports. |

---

## Launch Targets

- PyPI: `pip install agentwall`
- GitHub: public OSS (MIT license)
- Launch content: "We found memory leakage in 3 popular LangChain templates"
- Channels: Show HN, r/LangChain, r/MachineLearning, X/Twitter
- Success signal at week 4: 50+ installs, 30+ stars, 5+ issues filed
