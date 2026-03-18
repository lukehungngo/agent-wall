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
    <a href="docs/ANALYSIS_LAYERS.md">Analysis Layers</a> &middot;
    <a href="docs/APPLICATION_SECURITY_MODEL.md">ASM</a> &middot;
    <a href="#who-is-this-for">Who Is This For</a> &middot;
    <a href="#competitive-landscape">Landscape</a> &middot;
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

**AgentWall is built for teams shipping multi-platform agents to production.**

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
| **Memory poisoning** | Attacker injects malicious content into long-term memory | "Ignore previous instructions" planted via crafted query ([MINJA](https://arxiv.org/abs/2503.03704), NeurIPS 2025) |
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

## Static analysis Layers

AgentWall's detection pipeline stacks 9 analysis layers that form a progressive refinement funnel — each layer adds precision and catches what the previous layer structurally cannot.

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


**Layers are independently deployable.** CI users run L0–L2 in fast mode (< 10s). Full audits use L0–L5 (< 90s on 50K LOC). L6–L8 are opt-in for deep analysis.

```bash
# Default: L0-L6 (all static layers)
agentwall scan .

# Fast mode: L0-L2 only (< 10 seconds)
agentwall scan . --fast

# Pick specific layers
agentwall scan . --layers L1,L3,L6

# Enable runtime instrumentation
agentwall scan . --dynamic

# Enable LLM-assisted confidence scoring
agentwall scan . --llm-assist
```

**[Full layer-by-layer breakdown with code examples, detection matrix, and cost/precision chart →](docs/ANALYSIS_LAYERS.md)**

### Application Security Model (ASM) — Semantic Analysis

L0–L8 check individual code sites — "does this call have a filter?" The ASM goes further: it builds a **semantic model of the entire application** and queries it for violations that no single-file or cross-file check can find.

```
Source code  →  Extract nodes  →  Build graph  →  Query for violations
                (entry points,     (who writes      (can user A's data
                 write ops,         where? who       reach user B's
                 stores, reads,     reads it? is     context?)
                 sinks, auth)       auth enforced?)
```

**What it catches that L0–L8 cannot:**

| Finding | Why L0–L8 miss it |
|---|---|
| Ingestion writes `{"source": "web"}` but retrieval filters on `{"user_id": uid}` — **key mismatch** | L1 only checks the read side. Never sees the write path. |
| Background re-indexing job has no auth and drops metadata on rebuild — **lifecycle break** | L2 call graph doesn't connect cron jobs to API handlers. |
| `collection_name="faq"` is shared across all tenants — **false isolation** | L1 sees scoping but can't infer a string literal is shared, not per-user. |
| Retrieved docs concatenated into LLM prompt with no delimiter — **injection surface** | No layer tracks the full path from retrieval to prompt assembly. |

Every finding includes a **path witness** — the complete chain from entry point through storage to the violation point, with confidence levels at each hop.

```bash
# Enable ASM semantic analysis
agentwall scan . --asm
```

**[Full ASM design spec: IR schema, query definitions, extraction pipeline →](docs/APPLICATION_SECURITY_MODEL.md)**

---

## How It Works

```
agentwall scan ./project/
  │
  ├─ 1. Detect framework    (pyproject.toml, imports)
  ├─ 2. AST parse            (ast.parse — never imports or runs your code)
  ├─ 3. Extract AgentSpec    (tools, vector stores, memory configs)
  ├─ 4. Run analysis layers  (L1-L8, configurable)
  └─ 5. Report               (terminal, JSON, SARIF, agent-json, or patch)
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
| CrewAI | Planned (Phase 2) |
| AutoGen | Planned (Phase 2) |
| LlamaIndex | Planned (Phase 2) |
| OpenAI Agents SDK | Planned (Phase 4) |

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

## Competitive Landscape

We analyzed 24 AI security tools across 6 categories. **No tool performs pre-deployment static analysis for AI agent memory security.** AgentWall is the first.

### By Category

| Category | Tools | Memory Security? | When? |
|---|---|---|---|
| **SAST / Code Scanners** | Snyk, Semgrep, CodeQL, SonarQube, Checkmarx | No — zero rules for vector store isolation, RAG pipelines, or embedding security | Pre-deploy |
| **AI Red-Teaming** | Promptfoo, Garak, Giskard | No — test prompt-level attacks on live agents, not code-level memory misconfigurations | Test time |
| **Runtime Guardrails** | Guardrails AI, NeMo Guardrails, Lakera Guard, LLM Guard, Rebuff | No — filter I/O at inference time, don't audit memory architecture or tool permissions | Runtime |
| **AI Observability** | LangSmith, Arize, Langfuse, Helicone | No — trace and monitor deployed agents, can't prevent misconfigurations before deploy | Runtime |
| **AI Governance** | Noma, Galileo, Operant, Zenity, Credo AI, Holistic AI | No — enterprise policy enforcement and post-incident audit, not code-level scanning | Runtime / Post |
| **Guidelines** | OWASP Agent Memory Guard | Reference architecture only — no scanner, no automation, no CI/CD integration | N/A |

### Why the Gap Exists

Agent memory security requires specialized domain knowledge that generic tools don't have. A SAST tool doesn't understand that `similarity_search()` returns the globally closest vectors regardless of ownership. A runtime guardrail can't fix an unfiltered query already committed to the codebase. A governance platform audits after deployment — but the misconfiguration shipped weeks ago.

AgentWall fills the gap because it combines **static code analysis** with **agent-specific domain knowledge**: vector store retrieval patterns, metadata filter semantics, tool permission models, and memory backend access control.

### Where AgentWall Fits

```
Development         Pre-Deploy             Runtime              Post-Incident
───────────       ─────────────          ─────────────        ─────────────
Code → Build  →  ★ AgentWall scan ★  →  Galileo/Operant  →  Noma/Zenity
                 memory + tool audit     policy enforce       audit/forensics
                 "Is it safe to ship?"   "Block bad actions"  "What happened?"
```

AgentWall is **complementary** — we shift-left, they enforce at runtime. Different phases, same goal.

---

## Benchmark: 20 Real-World Projects

We scanned 20 popular LangChain ecosystem projects (5,085 files total). **12 of 20 have confirmed security issues.** 165 findings (57 CRITICAL, 74 HIGH).

| Project | Stars | Findings | CRIT | HIGH | Top Rule |
|---|---|---|---|---|---|
| [Langchain-Chatchat](https://github.com/chatchat-space/Langchain-Chatchat) | ~37k | 23 | 14 | 5 | AW-MEM-001 |
| [PrivateGPT](https://github.com/zylon-ai/private-gpt) | ~54k | 0 | 0 | 0 | — |
| [Quivr](https://github.com/QuivrHQ/quivr) | ~36k | 2 | 2 | 0 | AW-MEM-001 |
| [LocalGPT](https://github.com/PromtEngineer/localGPT) | ~22k | 0 | 0 | 0 | — |
| [DocsGPT](https://github.com/arc53/DocsGPT) | ~15k | 8 | 3 | 2 | AW-MEM-001 |
| [GPT-Researcher](https://github.com/assafelovic/gpt-researcher) | ~17k | 4 | 2 | 1 | AW-MEM-001 |
| [Onyx/Danswer](https://github.com/onyx-dot-app/onyx) | ~12k | 8 | 1 | 3 | AW-CFG |
| [DB-GPT](https://github.com/eosphoros-ai/DB-GPT) | ~17k | 6 | 2 | 2 | AW-MEM-001 |
| [Chat-LangChain](https://github.com/langchain-ai/chat-langchain) | ~6k | 7 | 0 | 7 | AW-CFG |
| [RasaGPT](https://github.com/paulpierre/RasaGPT) | ~2.4k | 0 | 0 | 0 | — |
| [Langflow](https://github.com/langflow-ai/langflow) | ~48k | 71 | 29 | 25 | AW-MEM-001 |
| [Chainlit](https://github.com/Chainlit/chainlit) | ~8k | 0 | 0 | 0 | — |
| [Mem0/Embedchain](https://github.com/mem0ai/mem0) | ~25k | 26 | 4 | 19 | AW-CFG |
| [LLM App (Pathway)](https://github.com/pathwaycom/llm-app) | ~4k | 4 | 0 | 4 | AW-CFG |
| [SuperAgent](https://github.com/superagent-ai/superagent) | ~5k | 1 | 0 | 1 | AW-CFG |
| [AgentGPT](https://github.com/reworkd/AgentGPT) | ~32k | 5 | 0 | 5 | AW-CFG |

*4 projects (Flowise, Open Interpreter, Haystack, AutoGPT) not scanned — require dedicated adapters.*

**Post-fix false positive rate: ~0%.** Full results, methodology, and reproduction script: **[BENCHMARK.md](BENCHMARK.md)**

---

## Research Background

AgentWall's detection rules are grounded in published security research and mapped to industry standards:

| Research | Finding | AgentWall Rule | Standard |
|---|---|---|---|
| **[MINJA](https://arxiv.org/abs/2503.03704)** (NeurIPS 2025) | >95% injection success rate via query-only memory manipulation | AW-MEM-001, AW-MEM-004 | OWASP ASI06 |
| **[PoisonedRAG](https://github.com/sleeepeer/PoisonedRAG)** (USENIX Security 2025) | 5 poisoned documents manipulate RAG with >90% success across millions of docs | AW-MEM-004 | OWASP LLM04 |
| **[CorruptRAG](https://arxiv.org/pdf/2504.03957)** (2026) | Single-document injection sufficient for attack | AW-MEM-004 | OWASP LLM04 |
| **[MemoryGraft](https://arxiv.org/abs/2503.03704)** (2025) | Semantic manipulation plants persistent false memories | AW-MEM-004, AW-MEM-005 | OWASP ASI06 |
| **[Palo Alto Unit42](https://www.paloaltonetworks.com/blog/cloud-security/owasp-agentic-ai-security/)** (2025) | Indirect prompt injection poisons long-term memory permanently | AW-MEM-004, AW-MEM-005 | OWASP ASI01 |
| **[EchoLeak](https://www.paloaltonetworks.com/blog/cloud-security/owasp-agentic-ai-security/)** (2025) | Single crafted email triggered M365 Copilot to disclose confidential data | AW-MEM-001 | OWASP LLM01 |
| **[Embedding Inversion](https://arxiv.org/html/2411.05034v1)** (ACL 2024) | 50–70% of original text recoverable from stored vectors | AW-MEM-003, AW-MEM-005 | OWASP LLM08 |
| **[LangGrinch CVE](https://nvd.nist.gov/)** (CVSS 9.3, Dec 2025) | LangChain core secrets exposure | AW-MEM-001, AW-MEM-003 | CVE |
| **[Schneider](https://christian-schneider.net/blog/persistent-memory-poisoning-in-ai-agents/)** (2025) | Persistent memory poisoning across agent architectures | AW-MEM-004, AW-MEM-005 | OWASP ASI06 |

AgentWall covers 10 of the 28 cataloged attack vectors through static analysis. The remaining 18 require runtime probing (planned for Phase 3). Full catalog: [`AgentWall_Attack_Vector_Catalog.md`](prd/AgentWall_Attack_Vector_Catalog.md).

---

## Roadmap

### Where We Are Today (v0.x) ✅

Core static scanner for LangChain + ChromaDB. 9 analysis layers (L0–L8), 10 detection rules, 5 output formats (terminal, JSON, SARIF, agent-json, patch). 216 tests, benchmark across 20 real-world projects (12/20 have confirmed issues). Inter-procedural call graph, config auditing, Semgrep rules, LLM confidence scoring — all shipped. Incremental `verify` command for fast fix-verify loops.

**The v0.x releases establish the foundation. What follows is the full vision for AgentWall as the definitive security layer for every AI agent ever shipped.**

---

### v1.0 — Multi-Framework Coverage

The agent ecosystem is fragmenting across LangChain, OpenAI Agents SDK, CrewAI, AutoGen, and emerging MCP-native agents. A single vulnerability class manifests differently in each framework. v1.0 ships a unified rule engine with per-framework adapters, so one scan command covers your entire polyglot agent codebase.

- [ ] OpenAI Agents SDK adapter (tool registration, handoff permissions, context scope)
- [ ] CrewAI adapter (crew-level vs. agent-level memory isolation, task permission boundaries)
- [ ] AutoGen adapter (multi-agent conversation memory, inter-agent trust levels)
- [ ] MCP tool permission auditing (server-level scope declarations, capability mismatches)
- [ ] Single `agentwall scan .` works across mixed-framework monorepos

### v1.1 — Agentic Supply Chain Security

Agents increasingly import third-party tools, retrievers, and memory plugins from PyPI and npm. A compromised package can silently remove your tenant filter or exfiltrate memory to an external endpoint. v1.1 treats the dependency graph as a first-class attack surface.

- [ ] Dependency scanning: flag tool packages with known CVEs or suspicious releases
- [ ] Import graph analysis: detect third-party code paths that touch vector store retrieval
- [ ] Plugin integrity: verify tool packages against known-safe checksums
- [ ] Shadow tool detection: tools registered by imported libraries without explicit developer consent
- [ ] SCA report integrated into the existing SARIF output — one report for code + deps

### v1.2 — Architectural Pattern Enforcement

Beyond individual findings, agents fail when their overall architecture violates isolation principles. v1.2 introduces architectural rules that reason about the full agent graph — not just individual files.

- [ ] Multi-agent trust boundary analysis: agent A should not access agent B's memory namespace
- [ ] Context leak detection: user PII flowing from one agent's scratchpad to another's system prompt
- [ ] Privilege escalation paths: sub-agent inheriting parent's tool permissions without explicit grant
- [ ] Memory scope diagrams: auto-generated visualization of which agents can read/write which stores
- [ ] Architecture scorecards: pass/fail report card for your agent topology against OWASP Agent Top 10

### v1.3 — Real-Time IDE Integration

Shift left all the way to the editor. v1.3 ships a Language Server Protocol (LSP) plugin that surfaces findings inline as you write code — before you even save the file.

- [ ] VS Code and Cursor extensions with inline squiggles and fix suggestions
- [ ] Pre-commit hook: `agentwall scan --staged` blocks commits with CRITICAL findings
- [ ] `# agentwall: safe` suppression with mandatory justification comment
- [ ] Fix suggestions as code actions: one-click remediation for AW-MEM-001, AW-TOOL-001
- [ ] Team baseline: commit a `.agentwall.yml` policy file that all developers inherit

### v1.4 — Live Vector Store Probing

Static analysis tells you the code is wrong. Live probing tells you the running system is exposed. v1.4 introduces authenticated probes against live vector store instances to verify isolation guarantees at the data layer — not just the code layer.

- [ ] Cross-tenant probe: attempt to retrieve user A's vectors as user B, report if successful
- [ ] Injection resistance probe: insert canary payloads and verify they don't surface in other users' contexts
- [ ] Permission probe: verify API-key-scoped collections enforce the assumed access control model
- [ ] Works against: Chroma, PGVector, Pinecone, Qdrant, Weaviate, Neo4j
- [ ] Safe by design: probes use isolated canary namespaces, never touching real user data

### v2.0 — Continuous Security Monitoring

Agents in production change. New tools get added, memory backends get swapped, framework versions get bumped. v2.0 extends AgentWall from a one-time scan into a continuous compliance monitor.

- [ ] GitHub App: comments on every PR with a security diff ("2 new findings, 1 resolved")
- [ ] Drift detection: alert when a previously-clean deployment introduces new memory access patterns
- [ ] CVE watch: notify when a new framework / vector store CVE matches your dependency version
- [ ] Security posture over time: trend charts for finding count, severity distribution, MTTR
- [ ] Policy-as-code: `.agentwall.yml` defines org-wide rules, exemptions, and escalation thresholds
- [ ] SIEM integration: push findings to Datadog, Splunk, or PagerDuty for security team workflows

### v2.1 — Compliance & Audit Trails

Enterprise teams need to prove to auditors that their agent systems are secure. v2.1 makes AgentWall the evidence layer for AI compliance.

- [ ] OWASP LLM Top 10 mapping: every finding cross-referenced to the relevant OWASP category
- [ ] SOC 2 evidence export: scan history as a compliance artifact for Type II audits
- [ ] GDPR memory audit: identify all code paths where user PII enters or persists in vector stores
- [ ] HIPAA agent checklist: automated verification of PHI isolation requirements
- [ ] Audit trail signing: cryptographically signed scan reports for regulatory non-repudiation

### The North Star

```
v0.x  ──────►  v1.x  ──────►  v2.x
Static          Full            Continuous
Scanner         Ecosystem       Compliance

"Does my         "Is my           "Is my
 code leak?"      agent stack      fleet still
                  secure?"         secure?"
```

Every AI agent shipped to production passes an AgentWall scan — the way every web app runs OWASP ZAP, every container runs Trivy, and every Python package runs Bandit. **We are building the Trivy for AI agents.**

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
3. **[Request framework adapters](https://github.com/lukehungngo/agentwall/issues/new?template=adapter_request.yml)** — CrewAI, AutoGen, LlamaIndex, OpenAI

Join the [Discussions](https://github.com/lukehungngo/agentwall/discussions) to share scan results, vote on the roadmap, or request frameworks.

---

## License

MIT
