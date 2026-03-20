# AgentWall — Product Requirements Document v5

## Unified Product Specification, Market Analysis & Technical Architecture

**Version:** 5.0
**Date:** 2026-03-20
**Author:** SoH Engineering
**Status:** v0.x complete. Engine upgrade (V5) shipped. FP reduction Phase 1 shipped.
**Classification:** Internal — Confidential
**License:** MIT
**Previous:** PRD v4 (archived)

---

## Table of Contents

**Part I — Market Intelligence**
1. Market Landscape
2. Competitive Analysis
3. Threat Assessment & Attack Research
4. Strategic Positioning

**Part II — Scope Decisions**
5. What We Cut and Why
6. What We Keep and Why

**Part III — Product Specification**
7. Executive Summary
8. Product Vision
9. Target Persona
10. Functional Requirements
11. Non-Functional Requirements
12. Constraints
13. Potential Technical Blockages

**Part IV — Technical Architecture**
14. High-Level Architecture
15. Detection Pipeline (L0–L8)
16. Attack Vector Catalog
17. Directory Structure
18. Technology Stack
19. Data Flow
20. Data Model
20b. Engine Architecture (V5)
20c. Framework Model Schema

**Part V — AI Agent Integration**
21. Problem Statement
22. Target Integration Environments
23. Machine-Readable Output (FR-500)
24. Guided Remediation Engine (FR-510)
25. Agent Workflow Integration (FR-520)
26. Contextual Explanation Engine (FR-530)
27. AI Agent NFRs

**Part VI — Execution**
28. Product Vision & Versioned Roadmap
29. v0.x Delivery Status
30. Success Metrics
31. Risk Matrix
32. Growth Path

---

## PART I — MARKET INTELLIGENCE

### 1. Market Landscape

From PRD v2 Section 1:
- AI agent memory security is a new attack surface. No dedicated pre-deployment scanner exists.
- 73% of RAG-based applications use LangChain. 43% use ChromaDB as their vector store. Most do not implement per-user filtering on retrieval calls.
- The OWASP Top 10 for LLM Applications (2025) includes LLM08: Vector and Embedding Weaknesses. The OWASP Agentic Top 10 (2026) adds ASI06: Memory Poisoning.
- The vector database market is $3.2B (2025) growing to $8.6B by 2028 (source: MarketsandMarkets). Every deployment is a potential AgentWall user.
- Existing security tools (Snyk, Semgrep, CodeQL) have zero rules for vector store isolation, memory leakage, or embedding security. This is an uncontested market position.
- "First to own the scanner category for AI agent memory = first to own mindshare."

### 2. Competitive Analysis

From PRD v2 Section 2. This is a table format:

| Tool | What It Does | Memory Security Coverage | Gap AgentWall Fills |
|---|---|---|---|
| Snyk | SCA + SAST for traditional code | Zero vector store rules | First memory-specific scanner |
| Semgrep | Pattern-based SAST | Community rules for web vulns, none for RAG | Pre-built rules for memory leakage |
| CodeQL | Deep semantic analysis (GitHub) | No agent-specific queries | Agent memory taint analysis |
| Giskard | ML model testing (fairness, bias) | Some RAG testing | Not a scanner — test framework |
| Promptfoo | LLM red-teaming (prompt injection) | Some RAG poisoning tests | Runtime testing, not static code |
| OWASP Agent Memory Guard | Reference architecture | No scanner — just guidelines | Turns guidelines into enforcement |
| LangSmith | LLM observability | Traces, not security | Orthogonal — we scan, they trace |
| Lakera Guard | Runtime prompt injection detection | Some indirect injection | Runtime vs. our pre-deployment |

**Our moat:** AgentWall is the ONLY pre-deployment static scanner focused on AI agent memory security. Everyone else is runtime, generic SAST, or guidelines.

### 3. Threat Assessment & Attack Research

NEW — merged from Attack Vector Catalog:

AgentWall's detection domain covers 28 known attack vectors across 8 categories:

| Category | ID Range | Count | Description |
|---|---|---|---|
| MEM | AW-ATK-MEM-001–004 | 4 | Memory isolation & tenant leakage |
| POI | AW-ATK-POI-001–006 | 6 | Data & memory poisoning |
| EMB | AW-ATK-EMB-001–005 | 5 | Embedding & vector-level attacks |
| INJ | AW-ATK-INJ-001–003 | 3 | Indirect prompt injection via memory |
| EXF | AW-ATK-EXF-001–003 | 3 | Data exfiltration & inference |
| CFG | AW-ATK-CFG-001–006 | 6 | Infrastructure & configuration |
| DOS | AW-ATK-DOS-001–003 | 3 | Denial of service & resource exhaustion |
| AGT | AW-ATK-AGT-001–005 | 5 | Agentic-specific (tool, delegation, persistence) |

Key findings from research:
- **PoisonedRAG** (USENIX Security 2025): 5 poisoned documents can manipulate RAG responses with >90% success rate against KBs with millions of documents.
- **CorruptRAG** (2026): Single-document poisoning — only ONE document needed per target query.
- **MINJA** (NeurIPS 2025): Memory injection via query-only interaction, >95% injection success rate. No write access to KB required.
- **EchoLeak**: Single crafted email triggered Microsoft 365 Copilot to disclose confidential emails, files, and chat logs.
- **Embedding Inversion** (ACL 2024): Embeddings are NOT one-way — 50–70% of original input words recoverable from stored vectors.

OWASP mapping table:

| AgentWall Attack ID | OWASP LLM Top 10 (2025) | OWASP Agentic Top 10 (2026) |
|---|---|---|
| AW-ATK-MEM-* | LLM08 Vector & Embedding | — |
| AW-ATK-POI-* | LLM04 Data Poisoning | ASI06 Memory Poisoning |
| AW-ATK-EMB-* | LLM08 | — |
| AW-ATK-INJ-* | LLM01 Prompt Injection | ASI01 / ASI06 |
| AW-ATK-EXF-* | LLM06 Sensitive Info / LLM08 | — |
| AW-ATK-CFG-* | LLM08 | — |
| AW-ATK-AGT-* | LLM07 Insecure Plugins | ASI05 / ASI07 |

The full attack vector catalog with detailed descriptions, test cases, and references is maintained as a companion document: `AgentWall_Attack_Vector_Catalog.md`.

### 4. Strategic Positioning

From PRD v2 Section 4:

**Position:** "The `eslint` for AI agent memory security."

| Attribute | Our Bet |
|---|---|
| Focus | Memory security only (not generic SAST) |
| Delivery | CLI tool, pip-installable, offline by default |
| Speed | < 90 seconds for 50K LOC |
| Audience | AI engineers building RAG / agent systems |
| Business model | Open-source core (MIT), hosted dashboard later |
| Distribution | PyPI → GitHub → blog → Hacker News → word-of-mouth |
| Defensibility | First-mover in AI memory scanning + community rules |

---

## PART II — SCOPE DECISIONS

### 5. What We Cut and Why

From PRD v2 Section 5:

| Cut | Rationale |
|---|---|
| Action Analyzer | Agent action-level security is a separate concern. Memory + Tool first. |
| Trace Analyzer | Requires runtime observation. Out of scope for static pre-deployment scanner. |
| Multi-framework support (CrewAI, AutoGen) | LangChain covers 73% of market. Others are v1.0. LlamaIndex: framework model added in v0.x (adapter pending). |
| Multi-vector-store support (Milvus, Pinecone, Weaviate, PGVector) | ChromaDB covers 43% of market. Others are v1.0. |
| Policy-as-code engine | Over-engineering for v1. Hardcode sensible defaults. |
| HTML report | Nice-to-have. Terminal + JSON + SARIF covers the launch. |
| Plugin system | Over-engineering. Rules ship in the package. |
| Cloud dashboard | Requires infrastructure. Post-traction feature. |

### 6. What We Keep and Why

From PRD v2 Section 6:

| Keep | Rationale |
|---|---|
| Memory Analyzer | Core detection engine — finds the real bugs |
| Tool Analyzer | Second highest-value finding category |
| LangChain adapter | 73% market coverage |
| ChromaDB adapter | 43% market coverage, easiest to test |
| Terminal reporter | Human-readable output (the default) |
| JSON reporter | Machine-readable for CI pipelines |
| SARIF reporter | GitHub Security tab integration |
| 27+ rules across 8 categories (MEM, TOOL, SEC, RAG, MCP, SER, AGT, CFG) | Minimum viable rule set for launch |
| 9-Layer Detection Pipeline (L0–L8) | Differentiator — no other tool has multi-layer memory analysis |
| AI Agent Integration (agent-json, MCP) | Primary users are AI agents, not humans |

---

## PART III — PRODUCT SPECIFICATION

### 7. Executive Summary

AgentWall is a pre-deployment memory security scanner for AI agents. It analyzes Python codebases to detect memory leakage, tenant isolation failures, unsafe vector store configurations, and tool-use vulnerabilities before they reach production.

Install with `pip install agentwall`. Run with `agentwall scan .`. Get findings in terminal, JSON, SARIF, agent-json, or patch format. Fix findings manually or let your AI coding agent fix them using the guided remediation output.

One person. One sprint cycle. MIT license. Ship it.

### 8. Product Vision

```
v0.x  ──────►  v1.x  ──────►  v2.x
Static          Full            Continuous
Scanner         Ecosystem       Compliance

"Does my         "Is my           "Is my
 code leak?"      agent stack      fleet still
                  secure?"         secure?"
```

**v0.x (shipped):** A CLI tool that any developer or AI agent can run against a LangChain + ChromaDB project and get actionable memory security findings in under 90 seconds. 9 analysis layers (L0–L8), 27+ rules across 8 categories, 5 output formats. Engine upgrade (V5) adds model-driven property extraction, PyCG-style call graph with composition detection, and Pysa-style fixpoint tenant isolation verification.

**v1.x (next):** Multi-framework coverage (OpenAI Agents SDK, CrewAI, AutoGen, MCP). Agentic supply chain security. Architectural pattern enforcement. IDE integration. Live vector store probing.

**v2.x (future):** Continuous security monitoring. GitHub App with PR-level diffs. Drift detection. CVE watch. Policy-as-code. Compliance & audit trails (SOC 2, GDPR, HIPAA).

**The north star:** Every AI agent shipped to production passes an AgentWall scan — the way every web app runs OWASP ZAP, every container runs Trivy, and every Python package runs Bandit. **We are building the Trivy for AI agents.**

### 9. Target Persona

| Attribute | Value |
|---|---|
| Role | AI Engineer / Backend Developer building RAG or agent systems |
| Stack | Python, LangChain, ChromaDB, FastAPI, Docker |
| Pain | "I know my vector store has no per-user filtering but I don't know where to start fixing it" |
| Behavior | Uses CLI tools, runs linters in CI, trusts scan results that show file:line |
| Buying signal | Has a multi-tenant RAG app about to go to production |
| Secondary persona | AI coding agent (Claude Code, Codex, Cursor) acting on behalf of the above |

### 10. Functional Requirements

#### FR-100: Detection Engine (Memory Analyzer)

**FR-101: Memory Leakage Detection**
The system SHALL detect vector store retrieval calls that lack per-user metadata filtering.

Rules:
- AW-MEM-001: No tenant isolation on retrieval (CRITICAL)
- AW-MEM-002: Weak isolation — filter exists but not user-scoped (HIGH)
- AW-MEM-003: Vector store without access control (HIGH)
- AW-MEM-004: Unsafe defaults (allow_reset, debug mode) (MEDIUM)
- AW-MEM-005: No encryption at rest or in transit (MEDIUM)

**FR-102: Configuration Auditing**
The system SHALL scan configuration files (YAML, TOML, JSON, .env, Python) for insecure vector store settings. Covers all AW-ATK-CFG attack vectors.

Config targets:
| Config Target | Check | Finding |
|---|---|---|
| ChromaDB | `allow_reset=True` in production | AW-MEM-004 |
| ChromaDB | No authentication configured | AW-MEM-005 |
| `.env` / `settings.py` | `DEBUG=True`, `ALLOW_RESET=True` | AW-MEM-004 |
| `docker-compose.yml` | Vector DB port exposed to `0.0.0.0` | AW-MEM-005 |
| Connection strings | No TLS/SSL (`?sslmode=disable`) | AW-MEM-005 |
| API keys | Hardcoded credentials in source/config | AW-ATK-CFG-004 |

#### FR-200: Detection Engine (Tool Analyzer)

**FR-201: Tool-Use Vulnerability Detection**
The system SHALL detect insecure tool definitions and invocations.

Rules:
- AW-TOOL-001: Unbounded tool permissions (CRITICAL)
- AW-TOOL-002: No input validation on tool parameters (HIGH)
- AW-TOOL-003: Tool output not sanitized before LLM consumption (HIGH)
- AW-TOOL-004: Sensitive operations without confirmation (MEDIUM)
- AW-TOOL-005: Tool definition allows code execution (MEDIUM)

#### FR-300: Reporting

**FR-301: Terminal Reporter** — Human-readable colored output with severity, file:line, description, remediation hint.

**FR-302: JSON Reporter** — Machine-parseable output with all finding fields. Pydantic model serialization.

**FR-303: SARIF Reporter** — SARIF v2.1.0 compliant output for GitHub Security tab. Includes AgentWall-specific properties in the `properties` bag.

**FR-304: Agent-JSON Reporter** — AI agent-optimized output (see Part V, FR-501).

**FR-305: Patch Reporter** — Unified diff output for auto-fixable findings (see Part V, FR-502).

#### FR-400: Framework & Adapter Support

**FR-401:** LangChain adapter (v0.2+) — detects retrieval patterns, chain construction, memory modules.

**FR-402:** ChromaDB adapter — detects collection creation, query patterns, settings.

**FR-403 (v1.0):** Additional framework adapters: CrewAI, AutoGen, LlamaIndex.

**FR-404 (v1.0):** Additional vector store adapters: Milvus, Pinecone, PGVector, Qdrant, Weaviate.

### 11. Non-Functional Requirements

| ID | Requirement | Target |
|---|---|---|
| NFR-01 | Total scan time (L0–L5, 50K LOC) | < 90 seconds |
| NFR-02 | L0–L1 only scan time (50K LOC) | < 10 seconds |
| NFR-03 | Memory usage | < 500 MB peak |
| NFR-04 | Zero network calls in default mode | Mandatory |
| NFR-05 | Python version support | 3.10, 3.11, 3.12, 3.13 |
| NFR-06 | Test coverage | > 80% line coverage |
| NFR-07 | `pip install agentwall` installs core (L0–L2, L4 YAML/TOML) | No optional deps required for basic scan |
| NFR-08 | CLI --help usable without reading docs | Mandatory |
| NFR-09 | False positive rate (benchmark suite) | < 15% |
| NFR-10 | True positive rate (benchmark suite) | > 85% |
| NFR-11 | SARIF v2.1.0 compliance | Mandatory |

Layer-specific NFRs:

| NFR | Target |
|---|---|
| L2 call graph build time (50K LOC) | < 10 seconds |
| L3 taint analysis time (50K LOC) | < 60 seconds |
| L4 config scan time | < 2 seconds |
| L5 Semgrep scan time (50K LOC) | < 30 seconds |
| L8 LLM scoring per finding (local) | < 5 seconds |
| L8 LLM scoring per finding (API) | < 3 seconds |
| Memory overhead per additional layer | < 100 MB |

### 12. Constraints

| ID | Constraint | Impact |
|---|---|---|
| C-01 | Solo engineer — one person builds and ships everything | Scope must be aggressively small. No speculative features. |
| C-02 | No external infrastructure (no cloud, no database, no auth) | CLI tool only. All analysis local. |
| C-03 | Python-only codebase analysis | No JavaScript, Go, Rust, Java agent support (v1). |
| C-04 | LangChain-first | Other frameworks are v1.0. 73% market coverage justifies this bet. |
| C-05 | Offline by default | Zero network calls unless user opts into LLM-assist (L8). |
| C-06 | Diff generation requires precise source ranges | Off-by-one line numbers produce broken patches. Must track exact AST locations. |
| C-07 | Framework API surface is large | Start with top 3 patterns per framework. Community contributes the long tail. |
| C-08 | AI agents have varying tool-use capabilities | Support CLI, MCP, and Python SDK integration modes. |
| C-09 | Remediation plans may conflict | Engine must detect conflicts and merge or sequence changes. |

### 13. Potential Technical Blockages

From PRD v2 Section 13:

| # | Blockage | Mitigation |
|---|---|---|
| 1 | AST parsing breaks on dynamic imports / metaprogramming | Skip unparseable files with warning. L8 LLM fallback for ambiguous patterns. |
| 2 | False positive rate too high for CI gating | Confidence scoring (L8). Suppression via `agentwall.yaml`. `--fail-on critical` to only gate on high-confidence findings. |
| 3 | SARIF schema complexity | Use existing `sarif-tools` library. Start with minimal valid SARIF and iterate. |
| 4 | Cross-file analysis too slow | L2 call graph is opt-in. `--fast` flag runs L0–L1 only (< 10s). |
| 5 | LLM-assist costs spiral | Capital-aware routing: regex → Ollama → API. Default is offline (no LLM). |

---

## PART IV — TECHNICAL ARCHITECTURE

### 14. High-Level Architecture

```
┌──────────────────────────────────────────────────────────────┐
│                     AI AGENT / HUMAN USER                     │
│                                                              │
│  reads system prompt fragment / runs CLI                      │
│  calls agentwall via CLI / MCP / Python SDK                  │
└──────┬────────────────┬────────────────┬─────────────────────┘
       │ CLI            │ MCP            │ Python SDK
       ▼                ▼                ▼
┌──────────────────────────────────────────────────────────────┐
│                     INTERFACE LAYER                            │
│  CLIApp (Typer)    MCPServer (MCP)     Scanner (importable)  │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                   DETECTION PIPELINE                          │
│                                                              │
│  L0  Regex / Import Matching         (framework detection)   │
│  L1  Single-File AST Visitor         (kwarg inspection)      │
│  L2  Inter-Procedural Call Graph     (cross-file resolution) │
│  L3  Taint Analysis                  (source → sink flow)    │
│  L4  Config Auditing                 (infra misconfiguration)│
│  L5  Semgrep Rules                   (declarative patterns)  │
│  L6  Symbolic / Abstract Interp.     (path-sensitive)        │
│  L7  Runtime Instrumentation         (dynamic, opt-in)       │
│  L8  LLM-Assisted Confidence         (ambiguity resolver)   │
│                                                              │
│  Each layer feeds findings into the same PolicyEngine.       │
│  Layers are additive — higher layers refine, not replace.    │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│              APPLICATION SECURITY MODEL (ASM)                 │
│  Extractors → Graph (EntryPoint, WriteOp, Store, ReadOp,    │
│               Sink, AuthBoundary) → Query Engine              │
│  Produces semantic-level findings with path witnesses.       │
│  Confirmed / Possible / Uncertain proof strength.            │
│  See: docs/APPLICATION_SECURITY_MODEL.md                     │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                    ENGINE LAYER (V5)                           │
│  frameworks/   → Declarative framework models (per-framework)│
│  engine/       → General analysis engines (built once)        │
│    extractor   → L1: value classification + property extract │
│    graph       → L2: PyCG call graph + composition detection │
│    verifier    → L3: fixpoint tenant isolation verification  │
│    pathcov     → L6: path coverage aggregation               │
└──────────────────────┬───────────────────────────────────────┘
                       │
                       ▼
┌──────────────────────────────────────────────────────────────┐
│                   OUTPUT FORMATTERS                            │
│  Terminal   JSON   SARIF   AgentJSON   Patch                 │
│  + Explain  + Verify  + PromptFragment  + Schema             │
└──────────────────────────────────────────────────────────────┘
```

### 15. Detection Pipeline (L0–L8)

**Design principle:** Each layer is independently deployable. CI users run L0–L2. Full audit runs L0–L5. L6–L8 are opt-in.

#### L0 — Regex / Import Matching
**Status:** Implemented
**Purpose:** Framework detection
**Method:** Frequency-scored import counting with `_SKIP_DIRS` filtering
**Output:** `FrameworkType` enum → selects adapter

#### L1 — Single-File AST Visitor
**Status:** Implemented
**Purpose:** Detect missing filter kwargs on retrieval calls within a single file
**Method:** `ast.NodeVisitor` walks each `.py` file independently
**Limitation:** Cannot follow function calls across file boundaries

#### L2 — Inter-Procedural Call Graph
**Status:** Implemented (V5 upgrade: PyCG-style assignment graph + LCEL/factory/decorator composition + single-level inheritance)
**Purpose:** Resolve method calls across files to trace the full retrieval chain
**Priority:** HIGH — biggest detection gap closer after L0–L1
**Approach:** Custom PyCG-style assignment graph (zero deps). Handles LCEL pipe operator, factory patterns, decorator composition, and single-level inheritance.
**Data Model:**
```python
@dataclass
class ProjectGraph:
    call_edges: list[CallEdgeV2]         # caller→callee with arg_names
    composition_edges: list[CompositionEdge]  # pipe, factory, decorator
    identifiers: dict[str, IdentifierState]  # PyCG pointsto sets
    extends: dict[str, str]              # single-level inheritance
    unresolved: list[UnresolvedCall]     # honest uncertainty
```
**Integration:** L1 findings where `has_metadata_filter_on_retrieval = False` are post-processed by L2 — if filter found upstream in call chain, downgrade to INFO.

#### L3 — Taint Analysis
**Status:** Implemented (V5 — per-function summaries + fixpoint iteration, scoped to tenant isolation)
**Purpose:** Track whether user identity flows from request entry point to retrieval filter
**Priority:** HIGH — definitive answer to "is this actually isolated?"
**Approach:** Pysa-style fixpoint iteration implemented in engine/verifier.py. Three-phase: (1) intraprocedural summaries, (2) interprocedural fixpoint propagation via call graph arg_names, (3) per-store verdict emission.
**Taint Model:**
- Sources: `request.user`, `session.user_id`, `current_user`, params named `user_id`/`tenant_id`/`org_id`
- Sinks: `similarity_search(filter=TAINTED)`, `collection.query(where=TAINTED)`
- Verdict: source reaches sink → ISOLATED. Source never reaches sink → AW-MEM-001 CRITICAL.

#### L4 — Configuration Auditing
**Status:** Implemented
**Purpose:** Detect insecure vector store and infrastructure configuration
**Method:** Pure file parsing (YAML, TOML, JSON, .env, Python config)
**Checks:** 12+ insecure patterns across ChromaDB, Milvus, PGVector, Pinecone, Qdrant, Weaviate, docker-compose, connection strings

#### L5 — Semgrep Rules
**Status:** Implemented
**Purpose:** Declarative, community-maintainable detection rules
**Dependency:** Optional (`pip install agentwall[semgrep]`)
**Ships with:** 10+ YAML rules covering AW-MEM-001 through AW-MEM-005
**User extensible:** Custom rules via `agentwall.yaml` → `semgrep_rules_dir`

#### L6 — Symbolic / Abstract Interpretation
**Status:** Implemented (V5 — path coverage aggregation over L3 verifications)
**Purpose:** Path-sensitive analysis — determine if filter is always applied, not just sometimes
**When to activate:** Only if FP rate from L1+L2+L3 exceeds 15%
**Approach:** FilterState lattice: TOP → FILTERED/UNFILTERED → BOTTOM

#### L7 — Runtime Instrumentation
**Status:** Implemented (opt-in)
**Purpose:** Observe actual retrieval calls at runtime
**CLI:** `agentwall scan ./project --dynamic`
**Method:** Monkey-patch `similarity_search`, `get_relevant_documents` at import time
**Positioned as:** Premium feature for confirmed (not theoretical) findings

#### L8 — LLM-Assisted Confidence Scoring
**Status:** Implemented
**Purpose:** Reduce false positives by semantic judgment of ambiguous patterns
**Capital-aware routing:**
1. Regex heuristic first (resolves ≥60% of cases)
2. Local model (Ollama `codellama:7b`) for ambiguous cases
3. API call (Claude Haiku) only if local returns AMBIGUOUS — opt-in only

### 16. Attack Vector Catalog

28 attack vectors across 8 categories. Full catalog with descriptions, test cases, preconditions, references, and OWASP mappings maintained in companion document: `AgentWall_Attack_Vector_Catalog.md`.

**Current Detection Coverage (verified 2026-03-18, 10/32 vectors):**

| Attack Vector | Detected By | Status | Real-World Evidence |
|---|---|---|---|
| AW-ATK-MEM-001 (no filter) | L1 AST + L3 Taint + L5 Semgrep | ✅ Reliable | 57 hits across 8 projects |
| AW-ATK-MEM-002 (weak filter) | L1 AST + L3 Taint | ✅ Reliable | 4 hits across 3 projects |
| AW-ATK-MEM-003 (namespace confusion) | L1 AST | ✅ Reliable | 19 hits across 6 projects |
| AW-ATK-MEM-004 (partition bypass) | L4 Config (heuristic) | ✅ Partial | Docker port/auth checks only |
| AW-ATK-INJ-001 (stored injection) | AW-MEM-005 / L1+L5 | ✅ Partial | 19 hits (sanitization absence) |
| AW-ATK-CFG-001 (unsafe reset) | L4 Config regex | ✅ Reliable | Fixture-only |
| AW-ATK-CFG-003 (no TLS/auth) | L4 Config regex | ✅ Reliable | 7 hits across 4 projects |
| AW-ATK-CFG-004 (hardcoded keys) | L4 Config regex | ✅ Reliable | 45 hits across 8 projects |
| AW-ATK-AGT-001 (unsafe tools) | AW-TOOL-001–003 / L1 | ✅ Reliable | 4 hits across 2 projects |
| AW-ATK-CFG-002 (no encryption) | — | ❌ Not detected | Needs config schema audit |
| AW-ATK-CFG-005 (no RBAC) | — | ❌ Not detected | Needs vector DB audit |
| AW-ATK-CFG-006 (no RLS) | — | ❌ Not detected | Needs PostgreSQL audit |
| AW-ATK-POI-* (poisoning, 6 vectors) | — | ❌ Out of reach | Requires runtime |
| AW-ATK-EMB-* (embedding, 5 vectors) | — | ❌ Out of reach | Requires model invocation |
| AW-ATK-EXF-* (exfiltration, 3 vectors) | — | ❌ Out of reach | Requires runtime |
| AW-ATK-DOS-* (DoS, 3 vectors) | — | ❌ Not detected | Needs rate-limit/bounds audit |
| AW-ATK-AGT-002–005 (agentic, 4 vectors) | — | ❌ Out of scope | Requires multi-agent analysis |
| AW-ATK-INJ-002–003 (injection, 2 vectors) | — | ❌ Out of scope | Requires session/action tracing |

**Detection Matrix by Layer:**

| Rule | L0 | L1 | L2 | L3 | L4 | L5 | L6 | L7 | L8 |
|---|---|---|---|---|---|---|---|---|---|
| AW-MEM-001 | — | Detect | Confirm | Prove | — | Detect | Path-split | Runtime | Score |
| AW-MEM-002 | — | — | — | Detect | — | — | Detect | Runtime | Score |
| AW-MEM-003 | — | Detect | — | — | Detect | Detect | — | Runtime | — |
| AW-MEM-004 | — | — | — | — | Detect | Detect | — | — | — |
| AW-MEM-005 | — | — | — | — | Detect | Detect | — | — | — |

### 17. Directory Structure

```
agentwall/
├── pyproject.toml
├── LICENSE                          # MIT
├── README.md
├── BENCHMARK.md                     # 20-project benchmark results
├── BENCHMARK3000.md                 # 107-project benchmark results
├── src/
│   └── agentwall/
│       ├── __init__.py
│       ├── cli.py                   # Typer CLI (scan, verify)
│       ├── scanner.py               # Orchestrator — wires L0–L8
│       ├── models.py                # Finding, AgentSpec, ASM models, CallGraph, TaintResult
│       ├── patterns.py              # Shared detection constants
│       ├── rules.py                 # 27+ rule definitions (AW-MEM/TOOL/SEC/RAG/MCP/SER/AGT)
│       ├── context.py               # AnalysisContext (shared mutable state)
│       ├── detector.py              # Framework auto-detection
│       ├── postprocess.py           # dedup, file context, sort
│       ├── version_resolver.py      # Version-aware rule modifiers
│       │
│       ├── engine/                  # V5: General analysis engines
│       │   ├── models.py            # ValueKind, StoreProfile, TenantFlowSummary, etc.
│       │   ├── extractor.py         # L1: model-driven property extraction
│       │   ├── graph.py             # L2: PyCG-style call graph + composition
│       │   ├── verifier.py          # L3: fixpoint tenant isolation verification
│       │   └── pathcov.py           # L6: path coverage aggregation
│       │
│       ├── frameworks/              # V5: Declarative framework models
│       │   ├── base.py              # FrameworkModel, StoreModel, Pattern schemas
│       │   ├── langchain.py         # LangChain model (12 vector stores)
│       │   └── llamaindex.py        # LlamaIndex model (3 vector stores)
│       │
│       ├── analyzers/               # 16 analyzers (L0–L8 + ASM)
│       │   ├── versions.py          # L0: version detection + CVE matching
│       │   ├── memory.py            # L1: AW-MEM-001..005 (engine FP reduction)
│       │   ├── tools.py             # L1: AW-TOOL-001..005
│       │   ├── secrets.py           # L1: AW-SEC-001,003 (FP-refined)
│       │   ├── serialization.py     # L1: AW-SER-001,003 (FP-refined)
│       │   ├── rag.py               # L1: AW-RAG-001..004
│       │   ├── mcp_security.py      # L1: AW-MCP-001..003
│       │   ├── agent_arch.py        # L2: AW-AGT-001..004
│       │   ├── callgraph.py         # L2: call graph (triggers engine)
│       │   ├── taint.py             # L3: taint analysis (triggers engine)
│       │   ├── config.py            # L4: config auditing (FP-refined)
│       │   ├── semgrep.py           # L5: declarative patterns
│       │   ├── symbolic.py          # L6: path-sensitive (triggers engine)
│       │   ├── asm.py               # ASM: graph-based queries
│       │   ├── runtime.py           # L7: runtime instrumentation (opt-in)
│       │   └── confidence.py        # L8: LLM confidence scoring (opt-in)
│       │
│       ├── adapters/                # Framework-specific AST → AgentSpec
│       │   ├── base.py              # AbstractAdapter protocol
│       │   └── langchain.py         # LangChain adapter
│       │
│       ├── extractors/              # ASM component extraction
│       │   ├── entry_points.py
│       │   ├── edge_linker.py
│       │   └── context_sinks.py
│       │
│       ├── reporters/               # Output formatters
│       │   ├── terminal.py
│       │   ├── json_reporter.py
│       │   ├── sarif.py
│       │   ├── agent_json.py
│       │   └── patch.py
│       │
│       ├── runtime/                 # L7 instrumentation
│       │   └── patcher.py
│       │
│       ├── semgrep_rules/           # L5 YAML rules
│       │   ├── memory.yaml
│       │   ├── tools.yaml
│       │   └── config.yaml
│       │
│       └── data/versions/           # Version-aware rule modifiers
│           └── (9 framework YAML files)
│
├── tests/                           # 39 test files, 623 tests
│   ├── test_engine_models.py        # V5 engine data models
│   ├── test_extractor.py            # V5 L1 engine
│   ├── test_graph.py                # V5 L2 engine
│   ├── test_verifier.py             # V5 L3 engine
│   ├── test_pathcov.py              # V5 L6 engine
│   ├── test_framework_model.py      # V5 framework models
│   ├── test_engine_integration.py   # V5 integration tests
│   ├── test_fp_reduction.py         # FP reduction regression tests
│   ├── test_memory_analyzer.py
│   ├── test_scanner.py
│   ├── ... (39 files total)
│   └── fixtures/                    # 26 fixture directories
│       ├── engine_basic/
│       ├── engine_tenant_collection/
│       ├── engine_static_filter/
│       ├── engine_cross_file/
│       ├── engine_lcel_pipe/
│       ├── engine_factory/
│       ├── engine_inheritance/
│       ├── engine_branching/
│       ├── langchain_basic/
│       ├── langchain_safe/
│       ├── ... (26 dirs total)
│
├── docs/
│   ├── ARCHITECTURE_V5.md           # V5 engine architecture
│   ├── COMPETITIVE_ANALYSIS.md
│   ├── ATTACK_VECTOR_CATALOG.md
│   └── superpowers/specs/           # Design specs
│
├── prd/                             # Product requirements
│   ├── AgentWall_PRD_v5.md          # This document
│   └── (previous versions)
│
└── scripts/
    ├── benchmark.sh                 # 20-project benchmark
    └── benchmark3000.sh             # 107-project benchmark
```

### 18. Technology Stack

| Component | Choice | Rationale |
|---|---|---|
| Language | Python 3.10+ | Same ecosystem as target users |
| CLI | Typer | Modern, typed CLI framework |
| AST | stdlib `ast` | Zero deps for core analysis |
| Config parsing | `pyyaml`, `tomllib` (stdlib 3.11+) | Config auditing |
| Call graph | Custom PyCG-style (stdlib `ast`) | Zero-dep, handles LCEL/factory/decorator |
| Semgrep (optional) | `semgrep` CLI | Community-maintainable rules |
| LLM (optional) | `ollama` / `anthropic` | Capital-aware confidence scoring |
| SARIF | `sarif-tools` or manual | GitHub Security integration |
| MCP | `mcp` SDK | AI agent protocol |
| Testing | `pytest` | Standard Python testing |
| Linting | `ruff` | Fast Python linter |
| Type checking | `mypy` (strict) | Correctness |
| Packaging | `hatch` / `uv` | Modern Python packaging |

**Install extras:**
```
pip install agentwall              # Core: L0, L1, L2 (custom), L4 (YAML/TOML)
pip install agentwall[semgrep]     # + L5 Semgrep rules
pip install agentwall[callgraph]   # + L2 enhanced (jedi)
pip install agentwall[llm]         # + L8 LLM-assist (ollama/anthropic)
pip install agentwall[config]      # + L4 extended (.env, dotenv)
pip install agentwall[all]         # Everything
```

### 19. Data Flow

```
Target Codebase
    │
    ▼
[L0: Framework Detection] → "langchain" | None
    │
    ▼
[Adapter: LangChainAdapter.parse()] → AgentSpec (tools, memory_configs, ASM)
    │
    ├──── OLD PATH ────────────────┐  ┌──── ENGINE PATH (V5) ─────────┐
    │                              │  │                                │
    ▼                              │  │                                │
[L1: AST Analyzers]                │  │                                │
  Memory, Tool, Secret,            │  │                                │
  Serialization, RAG, MCP,         │  │                                │
  Agent Arch                       │  │                                │
  → per-file findings              │  │                                │
    │                              │  │                                │
    ▼                              │  │                                │
[L2: CallGraphAnalyzer] ───────────┼──┤ build_project_graph()          │
  build_call_graph()               │  │ → ctx.project_graph            │
  → ctx.call_graph                 │  │ (call + composition + extends) │
    │                              │  │                                │
    ▼                              │  │                                │
[L3: TaintAnalyzer] ───────────────┼──┤ extract_properties()           │
  _TaintVisitor                    │  │ → ctx.store_profiles           │
  → ctx.taint_results              │  │                                │
                                   │  │ verify_tenant_isolation()      │
                                   │  │ → ctx.property_verifications   │
    │                              │  │                                │
    ▼                              │  │                                │
[L4: ConfigAuditor] (infra)        │  │                                │
[L5: SemgrepAnalyzer] (patterns)   │  │                                │
    │                              │  │                                │
    ▼                              │  │                                │
[L6: SymbolicAnalyzer] ────────────┼──┤ compute_path_coverage()        │
  _PathAnalyzer (lattice)          │  │ → ctx.path_coverages           │
    │                              │  │                                │
    └──────────────────────────────┘  └────────────────────────────────┘
    │
    ▼
[ASM: Graph Queries] → evidence_path findings
    │
    ▼
[L7: Runtime] (opt-in) → dynamic findings
[L8: LLM Confidence] (opt-in) → FP reduction
    │
    ▼
[Postprocess] → dedup → file context → sort
    │
    ▼
[Reporter] → Terminal | JSON | SARIF | AgentJSON | Patch
```

### 20. Data Model

```python
@dataclass
class Finding:
    rule_id: str           # AW-MEM-001
    severity: Severity     # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    description: str
    location: Location     # file, line, column, function, class
    evidence: Evidence     # code_snippet, explanation, data_flow
    confidence: Confidence # HIGH, MEDIUM, LOW
    attack_vector: str | None  # AW-ATK-MEM-001 (link to catalog)
    remediation: Remediation   # summary, framework_specific, verification
    related_findings: list[str]

@dataclass
class ScanResult:
    scan_id: str
    timestamp: str
    target: Path
    framework: FrameworkType
    findings: list[Finding]
    suppressed: list[str]
    scan_config: ScanConfig
    scan_duration_ms: int

@dataclass
class ScanConfig:
    rules: list[str]
    layers: list[str]        # ["L0", "L1", "L2", ...]
    dynamic: bool            # --dynamic flag
    llm_assist: bool         # --llm-assist flag
    fast: bool               # --fast (L0-L1 only)

@dataclass
class RemediationPlan:
    finding_id: str
    steps: list[RemediationStep]
    estimated_files_changed: int
    estimated_lines_changed: int
    breaking_change: bool
    breaking_change_reason: str | None

@dataclass
class RemediationStep:
    order: int
    action: str
    file: str
    function: str | None
    description: str
    diff: str | None
    confidence: FixConfidence  # AUTO, GUIDED, MANUAL
```

#### 20b. Engine Data Models (V5)

```python
class ValueKind(str, Enum):
    LITERAL = "literal"           # "global_docs", 42
    DYNAMIC = "dynamic"           # variable reference
    TENANT_SCOPED = "tenant"      # contains tenant identifier
    COMPOUND_STATIC = "cstatic"   # dict with all literal values
    COMPOUND_DYNAMIC = "cdynamic" # dict with at least one dynamic value
    COMPOUND_TENANT = "ctenant"   # dict with at least one tenant-scoped value

@dataclass
class StoreProfile:
    store_id: str
    backend: str
    collection_name_kind: ValueKind
    extractions: list[PropertyExtraction]
    isolation_strategy: IsolationStrategy  # COLLECTION_PER_TENANT | FILTER_ON_READ | NONE

@dataclass
class PropertyVerification:
    store_id: str
    verdict: Verdict  # VERIFIED | VIOLATED | UNKNOWN
    evidence: list[FlowStep]

@dataclass
class PathCoverage:
    store_id: str
    verified_paths: list[VerifiedPath]
    violated_paths: list[ViolatedPath]
    coverage_ratio: float
```

#### 20c. Framework Model Schema (V5)

```python
@dataclass
class FrameworkModel:
    name: str                         # "langchain"
    stores: dict[str, StoreModel]     # 12 vector store definitions
    pipe_patterns: list[PipePattern]  # LCEL "|" operator
    factory_patterns: list[FactoryPattern]
    decorator_patterns: list[DecoratorPattern]
    tenant_param_names: list[str]     # ["user_id", "tenant_id", ...]

@dataclass
class StoreModel:
    backend: str                      # "chromadb"
    isolation_params: list[str]       # ["collection_name"]
    read_methods: dict[str, str]      # {"similarity_search": "filter"}
    write_methods: dict[str, str]     # {"add_texts": "metadata"}
    has_builtin_acl: bool             # False for FAISS
```

Adding a new vector store = add a dict entry. Adding a new framework = write a ~50-line model file. Zero engine changes.

---

## PART V — AI AGENT INTEGRATION

### 21. Problem Statement

AgentWall's primary users will not run the tool manually. They will instruct an AI coding agent:

```
"Scan this project for memory security issues and fix them."
```

Today's output is designed for human eyes. AI agents face:
- **Ambiguous remediation** — "Add metadata filtering" — which calls? What filter shape?
- **No structured diff** — no before/after code change
- **No verification protocol** — no way to confirm a specific finding resolved
- **No codebase context** — no understanding of how `user_id` flows through the system
- **No framework-specific fixes** — LangChain, CrewAI, OpenAI SDK each have different APIs

This is a first-class product problem. If AI agents can't act on the output, adoption stalls.

### 22. Target Integration Environments

| Agent | How It Runs AgentWall | What It Needs |
|---|---|---|
| Claude Code | Bash → `agentwall scan . --format agent-json` | JSON, file paths, line numbers, fix suggestions |
| Codex | Shell command in sandbox | Same + exit codes for pass/fail |
| OpenClaw | Frontline agent delegates to tool-use agent | Structured findings as executable steps |
| Cursor / Windsurf | Terminal panel or plugin | SARIF + inline fix suggestions |
| Aider | Shell + file context | Diff-ready patches per finding |
| Devin | Autonomous sandbox execution | Full scan → fix → verify loop |
| GitHub Copilot Workspace | CI/CD integration | SARIF upload to GitHub Security tab |
| Custom MAS | Python SDK import | Typed return values |

### 23. Machine-Readable Output (FR-500)

**FR-501: Agent-Optimized JSON (`--format agent-json`)**

Key fields beyond standard JSON:
- `attack_vector` — links finding to catalog entry
- `evidence.data_flow` — cross-file call chain
- `remediation.framework_specific` — per-framework before/after code with diff
- `remediation.framework_specific.dependencies` — prerequisite changes
- `remediation.verification` — re-scan command + expected result
- `related_findings` — group findings sharing root cause
- `false_positive_hint` — when to suppress

**FR-502: Unified Diff Output (`--format patch`)**
```bash
agentwall scan . --format patch > fixes.patch
git apply fixes.patch
```
For auto-fixable findings: generate diff. For architectural changes: produce TODO comment.

**FR-503: SARIF with AI Extensions**
Custom properties in SARIF `properties` bag: `agentwall:attack_vector`, `agentwall:framework_fix`, `agentwall:diff`, `agentwall:dependencies`, `agentwall:verification_command`.

### 24. Guided Remediation Engine (FR-510)

**FR-511: Remediation Plan Generation**
For each finding, generate ordered list of changes with per-step diffs, file locations, and descriptions. Includes `estimated_files_changed`, `estimated_lines_changed`, `breaking_change` flag.

**FR-512: Fix Confidence Levels**

| Level | Meaning | AI Agent Action |
|---|---|---|
| AUTO | Fix can be applied mechanically | Apply directly |
| GUIDED | Pattern known, needs codebase adaptation | Apply with review |
| MANUAL | Requires architectural decision | Present to human |

**FR-513: Incremental Verification**
```bash
agentwall verify --finding AW-MEM-001-001
```
Fast single-finding re-check (< 3 seconds). Returns RESOLVED/UNRESOLVED status.

### 25. Agent Workflow Integration (FR-520)

**FR-521: Claude Code Integration**
Ships `.claude/commands/scan.md` template:
1. Run `agentwall scan . --format agent-json`
2. For AUTO/GUIDED findings: apply diff, verify
3. For MANUAL findings: add TODO comment
4. Re-scan to confirm

**FR-522: System Prompt Fragment**
```bash
agentwall prompt-fragment
```
Outputs reusable system prompt fragment for any AI agent.

**FR-523: MCP Server Mode**
```bash
agentwall mcp-serve
```
Exposes 4 MCP tools: `agentwall_scan`, `agentwall_verify`, `agentwall_explain`, `agentwall_remediation_plan`.

**FR-524: GitHub Actions Integration**
SARIF upload to GitHub Security tab + agent-readable JSON summary + PR comment.

### 26. Contextual Explanation Engine (FR-530)

**FR-531: Attack Vector Explanation**
```bash
agentwall explain AW-ATK-MEM-001
```
Returns structured explanation with severity, OWASP mapping, real-world evidence, test procedure, and impact description.

**FR-532: Codebase Context Enrichment**
Detects: authentication pattern, ingestion pipeline, existing filter patterns, test framework. Enables context-aware fixes matching project conventions.

### 27. AI Agent NFRs

| ID | Requirement | Target |
|---|---|---|
| NFR-50 | `--format agent-json` overhead vs plain JSON | < 20% |
| NFR-51 | `agentwall verify --finding X` execution time | < 3 seconds |
| NFR-52 | Remediation plan generation per finding | < 2 seconds |
| NFR-53 | MCP server cold start | < 3 seconds |
| NFR-54 | MCP server per-request latency | < 5s scan, < 1s explain/verify |
| NFR-60 | AUTO fix correctness | > 90% |
| NFR-61 | GUIDED fix relevance | > 80% |
| NFR-62 | Framework-specific API correctness | > 95% |
| NFR-63 | Codebase context detection accuracy | > 85% |
| NFR-70 | Agent-JSON schema backward compatibility | Semver |
| NFR-71 | MCP protocol compliance | MCP v1.0+ |
| NFR-80 | Zero ambiguity in remediation steps | Mandatory |
| NFR-81 | All file paths absolute or relative to scan root | Mandatory |
| NFR-82 | Code snippets include 5 lines context | Mandatory |
| NFR-83 | Structured error codes | Mandatory |
| NFR-84 | Schema self-documenting (`agentwall schema`) | Mandatory |
| NFR-90 | MCP server SHALL NOT execute arbitrary code | Mandatory |
| NFR-91 | Patch SHALL NOT modify files outside scan target | Mandatory |
| NFR-92 | Agent-JSON SHALL NOT include raw secrets | Mandatory |

---

## PART VI — EXECUTION

### 28. Product Vision & Versioned Roadmap

> **Current Position (2026-03-20):** v0.x complete + V5 engine upgrade shipped. 623 tests passing across 39 test files. Benchmark run on 107 real-world projects (BENCHMARK3000): 1,280 findings (147 CRITICAL) across 29,238 files. 9/35 attack vectors detected. FP reduction Phase 1 eliminated 159 findings (12.4% reduction). Engine layer adds model-driven property extraction (L1), PyCG-style call graph with LCEL/factory/decorator composition (L2), fixpoint tenant isolation verification (L3), and path coverage aggregation (L6). Framework model validated: LlamaIndex added with zero engine changes.

**The v0.x releases establish the foundation. What follows is the full vision for AgentWall as the definitive security layer for every AI agent ever shipped.**

```
v0.x  ──────►  v1.x  ──────►  v2.x
Static          Full            Continuous
Scanner         Ecosystem       Compliance

"Does my         "Is my           "Is my
 code leak?"      agent stack      fleet still
                  secure?"         secure?"
```

---

#### v0.x — Static Scanner ✅ COMPLETE

Core static scanner for LangChain + ChromaDB (+ LlamaIndex model). 9 analysis layers (L0–L8), 27+ detection rules across 8 categories (MEM, TOOL, SEC, RAG, MCP, SER, AGT, CFG), 5 output formats (terminal, JSON, SARIF, agent-json, patch). V5 engine upgrade: model-driven property extraction, PyCG-style call graph with composition detection, Pysa-style fixpoint verification, path coverage. FP reduction Phase 1 shipped. Benchmark expanded from 20 to 107 projects.

**What shipped:**

| Deliverable | Status |
|---|---|
| L0 regex framework detection | ✅ |
| L1 AST visitor (memory + tool analyzers) | ✅ |
| L2 inter-procedural call graph | ✅ |
| L3 taint analysis | ✅ |
| L4 config auditing | ✅ |
| L5 Semgrep rules (3 rule files) | ✅ |
| L6 symbolic / abstract interpretation | ✅ |
| L7 runtime instrumentation (`--dynamic`) | ✅ |
| L8 LLM confidence scoring (`--llm-assist`) | ✅ |
| Terminal, JSON, SARIF v2.1.0, agent-json, patch reporters | ✅ |
| `agentwall verify --finding` | ✅ |
| CLI with `--fail-on`, `--layers`, `--fast`, `--dynamic`, `--llm-assist` | ✅ |
| Benchmark: 20 real-world repos, 32 fixture tests | ✅ |
| PyPI packaging | ✅ |
| 623 tests (39 test files, 26 fixture dirs), ruff clean, mypy strict | ✅ |
| 2.0 | V5 engine data models | ValueKind, StoreProfile, PropertyVerification, etc. | ✅ Done |
| 2.1 | V5 framework model schema | FrameworkModel, StoreModel, Pattern schemas | ✅ Done |
| 2.2 | LangChain framework model | 12 vector stores, pipe/factory/decorator patterns | ✅ Done |
| 2.3 | L1 engine: property extractor | Model-driven value classification | ✅ Done |
| 2.4 | L2 engine: project graph | PyCG call graph + composition + inheritance | ✅ Done |
| 2.5 | L3 engine: fixpoint verifier | Tenant isolation verification | ✅ Done |
| 2.6 | L6 engine: path coverage | Aggregation over L3 verifications | ✅ Done |
| 2.7 | Engine wiring into analyzers | Backward-compatible integration | ✅ Done |
| 2.8 | LlamaIndex framework model | Abstraction validation (zero engine changes) | ✅ Done |
| 2.9 | AW-SEC/RAG/MCP/SER/AGT rules | 17 new rules across 5 categories | ✅ Done |
| 3.0 | FP-1: AW-SER-003 dict-lookup | Suppress dict-lookup dynamic imports | ✅ Done |
| 3.1 | FP-2: AW-SEC-003 content ref | Require content reference, not metadata | ✅ Done |
| 3.2 | FP-3: AW-MEM-001 per-tenant | Downgrade via engine StoreProfile | ✅ Done |
| 3.3 | FP-4: AW-CFG-hardcoded-secret | Skip templates, placeholders | ✅ Done |
| 3.4 | FP-5: AW-MEM-005 retrieval | Require retrieval path | ✅ Done |
| 3.5 | BENCHMARK3000 | 107 projects, 29,238 files, 1,280 findings | ✅ Done |

**Known gap:** Test coverage at 72% (target: 80%). Partially mitigated by engine upgrade test suite (95 new tests). Gap in L2 callgraph (56%), L8 confidence (44%), L7 runtime (26%).

---

#### v1.0 — Multi-Framework Coverage 🔲 NEXT

The agent ecosystem is fragmenting across LangChain, OpenAI Agents SDK, CrewAI, AutoGen, and emerging MCP-native agents. A single vulnerability class manifests differently in each framework. v1.0 ships a unified rule engine with per-framework adapters, so one scan command covers your entire polyglot agent codebase.

| Deliverable | FR | Status |
|---|---|---|
| OpenAI Agents SDK adapter (tool registration, handoff permissions, context scope) | FR-403 | ❌ |
| CrewAI adapter (crew-level vs. agent-level memory isolation, task permission boundaries) | FR-403 | ❌ |
| AutoGen adapter (multi-agent conversation memory, inter-agent trust levels) | FR-403 | ❌ |
| MCP tool permission auditing (server-level scope declarations, capability mismatches) | FR-403 | ❌ |
| Single `agentwall scan .` works across mixed-framework monorepos | — | ❌ |
| `agentwall explain` — structured attack vector + rule explanations | FR-531 | ❌ |
| `agentwall prompt-fragment` — system prompt fragment for AI agents | FR-522 | ❌ |
| Community rule registry — external Semgrep YAML rules via `agentwall.yaml` | — | ❌ |

**Why this first:** Framework + vector store expansion takes market coverage from ~35% (LangChain + ChromaDB only) to ~90%. Everything downstream (remediation templates, MCP server, supply chain scanning) becomes more valuable with broad framework support.

---

#### v1.1 — Agentic Supply Chain Security 🔲

Agents increasingly import third-party tools, retrievers, and memory plugins from PyPI and npm. A compromised package can silently remove your tenant filter or exfiltrate memory to an external endpoint. v1.1 treats the dependency graph as a first-class attack surface.

| Deliverable | Status |
|---|---|
| Dependency scanning: flag tool packages with known CVEs or suspicious releases | ❌ |
| Import graph analysis: detect third-party code paths that touch vector store retrieval | ❌ |
| Plugin integrity: verify tool packages against known-safe checksums | ❌ |
| Shadow tool detection: tools registered by imported libraries without explicit developer consent | ❌ |
| SCA report integrated into the existing SARIF output — one report for code + deps | ❌ |

---

#### v1.2 — Architectural Pattern Enforcement 🔲

Beyond individual findings, agents fail when their overall architecture violates isolation principles. v1.2 introduces architectural rules that reason about the full agent graph — not just individual files.

| Deliverable | Status |
|---|---|
| Multi-agent trust boundary analysis: agent A should not access agent B's memory namespace | ❌ |
| Context leak detection: user PII flowing from one agent's scratchpad to another's system prompt | ❌ |
| Privilege escalation paths: sub-agent inheriting parent's tool permissions without explicit grant | ❌ |
| Memory scope diagrams: auto-generated visualization of which agents can read/write which stores | ❌ |
| Architecture scorecards: pass/fail report card for agent topology against OWASP Agent Top 10 | ❌ |

---

#### v1.3 — Real-Time IDE Integration 🔲

Shift left all the way to the editor. v1.3 ships a Language Server Protocol (LSP) plugin that surfaces findings inline as you write code — before you even save the file.

| Deliverable | FR | Status |
|---|---|---|
| VS Code and Cursor extensions with inline squiggles and fix suggestions | — | ❌ |
| Pre-commit hook: `agentwall scan --staged` blocks commits with CRITICAL findings | — | ❌ |
| `# agentwall: safe` suppression with mandatory justification comment | — | ❌ |
| Fix suggestions as code actions: one-click remediation for AW-MEM-001, AW-TOOL-001 | — | ❌ |
| Team baseline: commit a `.agentwall.yml` policy file that all developers inherit | — | ❌ |
| MCP server (`agentwall mcp-serve`) — scan/verify/explain/remediate as MCP tools | FR-523 | ❌ |
| Guided remediation engine — context-aware fix generation (AUTO/GUIDED/MANUAL) | FR-511, FR-512 | ❌ |
| Codebase context enrichment — detect auth patterns, ingestion pipelines, test frameworks | FR-532 | ❌ |
| Claude Code integration template (`.claude/commands/scan.md`) | FR-521 | ❌ |
| GitHub Actions workflow — SARIF upload + PR comment + agent-json summary | FR-524 | ❌ |

---

#### v1.4 — Live Vector Store Probing 🔲

Static analysis tells you the code is wrong. Live probing tells you the running system is exposed. v1.4 introduces authenticated probes against live vector store instances to verify isolation guarantees at the data layer — not just the code layer.

| Deliverable | Status |
|---|---|
| Cross-tenant probe: attempt to retrieve user A's vectors as user B, report if successful | ❌ |
| Injection resistance probe: insert canary payloads and verify they don't surface in other users' contexts | ❌ |
| Permission probe: verify API-key-scoped collections enforce the assumed access control model | ❌ |
| Works against: Chroma, PGVector, Pinecone, Qdrant, Weaviate, Neo4j | ❌ |
| Safe by design: probes use isolated canary namespaces, never touching real user data | ❌ |

**Attack vector coverage expansion:** v1.4 enables detection of AW-ATK-POI-001–006 (poisoning), AW-ATK-EMB-001–005 (embedding attacks), AW-ATK-EXF-001–003 (exfiltration) — the 18 vectors unreachable by static analysis.

---

#### v2.0 — Continuous Security Monitoring 🔲

Agents in production change. New tools get added, memory backends get swapped, framework versions get bumped. v2.0 extends AgentWall from a one-time scan into a continuous compliance monitor.

| Deliverable | Status |
|---|---|
| GitHub App: comments on every PR with a security diff ("2 new findings, 1 resolved") | ❌ |
| Drift detection: alert when a previously-clean deployment introduces new memory access patterns | ❌ |
| CVE watch: notify when a new framework / vector store CVE matches your dependency version | ❌ |
| Security posture over time: trend charts for finding count, severity distribution, MTTR | ❌ |
| Policy-as-code: `.agentwall.yml` defines org-wide rules, exemptions, and escalation thresholds | ❌ |
| SIEM integration: push findings to Datadog, Splunk, or PagerDuty for security team workflows | ❌ |

---

#### v2.1 — Compliance & Audit Trails 🔲

Enterprise teams need to prove to auditors that their agent systems are secure. v2.1 makes AgentWall the evidence layer for AI compliance.

| Deliverable | Status |
|---|---|
| OWASP LLM Top 10 mapping: every finding cross-referenced to the relevant OWASP category | ❌ |
| SOC 2 evidence export: scan history as a compliance artifact for Type II audits | ❌ |
| GDPR memory audit: identify all code paths where user PII enters or persists in vector stores | ❌ |
| HIPAA agent checklist: automated verification of PHI isolation requirements | ❌ |
| Audit trail signing: cryptographically signed scan reports for regulatory non-repudiation | ❌ |

---

### 29. v0.x Delivery Status

**v0.x delivery details preserved from PRD v3 for audit trail:**

| Step | Task | Deliverable | Status |
|---|---|---|---|
| 0.1 | Project scaffolding (pyproject.toml, CI, linting) | Repo structure | ✅ Done |
| 0.2 | L0 regex framework detection | `FrameworkType` enum | ✅ Done |
| 0.3 | L1 AST visitor (memory analyzer) | AW-MEM-001–003 rules | ✅ Done |
| 0.4 | L1 AST visitor (tool analyzer) | AW-TOOL-001–005 rules | ✅ Done |
| 0.5 | Terminal reporter | Human-readable output | ✅ Done |
| 0.6 | JSON reporter | Machine-parseable output | ✅ Done |
| 0.7 | CLI (scan + version commands) | `agentwall scan .` works | ✅ Done |
| 0.8 | Core test suite + fixtures | > 80% coverage on core | ✅ Done (12 test files, 8 fixture dirs) |
| 0.9 | PyPI packaging | `pip install agentwall` works | ✅ Done |
| 1.1 | L4 config auditing | AW-MEM-004, AW-MEM-005, AW-ATK-CFG-* | ✅ Done |
| 1.2 | L5 Semgrep rules (10+ rules) | 3 rule files: memory, tools, config | ✅ Done |
| 1.3 | SARIF reporter | SARIF v2.1.0, attack vector properties (9 tests) | ✅ Done |
| 1.4 | `--format agent-json` (FR-501) | Flattened structure, verification, related_findings (9 tests) | ✅ Done |
| 1.5 | `--format patch` (FR-502) | Paren-depth counter, unified diff, manual fallback (9 tests) | ✅ Done |
| 1.6 | `agentwall verify --finding` (FR-513) | Fast L0-L2 scan, PASS/FAIL output, JSON (6 tests) | ✅ Done |
| 1.7 | L2 call graph | Cross-file resolution (built ahead of schedule) | ✅ Done |
| 1.8 | L8 LLM confidence scoring | Ambiguity resolution (built ahead of schedule) | ✅ Done |
| 1.9 | Benchmark suite (20 repos) | 32 fixture tests, 20 real-world repos (27 tests) | ✅ Done |

**33/33 steps complete (18 original + 15 V5 engine + FP reduction). 623 tests passing, ruff clean.**

**Attack Vector Detection Status (verified against code, 2026-03-18):**

10 / 32 vectors detected (31%). See `BENCHMARK.md` for full evidence.

| Vector | Description | Detection | Status | Real-World Hits |
|---|---|---|---|---|
| AW-ATK-MEM-001 | Cross-tenant retrieval | L1 AST + L3 taint + L5 Semgrep | ✅ Confirmed | 57 (8 projects) |
| AW-ATK-MEM-002 | Weak static filter | L1 AST + L3 taint | ✅ Confirmed | 4 (3 projects) |
| AW-ATK-MEM-003 | Namespace confusion | L1 AST | ✅ Confirmed | 19 (6 projects) |
| AW-ATK-MEM-004 | Partition bypass | L4 config (heuristic) | ✅ Partial | — |
| AW-ATK-INJ-001 | Stored prompt injection | AW-MEM-005 / L1+L5 | ✅ Confirmed | 19 (6 projects) |
| AW-ATK-CFG-001 | Unsafe reset | L4 config regex | ✅ Confirmed | — |
| AW-ATK-CFG-003 | No TLS / No auth | L4 config regex | ✅ Confirmed | 7 (4 projects) |
| AW-ATK-CFG-004 | Hardcoded API keys | L4 config regex | ✅ Confirmed | 45 (8 projects) |
| AW-ATK-AGT-001 | Unsafe tool access | AW-TOOL-001–003 | ✅ Confirmed | 4 (2 projects) |
| 22 vectors | POI, EMB, EXF, DOS, AGT-002–005 | Not detectable (static) | ❌ Requires runtime | — |

**Attack Vector Coverage by Version:**

| Version | Attack Vectors | Detection Method | Status |
|---|---|---|---|
| v0.x | AW-ATK-MEM-001–004, AW-ATK-INJ-001, AW-ATK-CFG-001/003/004, AW-ATK-AGT-001 | AST + Taint + Config + Semgrep | ✅ 10 vectors, 7 confirmed in 20 real-world repos |
| v1.0 | AW-ATK-CFG-002/005/006, AW-ATK-DOS-001–003, AW-ATK-AGT-002–005 | Config schema + parameter audit + multi-agent analysis | 🔲 Planned |
| v1.4 | AW-ATK-POI-001–006, AW-ATK-EMB-001–005, AW-ATK-EXF-001–003 | Runtime injection + query + verify | 🔲 Requires live probing |
| v1.2 | AW-ATK-INJ-002–003 | Multi-agent + session analysis | 🔲 Requires architectural analysis |

### 30. Success Metrics

| Metric | Target | Actual (2026-03-20) | Status |
|---|---|---|---|
| `pip install agentwall && agentwall scan .` works first try | 100% | Works | ✅ |
| Scan detects real bugs in Langchain-Chatchat | ≥ 3 CRITICAL findings | **147 CRITICAL** across 107 projects | ✅ |
| Scan completes in < 90s on 50K LOC (L0–L5) | Mandatory | < 10s for all 107 projects | ✅ |
| False positive rate on benchmark suite | < 15% | **~35% measured (45% before FP reduction, ~35% after Phase 1)** | 🔶 Phase 2 planned |
| True positive rate on benchmark suite | > 85% | **100%** (11/11 expected rules) | ✅ |
| Test suite | > 80% coverage | 72% (623 tests) — gap in L2/L7/L8 | 🔶 |
| Attack vectors detected | — | 9/35 (26%) — all statically detectable | ✅ |
| Real-world projects with findings | — | 84/107 (79%) | ✅ |
| AI agent can install + scan + parse output without human help | 100% for Claude Code, Codex | `--format agent-json` implemented | 🔶 Untested |
| AUTO-confidence fixes apply cleanly (`git apply`) | > 90% | Patch validity test passing | 🔶 Limited scope |
| AUTO-confidence fixes resolve finding on re-scan | > 85% | `agentwall verify` implemented | 🔶 Untested |
| Fix-verify loop < 60 seconds per finding | > 90% of findings | Verify command < 1s on fixtures | ✅ |
| GitHub stars within 30 days of launch | ≥ 100 | — | 🔲 Not launched |
| Hacker News front page | 1 post | — | 🔲 Not launched |

### 31. Risk Matrix

| Risk | Probability | Impact | Mitigation | Status |
|---|---|---|---|---|
| False positive rate too high for CI adoption | Medium | HIGH | L8 confidence, `--fail-on critical` | 🔶 ~35% FP rate (down from 45% after Phase 1). Phase 2 targets ~18%. Measured via 98-finding manual triage. |
| LangChain API changes break adapter | Medium | MEDIUM | Pin to v0.2+, adapter abstraction | 🔶 Monitoring |
| Scope creep beyond MVP | HIGH | HIGH | PRD is scope contract | ✅ Mitigated — L3/L6/L7 scope creep was beneficial |
| Solo engineer burnout | Medium | CRITICAL | Phase-gated delivery | 🔶 Phase 0+1 done in one sprint |
| No traction on launch | Medium | HIGH | Blog, HN, Reddit | 🔲 Not launched yet |
| SARIF complexity delays launch | Low | MEDIUM | Minimal valid SARIF | ✅ Resolved — SARIF v2.1.0 implemented, 9 tests |
| AI agents produce bad fixes from guided remediation | Medium | MEDIUM | AUTO only for simple patterns | ✅ Mitigated — patch only fixes AW-MEM-001, all others → manual comment |
| Attack vector claims inflated | Medium | HIGH | Audit detection code against catalog | ✅ Resolved — corrected 16/32 → 10/32, mapping fixed in agent_json.py |

### 32. Growth Path

**The maturity timeline:**

| Stage | Version | What It Is | Revenue Model |
|---|---|---|---|
| Foundation | v0.x ✅ | Static scanner, LangChain + ChromaDB. V5 engine upgrade. FP reduction Phase 1. | Open source (MIT) |
| Ecosystem | v1.0–v1.4 | Multi-framework, supply chain, IDE, live probing | Open source core + paid extras (advanced rules, priority support) |
| Platform | v2.0–v2.1 | Continuous monitoring, compliance, enterprise | SaaS (hosted dashboard, team management, audit trails) |

**If traction (>500 stars, >50 weekly installs):** Execute v1.x roadmap aggressively. Multi-framework coverage is the inflection point — it transforms AgentWall from a LangChain-specific tool into the universal agent security standard.

**If no traction:** Park the project. The codebase and rules are MIT-licensed and useful as reference material. Move on.

---

## Benchmark Suite

**Status: Implemented.** Full results in `BENCHMARK.md`. Reproducible via `./scripts/benchmark.sh`.

### Fixture Benchmark (automated, `tests/test_benchmark.py`)

39 test files, 26 fixture directories.

| Fixture | Findings | CRIT | Rules Fired | Use |
|---|---|---|---|---|
| langchain_unsafe | 8 | 1 | MEM-001, MEM-003, MEM-005, TOOL-001–003 | TP validation |
| langchain_basic | 3 | 1 | MEM-001, MEM-003, MEM-005 | TP validation |
| langchain_injection | 4 | 1 | MEM-001, MEM-003, MEM-004, MEM-005 | Injection detection |
| langchain_cross_file | 4 | 2 | MEM-001, MEM-003, MEM-005 | L2 cross-file |
| langchain_taint | 4 | 2 | MEM-001, MEM-002, MEM-005 | L3 taint flow |
| langchain_branching | 2 | 0 | MEM-001, MEM-005 | Path-sensitive |
| langchain_safe | 1 | 0 | MEM-005 only | FP test |

### Real-World Benchmark (107 OSS projects)

1,280 findings (147 CRITICAL, 526 HIGH) across 29,238 files in 107 projects. See BENCHMARK3000.md. Top projects:

| Repo | Stars | Findings | CRIT | HIGH | Top Attack Vector |
|---|---|---|---|---|---|
| Langflow | ~48k | 71 | 29 | 25 | AW-ATK-MEM-001 (29 hits) |
| Mem0/Embedchain | ~25k | 26 | 4 | 19 | AW-ATK-CFG-004 (15 hits) |
| Langchain-Chatchat | ~37k | 23 | 14 | 5 | AW-ATK-MEM-001 (14 hits) |
| DocsGPT | ~15k | 8 | 3 | 2 | AW-ATK-MEM-001 (3 hits) |
| Onyx/Danswer | ~12k | 8 | 1 | 3 | AW-ATK-CFG-003 + CFG-004 |
| Chat-LangChain | ~6k | 7 | 0 | 7 | AW-ATK-CFG-004 (7 hits) |
| DB-GPT | ~17k | 6 | 2 | 2 | AW-ATK-MEM-001 (2 hits) |

4 projects not scanned (Flowise, Open Interpreter, Haystack, AutoGPT) — non-Python or framework not detected by LangChain adapter.

---

## Dependencies

| Layer | Required | Optional | Install |
|---|---|---|---|
| L0–L1 | Python stdlib (`ast`, `re`) | — | Built-in |
| L2 | Python stdlib (`ast`) | — | Built-in (V5 PyCG-style graph) |
| L3 | Python stdlib (`ast`) | — | Built-in (V5 fixpoint verifier) |
| L4 | `pyyaml`, `tomllib` (3.11+) | `python-dotenv` | `pip install agentwall[config]` |
| L5 | — | `semgrep` | `pip install agentwall[semgrep]` |
| L6 | Python stdlib (`ast`) | — | Built-in (V5 path coverage) |
| L7 | Target app's deps | — | N/A (runtime) |
| L8 | — | `ollama`, `anthropic` | `pip install agentwall[llm]` |

**Core: `pip install agentwall` → L0, L1, L2 (custom resolver), L4 (YAML/TOML only). Everything else is optional extras.**

---

## CLI Surface

```
# ── Implemented (Phase 0–1) ──────────────────────────────────────────────
agentwall scan [PATH]                          # Scan with terminal output        ✅
agentwall scan [PATH] --format json            # JSON output                      ✅
agentwall scan [PATH] --format sarif           # SARIF v2.1.0 output              ✅
agentwall scan [PATH] --format agent-json      # AI agent-optimized output        ✅
agentwall scan [PATH] --format patch           # Unified diff output              ✅
agentwall scan [PATH] --output FILE            # Write to file                    ✅
agentwall scan [PATH] --layers L0,L1,L2        # Run specific layers              ✅
agentwall scan [PATH] --fast                   # L0-L2 only (< 10s)              ✅
agentwall scan [PATH] --dynamic                # Enable L7 runtime                ✅
agentwall scan [PATH] --llm-assist             # Enable L8 LLM scoring            ✅
agentwall scan [PATH] --fail-on critical       # Exit code 1 only on CRITICAL     ✅
agentwall verify --finding RULE_ID [PATH]      # Fast single-finding re-check     ✅
agentwall version                              # Version info                     ✅

# ── Planned (v1.x) ──────────────────────────────────────────────────────
agentwall explain RULE_OR_ATTACK_ID            # Structured explanation            🔲
agentwall remediate FINDING_ID                 # Generate remediation plan         🔲
agentwall schema [FORMAT]                      # Output JSON Schema                🔲
agentwall prompt-fragment                      # System prompt for AI agents       🔲
agentwall mcp-serve                            # Start MCP server                  🔲
```

---

## Open Questions

| # | Question | Impact | Resolution |
|---|---|---|---|
| 1 | Should `--format patch` attempt fixes for GUIDED-confidence findings or only AUTO? | Broken patches erode trust. | **Resolved:** AUTO only (AW-MEM-001). Falls back to manual comment for all others. Nested parens → manual fallback. |
| 2 | Should MCP server support streaming (SSE) for long scans? | Needed for large codebases (>60s scan). | Open — v1.x. All 20 benchmark projects scan in < 10s, so not urgent. |
| 3 | Should remediation plans include generated test cases? | High value for AI agents but significant effort. | Open — v1.x. |
| 4 | How to handle framework version differences in fix templates? | LangChain 0.2 vs 0.3 have different retriever APIs. | Open — v1.x. Current patch only generates `similarity_search()` filter additions. |
| 5 | Should `agentwall explain` fetch latest attack research from remote registry? | Breaks offline-first promise. | Open — lean toward opt-in `--online` flag. |
| 6 | Should `--format sarif/agent-json` without `--output` print to stdout or error? | UX consistency. | **Resolved:** Prints to stdout. User can pipe to file. |

---

## References

- [OWASP Top 10 for LLM Applications 2025](https://genai.owasp.org/llm-top-10/)
- [OWASP Top 10 for Agentic Applications 2026](https://www.aikido.dev/blog/owasp-top-10-agentic-applications)
- [OWASP LLM08:2025 — Vector and Embedding Weaknesses](https://genai.owasp.org/llmrisk/llm082025-vector-and-embedding-weaknesses/)
- [OWASP Agent Memory Guard](https://owasp.org/www-project-agent-memory-guard/)
- [PoisonedRAG — USENIX Security 2025](https://github.com/sleeepeer/PoisonedRAG)
- [CorruptRAG — arXiv 2504.03957](https://arxiv.org/pdf/2504.03957)
- [MINJA — NeurIPS 2025](https://arxiv.org/abs/2503.03704)
- [Lakera — Indirect Prompt Injection](https://www.lakera.ai/blog/indirect-prompt-injection)
- [EchoLeak — Silent Data Exfiltration](https://www.paloaltonetworks.com/blog/cloud-security/owasp-agentic-ai-security/)
- [Embedding Inversion — ACL 2024](https://arxiv.org/html/2411.05034v1)
- [Semantic Cache Poisoning — arXiv 2601.23088](https://arxiv.org/abs/2601.23088)

---

*End of document.*
