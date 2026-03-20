# AgentWall Architecture V5 — Engine-Powered Analysis Pipeline

**Version:** 5.0
**Date:** 2026-03-20
**Status:** Implemented (engine upgrade + FP reduction Phase 1)

---

## 1. System Overview

AgentWall is a static AST-based security scanner for AI agents. It detects memory isolation failures, tool misuse, credential leaks, RAG injection, and agent architecture vulnerabilities — security classes that no traditional SAST tool covers.

**Core invariant:** Never execute user code. All analysis via `ast.parse()` only.

```
agentwall scan ./project/
  → 9 analysis layers (L0–L8 + ASM)
  → 27+ rules across 8 categories
  → 5 output formats (terminal, JSON, SARIF, agent-json, patch)
  → exit 0 (clean) | 1 (findings ≥ threshold) | 2 (error)
```

**What makes V5 different from V4:** A new engine layer (engine + framework model split) sits inside the existing analyzers, providing deeper analysis without breaking backward compatibility. The engine uses proven SAST algorithms (PyCG call graph, Pysa-style fixpoint, CodeQL-style path coverage) scoped to AI security property verification.

---

## 2. Two-Layer Architecture: Engine + Framework Model

The key design principle: **Engine (general, reusable) + Framework Model (declarative, per-framework).**

```
┌─────────────────────────────────────────────────┐
│  Framework Model (declarative, per-framework)    │
│                                                  │
│  stores:      Chroma → filter="filter"           │
│               Pinecone → filter="filters"        │
│  composition: | operator, from_llm(), @tool      │
│  identity:    request.user, jwt.sub, tenant_id   │
└──────────────────┬───────────────────────────────┘
                   │ feeds
┌──────────────────▼───────────────────────────────┐
│  Analysis Engine (general, built once)            │
│                                                  │
│  L1 extractor:  classify values by security kind │
│  L2 graph:      call graph + composition graph   │
│  L3 verifier:   fixpoint tenant isolation check  │
│  L6 pathcov:    aggregate path coverage          │
└──────────────────────────────────────────────────┘
```

**Adding a new framework = writing a ~50-line model file. Zero engine changes.**
Validated: LlamaIndex model added with 3 vector stores, zero engine modifications.

---

## 3. Complete Data Flow Pipeline

### 3.1 High-Level Flow

```
scan(target)
  │
  ├─[1] DETECT ─── auto_detect_framework() → "langchain" | None
  │                _source_files() → list[Path]
  │
  ├─[2] PARSE ──── LangChainAdapter.parse() → AgentSpec
  │                 (tools, memory_configs, ASM ApplicationModel)
  │
  ├─[3] CONTEXT ── AnalysisContext created with all shared state
  │
  ├─[4] ANALYZE ── 16 analyzers in topological order
  │   │
  │   │  ┌─── OLD PATH (V4) ──────────┐  ┌─── NEW ENGINE PATH (V5) ────────┐
  │   │  │                             │  │                                  │
  │   ├─ L0: VersionsAnalyzer          │  │                                  │
  │   │  │ → version_modifiers         │  │                                  │
  │   │  │                             │  │                                  │
  │   ├─ L1: MemoryAnalyzer ◄──────────┼──┤ Reads ctx.store_profiles        │
  │   │  │ → AW-MEM-001..005           │  │ for FP reduction                 │
  │   │  │ (boolean flag checks)       │  │ (isolation_strategy check)       │
  │   │  │                             │  │                                  │
  │   ├─ L1: ToolAnalyzer              │  │                                  │
  │   ├─ L1: SecretsAnalyzer           │  │                                  │
  │   ├─ L1: SerializationAnalyzer     │  │                                  │
  │   ├─ L1: RAGAnalyzer               │  │                                  │
  │   ├─ L1: MCPSecurityAnalyzer       │  │                                  │
  │   │  │                             │  │                                  │
  │   ├─ L2: CallGraphAnalyzer ────────┼──┤ build_project_graph()            │
  │   │  │ build_call_graph()          │  │ → ctx.project_graph              │
  │   │  │ → ctx.call_graph            │  │ (call + composition + extends)   │
  │   │  │                             │  │                                  │
  │   ├─ L3: TaintAnalyzer ───────────┼──┤ extract_properties()             │
  │   │  │ _TaintVisitor              │  │ → ctx.store_profiles              │
  │   │  │ → ctx.taint_results        │  │                                  │
  │   │  │                             │  │ verify_tenant_isolation()        │
  │   │  │                             │  │ → ctx.property_verifications     │
  │   │  │                             │  │                                  │
  │   ├─ L4: ConfigAuditor            │  │                                  │
  │   ├─ L5: SemgrepAnalyzer          │  │                                  │
  │   │  │                             │  │                                  │
  │   ├─ L6: SymbolicAnalyzer ────────┼──┤ compute_path_coverage()          │
  │   │  │ _PathAnalyzer (lattice)    │  │ → ctx.path_coverages             │
  │   │  │                             │  │                                  │
  │   ├─ ASM: ASMAnalyzer             │  │                                  │
  │   ├─ L7: RuntimeAnalyzer (opt-in) │  │                                  │
  │   └─ L8: ConfidenceScorer (opt-in)│  │                                  │
  │      └────────────────────────────┘  └──────────────────────────────────┘
  │
  ├─[5] POST ──── dedup → apply_file_context → sort
  │
  └─[6] REPORT ── terminal | json | sarif | agent-json | patch
```

### 3.2 Shared State: AnalysisContext

The `AnalysisContext` is the shared mutable state flowing through all analyzers:

```python
@dataclass
class AnalysisContext:
    # Pre-populated by scanner
    target: Path
    config: ScanConfig
    spec: AgentSpec | None              # from adapter
    source_files: list[Path]            # all .py files

    # Populated by L0
    version_modifiers: dict[str, VersionModifier]

    # Populated by L2 (old path)
    call_graph: CallGraph | None

    # Populated by L3 (old path)
    taint_results: list[TaintResult] | None

    # ── NEW ENGINE FIELDS (V5) ────────────────────
    store_profiles: list[StoreProfile] | None       # L1 engine via L3
    project_graph: ProjectGraph | None              # L2 engine
    property_verifications: list[PropertyVerification] | None  # L3 engine
    path_coverages: list[PathCoverage] | None       # L6 engine

    # Output
    findings: list[Finding]
    errors: list[str]
```

### 3.3 Engine Data Flow Detail

```
                    ┌──────────────────────────────────┐
                    │  FrameworkModel (langchain.py)     │
                    │  stores: 12 vector store models    │
                    │  patterns: pipe, factory, @tool    │
                    │  identity: tenant_param_names      │
                    └───────────┬──────────────────────┘
                                │
         ┌──────────────────────┼──────────────────────┐
         │                      │                       │
         ▼                      ▼                       ▼
┌─────────────────┐  ┌──────────────────┐  ┌────────────────────┐
│ L1: extractor   │  │ L2: graph        │  │ L3: verifier       │
│                 │  │                  │  │                    │
│ extract_        │  │ build_project_   │  │ verify_tenant_     │
│ properties()    │  │ graph()          │  │ isolation()        │
│                 │  │                  │  │                    │
│ IN: files,model │  │ IN: files,model  │  │ IN: profiles,      │
│                 │  │                  │  │     graph, model   │
│ OUT:            │  │ OUT:             │  │                    │
│ StoreProfile[]  │  │ ProjectGraph     │  │ OUT:               │
│  .store_id      │  │  .call_edges     │  │ PropertyVerif[]    │
│  .backend       │  │  .composition    │  │  .store_id         │
│  .extractions[] │  │  .identifiers    │  │  .verdict          │
│    .operation   │  │  .extends        │  │  .evidence[]       │
│    .filter_kind │  │  .unresolved     │  │                    │
│    .has_filter   │  │                  │  │ ALGORITHM:         │
│  .isolation_    │  │ ALGORITHM:       │  │ 1. Intra summaries │
│   strategy      │  │ Two-pass PyCG   │  │ 2. Fixpoint prop   │
│                 │  │ + composition    │  │ 3. Verdict per read│
└────────┬────────┘  └────────┬─────────┘  └──────────┬─────────┘
         │                    │                        │
         ▼                    ▼                        ▼
┌─────────────────────────────────────────────────────────────┐
│                    AnalysisContext                            │
│  ctx.store_profiles ← extractor                              │
│  ctx.project_graph  ← graph                                  │
│  ctx.property_verifications ← verifier                       │
└───────────┬────────────────────────────────┬─────────────────┘
            │                                │
            ▼                                ▼
   ┌─────────────────┐            ┌──────────────────────┐
   │ L1-memory       │            │ L6: pathcov          │
   │ (FP reduction)  │            │                      │
   │                 │            │ compute_path_         │
   │ Checks store_   │            │ coverage()           │
   │ profiles for    │            │                      │
   │ isolation_      │            │ IN: profiles,graph,  │
   │ strategy:       │            │     verifications    │
   │                 │            │                      │
   │ PER_TENANT →    │            │ OUT: PathCoverage[]  │
   │  downgrade      │            │  .verified_paths     │
   │ FILTER_ON_READ →│            │  .violated_paths     │
   │  suppress       │            │  .coverage_ratio     │
   └─────────────────┘            └──────────────────────┘
```

---

## 4. Engine Algorithms

### 4.1 L1 Engine: Value Classification

The core innovation. Instead of binary "filter kwarg present/absent", classifies every extracted value:

```
ValueKind:
  LITERAL          "global_docs", 42
  DYNAMIC          variable reference, can't determine
  TENANT_SCOPED    contains tenant identifier (user_id, org_id)
  COMPOUND_STATIC  dict with all literal values: {"source": "web"}
  COMPOUND_DYNAMIC dict with at least one dynamic value
  COMPOUND_TENANT  dict with at least one tenant-scoped value
```

This enables precise security decisions:
- `filter={"source": "web"}` → `COMPOUND_STATIC` → **not tenant-scoped, still vulnerable**
- `filter={"user_id": uid}` → `COMPOUND_TENANT` → **tenant-scoped, verified**
- `collection_name=f"docs_{tenant_id}"` → `TENANT_SCOPED` → **per-tenant isolation**

### 4.2 L2 Engine: PyCG-Style Assignment Graph

Based on [PyCG (ICSE '21)](https://arxiv.org/pdf/2103.00587):

**Pass 1:** Collect definitions, imports, assignments, class hierarchy across ALL files.
**Pass 2:** Resolve call sites using identifier pointsto sets. Detect framework composition.

Uniquely handles AI framework patterns:
- **LCEL pipe:** `chain = prompt | llm | retriever` → composition edges via `BinOp(BitOr)`
- **Factory methods:** `ConversationalRetrievalChain.from_llm(retriever=r)` → factory edge
- **Decorators:** `@tool` → tool registration edge
- **Single-level inheritance:** `class TenantChroma(Chroma)` → extends map

### 4.3 L3 Engine: Fixpoint Property Verification

Based on [Pysa fixpointAnalysis](https://github.com/facebook/pyre-check/blob/main/source/interprocedural/fixpointAnalysis.ml):

**Phase 1 — Intraprocedural summaries:**
For each function, compute `TenantFlowSummary`:
- Which params carry tenant identity to a store filter?
- Does the function have unfiltered store reads?
- Does it return tenant-scoped data?

**Phase 2 — Interprocedural fixpoint:**
Iterate call edges. If callee's param reaches a filter, and caller passes a tenant-named arg at that position, mark caller's read as transitively safe. Repeat until stable (max 20 iterations).

**Phase 3 — Verdict:**
For each store read, emit `VERIFIED` / `VIOLATED` / `UNKNOWN` based on filter classification.

### 4.4 L6 Engine: Path Coverage Aggregation

Groups L3 verifications by store and reports coverage:
- How many read paths are verified vs violated?
- What's the coverage ratio?
- Which specific paths are missing isolation?

---

## 5. Fallback Design: Old + New Coexistence

Every engine call is wrapped in `try/except`:

```python
# In each analyzer:
try:
    result = engine_function(...)
    ctx.engine_field = result
except Exception:
    pass  # Silent fallback to old logic

# Old logic always runs regardless
old_result = old_analysis(...)
```

**Guarantees:**
- Engine failure never crashes a scan
- Old findings always produced
- Engine results are additive (FP reduction, better classification)
- No breaking changes to CLI, output formats, or rule IDs

---

## 6. Framework Model Schema

```python
FrameworkModel:
  name: str                         # "langchain"
  stores: dict[str, StoreModel]     # 12 vector store definitions
  pipe_patterns: list[PipePattern]  # LCEL "|" operator
  factory_patterns: list[FactoryPattern]  # from_llm(), from_chain_type()
  decorator_patterns: list[DecoratorPattern]  # @tool
  auth_sources: list[str]           # request.user, jwt.sub, ...
  tenant_param_names: list[str]     # user_id, tenant_id, org_id, ...
  memory_classes: list[str]         # ConversationBufferMemory, ...

StoreModel:
  backend: str                      # "chromadb", "pgvector", "pinecone"
  isolation_params: list[str]       # ["collection_name"] or ["namespace"]
  write_methods: dict[str, str]     # {"add_texts": "metadata"}
  read_methods: dict[str, str]      # {"similarity_search": "filter"}
  retriever_factory: str | None     # "as_retriever"
  retriever_filter_path: str | None # "search_kwargs.filter"
  auth_params: list[str]            # ["api_key", "connection_string"]
  has_builtin_acl: bool             # False for FAISS
```

**Current models:**
- `frameworks/langchain.py` — 12 vector stores, full composition/decorator support
- `frameworks/llamaindex.py` — 3 vector stores (Pinecone, Chroma, Qdrant)

---

## 7. Module Map

```
src/agentwall/
├── scanner.py              # Orchestrator: scan() → ScanResult
├── context.py              # AnalysisContext + Analyzer Protocol
├── detector.py             # Framework auto-detection
├── cli.py                  # CLI interface
├── models.py               # Core models (Finding, AgentSpec, ASM, etc.)
├── patterns.py             # Shared detection constants
├── rules.py                # Rule registry (27+ rules)
├── postprocess.py          # dedup, file context, sort
├── version_resolver.py     # Version-aware rule modifiers
│
├── engine/                 # NEW: General analysis engines
│   ├── models.py           # ValueKind, StoreProfile, TenantFlowSummary, etc.
│   ├── extractor.py        # L1: Model-driven property extraction
│   ├── graph.py            # L2: PyCG-style call graph + composition
│   ├── verifier.py         # L3: Fixpoint tenant isolation verification
│   └── pathcov.py          # L6: Path coverage aggregation
│
├── frameworks/             # NEW: Declarative framework models
│   ├── base.py             # FrameworkModel, StoreModel, Pattern schemas
│   ├── langchain.py        # LangChain model (12 stores)
│   └── llamaindex.py       # LlamaIndex model (3 stores)
│
├── adapters/               # Framework-specific AST parsing
│   ├── base.py             # AbstractAdapter protocol
│   └── langchain.py        # LangChainAdapter → AgentSpec
│
├── analyzers/              # 16 analyzers across L0–L8 + ASM
│   ├── versions.py         # L0: version detection + CVE matching
│   ├── memory.py           # L1: AW-MEM-001..005 (uses engine for FP reduction)
│   ├── tools.py            # L1: AW-TOOL-001..005
│   ├── secrets.py          # L1: AW-SEC-001,003 (refined for FP reduction)
│   ├── serialization.py    # L1: AW-SER-001,003 (refined for FP reduction)
│   ├── rag.py              # L1: AW-RAG-001..004
│   ├── mcp_security.py     # L1: AW-MCP-001..003
│   ├── agent_arch.py       # L2: AW-AGT-001..004
│   ├── callgraph.py        # L2: call graph (triggers engine)
│   ├── taint.py            # L3: taint analysis (triggers engine)
│   ├── config.py           # L4: config auditing (refined for FP reduction)
│   ├── semgrep.py          # L5: declarative patterns
│   ├── symbolic.py         # L6: path-sensitive (triggers engine)
│   ├── asm.py              # ASM: graph-based queries
│   ├── runtime.py          # L7: runtime instrumentation (opt-in)
│   └── confidence.py       # L8: LLM confidence scoring (opt-in)
│
├── extractors/             # ASM component extraction
│   ├── entry_points.py
│   ├── edge_linker.py
│   └── context_sinks.py
│
├── reporters/              # Output formatters
│   ├── terminal.py
│   ├── json_reporter.py
│   ├── sarif.py
│   ├── agent_json.py
│   └── patch.py
│
└── runtime/                # L7 instrumentation
    └── patcher.py
```

---

## 8. Metrics

| Metric | Value |
|--------|-------|
| Total Python LOC | ~9,400 |
| Source modules | 54 |
| Test files | 39 |
| Test functions | 618 |
| Analysis layers | 9 (L0–L8) + ASM |
| Rules | 27+ across 8 categories |
| Vector stores modeled | 12 (LangChain) + 3 (LlamaIndex) |
| Output formats | 5 |
| Measured FP reduction (Phase 1) | 149 findings / 11.6% across 106 projects |
