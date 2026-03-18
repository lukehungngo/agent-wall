# AgentWall Architecture v3

**Version:** 3.0 (Phase 1 complete)
**Last updated:** 2026-03-18

---

## 1. Logical → Physical Model Mapping

```
LOGICAL DOMAIN                          PHYSICAL MODEL (models.py)
─────────────────────────────────────── ──────────────────────────────────
"An AI agent project"                   AgentSpec
  "each tool the agent can invoke"        ├── ToolSpec[]
  "each memory/vector store connection"   ├── MemoryConfig[]
  "all Python files in the project"       └── source_files[]

"A security issue found"                Finding
"Everything we learned from scanning"   ScanResult
"What layers to run, how deep to go"    ScanConfig

"Which functions call which" (L2)       CallGraph + CallEdge + FunctionRef
"Where user identity enters/reaches"    TaintSource + TaintSink + TaintResult
```

---

## 2. End-to-End Data Flow

```
  User runs: agentwall scan ./project/
                    │
                    ▼
 ┌──────────────────────────────────┐
 │  CLI (cli.py)                    │
 │  Parses flags → ScanConfig       │
 │  --confidence, --layers, --fast  │
 └──────────────┬───────────────────┘
                │
                ▼
 ┌──────────────────────────────────┐
 │  Scanner Orchestrator            │
 │  (scanner.py::scan())            │
 │  Controls the full pipeline      │
 └──────────────┬───────────────────┘
                │
    ┌───────────┴───────────────────────────────────────┐
    │                                                    │
    ▼                                                    │
 ┌─────────────────────┐                                 │
 │ L0: detector.py     │                                 │
 │                     │                                 │
 │ Path ──→ "langchain"│  Reads pyproject.toml +         │
 │                     │  scores imports across files     │
 └─────────┬───────────┘                                 │
           │ framework name                              │
           ▼                                             │
 ┌─────────────────────────────────────┐                 │
 │ L1: adapters/langchain.py           │                 │
 │                                     │                 │
 │ Path ──→ AgentSpec                  │                 │
 │   AST walks every .py file:         │                 │
 │   • @tool decorators  ──→ ToolSpec  │                 │
 │   • BaseTool classes  ──→ ToolSpec  │                 │
 │   • Chroma()/FAISS()  ──→ MemConfig │                 │
 │   • .similarity_search(filter=...)  │                 │
 │     updates MemoryConfig flags      │                 │
 └─────────┬───────────────────────────┘                 │
           │ AgentSpec                                   │
           ▼                                             │
 ┌─────────────────────────────────────┐                 │
 │ L1: analyzers/memory.py            │                 │
 │     analyzers/tools.py             │                 │
 │                                     │                 │
 │ AgentSpec ──→ Finding[]             │                 │
 │                                     │                 │
 │ MemoryConfig → AW-MEM-001..005     │                 │
 │ ToolSpec    → AW-TOOL-001..005     │                 │
 └─────────┬───────────────────────────┘                 │
           │ Finding[]                                   │
           ▼                                             │
 ┌─────────────────────────────────────┐                 │
 │ L2: analyzers/callgraph.py         │  REFINES        │
 │                                     │                 │
 │ AgentSpec + Finding[] ──→ Finding[] │                 │
 │ Builds inter-file call graph        │                 │
 │ If filter via wrapper: downgrade    │                 │
 └─────────┬───────────────────────────┘                 │
           ▼                                             │
 ┌─────────────────────────────────────┐                 │
 │ L3: analyzers/taint.py             │  ADDS           │
 │                                     │                 │
 │ AgentSpec ──→ Finding[]             │                 │
 │ Tracks user_id flow → filter sink   │                 │
 └─────────┬───────────────────────────┘                 │
           ▼                                             │
 ┌─────────────────────────────────────┐                 │
 │ L4: analyzers/config.py            │  ADDS           │
 │ Path ──→ Finding[]                  │                 │
 │ .env, docker-compose, settings.py   │                 │
 └─────────┬───────────────────────────┘                 │
           ▼                                             │
 ┌─────────────────────────────────────┐                 │
 │ L5: analyzers/semgrep.py           │  ADDS           │
 │ L6: analyzers/symbolic.py          │  ADDS           │
 │ Declarative patterns + path-        │                 │
 │ sensitive lattice analysis          │                 │
 └─────────┬───────────────────────────┘                 │
           ▼                                             │
 ┌─────────────────────────────────────────┐             │
 │ Post-Processing (scanner.py)            │             │
 │                                         │             │
 │ 1. _dedup_findings()                    │             │
 │    (rule_id, file, line) → unique       │             │
 │                                         │             │
 │ 2. _apply_file_context()                │             │
 │    tests/, examples/ → cap LOW conf     │             │
 │    tag: "test file" | "example"         │             │
 │                                         │             │
 │ 3. _sort_findings()                     │             │
 │    primary: severity (CRIT→INFO)        │             │
 │    secondary: confidence (HIGH→LOW)     │             │
 └─────────┬───────────────────────────────┘             │
           │ ScanResult                                  │
           ▼                                             │
 ┌─────────────────────────────────────────┐             │
 │ CLI: --confidence filter                │             │
 │ --confidence high   → only HIGH         │             │
 │ --confidence medium → HIGH + MEDIUM     │             │
 │ --confidence all    → all (default)     │             │
 └─────────┬───────────────────────────────┘             │
           ▼                                             │
 ┌─────────────────────────────────────────────────────┐
 │ Reporters                                           │
 │  terminal.py    → Rich console (severity + conf)    │
 │  json_reporter  → model_dump_json()                 │
 │  agent_json.py  → flattened + hints + attack IDs    │
 │  sarif.py       → SARIF v2.1.0 (GitHub Security)   │
 │  patch.py       → unified diff                      │
 └─────────────────────────────────────────────────────┘
```

---

## 3. Physical Models Detail

### Core Models (Pydantic v2)

```python
class AgentSpec(BaseModel):
    framework: str                          # "langchain"
    source_files: list[Path]                # all scanned .py files
    tools: list[ToolSpec]                   # detected tool registrations
    memory_configs: list[MemoryConfig]      # detected vector store connections
    metadata: dict[str, object]             # framework-specific extras
```

```python
class ToolSpec(BaseModel):
    name: str
    description: str | None                 # from docstring or description=
    is_destructive: bool                    # delete, remove, drop, execute...
    accepts_code_execution: bool            # subprocess, eval, exec, shell
    has_approval_gate: bool                 # HumanApprovalCallbackHandler
    has_user_scope_check: bool              # raises PermissionError or checks user_id
    source_file: Path | None
    source_line: int | None
```

```python
class MemoryConfig(BaseModel):
    backend: str                            # "chroma", "faiss", "pinecone"...
    has_tenant_isolation: bool              # any form of user scoping
    has_metadata_filter_on_retrieval: bool  # filter= on similarity_search()
    has_metadata_on_write: bool             # metadata= on add_texts()
    sanitizes_retrieved_content: bool       # sanitize/clean/bleach before prompt
    has_injection_risk: bool                # ConversationBufferMemory etc.
    collection_name: str | None
    source_file: Path | None
    source_line: int | None
```

```python
class Finding(BaseModel):
    rule_id: str                            # "AW-MEM-001"
    title: str
    severity: Severity                      # CRITICAL | HIGH | MEDIUM | LOW | INFO
    category: Category                      # MEMORY | TOOL
    description: str
    file: Path | None
    line: int | None
    fix: str | None
    confidence: ConfidenceLevel             # HIGH | MEDIUM | LOW
    layer: str | None                       # "L1", "L2", "L3"...
    file_context: str | None                # "test file", "example"
```

```python
class ScanResult(BaseModel):
    target: Path
    framework: str | None
    findings: list[Finding]
    scanned_files: int
    errors: list[str]
    # Properties: .critical, .high, .by_severity
```

### Graph Models (dataclass, L2)

```python
@dataclass(frozen=True)
class FunctionRef:
    file: Path
    name: str           # "ClassName.method" or "function_name"
    lineno: int

@dataclass(frozen=True)
class CallEdge:
    caller: FunctionRef
    callee: FunctionRef
    call_site_line: int
    resolved: bool      # True if statically resolved

@dataclass
class CallGraph:
    edges: list[CallEdge]
    unresolved: list[tuple[Path, int]]
    # Methods: callers_of(), callees_of(), reachable_from()
```

### Taint Models (dataclass, L3)

```python
@dataclass(frozen=True)
class TaintSource:
    name: str           # "request.user", "user_id"
    file: Path
    lineno: int

@dataclass(frozen=True)
class TaintSink:
    name: str           # "similarity_search.filter"
    file: Path
    lineno: int

@dataclass
class TaintResult:
    source: TaintSource
    sink: TaintSink
    reaches: bool       # True if source data reaches the sink
    path: list[str]     # variable chain
```

---

## 4. Layer Interaction Pattern

```
L1 DETECTS everything (high recall, accepts false positives)
   │
L2 REFINES by checking cross-file call chains
   │         (downgrades if wrapper applies filter)
   │
L3 ADDS taint-confirmed findings
   │     (promotes confidence when user_id flow verified)
   │
L4 ADDS infra-level misconfigurations
   │     (orthogonal — reads config files, not Python AST)
   │
L5 ADDS Semgrep pattern matches
   │     (declarative rules, complementary to AST)
   │
L6 ADDS path-sensitive findings
   │     (catches "filter on if-branch but not else-branch")
   │
   ▼
All findings deduped → context-tagged → sorted → filtered → reported
```

**Design principle:** L1 casts a wide net, higher layers narrow it down. Every layer is additive — they refine or confirm, never suppress. False positives are managed through confidence levels and `--confidence` filtering, not by hiding findings.

---

## 5. Analyzer → Rule Mapping

### Memory Analyzer (L1)

| Rule | Trigger Condition | Severity | Confidence |
|---|---|---|---|
| AW-MEM-001 | `has_metadata_filter_on_retrieval == False` | CRITICAL | HIGH |
| AW-MEM-002 | `has_metadata_on_write == True` but no read filter | HIGH | HIGH |
| AW-MEM-003 | No access control detected at all | HIGH | MEDIUM |
| AW-MEM-004 | Known injection pattern (ConversationBufferMemory etc.) | HIGH | HIGH |
| AW-MEM-005 | `sanitizes_retrieved_content == False` | MEDIUM | MEDIUM |

### Tool Analyzer (L1)

| Rule | Trigger Condition | Severity | Confidence |
|---|---|---|---|
| AW-TOOL-001 | `is_destructive` and not `has_approval_gate` | HIGH | HIGH |
| AW-TOOL-002 | `accepts_code_execution` | MEDIUM | HIGH |
| AW-TOOL-003 | `is_destructive` and not `has_user_scope_check` | MEDIUM | MEDIUM |
| AW-TOOL-004 | `description is None` | LOW | HIGH |
| AW-TOOL-005 | `len(tools) > 15` | INFO | LOW |

### Config Auditor (L4)

| Rule | Trigger Condition | Severity |
|---|---|---|
| AW-CFG-allow-reset | `allow_reset=True` in vector DB config | HIGH |
| AW-CFG-no-auth | No authentication on vector DB endpoints | HIGH |
| AW-CFG-docker-no-auth | Docker service without auth | HIGH |
| AW-CFG-hardcoded-secret | API keys in config/env files | HIGH |
| AW-CFG-no-tls | `sslmode=disable` or no TLS | HIGH |
| AW-CFG-debug-mode | `DEBUG=True` | MEDIUM |
| AW-CFG-exposed-port | `0.0.0.0:<port>` binding | MEDIUM |

---

## 6. L6 Symbolic Analysis Lattice

```
       TOP (unknown / mixed paths)
      /           \
  FILTERED    UNFILTERED
      \           /
      BOTTOM (unreachable)
```

Join semantics at control-flow merge points:
- FILTERED + FILTERED → FILTERED (all paths safe)
- UNFILTERED + UNFILTERED → UNFILTERED (all paths unsafe)
- FILTERED + UNFILTERED → TOP (some paths miss filter)
- Anything + BOTTOM → the other value

---

## 7. Reporter Output Contracts

| Reporter | Input | Output | Use Case |
|---|---|---|---|
| `terminal.py` | `ScanResult` | Rich console (stdout) | Human developer |
| `json_reporter.py` | `ScanResult` | Pydantic JSON | CI pipelines |
| `agent_json.py` | `ScanResult` | Flattened JSON + hints | AI agent consumption |
| `sarif.py` | `ScanResult` | SARIF v2.1.0 | GitHub Security tab |
| `patch.py` | `ScanResult` | Unified diff | Auto-fix proposals |

### Agent JSON enrichments (beyond raw Finding)

```
Finding → {
    ...all Finding fields...
    + remediation_hint      # contextual fix advice per rule
    + false_positive_hint   # when this might be a FP
    + attack_vector_id      # maps to AW-ATK-* catalog
    + affected_component    # "memory_store" | "tool_registration"
    + verification          # agentwall verify --finding AW-MEM-001 .
    + related_findings      # other findings with same rule_id
}
```

---

## 8. File Map

```
src/agentwall/
├── cli.py                      # CLI entry point, flag parsing
├── scanner.py                  # Orchestrator: L0→L6 pipeline
├── detector.py                 # L0: framework detection
├── models.py                   # All data models
├── rules.py                    # Rule definitions registry
├── adapters/
│   └── langchain.py            # L1: AST parser → AgentSpec
├── analyzers/
│   ├── memory.py               # L1: MemoryConfig → Finding[]
│   ├── tools.py                # L1: ToolSpec → Finding[]
│   ├── callgraph.py            # L2: inter-file call graph
│   ├── taint.py                # L3: source→sink taint tracking
│   ├── config.py               # L4: infra config auditing
│   ├── semgrep.py              # L5: declarative pattern rules
│   ├── symbolic.py             # L6: path-sensitive lattice
│   └── confidence.py           # L8: LLM-assisted scoring
└── reporters/
    ├── terminal.py             # Rich console output
    ├── json_reporter.py        # Raw Pydantic JSON
    ├── agent_json.py           # AI-agent optimized JSON
    ├── sarif.py                # SARIF v2.1.0
    └── patch.py                # Unified diff
```

---

## 9. Key Invariants

1. **Never execute user code.** All analysis via `ast.parse()` only.
2. **Static by default.** No network calls unless `--live` flag.
3. **Fail safe.** Parse error → warning + skip. Never crash the scan.
4. **Layers are additive.** Higher layers refine, never suppress.
5. **Confidence > suppression.** Noise managed via confidence levels, not hidden findings.
6. **Severity discipline.** CRITICAL only for confirmed cross-tenant data access.
