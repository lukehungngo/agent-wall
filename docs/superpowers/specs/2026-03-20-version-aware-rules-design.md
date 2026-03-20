# Version-Aware Rules & Expanded Rule Categories

**Date:** 2026-03-20
**Status:** Draft
**Author:** SoH + Claude

## Goal

Expand AgentWall's detection surface from 10 rules (AW-MEM, AW-TOOL) to 28 rules across 7 categories, with a version-aware refinement system that adjusts finding severity/confidence based on resolved library versions. Framework-agnostic analyzers enable scanning of non-langchain projects for secrets, serialization, and MCP issues.

## Architecture

Two additions to the scanner pipeline:

1. **L0-versions analyzer** runs first. Reads dependency files, resolves library versions against YAML data files, injects `VersionModifier` objects into `AnalysisContext`. Downstream analyzers consume modifiers to downgrade/upgrade/suppress findings in real-time (suppression is rare — prefer downgrade).

2. **Framework-agnostic analyzers** (AW-SEC, AW-SER, AW-MCP) operate on raw Python AST via `ctx.source_files`. They run for all projects regardless of detected framework. AW-RAG and AW-AGT remain adapter-dependent (LangChain only).

### Category Enum Expansion

The existing `Category` enum (`MEMORY`, `TOOL`) must be extended:

```python
class Category(str, Enum):
    MEMORY = "memory"
    TOOL = "tool"
    SECRETS = "secrets"       # AW-SEC-*
    RAG = "rag"               # AW-RAG-*
    MCP = "mcp"               # AW-MCP-*
    SERIALIZATION = "serialization"  # AW-SER-*
    AGENT = "agent"           # AW-AGT-*
```

### Pipeline

```
L0-versions(target)
  → populates ctx.version_modifiers + ctx.source_files
  → detect framework
  → if supported: adapter.parse() → ctx.spec populated
  → if unsupported: ctx.spec stays empty (warnings set)

Framework-agnostic:  L1-secrets, L1-serialization, L1-mcp, L4-config
Adapter-dependent:   L1-memory, L1-tools, L1-rag, L2, L2-agent, L3, L3-agent, ASM, L5, L6
All analyzers consume ctx.version_modifiers
```

### Exit Code Semantics (unchanged)

| Code | Meaning |
|------|---------|
| 0 | Scan completed, no findings above threshold |
| 1 | Scan completed, findings above threshold |
| 2 | User error or internal scan failure |

---

## Version Data Files

### Location

`src/agentwall/data/versions/<library>.yaml` — one file per library, auto-discovered at scan time.

### Schema

```yaml
library: chromadb
pypi_name: chromadb
import_names: [chromadb]

versions:
  - range: "<0.4.0"
    facts:
      has_native_tenant_isolation: false
      has_auth_support: false
      default_persist_encrypted: false

  - range: ">=0.4.0,<0.5.0"
    facts:
      has_native_tenant_isolation: false
      has_auth_support: true
      default_persist_encrypted: false

  - range: ">=0.5.0"
    facts:
      has_native_tenant_isolation: true
      has_auth_support: true
      default_persist_encrypted: false

cves:
  - id: CVE-2024-XXXXX
    range: "<0.4.3"
    severity: HIGH
    description: "Auth bypass in HTTP client"

modifiers:
  - range: ">=0.5.0"
    downgrade:
      AW-MEM-001: HIGH        # library supports tenant isolation, but must verify usage
    condition: "tenant isolation API available — downgrade, not suppress, since code must still use it"
  - range: "<0.4.0"
    upgrade:
      AW-MEM-003: HIGH
```

### Fields

- `library`: Human-readable name
- `pypi_name`: For matching `pyproject.toml` / `requirements.txt`
- `import_names`: For matching when no deps file exists (import-only detection)
- `versions[].range`: PEP 440 version specifier
- `versions[].facts`: Arbitrary key-value facts queryable by analyzers
- `cves[]`: Known CVEs to emit as findings when version matches
- `modifiers[]`: Rule adjustments — `suppress` (list of rule IDs to skip), `upgrade`/`downgrade` (rule_id → new severity). **Suppression should be rare** — prefer `downgrade` for cases where library capability exists but code must still use it correctly (e.g., tenant isolation API available ≠ tenant isolation used).

### Version Resolution Order

1. Lock files: `uv.lock`, `poetry.lock`, `Pipfile.lock` → exact version
2. `pyproject.toml` dependencies → pinned or range
3. `requirements.txt` → pinned or range
4. Range found → use lower bound (pessimistic)
5. Unpinned/missing → no modifiers applied (worst case). AW-SER-002 fires only for agent framework libraries specifically (langchain, crewai, autogen, mcp, llama-index), not for all unresolved dependencies.

### Libraries at Launch (Tier 1 + Tier 2)

| Library | PyPI Name | Tier |
|---------|-----------|------|
| LangChain | langchain | 1 |
| LangChain Community | langchain-community | 1 |
| ChromaDB | chromadb | 1 |
| FAISS | faiss-cpu | 1 |
| Pinecone | pinecone-client | 1 |
| Weaviate | weaviate-client | 1 |
| Qdrant | qdrant-client | 1 |
| MCP | mcp | 2 |
| PyYAML | pyyaml | 2 |

Extending to Tier 3 (crewai, autogen, llama-index, etc.) = dropping new YAML files into the directory. Zero code changes.

**File naming convention:** PyPI name with hyphens replaced by underscores (e.g., `faiss-cpu` → `faiss_cpu.yaml`, `pinecone-client` → `pinecone_client.yaml`). The version resolver normalizes PyPI names to match.

---

## New Data Models

### VersionModifier

```python
class CVEMatch(BaseModel):
    id: str
    severity: Severity
    description: str
    library: str
    version: str

class VersionModifier(BaseModel):
    library: str
    resolved_version: str | None = None   # None if unresolved
    suppress: list[str] = Field(default_factory=list)          # rule IDs to skip
    downgrade: dict[str, Severity] = Field(default_factory=dict)  # rule_id -> new severity
    upgrade: dict[str, Severity] = Field(default_factory=dict)    # rule_id -> new severity
    facts: dict[str, bool | str] = Field(default_factory=dict)    # queryable by analyzers
    cves: list[CVEMatch] = Field(default_factory=list)            # matched CVEs to emit as findings
```

### AnalysisContext Additions

```python
@dataclass
class AnalysisContext:
    # ... existing fields unchanged ...

    # New
    source_files: list[Path] = field(default_factory=list)
    version_modifiers: dict[str, VersionModifier] = field(default_factory=dict)

    def should_suppress(self, rule_id: str) -> bool:
        """Check if any version modifier suppresses this rule."""
        return any(rule_id in m.suppress for m in self.version_modifiers.values())

    def severity_override(self, rule_id: str) -> Severity | None:
        """Return overridden severity from version modifiers.

        Precedence: upgrade always wins over downgrade (most severe wins).
        If multiple modifiers conflict, the highest severity is returned.
        """
        candidates: list[Severity] = []
        for m in self.version_modifiers.values():
            if rule_id in m.upgrade:
                candidates.append(m.upgrade[rule_id])
            if rule_id in m.downgrade:
                candidates.append(m.downgrade[rule_id])
        if not candidates:
            return None
        # Most severe wins (lowest rank = most severe)
        rank = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2, Severity.LOW: 3, Severity.INFO: 4}
        return min(candidates, key=lambda s: rank[s])
```

### Analyzer Consumption Pattern

```python
# In any analyzer, after producing a finding:
if ctx.should_suppress(finding.rule_id):
    continue

override = ctx.severity_override(finding.rule_id)
if override is not None:
    finding = finding.model_copy(update={"severity": override})
```

---

## New Rules

### AW-SEC (Secrets & Leakage) — Framework-agnostic (L1) + Adapter-dependent (L2)

| Rule | Title | Severity | Layer | Framework-agnostic |
|------|-------|----------|-------|--------------------|
| AW-SEC-001 | Hardcoded API key/secret in agent config | HIGH | L1 | Yes |
| AW-SEC-002 | Env var injected into prompt template | MEDIUM | L2 | No (needs call graph) |
| AW-SEC-003 | Agent context logged at DEBUG level | MEDIUM | L1 | Yes |

**AW-SEC-001 detection:** AST walk for string literals matching known secret prefixes (`sk-`, `AKIA`, `ghp_`, `xoxb-`, `Bearer `, `eyJ`) in function call kwargs, variable assignments, and dict values. For non-prefixed secrets: high-entropy heuristic with constraints — minimum 20 chars, Shannon entropy > 4.5, must appear in a kwarg named `key`/`secret`/`token`/`password`/`api_key`/`auth`. Entropy-only matches get confidence=LOW.

**AW-SEC-002 detection:** Cross-file: `os.getenv()` / `os.environ[]` result flows into `PromptTemplate` / `ChatPromptTemplate` / f-string that becomes a prompt. Requires L2 call graph. **This rule is adapter-dependent** — it lives in L2-secrets analyzer alongside the existing call graph infrastructure and only runs when an adapter has populated the spec.

**AW-SEC-003 detection:** AST walk for `logging.debug()`, `logging.info()`, `print()` calls where the argument references variables named `memory`, `chat_history`, `messages`, `context`, `conversation`. Default confidence=LOW for framework-agnostic scans (variable name matching alone is fragile). Upgraded to confidence=HIGH when the file also imports an agent framework library.

### AW-RAG (Retrieval Security) — Adapter-dependent, L1-L2

| Rule | Title | Severity | Layer |
|------|-------|----------|-------|
| AW-RAG-001 | Retrieved context injected into prompt without delimiters | HIGH | L2 |
| AW-RAG-002 | Ingestion from untrusted source without validation | HIGH | L2 |
| AW-RAG-003 | Unencrypted local vector store persistence | MEDIUM | L1 |
| AW-RAG-004 | Vector store exposed on network without auth | HIGH | L1 |

**AW-RAG-001 detection:** `similarity_search()` / `get_relevant_documents()` result variable used in f-string or `.format()` prompt construction without structural delimiters. Delimiter allowlist: XML-style tags (`<context>`, `<documents>`, `<retrieved>`), bracket markers (`[CONTEXT]`, `[DOCUMENTS]`), triple-backtick fenced blocks. Delimiters reduce severity but do not suppress — finding fires at MEDIUM with delimiters, HIGH without.

**AW-RAG-002 detection:** `add_documents()` / `add_texts()` where the document source traces to `requests.get()`, `BeautifulSoup`, `WebBaseLoader`, `UnstructuredFileLoader`, or function parameters from HTTP handlers — with no sanitization/validation step between source and store write.

**AW-RAG-003 detection:** FAISS `save_local()`, Chroma `persist_directory=` without encryption wrapper. **Version-aware:** suppressed if library version defaults to encrypted persistence.

**AW-RAG-004 detection:** `HttpClient()`, `QdrantClient(url=)`, `weaviate.connect_to_custom()` without `api_key`, `auth_credentials`, or auth params. **Version-aware:** downgraded if version enforces auth by default.

### AW-MCP (MCP Server Security) — Framework-agnostic, L1

| Rule | Title | Severity | Layer |
|------|-------|----------|-------|
| AW-MCP-001 | MCP server over HTTP without authentication | HIGH | L1 |
| AW-MCP-002 | Static long-lived token in MCP config | HIGH | L1 |
| AW-MCP-003 | MCP tool with shell/filesystem access | MEDIUM | L1 |

**AW-MCP-001 detection:** Import of `mcp.server` + `Server()` instantiation with HTTP/SSE transport. No auth middleware in handler chain (no `authenticate`, `verify_token`, `check_auth` in decorator/middleware stack).

**AW-MCP-002 detection:** String literal matching secret patterns in MCP server/client initialization kwargs (`api_key=`, `token=`, `secret=`).

**AW-MCP-003 detection:** MCP `@tool` decorated functions containing `subprocess.run`, `subprocess.Popen`, `os.system`, `os.exec*`, `open()` with variable path argument.

### AW-SER (Serialization & Supply Chain) — Framework-agnostic, L0-L1

| Rule | Title | Severity | Layer |
|------|-------|----------|-------|
| AW-SER-001 | Unsafe deserialization of agent state | HIGH | L1 |
| AW-SER-002 | Unpinned agent framework dependency | MEDIUM | L0 |
| AW-SER-003 | Dynamic import of external tool/plugin | MEDIUM | L1 |

**AW-SER-001 detection:** `pickle.load()`, `pickle.loads()`, `yaml.load()` without `Loader=SafeLoader`, `yaml.unsafe_load()`, `torch.load()`, `dill.load()`, `shelve.open()` in agent/memory code paths. Default severity HIGH. **Version-aware:** upgraded to CRITICAL if library version has a known deserialization CVE.

**AW-SER-002 detection:** L0-versions analyzer: scan `pyproject.toml` / `requirements.txt` for agent framework libraries (`langchain`, `crewai`, `autogen`, `mcp`, `llama-index`) without version pin or with unbounded range (`>=0.2`).

**AW-SER-003 detection:** `importlib.import_module()`, `__import__()` where the argument is a variable (not a string literal) in tool registration or plugin loading paths.

### AW-AGT (Agent Architecture) — Adapter-dependent, L2-L3

| Rule | Title | Severity | Layer |
|------|-------|----------|-------|
| AW-AGT-001 | Sub-agent inherits full parent tool set | HIGH | L2 |
| AW-AGT-002 | Agent-to-agent communication without authentication | MEDIUM | L2 |
| AW-AGT-003 | Agent has read+write+delete on same resource without separate approval | MEDIUM | L3 |
| AW-AGT-004 | LLM output stored to memory without validation | HIGH | L3 |

**AW-AGT-001 detection:** Agent constructor where `tools=` argument references another agent's `.tools` attribute or a shared tools list without filtering/slicing. LangChain: `AgentExecutor(tools=parent_agent.tools)`.

**AW-AGT-002 detection:** Agent delegation calls (`AgentExecutor.invoke()` called by another agent, `RunnableSequence` with multiple agents) without auth-related kwargs (`auth`, `token`, `session`, `credentials`, `api_key`) in the delegation call. Default confidence=LOW — static detection of absent auth in delegation is inherently uncertain.

**AW-AGT-003 detection:** Same agent has tools whose names match read+write+delete patterns for the same resource (e.g., `query_users` + `delete_users`) where the delete tool has no separate approval gate (no `HumanApprovalCallbackHandler` or equivalent).

**AW-AGT-004 detection:** Taint: `llm.invoke()` / `chain.invoke()` result flows to `memory.save_context()`, `vectorstore.add_texts()`, or `add_documents()` without a validation/sanitization function in between. MemoryGraft attack vector.

---

## Version-Aware Interactions

| Rule | Version Interaction |
|------|---------------------|
| AW-MEM-001 | Downgraded to HIGH if chromadb >= 0.5 (native tenant isolation available, but code must still use it) |
| AW-MEM-003 | Upgraded to HIGH if chromadb < 0.4 (no auth support) |
| AW-RAG-003 | Suppressed if library defaults to encrypted persistence |
| AW-RAG-004 | Downgraded if library version enforces auth by default |
| AW-SER-001 | Upgraded if library has known deserialization CVE |
| AW-SER-002 | Fires regardless (it IS the version rule) |
| Any rule | CVE-matched libraries emit additional findings |

---

## Framework-Agnostic Scanning

### Scanner Flow Change

```python
# scanner.py changes:
def scan(target, framework=None, config=None):
    # 1. Populate source_files for all projects
    source_files = _collect_source_files(target)  # rglob("*.py") with skip-dirs

    # 2. Run L0-versions (needs source_files for import detection)
    ctx = AnalysisContext(target=target, config=config, spec=AgentSpec(...), source_files=source_files)
    # L0-versions populates ctx.version_modifiers

    # 3. Framework detection + adapter
    detected = framework or auto_detect_framework(target)
    if detected == "langchain":
        spec = LangChainAdapter().parse(target)
        ctx.spec = spec

    # 4. Run analyzers
    for analyzer_cls in ordered:
        if not analyzer_cls.framework_agnostic and ctx.spec is None:
            continue  # skip adapter-dependent analyzers when no adapter ran
        findings = analyzer_cls().analyze(ctx)
        # ... existing collection logic
```

### Analyzer Flag

```python
class Analyzer(Protocol):
    name: str
    depends_on: Sequence[str]
    replace: bool
    opt_in: bool
    framework_agnostic: bool  # NEW — default False
```

| Analyzer | framework_agnostic |
|----------|--------------------|
| L0-versions | True |
| L1-secrets | True |
| L1-serialization | True |
| L1-mcp | True |
| L2-secrets (AW-SEC-002) | False |
| L4-config | True |
| L1-memory | False |
| L1-tools | False |
| L1-rag | False |
| L2, L3, L6, ASM | False |
| L2-agent, L3-agent | False |

### Source Files Clarification

Two separate source file lists exist:

- **`ctx.source_files`** — All `.py` files in target (rglob with skip-dirs). Populated by scanner before any analyzer runs. Used by **framework-agnostic analyzers**.
- **`ctx.spec.source_files`** — Files relevant to the detected framework, populated by the adapter. Used by **adapter-dependent analyzers**.

Framework-agnostic analyzers must use `ctx.source_files`, never `ctx.spec.source_files`.

### Migration

All 10 existing analyzer classes must add `framework_agnostic = False` to maintain current behavior. Both the `Analyzer` Protocol in `context.py` and every concrete analyzer class must be updated — the Protocol gains the field declaration, each class gains the explicit value.

---

## File Structure

```
src/agentwall/
├── data/
│   └── versions/                    # NEW
│       ├── chromadb.yaml
│       ├── faiss_cpu.yaml
│       ├── langchain.yaml
│       ├── langchain_community.yaml
│       ├── mcp.yaml
│       ├── pinecone_client.yaml
│       ├── pyyaml.yaml
│       ├── qdrant_client.yaml
│       └── weaviate_client.yaml
├── analyzers/
│   ├── __init__.py                  # MODIFY — register new analyzers
│   ├── versions.py                  # NEW — L0-versions
│   ├── secrets.py                   # NEW — L1-secrets (AW-SEC-001, 003) framework-agnostic
│   ├── secrets_crossfile.py        # NEW — L2-secrets (AW-SEC-002) adapter-dependent
│   ├── serialization.py            # NEW — L1-serialization (AW-SER-*) framework-agnostic
│   ├── mcp_security.py             # NEW — L1-mcp (AW-MCP-*) framework-agnostic
│   ├── rag.py                       # NEW — L1/L2-rag (AW-RAG-*) adapter-dependent
│   └── agent_arch.py               # NEW — L2/L3-agent (AW-AGT-*) adapter-dependent
├── version_resolver.py             # NEW — parse deps files, resolve against YAML
├── context.py                       # MODIFY
├── models.py                        # MODIFY
├── rules.py                         # MODIFY
├── scanner.py                       # MODIFY
└── patterns.py                      # MODIFY
```

---

## Testing Strategy

- Unit tests per analyzer: fixture directories with known vulnerable patterns
- Version resolver tests: mock `pyproject.toml`/`requirements.txt` with various pin styles
- Integration tests: full scan of fixture projects, assert expected rule IDs fire
- Version modifier tests: same fixture scanned with different version data, verify severity changes
- Framework-agnostic tests: scan a non-langchain fixture, verify AW-SEC/SER/MCP rules fire
- Existing tests must not regress

---

## Non-Goals

- No new adapters (CrewAI, AutoGen) in this work — just the infrastructure for them
- No L7/L8 changes
- No CLI flag changes (version-aware is always on)
- No live probing changes
