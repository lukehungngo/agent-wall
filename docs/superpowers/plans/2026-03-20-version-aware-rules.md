# Version-Aware Rules & Expanded Rule Categories — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add 18 new security rules across 5 categories with a version-aware refinement system, and enable scanning of non-langchain projects via framework-agnostic analyzers.

**Architecture:** L0-versions analyzer resolves library versions from deps files against YAML data, injects modifiers into context. Framework-agnostic analyzers (secrets, serialization, MCP) run on all projects via `ctx.source_files`. Adapter-dependent analyzers (RAG, agent arch) only run when framework is detected. All analyzers consume version modifiers to adjust severity in real-time.

**Tech Stack:** Python 3.10+, Pydantic v2, PyYAML, pytest, packaging (for PEP 440 version parsing)

**Spec:** `docs/superpowers/specs/2026-03-20-version-aware-rules-design.md`

---

## Task Dependency Graph

```
Task 1 (models + Category enum)
  ↓
Task 2 (rules.py — 18 new rules)
  ↓
Task 3 (patterns.py — new pattern constants)
  ↓
Task 4 (context.py + scanner.py — framework-agnostic infra)
  ↓
Task 5 (version_resolver.py + YAML data files)
  ↓
Task 6 (L0-versions analyzer)
  ↓
Task 7 (L1-secrets analyzer)
Task 8 (L1-serialization analyzer)  ← can run in parallel with 7
Task 9 (L1-mcp analyzer)            ← can run in parallel with 7, 8
  ↓
Task 10 (L1/L2-rag analyzer)
Task 11 (L2/L3-agent analyzer)      ← can run in parallel with 10
  ↓
Task 12 (final verification)
```

---

### Task 1: Extend data models — Category enum, VersionModifier, CVEMatch

**Files:**
- Modify: `src/agentwall/models.py`
- Test: `tests/test_models.py` (create if needed)

- [ ] **Step 1: Write test for new Category values**

```python
# tests/test_version_models.py
from agentwall.models import Category

class TestCategoryEnum:
    def test_new_categories_exist(self) -> None:
        assert Category.SECRETS == "secrets"
        assert Category.RAG == "rag"
        assert Category.MCP == "mcp"
        assert Category.SERIALIZATION == "serialization"
        assert Category.AGENT == "agent"

    def test_existing_categories_unchanged(self) -> None:
        assert Category.MEMORY == "memory"
        assert Category.TOOL == "tool"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_version_models.py::TestCategoryEnum -v`
Expected: FAIL — `Category` has no `SECRETS` attribute.

- [ ] **Step 3: Add new Category values**

In `src/agentwall/models.py`, expand the `Category` enum (~line 20):

```python
class Category(str, Enum):
    MEMORY = "memory"
    TOOL = "tool"
    SECRETS = "secrets"
    RAG = "rag"
    MCP = "mcp"
    SERIALIZATION = "serialization"
    AGENT = "agent"
```

- [ ] **Step 4: Write test for VersionModifier and CVEMatch**

```python
# tests/test_version_models.py (append)
from agentwall.models import CVEMatch, Severity, VersionModifier


class TestVersionModifier:
    def test_defaults(self) -> None:
        m = VersionModifier(library="chromadb")
        assert m.resolved_version is None
        assert m.suppress == []
        assert m.downgrade == {}
        assert m.upgrade == {}
        assert m.facts == {}
        assert m.cves == []

    def test_with_values(self) -> None:
        m = VersionModifier(
            library="chromadb",
            resolved_version="0.4.1",
            upgrade={"AW-MEM-003": Severity.HIGH},
            facts={"has_auth_support": True},
        )
        assert m.resolved_version == "0.4.1"
        assert m.upgrade["AW-MEM-003"] == Severity.HIGH
        assert m.facts["has_auth_support"] is True


class TestCVEMatch:
    def test_creation(self) -> None:
        cve = CVEMatch(
            id="CVE-2024-12345",
            severity=Severity.HIGH,
            description="Auth bypass",
            library="chromadb",
            version="0.4.1",
        )
        assert cve.id == "CVE-2024-12345"
        assert cve.library == "chromadb"
```

- [ ] **Step 5: Add VersionModifier and CVEMatch to models.py**

In `src/agentwall/models.py`, after the `ScanResult` class:

```python
class CVEMatch(BaseModel):
    id: str
    severity: Severity
    description: str
    library: str
    version: str


class VersionModifier(BaseModel):
    library: str
    resolved_version: str | None = None
    suppress: list[str] = Field(default_factory=list)
    downgrade: dict[str, Severity] = Field(default_factory=dict)
    upgrade: dict[str, Severity] = Field(default_factory=dict)
    facts: dict[str, bool | str] = Field(default_factory=dict)
    cves: list[CVEMatch] = Field(default_factory=list)
```

- [ ] **Step 6: Run all tests**

Run: `pytest tests/test_version_models.py -v`
Expected: All PASS.

- [ ] **Step 7: Commit**

```bash
git add src/agentwall/models.py tests/test_version_models.py
git commit -m "feat(models): add Category enum expansion, VersionModifier, CVEMatch"
```

---

### Task 2: Add 18 new rule definitions

**Files:**
- Modify: `src/agentwall/rules.py`
- Test: `tests/test_rules.py` (create)

- [ ] **Step 1: Write test for new rules**

```python
# tests/test_rules.py
from agentwall.rules import ALL_RULES


class TestRuleRegistry:
    def test_total_rule_count(self) -> None:
        assert len(ALL_RULES) == 28  # 10 existing + 18 new

    def test_sec_rules_exist(self) -> None:
        for i in range(1, 4):
            assert f"AW-SEC-00{i}" in ALL_RULES

    def test_rag_rules_exist(self) -> None:
        for i in range(1, 5):
            assert f"AW-RAG-00{i}" in ALL_RULES

    def test_mcp_rules_exist(self) -> None:
        for i in range(1, 4):
            assert f"AW-MCP-00{i}" in ALL_RULES

    def test_ser_rules_exist(self) -> None:
        for i in range(1, 4):
            assert f"AW-SER-00{i}" in ALL_RULES

    def test_agt_rules_exist(self) -> None:
        for i in range(1, 5):
            assert f"AW-AGT-00{i}" in ALL_RULES

    def test_existing_rules_unchanged(self) -> None:
        assert "AW-MEM-001" in ALL_RULES
        assert "AW-TOOL-005" in ALL_RULES

    def test_severity_discipline_no_new_critical(self) -> None:
        """CRITICAL is reserved for confirmed cross-tenant data access (CLAUDE.md invariant)."""
        new_prefixes = ("AW-SEC-", "AW-RAG-", "AW-MCP-", "AW-SER-", "AW-AGT-")
        from agentwall.models import Severity
        for rule_id, rule in ALL_RULES.items():
            if any(rule_id.startswith(p) for p in new_prefixes):
                assert rule.severity != Severity.CRITICAL, f"{rule_id} should not be CRITICAL"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_rules.py -v`
Expected: FAIL — only 10 rules exist.

- [ ] **Step 3: Add all 18 new rule definitions**

In `src/agentwall/rules.py`, add after the existing tool rules and before the registry:

```python
# ── Secrets rules ────────────────────────────────────────────────────────────

AW_SEC_001 = RuleDef(
    rule_id="AW-SEC-001",
    title="Hardcoded API key/secret in agent config",
    severity=Severity.HIGH,
    category=Category.SECRETS,
    description=(
        "A string literal matching known API key patterns (sk-, AKIA, ghp_, xoxb-) "
        "was found in agent or tool configuration code."
    ),
    fix="Move secrets to environment variables or a secrets manager.",
)

AW_SEC_002 = RuleDef(
    rule_id="AW-SEC-002",
    title="Env var injected into prompt template",
    severity=Severity.MEDIUM,
    category=Category.SECRETS,
    description=(
        "An environment variable value flows into a prompt template. "
        "If the env var contains sensitive data, it will be sent to the LLM."
    ),
    fix="Redact sensitive env vars before injecting into prompts.",
)

AW_SEC_003 = RuleDef(
    rule_id="AW-SEC-003",
    title="Agent context logged at DEBUG level",
    severity=Severity.MEDIUM,
    category=Category.SECRETS,
    description=(
        "Agent memory, chat history, or conversation context is passed to "
        "a logging or print call. This may expose sensitive user data in logs."
    ),
    fix="Redact or summarize context before logging. Never log full conversation state.",
)

# ── RAG rules ────────────────────────────────────────────────────────────────

AW_RAG_001 = RuleDef(
    rule_id="AW-RAG-001",
    title="Retrieved context injected into prompt without delimiters",
    severity=Severity.HIGH,
    category=Category.RAG,
    description=(
        "Retrieved documents are concatenated directly into a prompt without structural "
        "delimiters (XML tags, fenced blocks). This increases indirect prompt injection risk."
    ),
    fix="Wrap retrieved content in explicit delimiters: <context>...</context> or similar.",
)

AW_RAG_002 = RuleDef(
    rule_id="AW-RAG-002",
    title="Ingestion from untrusted source without validation",
    severity=Severity.HIGH,
    category=Category.RAG,
    description=(
        "Documents from an external source (HTTP, file upload, web scraper) are ingested "
        "into the vector store without content validation or sanitization."
    ),
    fix="Validate and sanitize document content before calling add_documents/add_texts.",
)

AW_RAG_003 = RuleDef(
    rule_id="AW-RAG-003",
    title="Unencrypted local vector store persistence",
    severity=Severity.MEDIUM,
    category=Category.RAG,
    description=(
        "A local vector store (FAISS, Chroma) persists data to disk without encryption. "
        "Stored embeddings and documents are readable by any process with file access."
    ),
    fix="Encrypt the persistence directory or use a vector store with built-in encryption.",
)

AW_RAG_004 = RuleDef(
    rule_id="AW-RAG-004",
    title="Vector store exposed on network without auth",
    severity=Severity.HIGH,
    category=Category.RAG,
    description=(
        "A vector store client connects to a remote server without authentication parameters. "
        "The store may be accessible to anyone on the network."
    ),
    fix="Add api_key, auth_credentials, or equivalent auth parameters to the client.",
)

# ── MCP rules ────────────────────────────────────────────────────────────────

AW_MCP_001 = RuleDef(
    rule_id="AW-MCP-001",
    title="MCP server over HTTP without authentication",
    severity=Severity.HIGH,
    category=Category.MCP,
    description=(
        "An MCP server is exposed over HTTP/SSE without authentication middleware. "
        "Any client on the network can invoke its tools."
    ),
    fix="Add authentication middleware to the MCP server handler chain.",
)

AW_MCP_002 = RuleDef(
    rule_id="AW-MCP-002",
    title="Static long-lived token in MCP config",
    severity=Severity.HIGH,
    category=Category.MCP,
    description=(
        "A hardcoded token or API key was found in MCP server/client initialization. "
        "Static credentials cannot be rotated without redeployment."
    ),
    fix="Load MCP credentials from environment variables or a secrets manager.",
)

AW_MCP_003 = RuleDef(
    rule_id="AW-MCP-003",
    title="MCP tool with shell/filesystem access",
    severity=Severity.MEDIUM,
    category=Category.MCP,
    description=(
        "An MCP tool handler contains subprocess, os.system, or open() calls with "
        "variable arguments. This enables arbitrary command/file execution via the tool."
    ),
    fix="Restrict tool inputs with an allowlist. Avoid shell=True and variable file paths.",
)

# ── Serialization rules ─────────────────────────────────────────────────────

AW_SER_001 = RuleDef(
    rule_id="AW-SER-001",
    title="Unsafe deserialization of agent state",
    severity=Severity.HIGH,
    category=Category.SERIALIZATION,
    description=(
        "Unsafe deserialization (pickle.load, yaml.unsafe_load, torch.load) is used "
        "in an agent or memory code path. This enables remote code execution if the "
        "serialized data is attacker-controlled."
    ),
    fix="Use safe alternatives: json, yaml.safe_load, torch.load(weights_only=True).",
)

AW_SER_002 = RuleDef(
    rule_id="AW-SER-002",
    title="Unpinned agent framework dependency",
    severity=Severity.MEDIUM,
    category=Category.SERIALIZATION,
    description=(
        "An agent framework library is listed as a dependency without a version pin. "
        "Unpinned dependencies can introduce breaking changes or vulnerabilities silently."
    ),
    fix="Pin agent framework dependencies to a specific version or bounded range.",
)

AW_SER_003 = RuleDef(
    rule_id="AW-SER-003",
    title="Dynamic import of external tool/plugin",
    severity=Severity.MEDIUM,
    category=Category.SERIALIZATION,
    description=(
        "importlib.import_module() or __import__() is called with a variable argument "
        "in a tool registration path. This enables loading arbitrary code as a tool."
    ),
    fix="Use a static tool registry with explicit imports. Avoid dynamic plugin loading.",
)

# ── Agent architecture rules ────────────────────────────────────────────────

AW_AGT_001 = RuleDef(
    rule_id="AW-AGT-001",
    title="Sub-agent inherits full parent tool set",
    severity=Severity.HIGH,
    category=Category.AGENT,
    description=(
        "A sub-agent receives the full tool set of its parent agent without filtering. "
        "This violates the principle of least privilege."
    ),
    fix="Filter the tool list to only tools the sub-agent needs.",
)

AW_AGT_002 = RuleDef(
    rule_id="AW-AGT-002",
    title="Agent-to-agent communication without authentication",
    severity=Severity.MEDIUM,
    category=Category.AGENT,
    description=(
        "An agent delegation call passes no authentication-related parameters. "
        "The receiving agent cannot verify the caller's identity."
    ),
    fix="Pass auth tokens or session credentials in agent delegation calls.",
)

AW_AGT_003 = RuleDef(
    rule_id="AW-AGT-003",
    title="Agent has read+write+delete on same resource without separate approval",
    severity=Severity.MEDIUM,
    category=Category.AGENT,
    description=(
        "An agent has tools for reading, writing, and deleting the same resource type "
        "but the destructive tools lack a separate approval gate."
    ),
    fix="Add a separate approval gate for destructive tools on shared resources.",
)

AW_AGT_004 = RuleDef(
    rule_id="AW-AGT-004",
    title="LLM output stored to memory without validation",
    severity=Severity.HIGH,
    category=Category.AGENT,
    description=(
        "LLM output is stored directly into agent memory or a vector store without "
        "validation. This enables memory poisoning (MemoryGraft) attacks."
    ),
    fix="Validate or sanitize LLM output before persisting to memory.",
)
```

Update the `ALL_RULES` registry to include all 28 rules.

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_rules.py -v`
Expected: All PASS.

- [ ] **Step 5: Run existing tests to check no regression**

Run: `pytest tests/ -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/rules.py tests/test_rules.py
git commit -m "feat(rules): add 18 new rules — AW-SEC, AW-RAG, AW-MCP, AW-SER, AW-AGT"
```

---

### Task 3: Add new pattern constants

**Files:**
- Modify: `src/agentwall/patterns.py`
- Test: `tests/test_patterns.py` (create)

- [ ] **Step 1: Write test**

```python
# tests/test_patterns.py
from agentwall import patterns


class TestNewPatterns:
    def test_secret_prefixes_exist(self) -> None:
        assert "sk-" in patterns.SECRET_PREFIXES
        assert "AKIA" in patterns.SECRET_PREFIXES
        assert "ghp_" in patterns.SECRET_PREFIXES

    def test_secret_kwarg_names_exist(self) -> None:
        assert "api_key" in patterns.SECRET_KWARG_NAMES
        assert "token" in patterns.SECRET_KWARG_NAMES

    def test_unsafe_deser_calls_exist(self) -> None:
        assert "pickle.load" in patterns.UNSAFE_DESER_CALLS
        assert "yaml.unsafe_load" in patterns.UNSAFE_DESER_CALLS

    def test_mcp_imports_exist(self) -> None:
        assert "mcp" in patterns.MCP_IMPORTS

    def test_context_var_names_exist(self) -> None:
        assert "chat_history" in patterns.CONTEXT_VAR_NAMES

    def test_agent_framework_packages_exist(self) -> None:
        assert "langchain" in patterns.AGENT_FRAMEWORK_PACKAGES

    def test_delimiter_patterns_exist(self) -> None:
        assert len(patterns.RAG_DELIMITER_PATTERNS) > 0

    def test_existing_patterns_unchanged(self) -> None:
        assert len(patterns.RETRIEVAL_METHODS) == 5
        assert len(patterns.FILTER_KWARGS) == 3
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_patterns.py -v`
Expected: FAIL — no `SECRET_PREFIXES` attribute.

- [ ] **Step 3: Add new constants to patterns.py**

Append to `src/agentwall/patterns.py`:

```python
# ── Secret detection ─────────────────────────────────────────────────────────

SECRET_PREFIXES: list[str] = [
    "sk-", "AKIA", "ghp_", "gho_", "ghu_", "ghs_", "ghr_",
    "xoxb-", "xoxp-", "xoxa-", "xoxr-",
    "Bearer ", "eyJ",
    "FLWSECK_", "sk_live_", "pk_live_", "rk_live_",
    "SG.", "key-",
]

SECRET_KWARG_NAMES: frozenset[str] = frozenset({
    "api_key", "apikey", "secret", "token", "password", "passwd",
    "secret_key", "access_key", "auth_token", "private_key",
    "client_secret", "api_secret",
})

SECRET_ENTROPY_MIN_LEN: int = 20
SECRET_ENTROPY_THRESHOLD: float = 4.5

# ── Context variable names (for logging detection) ──────────────────────────

CONTEXT_VAR_NAMES: frozenset[str] = frozenset({
    "memory", "chat_history", "messages", "context",
    "conversation", "history", "chat_messages",
    "conversation_history", "message_history",
})

# ── Unsafe deserialization ───────────────────────────────────────────────────

UNSAFE_DESER_CALLS: frozenset[str] = frozenset({
    "pickle.load", "pickle.loads",
    "yaml.load", "yaml.unsafe_load",
    "torch.load",
    "dill.load", "dill.loads",
    "shelve.open",
    "joblib.load",
})

SAFE_YAML_LOADERS: frozenset[str] = frozenset({
    "SafeLoader", "CSafeLoader", "yaml.SafeLoader", "yaml.CSafeLoader",
})

# ── MCP detection ────────────────────────────────────────────────────────────

MCP_IMPORTS: frozenset[str] = frozenset({
    "mcp", "mcp.server", "mcp.client",
    "modelcontextprotocol",
})

MCP_SHELL_CALLS: frozenset[str] = frozenset({
    "subprocess.run", "subprocess.Popen", "subprocess.call", "subprocess.check_output",
    "os.system", "os.popen", "os.exec", "os.execvp",
})

# ── Dynamic imports ──────────────────────────────────────────────────────────

DYNAMIC_IMPORT_CALLS: frozenset[str] = frozenset({
    "importlib.import_module", "__import__",
})

# ── Agent framework packages (for AW-SER-002) ───────────────────────────────

AGENT_FRAMEWORK_PACKAGES: frozenset[str] = frozenset({
    "langchain", "langchain-core", "langchain-community",
    "crewai", "autogen", "pyautogen",
    "mcp", "llama-index", "llama-index-core",
    "openai-agents",
})

# ── RAG delimiters ───────────────────────────────────────────────────────────

RAG_DELIMITER_PATTERNS: list[str] = [
    "<context>", "</context>",
    "<documents>", "</documents>",
    "<retrieved>", "</retrieved>",
    "[CONTEXT]", "[/CONTEXT]",
    "[DOCUMENTS]", "[/DOCUMENTS]",
    "```",
]

# ── Untrusted ingestion sources ──────────────────────────────────────────────

UNTRUSTED_SOURCE_CALLS: frozenset[str] = frozenset({
    "requests.get", "requests.post",
    "httpx.get", "httpx.post",
    "urllib.request.urlopen",
    "BeautifulSoup",
    "WebBaseLoader", "UnstructuredFileLoader",
    "SeleniumURLLoader", "PlaywrightURLLoader",
})

# ── Vector store network clients (for AW-RAG-004) ───────────────────────────

VECTOR_STORE_NETWORK_CLIENTS: frozenset[str] = frozenset({
    "HttpClient", "QdrantClient", "WeaviateClient",
    "connect_to_custom", "connect_to_wcs",
})

VECTOR_STORE_AUTH_KWARGS: frozenset[str] = frozenset({
    "api_key", "auth_credentials", "token",
    "username", "password", "auth",
})
```

- [ ] **Step 4: Run tests**

Run: `pytest tests/test_patterns.py -v`
Expected: All PASS.

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/patterns.py tests/test_patterns.py
git commit -m "feat(patterns): add secret, MCP, serialization, RAG pattern constants"
```

---

### Task 4: Framework-agnostic scanning infrastructure

**Files:**
- Modify: `src/agentwall/context.py` (~lines 23-60)
- Modify: `src/agentwall/scanner.py` (~lines 93-184)
- Test: `tests/test_context.py` (create), `tests/test_scanner.py` (modify)

- [ ] **Step 1: Write tests for AnalysisContext additions**

```python
# tests/test_context.py
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig, Severity, VersionModifier


class TestContextVersionModifiers:
    def test_should_suppress_empty(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        assert not ctx.should_suppress("AW-MEM-001")

    def test_should_suppress_match(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        ctx.version_modifiers["chromadb"] = VersionModifier(
            library="chromadb", suppress=["AW-MEM-001"]
        )
        assert ctx.should_suppress("AW-MEM-001")
        assert not ctx.should_suppress("AW-MEM-002")

    def test_severity_override_upgrade(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        ctx.version_modifiers["chromadb"] = VersionModifier(
            library="chromadb", upgrade={"AW-MEM-003": Severity.HIGH}
        )
        assert ctx.severity_override("AW-MEM-003") == Severity.HIGH
        assert ctx.severity_override("AW-MEM-001") is None

    def test_severity_override_most_severe_wins(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        ctx.version_modifiers["lib_a"] = VersionModifier(
            library="lib_a", downgrade={"AW-MEM-001": Severity.LOW}
        )
        ctx.version_modifiers["lib_b"] = VersionModifier(
            library="lib_b", upgrade={"AW-MEM-001": Severity.HIGH}
        )
        assert ctx.severity_override("AW-MEM-001") == Severity.HIGH

    def test_source_files_default_empty(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        assert ctx.source_files == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_context.py -v`
Expected: FAIL — `AnalysisContext` has no `source_files` or `version_modifiers`.

- [ ] **Step 3: Update AnalysisContext**

In `src/agentwall/context.py`, add to `AnalysisContext` dataclass:

```python
source_files: list[Path] = field(default_factory=list)
version_modifiers: dict[str, VersionModifier] = field(default_factory=dict)

def should_suppress(self, rule_id: str) -> bool:
    return any(rule_id in m.suppress for m in self.version_modifiers.values())

def severity_override(self, rule_id: str) -> Severity | None:
    from agentwall.models import Severity as Sev
    rank = {Sev.CRITICAL: 0, Sev.HIGH: 1, Sev.MEDIUM: 2, Sev.LOW: 3, Sev.INFO: 4}
    candidates: list[Sev] = []
    for m in self.version_modifiers.values():
        if rule_id in m.upgrade:
            candidates.append(m.upgrade[rule_id])
        if rule_id in m.downgrade:
            candidates.append(m.downgrade[rule_id])
    if not candidates:
        return None
    return min(candidates, key=lambda s: rank[s])
```

Add `framework_agnostic: bool` to the `Analyzer` Protocol. Add necessary imports.

- [ ] **Step 4: Update all existing analyzers with `framework_agnostic = False`**

Add `framework_agnostic = False` to each of the 10 existing analyzer classes in:
- `src/agentwall/analyzers/memory.py`
- `src/agentwall/analyzers/tools.py`
- `src/agentwall/analyzers/callgraph.py`
- `src/agentwall/analyzers/taint.py`
- `src/agentwall/analyzers/config.py` (set to `True` — config auditor is framework-agnostic)
- `src/agentwall/analyzers/semgrep.py`
- `src/agentwall/analyzers/symbolic.py`
- `src/agentwall/analyzers/asm.py`
- `src/agentwall/analyzers/runtime.py`
- `src/agentwall/analyzers/confidence.py`

- [ ] **Step 5: Write test for framework-agnostic scanner behavior**

```python
# tests/test_scanner.py (append to TestScannerFrameworkOverride)
def test_unsupported_framework_has_source_files(self) -> None:
    """Non-langchain projects should still get source_files populated."""
    result = scan(FIXTURES / "langchain_unsafe", framework="crewai")
    # Result has warnings but scan completes — source_files were available internally
    assert not result.errors
    assert result.warnings
```

- [ ] **Step 6: Update scanner.py — populate source_files, gate adapter-dependent analyzers**

In `src/agentwall/scanner.py`:

1. Add `_collect_source_files(target: Path) -> list[Path]` function (reuse `_SKIP_DIRS` from detector).
2. Create `AnalysisContext` with `source_files` populated before adapter runs.
3. After the unsupported-framework early return, instead of returning immediately, continue to run framework-agnostic analyzers. Change the flow to:
   - Always create `ctx` with `source_files`
   - If framework is langchain, run adapter and set `ctx.spec`
   - If not, leave `ctx.spec` as None but continue
   - In the analyzer loop, skip non-framework-agnostic analyzers when `ctx.spec is None`

- [ ] **Step 7: Run all tests**

Run: `pytest -v`
Expected: All PASS (373+ existing + new tests).

- [ ] **Step 8: Commit**

```bash
git add src/agentwall/context.py src/agentwall/scanner.py src/agentwall/analyzers/ tests/
git commit -m "feat: framework-agnostic scanning infrastructure

- Add source_files, version_modifiers to AnalysisContext
- Add should_suppress(), severity_override() helpers
- Add framework_agnostic flag to Analyzer protocol
- Scanner populates source_files and gates adapter-dependent analyzers"
```

---

### Task 5: Version resolver + YAML data files

**Files:**
- Create: `src/agentwall/version_resolver.py`
- Create: `src/agentwall/data/versions/*.yaml` (9 files)
- Modify: `pyproject.toml` (package-data)
- Test: `tests/test_version_resolver.py`

- [ ] **Step 1: Write tests for version resolver**

```python
# tests/test_version_resolver.py
from pathlib import Path

from agentwall.version_resolver import (
    load_version_data,
    resolve_version_from_requirements,
    resolve_version_from_pyproject,
    resolve_modifiers,
)


class TestLoadVersionData:
    def test_loads_chromadb_yaml(self) -> None:
        data = load_version_data()
        assert "chromadb" in data
        assert data["chromadb"]["pypi_name"] == "chromadb"
        assert len(data["chromadb"]["versions"]) > 0

    def test_loads_all_yaml_files(self) -> None:
        data = load_version_data()
        assert len(data) >= 9  # Tier 1 + Tier 2


class TestResolveFromRequirements:
    def test_pinned_version(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("chromadb==0.4.1\n")
        versions = resolve_version_from_requirements(tmp_path / "requirements.txt")
        assert versions["chromadb"] == "0.4.1"

    def test_range_uses_lower_bound(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("chromadb>=0.4.0,<0.5.0\n")
        versions = resolve_version_from_requirements(tmp_path / "requirements.txt")
        assert versions["chromadb"] == "0.4.0"

    def test_unpinned_returns_none(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("chromadb\n")
        versions = resolve_version_from_requirements(tmp_path / "requirements.txt")
        assert versions["chromadb"] is None

    def test_missing_file(self, tmp_path: Path) -> None:
        versions = resolve_version_from_requirements(tmp_path / "requirements.txt")
        assert versions == {}


class TestResolveFromPyproject:
    def test_pinned_version(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text(
            '[project]\ndependencies = ["chromadb==0.4.1"]\n'
        )
        versions = resolve_version_from_pyproject(tmp_path / "pyproject.toml")
        assert versions["chromadb"] == "0.4.1"


class TestResolveModifiers:
    def test_matching_version_returns_modifier(self) -> None:
        data = load_version_data()
        modifiers = resolve_modifiers({"chromadb": "0.3.0"}, data)
        assert "chromadb" in modifiers
        # chromadb < 0.4.0 should have upgrade for AW-MEM-003
        m = modifiers["chromadb"]
        assert "AW-MEM-003" in m.upgrade

    def test_no_match_returns_empty(self) -> None:
        data = load_version_data()
        modifiers = resolve_modifiers({"unknown_lib": "1.0.0"}, data)
        assert "unknown_lib" not in modifiers

    def test_unresolved_version_returns_no_modifiers(self) -> None:
        data = load_version_data()
        modifiers = resolve_modifiers({"chromadb": None}, data)
        m = modifiers.get("chromadb")
        # No version resolved → no modifiers applied (worst case)
        assert m is None or (m.suppress == [] and m.upgrade == {} and m.downgrade == {})
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_version_resolver.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Create YAML data files**

Create `src/agentwall/data/versions/` directory with 9 YAML files. Example for `chromadb.yaml`:

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

cves: []

modifiers:
  - range: ">=0.5.0"
    downgrade:
      AW-MEM-001: HIGH
    condition: "tenant isolation API available — downgrade since code must still use it"
  - range: "<0.4.0"
    upgrade:
      AW-MEM-003: HIGH
```

Create similar files for: `langchain.yaml`, `langchain_community.yaml`, `faiss_cpu.yaml`, `pinecone_client.yaml`, `weaviate_client.yaml`, `qdrant_client.yaml`, `mcp.yaml`, `pyyaml.yaml`.

- [ ] **Step 4: Add package-data to pyproject.toml**

Add to `pyproject.toml` under `[tool.hatch.build.targets.wheel]`:

```toml
[tool.hatch.build.targets.wheel]
packages = ["src/agentwall"]

[tool.hatch.build.targets.wheel.force-include]
"src/agentwall/data" = "agentwall/data"
```

- [ ] **Step 5: Implement version_resolver.py**

Create `src/agentwall/version_resolver.py`:

```python
"""Resolve library versions from dependency files and match against YAML version data."""

from __future__ import annotations

import re
from importlib import resources
from pathlib import Path
from typing import Any

import yaml
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from agentwall.models import Severity, VersionModifier

_SEVERITY_MAP = {"critical": Severity.CRITICAL, "high": Severity.HIGH, "medium": Severity.MEDIUM, "low": Severity.LOW}


def load_version_data() -> dict[str, dict[str, Any]]:
    """Load all YAML version data files from package data directory."""
    data_dir = Path(__file__).parent / "data" / "versions"
    result: dict[str, dict[str, Any]] = {}
    if not data_dir.exists():
        return result
    for yaml_file in sorted(data_dir.glob("*.yaml")):
        with open(yaml_file) as f:
            doc = yaml.safe_load(f)
        if doc and "pypi_name" in doc:
            result[doc["pypi_name"]] = doc
    return result


def _normalize_name(name: str) -> str:
    """Normalize PyPI package name: lowercase, hyphens to underscores."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_lower_bound(spec_str: str) -> str | None:
    """Extract lower bound version from a PEP 440 specifier string."""
    for part in spec_str.split(","):
        part = part.strip()
        if part.startswith(">="):
            return part[2:].strip()
        if part.startswith("=="):
            return part[2:].strip()
    return None


def resolve_version_from_requirements(path: Path) -> dict[str, str | None]:
    """Parse requirements.txt and extract package versions."""
    if not path.exists():
        return {}
    result: dict[str, str | None] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)", line)
        if not match:
            continue
        name = _normalize_name(match.group(1))
        spec = match.group(2).strip()
        if not spec:
            result[name] = None
        elif spec.startswith("=="):
            result[name] = spec[2:].strip()
        else:
            result[name] = _extract_lower_bound(spec)
    return result


def resolve_version_from_pyproject(path: Path) -> dict[str, str | None]:
    """Parse pyproject.toml [project].dependencies for versions."""
    if not path.exists():
        return {}
    import tomllib
    with open(path, "rb") as f:
        data = tomllib.load(f)
    deps = data.get("project", {}).get("dependencies", [])
    result: dict[str, str | None] = {}
    for dep in deps:
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)", dep)
        if not match:
            continue
        name = _normalize_name(match.group(1))
        spec = match.group(2).strip()
        if not spec:
            result[name] = None
        elif spec.startswith("=="):
            result[name] = spec[2:].strip()
        else:
            result[name] = _extract_lower_bound(spec)
    return result


def resolve_versions(target: Path) -> dict[str, str | None]:
    """Resolve library versions from a project directory. Best-effort, pessimistic."""
    versions: dict[str, str | None] = {}
    # Priority: lock files > pyproject.toml > requirements.txt
    for req_file in ["requirements.txt", "requirements-dev.txt"]:
        versions.update(resolve_version_from_requirements(target / req_file))
    pyproject = target / "pyproject.toml"
    if pyproject.exists():
        versions.update(resolve_version_from_pyproject(pyproject))
    # TODO: lock file support (uv.lock, poetry.lock) in future iteration
    return versions


def resolve_modifiers(
    versions: dict[str, str | None],
    version_data: dict[str, dict[str, Any]],
) -> dict[str, VersionModifier]:
    """Match resolved versions against YAML data and produce VersionModifiers."""
    result: dict[str, VersionModifier] = {}
    for pypi_name, data in version_data.items():
        normalized = _normalize_name(pypi_name)
        version_str = versions.get(normalized)
        if version_str is None:
            continue
        try:
            ver = Version(version_str)
        except Exception:
            continue
        # Collect facts from matching version ranges
        facts: dict[str, bool | str] = {}
        for v_entry in data.get("versions", []):
            spec = SpecifierSet(v_entry["range"])
            if ver in spec:
                facts.update(v_entry.get("facts", {}))

        # Collect modifiers from matching ranges
        suppress: list[str] = []
        downgrade: dict[str, Severity] = {}
        upgrade: dict[str, Severity] = {}
        for mod in data.get("modifiers", []):
            spec = SpecifierSet(mod["range"])
            if ver in spec:
                suppress.extend(mod.get("suppress", []))
                for rule_id, sev_str in mod.get("downgrade", {}).items():
                    downgrade[rule_id] = _SEVERITY_MAP[sev_str.lower()]
                for rule_id, sev_str in mod.get("upgrade", {}).items():
                    upgrade[rule_id] = _SEVERITY_MAP[sev_str.lower()]

        # Collect CVE matches
        from agentwall.models import CVEMatch
        cves: list[CVEMatch] = []
        for cve in data.get("cves", []):
            spec = SpecifierSet(cve["range"])
            if ver in spec:
                cves.append(CVEMatch(
                    id=cve["id"],
                    severity=_SEVERITY_MAP[cve["severity"].lower()],
                    description=cve["description"],
                    library=pypi_name,
                    version=version_str,
                ))

        result[normalized] = VersionModifier(
            library=pypi_name,
            resolved_version=version_str,
            suppress=suppress,
            downgrade=downgrade,
            upgrade=upgrade,
            facts=facts,
            cves=cves,
        )
    return result
```

- [ ] **Step 6: Add `pyyaml` and `packaging` to dependencies**

In `pyproject.toml`, add `pyyaml` and `packaging` to `[project].dependencies`.

- [ ] **Step 7: Run tests**

Run: `pytest tests/test_version_resolver.py -v`
Expected: All PASS.

- [ ] **Step 8: Commit**

```bash
git add src/agentwall/version_resolver.py src/agentwall/data/ tests/test_version_resolver.py pyproject.toml
git commit -m "feat: version resolver with YAML data files for 9 libraries"
```

---

### Task 6: L0-versions analyzer

**Files:**
- Create: `src/agentwall/analyzers/versions.py`
- Modify: `src/agentwall/analyzers/__init__.py`
- Test: `tests/test_versions_analyzer.py`

- [ ] **Step 1: Write test**

```python
# tests/test_versions_analyzer.py
from pathlib import Path

from agentwall.analyzers.versions import VersionsAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig


class TestVersionsAnalyzer:
    def test_name(self) -> None:
        assert VersionsAnalyzer.name == "L0-versions"
        assert VersionsAnalyzer.framework_agnostic is True

    def test_populates_version_modifiers(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("chromadb==0.3.0\n")
        (tmp_path / "app.py").write_text("import chromadb\n")
        ctx = AnalysisContext(
            target=tmp_path, config=ScanConfig(), source_files=[tmp_path / "app.py"]
        )
        findings = VersionsAnalyzer().analyze(ctx)
        assert "chromadb" in ctx.version_modifiers

    def test_flags_unpinned_agent_framework(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain\n")
        (tmp_path / "app.py").write_text("import langchain\n")
        ctx = AnalysisContext(
            target=tmp_path, config=ScanConfig(), source_files=[tmp_path / "app.py"]
        )
        findings = VersionsAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in findings]
        assert "AW-SER-002" in rule_ids

    def test_no_deps_file_no_crash(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("print('hello')\n")
        ctx = AnalysisContext(
            target=tmp_path, config=ScanConfig(), source_files=[tmp_path / "app.py"]
        )
        findings = VersionsAnalyzer().analyze(ctx)
        assert ctx.version_modifiers == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_versions_analyzer.py -v`
Expected: FAIL — module doesn't exist.

- [ ] **Step 3: Implement L0-versions analyzer**

Create `src/agentwall/analyzers/versions.py`:

```python
"""L0-versions analyzer — resolve library versions and inject modifiers into context."""

from __future__ import annotations

from agentwall.context import AnalysisContext
from agentwall.models import Category, Finding, Severity
from agentwall.patterns import AGENT_FRAMEWORK_PACKAGES
from agentwall.rules import AW_SER_002
from agentwall.version_resolver import load_version_data, resolve_modifiers, resolve_versions


class VersionsAnalyzer:
    name = "L0-versions"
    depends_on: tuple[str, ...] = ()
    replace = False
    opt_in = False
    framework_agnostic = True

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        # Resolve versions from deps files
        versions = resolve_versions(ctx.target)

        # Load YAML data and produce modifiers
        version_data = load_version_data()
        ctx.version_modifiers = resolve_modifiers(versions, version_data)

        # Flag unpinned agent framework dependencies (AW-SER-002)
        normalized_agent_pkgs = {
            name.lower().replace("-", "-") for name in AGENT_FRAMEWORK_PACKAGES
        }
        for pkg_name, ver in versions.items():
            if pkg_name in normalized_agent_pkgs and ver is None:
                findings.append(Finding(
                    rule_id=AW_SER_002.rule_id,
                    title=AW_SER_002.title,
                    severity=AW_SER_002.severity,
                    category=AW_SER_002.category,
                    description=f"{pkg_name} has no version pin. {AW_SER_002.description}",
                    layer="L0",
                ))

        # Emit CVE findings
        for modifier in ctx.version_modifiers.values():
            for cve in modifier.cves:
                findings.append(Finding(
                    rule_id=cve.id,
                    title=f"Known CVE in {cve.library} {cve.version}",
                    severity=cve.severity,
                    category=Category.SERIALIZATION,
                    description=cve.description,
                    layer="L0",
                ))

        return findings
```

- [ ] **Step 4: Register in analyzers/__init__.py**

Add `VersionsAnalyzer` as the first entry in the `ANALYZERS` list.

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_versions_analyzer.py -v && pytest -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/versions.py src/agentwall/analyzers/__init__.py tests/test_versions_analyzer.py
git commit -m "feat(analyzer): L0-versions — resolve library versions, inject modifiers, flag unpinned deps"
```

---

### Task 7: L1-secrets analyzer (AW-SEC-001, AW-SEC-003)

**Files:**
- Create: `src/agentwall/analyzers/secrets.py`
- Create: `tests/fixtures/secrets_unsafe/app.py`
- Modify: `src/agentwall/analyzers/__init__.py`
- Test: `tests/test_secrets_analyzer.py`

- [ ] **Step 1: Create test fixture**

```python
# tests/fixtures/secrets_unsafe/app.py
import os
import logging

API_KEY = "sk-1234567890abcdef1234567890abcdef"
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"

client = SomeClient(api_key="ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx")

logger = logging.getLogger(__name__)

def process():
    chat_history = get_history()
    logger.debug(f"History: {chat_history}")
    print(messages)
```

- [ ] **Step 2: Write tests**

```python
# tests/test_secrets_analyzer.py
from pathlib import Path

from agentwall.analyzers.secrets import SecretsAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"


class TestSecretsAnalyzer:
    def test_name_and_flags(self) -> None:
        assert SecretsAnalyzer.name == "L1-secrets"
        assert SecretsAnalyzer.framework_agnostic is True

    def test_detects_hardcoded_secret(self) -> None:
        fixture = FIXTURES / "secrets_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SecretsAnalyzer().analyze(ctx)
        sec_001 = [f for f in findings if f.rule_id == "AW-SEC-001"]
        assert len(sec_001) >= 2  # sk- and AKIA prefixes

    def test_detects_context_logging(self) -> None:
        fixture = FIXTURES / "secrets_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SecretsAnalyzer().analyze(ctx)
        sec_003 = [f for f in findings if f.rule_id == "AW-SEC-003"]
        assert len(sec_003) >= 1

    def test_no_findings_in_clean_file(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("x = 42\nprint(x)\n")
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "clean.py"],
        )
        findings = SecretsAnalyzer().analyze(ctx)
        assert findings == []
```

- [ ] **Step 3: Implement SecretsAnalyzer**

Create `src/agentwall/analyzers/secrets.py`. AST walker that:
1. Visits `ast.Constant` string nodes, checks against `SECRET_PREFIXES`
2. For non-prefixed strings: check length >= `SECRET_ENTROPY_MIN_LEN`, Shannon entropy > `SECRET_ENTROPY_THRESHOLD`, in a kwarg from `SECRET_KWARG_NAMES` → confidence=LOW
3. Visits `ast.Call` for `logging.*` and `print`, checks if args reference `CONTEXT_VAR_NAMES`
4. Respects `ctx.should_suppress()` and `ctx.severity_override()`

- [ ] **Step 4: Register in analyzers/__init__.py**

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_secrets_analyzer.py -v && pytest -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/secrets.py tests/test_secrets_analyzer.py tests/fixtures/secrets_unsafe/ src/agentwall/analyzers/__init__.py
git commit -m "feat(analyzer): L1-secrets — detect hardcoded secrets and context logging"
```

---

### Task 8: L1-serialization analyzer (AW-SER-001, AW-SER-003)

**Files:**
- Create: `src/agentwall/analyzers/serialization.py`
- Create: `tests/fixtures/serialization_unsafe/app.py`
- Modify: `src/agentwall/analyzers/__init__.py`
- Test: `tests/test_serialization_analyzer.py`

- [ ] **Step 1: Create test fixture**

```python
# tests/fixtures/serialization_unsafe/app.py
import pickle
import yaml
import importlib

def load_state(path):
    with open(path, "rb") as f:
        return pickle.load(f)

def load_config(path):
    with open(path) as f:
        return yaml.load(f)  # no SafeLoader

def load_plugin(name):
    mod = importlib.import_module(name)
    return mod.create_tool()
```

- [ ] **Step 2: Write tests**

```python
# tests/test_serialization_analyzer.py
from pathlib import Path

from agentwall.analyzers.serialization import SerializationAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"


class TestSerializationAnalyzer:
    def test_name_and_flags(self) -> None:
        assert SerializationAnalyzer.name == "L1-serialization"
        assert SerializationAnalyzer.framework_agnostic is True

    def test_detects_pickle_load(self) -> None:
        fixture = FIXTURES / "serialization_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_001 = [f for f in findings if f.rule_id == "AW-SER-001"]
        assert len(ser_001) >= 1

    def test_detects_yaml_load_without_safe_loader(self) -> None:
        fixture = FIXTURES / "serialization_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_001 = [f for f in findings if f.rule_id == "AW-SER-001"]
        descs = [f.description for f in ser_001]
        assert any("yaml" in d.lower() for d in descs)

    def test_detects_dynamic_import(self) -> None:
        fixture = FIXTURES / "serialization_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser_003) >= 1

    def test_safe_yaml_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "safe.py").write_text(
            "import yaml\ndata = yaml.load(f, Loader=yaml.SafeLoader)\n"
        )
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "safe.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        assert all(f.rule_id != "AW-SER-001" for f in findings)
```

- [ ] **Step 3: Implement SerializationAnalyzer**

Create `src/agentwall/analyzers/serialization.py`. AST walker that:
1. Detects calls matching `UNSAFE_DESER_CALLS`
2. For `yaml.load`: check if `Loader=` kwarg uses a value from `SAFE_YAML_LOADERS` → skip
3. Detects `importlib.import_module()` / `__import__()` with non-literal argument → AW-SER-003
4. Respects version modifiers

- [ ] **Step 4: Register in analyzers/__init__.py**

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_serialization_analyzer.py -v && pytest -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/serialization.py tests/test_serialization_analyzer.py tests/fixtures/serialization_unsafe/ src/agentwall/analyzers/__init__.py
git commit -m "feat(analyzer): L1-serialization — detect unsafe deser and dynamic imports"
```

---

### Task 9: L1-mcp analyzer (AW-MCP-001, AW-MCP-002, AW-MCP-003)

**Files:**
- Create: `src/agentwall/analyzers/mcp_security.py`
- Create: `tests/fixtures/mcp_unsafe/server.py`
- Modify: `src/agentwall/analyzers/__init__.py`
- Test: `tests/test_mcp_analyzer.py`

- [ ] **Step 1: Create test fixture**

```python
# tests/fixtures/mcp_unsafe/server.py
from mcp.server import Server
import subprocess

server = Server("my-server")

API_TOKEN = "sk-1234567890abcdef1234567890abcdef"

@server.tool()
def run_command(command: str) -> str:
    result = subprocess.run(command, shell=True, capture_output=True)
    return result.stdout.decode()
```

- [ ] **Step 2: Write tests**

```python
# tests/test_mcp_analyzer.py
from pathlib import Path

from agentwall.analyzers.mcp_security import MCPSecurityAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"


class TestMCPSecurityAnalyzer:
    def test_name_and_flags(self) -> None:
        assert MCPSecurityAnalyzer.name == "L1-mcp"
        assert MCPSecurityAnalyzer.framework_agnostic is True

    def test_detects_mcp_server_without_auth(self) -> None:
        fixture = FIXTURES / "mcp_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = MCPSecurityAnalyzer().analyze(ctx)
        mcp_001 = [f for f in findings if f.rule_id == "AW-MCP-001"]
        assert len(mcp_001) >= 1

    def test_detects_hardcoded_token(self) -> None:
        fixture = FIXTURES / "mcp_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = MCPSecurityAnalyzer().analyze(ctx)
        mcp_002 = [f for f in findings if f.rule_id == "AW-MCP-002"]
        assert len(mcp_002) >= 1

    def test_detects_shell_in_tool(self) -> None:
        fixture = FIXTURES / "mcp_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = MCPSecurityAnalyzer().analyze(ctx)
        mcp_003 = [f for f in findings if f.rule_id == "AW-MCP-003"]
        assert len(mcp_003) >= 1

    def test_no_findings_without_mcp(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import flask\napp = flask.Flask(__name__)\n")
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "app.py"],
        )
        findings = MCPSecurityAnalyzer().analyze(ctx)
        assert findings == []
```

- [ ] **Step 3: Implement MCPSecurityAnalyzer**

Create `src/agentwall/analyzers/mcp_security.py`. Two-pass AST analysis:
1. First pass: check if file imports from `MCP_IMPORTS`. If not, skip file entirely.
2. Second pass: detect `Server()` instantiation without auth middleware (AW-MCP-001), hardcoded tokens (AW-MCP-002 — reuse secret prefix logic), `@server.tool()` functions with `MCP_SHELL_CALLS` (AW-MCP-003).

- [ ] **Step 4: Register in analyzers/__init__.py**

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_mcp_analyzer.py -v && pytest -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/mcp_security.py tests/test_mcp_analyzer.py tests/fixtures/mcp_unsafe/ src/agentwall/analyzers/__init__.py
git commit -m "feat(analyzer): L1-mcp — detect unauthenticated servers, static tokens, shell tools"
```

---

### Task 10: L1/L2-rag analyzer (AW-RAG-001..004)

**Files:**
- Create: `src/agentwall/analyzers/rag.py`
- Create: `tests/fixtures/rag_unsafe/app.py`
- Modify: `src/agentwall/analyzers/__init__.py`
- Test: `tests/test_rag_analyzer.py`

- [ ] **Step 1: Create test fixture**

```python
# tests/fixtures/rag_unsafe/app.py
from langchain_community.vectorstores import Chroma, FAISS
from langchain_core.prompts import ChatPromptTemplate

# AW-RAG-003: unencrypted persistence
db = FAISS.load_local("./faiss_index", embeddings)

# AW-RAG-004: no auth
from chromadb import HttpClient
client = HttpClient(host="localhost", port=8000)

# AW-RAG-001: no delimiters
docs = db.similarity_search(query)
prompt = f"Answer based on: {docs}\n\nQuestion: {query}"

# AW-RAG-002: untrusted ingestion
import requests
response = requests.get("https://example.com/data")
db.add_texts(response.json()["texts"])
```

- [ ] **Step 2: Write tests**

```python
# tests/test_rag_analyzer.py
from pathlib import Path

from agentwall.analyzers.rag import RAGAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig
from agentwall.adapters.langchain import LangChainAdapter

FIXTURES = Path(__file__).parent / "fixtures"


class TestRAGAnalyzer:
    def test_name_and_flags(self) -> None:
        assert RAGAnalyzer.name == "L1-rag"
        assert RAGAnalyzer.framework_agnostic is False

    def test_detects_unencrypted_persistence(self) -> None:
        fixture = FIXTURES / "rag_unsafe"
        spec = LangChainAdapter().parse(fixture)
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            spec=spec,
            source_files=list(fixture.glob("*.py")),
        )
        findings = RAGAnalyzer().analyze(ctx)
        rag_003 = [f for f in findings if f.rule_id == "AW-RAG-003"]
        assert len(rag_003) >= 1

    def test_detects_network_store_without_auth(self) -> None:
        fixture = FIXTURES / "rag_unsafe"
        spec = LangChainAdapter().parse(fixture)
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            spec=spec,
            source_files=list(fixture.glob("*.py")),
        )
        findings = RAGAnalyzer().analyze(ctx)
        rag_004 = [f for f in findings if f.rule_id == "AW-RAG-004"]
        assert len(rag_004) >= 1
```

- [ ] **Step 3: Implement RAGAnalyzer**

Create `src/agentwall/analyzers/rag.py`. AST walker on `ctx.spec.source_files`:
1. AW-RAG-003: detect `save_local()`, `persist_directory=` → MEDIUM
2. AW-RAG-004: detect `VECTOR_STORE_NETWORK_CLIENTS` without `VECTOR_STORE_AUTH_KWARGS` → HIGH
3. AW-RAG-001: detect retrieval method result → f-string/format without `RAG_DELIMITER_PATTERNS` → HIGH (MEDIUM with delimiters)
4. AW-RAG-002: detect `add_documents`/`add_texts` where source is from `UNTRUSTED_SOURCE_CALLS` → HIGH

- [ ] **Step 4: Register in analyzers/__init__.py**

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_rag_analyzer.py -v && pytest -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/rag.py tests/test_rag_analyzer.py tests/fixtures/rag_unsafe/ src/agentwall/analyzers/__init__.py
git commit -m "feat(analyzer): L1-rag — detect unencrypted stores, missing auth, raw prompt injection, untrusted ingestion"
```

---

### Task 11: L2/L3-agent analyzer (AW-AGT-001..004)

**Files:**
- Create: `src/agentwall/analyzers/agent_arch.py`
- Create: `tests/fixtures/agent_unsafe/app.py`
- Modify: `src/agentwall/analyzers/__init__.py`
- Test: `tests/test_agent_arch_analyzer.py`

- [ ] **Step 1: Create test fixture**

```python
# tests/fixtures/agent_unsafe/app.py
from langchain.agents import AgentExecutor
from langchain.tools import tool
from langchain_community.vectorstores import Chroma

@tool
def query_users(query: str) -> str:
    """Query user database."""
    return "results"

@tool
def delete_users(user_id: str) -> str:
    """Delete a user from the database."""
    return "deleted"

# AW-AGT-001: sub-agent inherits all tools
parent_tools = [query_users, delete_users]
sub_agent = AgentExecutor(agent=llm, tools=parent_tools)

# AW-AGT-004: LLM output to memory without validation
result = llm.invoke("generate something")
vectorstore = Chroma()
vectorstore.add_texts([result.content])
```

- [ ] **Step 2: Write tests**

```python
# tests/test_agent_arch_analyzer.py
from pathlib import Path

from agentwall.analyzers.agent_arch import AgentArchAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig
from agentwall.adapters.langchain import LangChainAdapter

FIXTURES = Path(__file__).parent / "fixtures"


class TestAgentArchAnalyzer:
    def test_name_and_flags(self) -> None:
        assert AgentArchAnalyzer.name == "L2-agent"
        assert AgentArchAnalyzer.framework_agnostic is False

    def test_detects_inherited_tools(self) -> None:
        fixture = FIXTURES / "agent_unsafe"
        spec = LangChainAdapter().parse(fixture)
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            spec=spec,
            source_files=list(fixture.glob("*.py")),
        )
        findings = AgentArchAnalyzer().analyze(ctx)
        agt_001 = [f for f in findings if f.rule_id == "AW-AGT-001"]
        assert len(agt_001) >= 1
```

- [ ] **Step 3: Implement AgentArchAnalyzer**

Create `src/agentwall/analyzers/agent_arch.py`. AST analysis:
1. AW-AGT-001: detect `AgentExecutor(tools=X)` where X is a variable referencing another agent's tools
2. AW-AGT-003: detect same agent with read + delete tools for same resource pattern, delete lacking approval gate
3. AW-AGT-004: detect `llm.invoke()` result flowing to `add_texts()`/`save_context()` without sanitization
4. AW-AGT-002: detect delegation calls without auth kwargs → confidence=LOW

- [ ] **Step 4: Register in analyzers/__init__.py**

- [ ] **Step 5: Run tests**

Run: `pytest tests/test_agent_arch_analyzer.py -v && pytest -v`
Expected: All PASS.

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/agent_arch.py tests/test_agent_arch_analyzer.py tests/fixtures/agent_unsafe/ src/agentwall/analyzers/__init__.py
git commit -m "feat(analyzer): L2-agent — detect tool inheritance, resource conflicts, memory poisoning"
```

---

### Task 12: Final verification

- [ ] **Step 1: Run ruff**

```bash
ruff check src/ tests/
ruff format --check src/ tests/
```

- [ ] **Step 2: Run mypy**

```bash
mypy src/
```

- [ ] **Step 3: Run full test suite with coverage**

```bash
pytest --cov=agentwall --cov-report=term-missing -v
```

- [ ] **Step 4: Integration smoke test — non-langchain project**

```bash
agentwall scan /home/soh/working/agent-wall/src --fail-on none
echo "Exit code: $?"
```

Expected: exit 0, AW-SEC/SER/MCP rules may fire, no crash.

- [ ] **Step 5: Integration smoke test — langchain fixture**

```bash
agentwall scan tests/fixtures/langchain_unsafe --fail-on none --format json | python3 -c "
import sys, json
d = json.load(sys.stdin)
rules = {f['rule_id'] for f in d['findings']}
print(f'Rules: {sorted(rules)}')
print(f'Total: {len(d[\"findings\"])}')
print(f'Warnings: {d.get(\"warnings\", [])}')
"
```

Expected: existing AW-MEM/TOOL rules + new rules fire.

- [ ] **Step 6: Verify rule count**

```bash
python3 -c "from agentwall.rules import ALL_RULES; print(f'Total rules: {len(ALL_RULES)}')"
```

Expected: `Total rules: 28`

- [ ] **Step 7: Final commit if any fixes needed**
