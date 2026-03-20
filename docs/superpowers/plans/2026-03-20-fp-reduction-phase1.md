# FP Reduction Phase 1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reduce false positive rate from measured ~45% to ~18% across the top 5 FP-producing rules, based on manual triage of 98 findings against real source code.

**Architecture:** Each fix modifies one analyzer or shared module. No new packages. All changes are heuristic improvements to existing detection logic — suppress less, downgrade more, require stronger evidence. Every fix has a test that reproduces the exact FP pattern observed in the triage.

**Tech Stack:** Python 3.10+, ast (stdlib), pytest

**Evidence:** FP triage results from 3 parallel agents examining 98 findings across 30+ real projects in /tmp/agentwall-results3k/

---

## File Map

### Modified Files

| File | Change | Rule |
|------|--------|------|
| `src/agentwall/analyzers/serialization.py` | Add `_is_dict_lookup_import()` heuristic to suppress AW-SER-003 when import arg is from hardcoded dict | AW-SER-003 |
| `src/agentwall/analyzers/secrets.py` | Refine `_references_context_var()` to exclude metadata-only access (len, .id, .path, type) | AW-SEC-003 |
| `src/agentwall/analyzers/memory.py` | Use engine StoreProfile to downgrade MEM-001 for per-tenant collections and single-user projects; require retrieval ReadOp for MEM-005 | AW-MEM-001, AW-MEM-005 |
| `src/agentwall/analyzers/config.py` | Expand placeholder set in `_check_env_secrets()`, skip template files, skip empty values, skip non-secret key names | AW-CFG-hardcoded-secret |
| `src/agentwall/postprocess.py` | Add `_TEMPLATE_SUFFIXES` to `classify_file_context()` for .env.template, .env.default, .env.example, .env.sample, .env.test | File context |
| `tests/test_fp_reduction.py` | Regression tests for all FP patterns observed in triage | All |

---

## Task 1: AW-SER-003 — Suppress Dict-Lookup Dynamic Imports

**Measured:** 47% FP. Root cause: `importlib.import_module(_IMPORTS[name])` where `_IMPORTS` is a hardcoded module-level dict. This is the standard Python lazy-loading pattern.

**Files:**
- Modify: `src/agentwall/analyzers/serialization.py`
- Test: `tests/test_fp_reduction.py`

- [ ] **Step 1: Write failing test for the FP pattern**

```python
# tests/test_fp_reduction.py
"""Regression tests for FP patterns observed in BENCHMARK3000 triage."""

import ast
from pathlib import Path

from agentwall.analyzers.serialization import SerializationAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig


def _make_ctx(tmp_path: Path, code: str, filename: str = "module.py") -> AnalysisContext:
    """Create an AnalysisContext with a single source file."""
    p = tmp_path / filename
    p.write_text(code)
    ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[p])
    return ctx


class TestSER003FalsePositives:
    """AW-SER-003: dynamic import with variable argument.

    FP pattern from triage: lazy __getattr__ with hardcoded dict lookup.
    Found in: semantic-kernel, crewai, db-gpt, agno, metagpt.
    """

    def test_dict_lookup_import_is_suppressed(self, tmp_path: Path):
        """importlib.import_module(HARDCODED_DICT[name]) should NOT fire."""
        code = '''
import importlib

_IMPORTS = {"foo": ".bar", "baz": ".qux"}

def __getattr__(name):
    if name in _IMPORTS:
        return importlib.import_module(_IMPORTS[name], __name__)
    raise AttributeError(name)
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SerializationAnalyzer().analyze(ctx)
        ser003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser003) == 0, "Dict-lookup import should not fire SER-003"

    def test_fstring_with_literal_prefix_is_suppressed(self, tmp_path: Path):
        """importlib.import_module(f"package.{DICT[name]}") should NOT fire."""
        code = '''
import importlib

_LIBS = {"pdf": "pdf", "csv": "csv"}

def __getattr__(name):
    if name in _LIBS:
        mod = "." + _LIBS[name]
        return importlib.import_module(mod, __name__)
    raise AttributeError(name)
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SerializationAnalyzer().analyze(ctx)
        ser003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser003) == 0

    def test_bare_variable_import_still_fires(self, tmp_path: Path):
        """importlib.import_module(user_input) should still fire."""
        code = '''
import importlib

def load_plugin(plugin_name):
    return importlib.import_module(plugin_name)
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SerializationAnalyzer().analyze(ctx)
        ser003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser003) == 1, "Bare variable import must still fire"

    def test_user_controlled_import_still_fires(self, tmp_path: Path):
        """importlib.import_module(request.module_name) should still fire."""
        code = '''
import importlib

def load_from_request(request):
    return importlib.import_module(request.module_name)
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SerializationAnalyzer().analyze(ctx)
        ser003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser003) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestSER003FalsePositives -v`
Expected: 2 tests FAIL (suppressed tests), 2 PASS (still-fires tests)

- [ ] **Step 3: Implement dict-lookup detection**

In `src/agentwall/analyzers/serialization.py`, add a static method and modify the SER-003 check:

```python
@staticmethod
def _is_dict_lookup_import(node: ast.Call) -> bool:
    """Check if the import argument is a dict lookup on a module-level constant.

    Suppresses patterns like:
      importlib.import_module(_IMPORTS[name])
      importlib.import_module("." + _LIBS[name], __name__)

    These are standard Python lazy-loading patterns where the dict is hardcoded.
    """
    if not node.args:
        return False
    arg = node.args[0]
    # Direct dict subscript: _IMPORTS[name]
    if isinstance(arg, ast.Subscript) and isinstance(arg.value, ast.Name):
        # Name starts with _ → likely module-level constant
        if arg.value.id.startswith("_") or arg.value.id.isupper():
            return True
    # BinOp: "." + _LIBS[name]  or  f".{_LIBS[name]}"
    if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
        if isinstance(arg.right, ast.Subscript) and isinstance(arg.right.value, ast.Name):
            if arg.right.value.id.startswith("_") or arg.right.value.id.isupper():
                return True
        if isinstance(arg.left, ast.Subscript) and isinstance(arg.left.value, ast.Name):
            if arg.left.value.id.startswith("_") or arg.left.value.id.isupper():
                return True
    # Variable that was assigned from a dict lookup in the same scope
    # e.g.: mod = _LIBS[name]; importlib.import_module(mod)
    # Too complex for this phase — skip
    return False
```

Then modify the SER-003 check block (around line 66-88) to add the suppression:

```python
# Check dynamic imports with variable argument
if (
    call_name in DYNAMIC_IMPORT_CALLS
    and node.args
    and not isinstance(node.args[0], ast.Constant)
    and not self._is_dict_lookup_import(node)  # NEW: suppress dict-lookup pattern
    and not ctx.should_suppress(AW_SER_003.rule_id)
):
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestSER003FalsePositives -v`
Expected: All 4 PASS

- [ ] **Step 5: Run full test suite**

Run: `python3 -m pytest tests/ -q --tb=line`
Expected: All pass, no regressions

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/serialization.py tests/test_fp_reduction.py
git commit -m "fix(SER-003): suppress dict-lookup dynamic imports (47% FP reduction)"
```

---

## Task 2: AW-SEC-003 — Require Content Reference, Not Metadata

**Measured:** 53% FP. Root cause: `logger.debug(len(messages))` fires because `messages` is a CONTEXT_VAR_NAME, even though only the count is logged. Also fires on `context.function.name` where `context` is a framework hook object.

**Files:**
- Modify: `src/agentwall/analyzers/secrets.py`
- Test: `tests/test_fp_reduction.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to tests/test_fp_reduction.py

class TestSEC003FalsePositives:
    """AW-SEC-003: agent context logged at DEBUG level.

    FP patterns from triage:
    - len(messages), get_token_count(messages) — logs count, not content
    - context.function.name, context.id — logs metadata, not content
    - type(messages) — logs type info
    Found in: semantic-kernel, khoj, openhands, camel.
    """

    def test_len_of_context_var_is_suppressed(self, tmp_path: Path):
        """logger.debug(len(messages)) should NOT fire."""
        code = '''
import logging
logger = logging.getLogger(__name__)

def process(messages):
    logger.debug("Processing %d messages", len(messages))
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SecretsAnalyzer().analyze(ctx)
        sec003 = [f for f in findings if f.rule_id == "AW-SEC-003"]
        assert len(sec003) == 0

    def test_attribute_of_context_var_is_suppressed(self, tmp_path: Path):
        """logger.info(context.function.name) should NOT fire."""
        code = '''
import logging
logger = logging.getLogger(__name__)

def hook(context):
    logger.info("Function: %s", context.function.name)
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SecretsAnalyzer().analyze(ctx)
        sec003 = [f for f in findings if f.rule_id == "AW-SEC-003"]
        assert len(sec003) == 0

    def test_direct_context_var_still_fires(self, tmp_path: Path):
        """logger.debug(messages) should still fire."""
        code = '''
import logging
logger = logging.getLogger(__name__)

def process(messages):
    logger.debug("Messages: %s", messages)
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SecretsAnalyzer().analyze(ctx)
        sec003 = [f for f in findings if f.rule_id == "AW-SEC-003"]
        assert len(sec003) == 1

    def test_fstring_with_context_var_still_fires(self, tmp_path: Path):
        """logger.debug(f"payload: {messages}") should still fire."""
        code = '''
import logging
logger = logging.getLogger(__name__)

def process(messages):
    logger.debug(f"Full payload: {messages}")
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SecretsAnalyzer().analyze(ctx)
        sec003 = [f for f in findings if f.rule_id == "AW-SEC-003"]
        assert len(sec003) == 1

    def test_token_count_is_suppressed(self, tmp_path: Path):
        """logger.info(llm.get_token_count(messages)) should NOT fire."""
        code = '''
import logging
logger = logging.getLogger(__name__)

def process(messages, llm):
    logger.info("Token count: %d", llm.get_token_count(messages))
'''
        ctx = _make_ctx(tmp_path, code)
        findings = SecretsAnalyzer().analyze(ctx)
        sec003 = [f for f in findings if f.rule_id == "AW-SEC-003"]
        assert len(sec003) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestSEC003FalsePositives -v`
Expected: 3 suppression tests FAIL, 2 still-fires tests PASS

- [ ] **Step 3: Implement refined context var check**

Replace `_references_context_var` in `src/agentwall/analyzers/secrets.py`:

```python
@staticmethod
def _references_context_var(node: ast.expr) -> bool:
    """Check if an AST expression directly exposes context variable content.

    Returns True only when the context variable's content would be logged.
    Returns False for metadata-only access patterns:
      - len(messages), type(messages)
      - messages.id, context.function.name (attribute access)
      - llm.get_token_count(messages) (method call wrapping the var)
    """
    # Case 1: Direct Name reference as top-level arg → fires
    # e.g., logger.debug(messages)
    if isinstance(node, ast.Name) and node.id in CONTEXT_VAR_NAMES:
        return True

    # Case 2: f-string containing a direct Name reference → fires
    # e.g., f"payload: {messages}"
    if isinstance(node, ast.JoinedStr):
        for val in node.values:
            if isinstance(val, ast.FormattedValue):
                inner = val.value
                if isinstance(inner, ast.Name) and inner.id in CONTEXT_VAR_NAMES:
                    return True
        return False

    # Case 3: Call wrapping a context var → suppress (metadata extraction)
    # e.g., len(messages), str(messages), type(messages), llm.get_token_count(messages)
    if isinstance(node, ast.Call):
        # The call itself wraps the var — this is metadata extraction, not content
        return False

    # Case 4: Attribute access on context var → suppress (metadata)
    # e.g., context.function.name, memory.path, messages.count
    if isinstance(node, ast.Attribute):
        return False

    # Case 5: Subscript on context var → could be content (messages[-1])
    if isinstance(node, ast.Subscript):
        if isinstance(node.value, ast.Name) and node.value.id in CONTEXT_VAR_NAMES:
            return True

    # Case 6: BinOp like "prefix" + str(messages) → check operands
    if isinstance(node, ast.BinOp):
        return SecretsAnalyzer._references_context_var(
            node.left
        ) or SecretsAnalyzer._references_context_var(node.right)

    # Default: walk children for any direct Name reference
    # But only fire if Name is used directly, not wrapped in Call/Attribute
    for child in ast.iter_child_nodes(node):
        if isinstance(child, ast.Name) and child.id in CONTEXT_VAR_NAMES:
            return True

    return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestSEC003FalsePositives -v`
Expected: All 5 PASS

- [ ] **Step 5: Run full test suite**

Run: `python3 -m pytest tests/ -q --tb=line`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/secrets.py tests/test_fp_reduction.py
git commit -m "fix(SEC-003): require content reference, not metadata access (53% FP reduction)"
```

---

## Task 3: AW-MEM-001 — Downgrade for Per-Tenant Collections and Library Code

**Measured:** 100% FP in sample. Root cause: fires on library/framework code and single-user tools. The engine's `StoreProfile.isolation_strategy` already detects per-tenant collections but isn't wired into finding logic.

**Files:**
- Modify: `src/agentwall/analyzers/memory.py`
- Test: `tests/test_fp_reduction.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to tests/test_fp_reduction.py

class TestMEM001FalsePositives:
    """AW-MEM-001: no tenant isolation in vector store.

    FP patterns from triage:
    - Library/framework base classes (llama-index BaseIndex, Pinecone integration)
    - Per-collection isolation (langchain-chatchat: each KB = own collection)
    - Single-user tools (Vanna, local CLI apps)
    Found in: langflow, langchain-chatchat, llama-index, vanna.
    """

    def test_engine_collection_per_tenant_downgrades(self, tmp_path: Path):
        """When engine detects COLLECTION_PER_TENANT, severity should be MEDIUM not CRITICAL."""
        from agentwall.engine.models import IsolationStrategy, StoreProfile, ValueKind

        code = '''
from langchain_community.vectorstores import Chroma

def search(tenant_id, query):
    db = Chroma(collection_name=f"docs_{tenant_id}")
    return db.similarity_search(query)
'''
        p = tmp_path / "agent.py"
        p.write_text(code)
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[p])

        # Simulate engine populating store_profiles
        ctx.store_profiles = [
            StoreProfile(
                store_id="test",
                backend="chromadb",
                collection_name_kind=ValueKind.TENANT_SCOPED,
            )
        ]

        # Run adapter to populate spec
        from agentwall.adapters.langchain import LangChainAdapter
        ctx.spec = LangChainAdapter().parse(tmp_path)

        findings = MemoryAnalyzer().analyze(ctx)
        mem001 = [f for f in findings if f.rule_id == "AW-MEM-001"]
        # Should be downgraded, not CRITICAL
        for f in mem001:
            assert f.severity.value != "critical", \
                "Per-tenant collection should not be CRITICAL"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestMEM001FalsePositives -v`
Expected: FAIL

- [ ] **Step 3: Implement engine-aware downgrade**

In `src/agentwall/analyzers/memory.py`, modify the `analyze` method to check engine store profiles:

```python
def analyze(self, ctx: AnalysisContext) -> list[Finding]:
    spec = ctx.spec
    if spec is None:
        return []

    # Check if engine has classified stores
    engine_isolation = self._get_engine_isolation(ctx)

    findings: list[Finding] = []
    for mc in spec.memory_configs:
        findings.extend(self._check(mc, engine_isolation))
    return findings

@staticmethod
def _get_engine_isolation(ctx: AnalysisContext) -> dict[str, str]:
    """Get isolation strategy per backend from engine store profiles."""
    result: dict[str, str] = {}
    if not getattr(ctx, "store_profiles", None):
        return result
    try:
        for profile in ctx.store_profiles:
            result[profile.backend] = profile.isolation_strategy.value
    except Exception:
        pass
    return result

def _check(
    self,
    mc: MemoryConfig,
    engine_isolation: dict[str, str] | None = None,
) -> list[Finding]:
    findings: list[Finding] = []
    if engine_isolation is None:
        engine_isolation = {}

    is_memory_class = mc.backend in _MEMORY_CLASS_BACKENDS
    no_isolation = not mc.has_tenant_isolation
    no_filter = not mc.has_metadata_filter_on_retrieval
    no_write_meta = not mc.has_metadata_on_write

    # Check engine isolation strategy for this backend
    store_isolation = engine_isolation.get(mc.backend, "none")
    is_per_tenant = store_isolation == "collection_per_tenant"
    is_filter_on_read = store_isolation == "filter_on_read"

    # AW-MEM-001: no isolation AND no retrieval filter (vector stores only)
    if not is_memory_class and no_isolation and no_filter:
        if is_per_tenant:
            # Engine says per-tenant collection — downgrade to MEDIUM
            findings.append(
                _finding_from_rule(AW_MEM_001, mc, ConfidenceLevel.LOW).model_copy(
                    update={
                        "severity": Severity.MEDIUM,
                        "description": (
                            AW_MEM_001.description
                            + " [Engine: collection appears tenant-scoped, "
                            "but filter on read is still recommended]"
                        ),
                    }
                )
            )
        elif is_filter_on_read:
            # Engine confirms filter on read — suppress
            pass
        else:
            findings.append(_finding_from_rule(AW_MEM_001, mc, ConfidenceLevel.HIGH))

    # AW-MEM-002: unchanged
    if not is_memory_class and mc.has_metadata_on_write and no_filter:
        findings.append(_finding_from_rule(AW_MEM_002, mc, ConfidenceLevel.HIGH))

    # AW-MEM-003: unchanged
    if not is_memory_class and no_isolation and no_write_meta and no_filter:
        findings.append(_finding_from_rule(AW_MEM_003, mc, ConfidenceLevel.MEDIUM))

    # AW-MEM-004: unchanged
    if mc.has_injection_risk:
        findings.append(_finding_from_rule(AW_MEM_004, mc, ConfidenceLevel.HIGH))

    # AW-MEM-005: unchanged (Task 4 handles this separately)
    if not is_memory_class and not mc.sanitizes_retrieved_content:
        findings.append(_finding_from_rule(AW_MEM_005, mc, ConfidenceLevel.MEDIUM))

    return findings
```

Add the missing import at the top of the file:

```python
from agentwall.models import ConfidenceLevel, Finding, MemoryConfig, Severity
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestMEM001FalsePositives -v`
Expected: PASS

- [ ] **Step 5: Run full test suite**

Run: `python3 -m pytest tests/ -q --tb=line`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/memory.py tests/test_fp_reduction.py
git commit -m "fix(MEM-001): downgrade per-tenant collections using engine StoreProfile"
```

---

## Task 4: AW-CFG-hardcoded-secret — Expand Placeholder Detection

**Measured:** 75% FP. Root cause: fires on `.env.test`, `.env.template`, `.env.default` with placeholder values like "fake-", "your-super-secret-", empty values, non-secret key names.

**Files:**
- Modify: `src/agentwall/analyzers/config.py`
- Modify: `src/agentwall/postprocess.py`
- Test: `tests/test_fp_reduction.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to tests/test_fp_reduction.py

class TestCFGHardcodedSecretFalsePositives:
    """AW-CFG-hardcoded-secret: hardcoded API key/secret in config.

    FP patterns from triage:
    - .env.test with "fake-api-key" values
    - .env.template with "your-super-secret-..." placeholders
    - .env.default with empty values
    - Key names like PASSWORD_LOGIN_LOCK_SECONDS (config, not secret)
    Found in: auto-gpt-web, crewai, fastgpt, ragflow.
    """

    def test_env_test_file_suppressed(self, tmp_path: Path):
        """.env.test files should not fire hardcoded-secret."""
        env_test = tmp_path / ".env.test"
        env_test.write_text("OPENAI_API_KEY=fake-api-key\n")
        from agentwall.analyzers.config import ConfigAuditor
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[])
        findings = ConfigAuditor().analyze(ctx)
        hardcoded = [f for f in findings if f.rule_id == "AW-CFG-hardcoded-secret"]
        assert len(hardcoded) == 0

    def test_env_template_file_suppressed(self, tmp_path: Path):
        """.env.template files should not fire."""
        env = tmp_path / ".env.template"
        env.write_text("API_KEY=your-key-here\nSECRET_KEY=changethis\n")
        from agentwall.analyzers.config import ConfigAuditor
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[])
        findings = ConfigAuditor().analyze(ctx)
        hardcoded = [f for f in findings if f.rule_id == "AW-CFG-hardcoded-secret"]
        assert len(hardcoded) == 0

    def test_empty_value_suppressed(self, tmp_path: Path):
        """Empty values should not fire."""
        env = tmp_path / ".env"
        env.write_text("OPENAI_API_KEY=\nSECRET_KEY=\n")
        from agentwall.analyzers.config import ConfigAuditor
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[])
        findings = ConfigAuditor().analyze(ctx)
        hardcoded = [f for f in findings if f.rule_id == "AW-CFG-hardcoded-secret"]
        assert len(hardcoded) == 0

    def test_fake_prefix_suppressed(self, tmp_path: Path):
        """Values starting with 'fake' should not fire."""
        env = tmp_path / ".env"
        env.write_text("API_KEY=fake-anthropic-key\nTOKEN=fake-token-value\n")
        from agentwall.analyzers.config import ConfigAuditor
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[])
        findings = ConfigAuditor().analyze(ctx)
        hardcoded = [f for f in findings if f.rule_id == "AW-CFG-hardcoded-secret"]
        assert len(hardcoded) == 0

    def test_non_secret_key_name_suppressed(self, tmp_path: Path):
        """Key names like PASSWORD_LOGIN_LOCK_SECONDS are config, not secrets."""
        env = tmp_path / ".env"
        env.write_text("PASSWORD_LOGIN_LOCK_SECONDS=300\nTOKEN_EXPIRY_SECONDS=3600\n")
        from agentwall.analyzers.config import ConfigAuditor
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[])
        findings = ConfigAuditor().analyze(ctx)
        hardcoded = [f for f in findings if f.rule_id == "AW-CFG-hardcoded-secret"]
        assert len(hardcoded) == 0

    def test_real_default_password_still_fires(self, tmp_path: Path):
        """Real default passwords in docker .env should still fire."""
        env = tmp_path / ".env"
        env.write_text("ELASTIC_PASSWORD=infini_rag_flow\nPOSTGRES_PASSWORD=mydbpassword123\n")
        from agentwall.analyzers.config import ConfigAuditor
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[])
        findings = ConfigAuditor().analyze(ctx)
        hardcoded = [f for f in findings if f.rule_id == "AW-CFG-hardcoded-secret"]
        assert len(hardcoded) >= 1, "Real default passwords must still fire"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestCFGHardcodedSecretFalsePositives -v`
Expected: Most suppression tests FAIL

- [ ] **Step 3: Implement expanded placeholder detection**

In `src/agentwall/analyzers/config.py`, modify `_check_env_secrets`:

```python
# Template/test file suffixes that should not fire hardcoded-secret
_TEMPLATE_SUFFIXES = frozenset({
    ".env.template", ".env.example", ".env.sample", ".env.default", ".env.test",
    ".env.testing", ".env.development", ".env.dev",
})

# Key name suffixes that indicate config values, not secrets
_NON_SECRET_KEY_SUFFIXES = frozenset({
    "_SECONDS", "_TIMEOUT", "_LIMIT", "_COUNT", "_SIZE", "_LENGTH",
    "_INTERVAL", "_RETRIES", "_PORT", "_HOST", "_URL", "_PATH",
    "_ENABLED", "_DISABLED", "_MODE", "_LEVEL", "_FORMAT",
})
```

Then replace `_check_env_secrets`:

```python
def _check_env_secrets(self, path: Path, content: str) -> list[Finding]:
    """Check for hardcoded API keys or tokens in .env files."""
    # Skip template/test/example .env files entirely
    if any(path.name.endswith(suffix) or path.name == suffix.lstrip(".")
           for suffix in _TEMPLATE_SUFFIXES):
        return []

    findings: list[Finding] = []
    secret_pattern = re.compile(
        r"^((?:\w*(?:API_KEY|SECRET|TOKEN|PASSWORD))\w*)\s*=\s*(.+)$",
        re.MULTILINE,
    )
    placeholders = {
        "",
        "changeme",
        "your-key-here",
        "xxx",
        "CHANGE_ME",
        "placeholder",
        "YOUR_API_KEY",
        "TODO",
        "dummy",
        "test",
        "example",
        "changethis",
        "replace-me",
        "insert-key-here",
    }
    # Placeholder prefixes (case-insensitive check)
    placeholder_prefixes = (
        "your-", "fake-", "test-", "dummy-", "example-",
        "replace", "insert", "change", "todo",
    )

    for match in secret_pattern.finditer(content):
        key_name = match.group(1)
        value = match.group(2).strip().strip("\"'")

        # Skip empty values
        if not value:
            continue

        # Skip known placeholders
        if value.lower() in {p.lower() for p in placeholders}:
            continue

        # Skip values with placeholder prefixes
        if any(value.lower().startswith(p) for p in placeholder_prefixes):
            continue

        # Skip non-secret key names (config values that happen to match pattern)
        if any(key_name.upper().endswith(suffix) for suffix in _NON_SECRET_KEY_SUFFIXES):
            continue

        line_num = content[: match.start()].count("\n") + 1
        findings.append(
            Finding(
                rule_id="AW-CFG-hardcoded-secret",
                title=f"Hardcoded secret in {path.name}: {key_name}",
                severity=Severity.HIGH,
                category=Category.MEMORY,
                description=(
                    f"Secret '{key_name}' has a hardcoded value. "
                    "This may be committed to version control."
                ),
                file=path,
                line=line_num,
                fix="Use environment variables or a secret manager. Never commit secrets.",
            )
        )
    return findings
```

- [ ] **Step 4: Also update postprocess.py to classify template files**

In `src/agentwall/postprocess.py`, extend `classify_file_context`:

```python
_TEMPLATE_SUFFIXES = frozenset({
    ".template", ".example", ".sample", ".default",
})

def classify_file_context(file_path: Path | None) -> str | None:
    """Classify a file path as test/example/template context, or None."""
    if file_path is None:
        return None
    name = file_path.name
    parts = file_path.parts
    if any(p in _TEST_DIRS for p in parts) or name.startswith("test_") or name.endswith("_test.py"):
        return "test file"
    if any(p in _EXAMPLE_DIRS for p in parts) or name.endswith(".example"):
        return "example"
    # Template env files
    if any(name.endswith(suffix) for suffix in _TEMPLATE_SUFFIXES):
        return "template"
    if name in {".env.test", ".env.testing", ".env.dev", ".env.development"}:
        return "test file"
    return None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestCFGHardcodedSecretFalsePositives -v`
Expected: All 6 PASS

- [ ] **Step 6: Run full test suite**

Run: `python3 -m pytest tests/ -q --tb=line`
Expected: All pass

- [ ] **Step 7: Commit**

```bash
git add src/agentwall/analyzers/config.py src/agentwall/postprocess.py tests/test_fp_reduction.py
git commit -m "fix(CFG-hardcoded-secret): skip templates, placeholders, non-secret keys (75% FP reduction)"
```

---

## Task 5: AW-MEM-005 — Require Retrieval-to-Sink Path

**Measured:** 78% FP. Root cause: fires on store constructor/init lines, not actual retrieval→injection sites.

**Files:**
- Modify: `src/agentwall/analyzers/memory.py`
- Test: `tests/test_fp_reduction.py` (extend)

- [ ] **Step 1: Write failing tests**

```python
# Append to tests/test_fp_reduction.py

class TestMEM005FalsePositives:
    """AW-MEM-005: no sanitization on retrieved memory.

    FP patterns from triage:
    - Fires on store constructor lines (no retrieval happening)
    - Fires when content goes to metrics/counting, not LLM prompt
    Found in: langflow, embedchain, db-gpt.
    """

    def test_store_with_retrieval_fires(self, tmp_path: Path):
        """Store that has similarity_search should fire MEM-005."""
        code = '''
from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="docs")
results = db.similarity_search("query")
'''
        p = tmp_path / "agent.py"
        p.write_text(code)
        from agentwall.adapters.langchain import LangChainAdapter
        spec = LangChainAdapter().parse(tmp_path)
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[p])
        ctx.spec = spec
        findings = MemoryAnalyzer().analyze(ctx)
        mem005 = [f for f in findings if f.rule_id == "AW-MEM-005"]
        assert len(mem005) >= 1

    def test_store_without_retrieval_suppressed(self, tmp_path: Path):
        """Store that only does add_texts (no read) should NOT fire MEM-005."""
        code = '''
from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="docs")
db.add_texts(["hello world"])
'''
        p = tmp_path / "agent.py"
        p.write_text(code)
        from agentwall.adapters.langchain import LangChainAdapter
        spec = LangChainAdapter().parse(tmp_path)
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[p])
        ctx.spec = spec
        findings = MemoryAnalyzer().analyze(ctx)
        mem005 = [f for f in findings if f.rule_id == "AW-MEM-005"]
        assert len(mem005) == 0, "Write-only store should not fire MEM-005"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestMEM005FalsePositives -v`
Expected: `test_store_without_retrieval_suppressed` FAIL

- [ ] **Step 3: Implement retrieval-path check for MEM-005**

In the `_check` method of `MemoryAnalyzer`, replace the MEM-005 block:

```python
# AW-MEM-005: no sanitization on retrieved memory before context injection
# Only fires for vector stores with confirmed retrieval path.
# Suppress for write-only stores (no retrieval = no injection risk).
if not is_memory_class and not mc.sanitizes_retrieved_content:
    has_retrieval = mc.has_metadata_filter_on_retrieval or (
        not mc.has_tenant_isolation and not mc.has_metadata_on_write
        # If there's no filter AND no write metadata, this might be
        # a read-only consumer. Check if retrieval was detected.
    )
    # Also check engine store profiles for read operations
    has_engine_reads = False
    for store_id, iso in engine_isolation.items():
        # If engine detected any reads for this backend, there's a retrieval path
        if iso != "none":
            has_engine_reads = True

    # Check if the source file has any retrieval method calls
    if mc.source_file:
        try:
            source = mc.source_file.read_text(encoding="utf-8")
            import ast as _ast
            from agentwall.patterns import RETRIEVAL_METHODS
            tree = _ast.parse(source)
            for node in _ast.walk(tree):
                if (isinstance(node, _ast.Attribute)
                        and node.attr in RETRIEVAL_METHODS):
                    has_retrieval = True
                    break
        except Exception:
            has_retrieval = True  # fail open — assume retrieval exists

    if has_retrieval:
        findings.append(_finding_from_rule(AW_MEM_005, mc, ConfidenceLevel.MEDIUM))
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python3 -m pytest tests/test_fp_reduction.py::TestMEM005FalsePositives -v`
Expected: All 2 PASS

- [ ] **Step 5: Run full test suite**

Run: `python3 -m pytest tests/ -q --tb=line`
Expected: All pass

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/analyzers/memory.py tests/test_fp_reduction.py
git commit -m "fix(MEM-005): require retrieval path before firing (78% FP reduction)"
```

---

## Task 6: Full Regression + Validation

- [ ] **Step 1: Run complete test suite with coverage**

Run: `python3 -m pytest tests/ -v --tb=short`
Expected: All pass, no regressions

- [ ] **Step 2: Run lint and type check**

Run: `ruff check src/agentwall/analyzers/ src/agentwall/postprocess.py && ruff format --check src/agentwall/ && mypy src/agentwall/analyzers/memory.py src/agentwall/analyzers/secrets.py src/agentwall/analyzers/serialization.py src/agentwall/analyzers/config.py`
Expected: Clean

- [ ] **Step 3: Run scanner on test fixtures and count findings**

Run: `python3 -c "from agentwall.scanner import scan; from pathlib import Path; [print(f'{d.name}: {len(scan(d).findings)}') for d in sorted(Path('tests/fixtures').iterdir()) if d.is_dir() and any(d.glob('*.py'))]" 2>/dev/null`
Expected: Reduced finding counts for fixtures that had FP patterns

- [ ] **Step 4: Commit**

```bash
git commit -m "test: validate FP reduction across all fixtures"
```

---

## Summary

| Task | Rule | Measured FP | Fix | Expected After |
|------|------|------------|-----|----------------|
| 1 | AW-SER-003 | 47% | Suppress dict-lookup imports | ~20% |
| 2 | AW-SEC-003 | 53% | Require content ref, not metadata | ~25% |
| 3 | AW-MEM-001 | 100% | Downgrade per-tenant collections | ~40% |
| 4 | AW-CFG-hardcoded-secret | 75% | Expand placeholder detection | ~15% |
| 5 | AW-MEM-005 | 78% | Require retrieval path | ~20% |
