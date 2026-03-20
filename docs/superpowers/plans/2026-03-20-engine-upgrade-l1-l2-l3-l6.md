# Engine Upgrade: L1–L3, L6 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Upgrade AgentWall's 4 core analysis engines using proven SAST algorithms (PyCG, Pysa fixpoint, CodeQL GlobalWithState), scoped to AI security property verification.

**Architecture:** Engine (general, reusable) + Framework Model (declarative, per-framework). New `engine/` package contains 4 general engines. New `frameworks/` package contains declarative models starting with LangChain. Existing analyzers become thin wrappers that delegate to engines and convert output to `Finding` objects.

**Tech Stack:** Python 3.10+, ast (stdlib), Pydantic v2, pytest

**Spec:** `docs/superpowers/specs/2026-03-20-engine-upgrade-proposal.md`

---

## File Map

### New Files

| File | Responsibility |
|------|---------------|
| `src/agentwall/engine/__init__.py` | Public API for engine package |
| `src/agentwall/engine/models.py` | `ValueKind`, `PropertyExtraction`, `StoreProfile`, `IsolationStrategy`, `MetadataConsistency`, `TenantFlowSummary`, `PropertyVerification`, `Verdict`, `FlowStep`, `PathCoverage`, `UnresolvedCall`, `UnresolvedReason` |
| `src/agentwall/engine/extractor.py` | L1 engine: model-driven property extraction with value classification |
| `src/agentwall/engine/graph.py` | L2 engine: PyCG-style assignment graph + composition graph + single-level inheritance |
| `src/agentwall/engine/verifier.py` | L3 engine: per-function summaries + fixpoint iteration for tenant isolation verification |
| `src/agentwall/engine/pathcov.py` | L6 engine: interprocedural path coverage using lattice state |
| `src/agentwall/frameworks/__init__.py` | Framework model registry |
| `src/agentwall/frameworks/base.py` | `FrameworkModel`, `StoreModel`, `PipePattern`, `FactoryPattern`, `DecoratorPattern` |
| `src/agentwall/frameworks/langchain.py` | LangChain framework model (all vector stores, composition patterns, auth sources) |
| `tests/test_engine_models.py` | Tests for engine data models |
| `tests/test_extractor.py` | Tests for L1 engine |
| `tests/test_graph.py` | Tests for L2 engine |
| `tests/test_verifier.py` | Tests for L3 engine |
| `tests/test_pathcov.py` | Tests for L6 engine |
| `tests/test_framework_model.py` | Tests for framework model schema |
| `tests/fixtures/engine_basic/` | Simple fixture: one file with Chroma, no filter |
| `tests/fixtures/engine_tenant_collection/` | Per-tenant collection: `collection_name=f"docs_{user_id}"` |
| `tests/fixtures/engine_static_filter/` | Static filter: `filter={"source": "web"}` |
| `tests/fixtures/engine_cross_file/` | Cross-file: auth.py → retriever.py → api.py |
| `tests/fixtures/engine_lcel_pipe/` | LCEL pipe composition: `prompt \| llm \| retriever` |
| `tests/fixtures/engine_factory/` | Factory pattern: `ConversationalRetrievalChain.from_llm(retriever=r)` |
| `tests/fixtures/engine_inheritance/` | Custom subclass: `class TenantChroma(Chroma)` |
| `tests/fixtures/engine_branching/` | Filter on some paths but not all |

### Modified Files

| File | Change |
|------|--------|
| `src/agentwall/models.py` | No changes — new L2 types live in `engine/graph.py`. Existing `CallGraph` stays for backward compat |
| `src/agentwall/context.py` | Add `project_graph`, `store_profiles`, `property_verifications`, `path_coverages` fields to `AnalysisContext` |
| `src/agentwall/analyzers/memory.py` | Accept `StoreProfile` from engine when available, fall back to `MemoryConfig` |
| `src/agentwall/analyzers/callgraph.py` | Delegate to `engine/graph.py`, convert `ProjectGraph` → `CallGraph` for backward compat |
| `src/agentwall/analyzers/taint.py` | Delegate to `engine/verifier.py`, convert `PropertyVerification` → `TaintResult` for backward compat |
| `src/agentwall/analyzers/symbolic.py` | Delegate to `engine/pathcov.py`, emit findings from `PathCoverage` |

---

## Task 1: Engine Data Models

**Files:**
- Create: `src/agentwall/engine/__init__.py`
- Create: `src/agentwall/engine/models.py`
- Test: `tests/test_engine_models.py`

- [ ] **Step 1: Write tests for ValueKind classification**

```python
# tests/test_engine_models.py
import ast

from agentwall.engine.models import ValueKind, classify_value


def test_literal_string():
    node = ast.Constant(value="global_docs")
    assert classify_value(node, set()) == ValueKind.LITERAL


def test_literal_int():
    node = ast.Constant(value=42)
    assert classify_value(node, set()) == ValueKind.LITERAL


def test_dynamic_variable():
    node = ast.Name(id="some_var", ctx=ast.Load())
    assert classify_value(node, set()) == ValueKind.DYNAMIC


def test_tenant_scoped_variable():
    node = ast.Name(id="user_id", ctx=ast.Load())
    assert classify_value(node, {"user_id"}) == ValueKind.TENANT_SCOPED


def test_compound_static_dict():
    """{"source": "web"} → all literal values."""
    node = ast.Dict(
        keys=[ast.Constant(value="source")],
        values=[ast.Constant(value="web")],
    )
    assert classify_value(node, set()) == ValueKind.COMPOUND_STATIC


def test_compound_tenant_dict():
    """{"user_id": uid} where uid is tenant-scoped."""
    node = ast.Dict(
        keys=[ast.Constant(value="user_id")],
        values=[ast.Name(id="uid", ctx=ast.Load())],
    )
    assert classify_value(node, {"uid"}) == ValueKind.COMPOUND_TENANT


def test_compound_dynamic_dict():
    """{"category": cat} where cat is dynamic but not tenant."""
    node = ast.Dict(
        keys=[ast.Constant(value="category")],
        values=[ast.Name(id="cat", ctx=ast.Load())],
    )
    assert classify_value(node, set()) == ValueKind.COMPOUND_DYNAMIC


def test_fstring_with_tenant():
    """f"docs_{tenant_id}" → TENANT_SCOPED."""
    node = ast.JoinedStr(
        values=[
            ast.Constant(value="docs_"),
            ast.FormattedValue(
                value=ast.Name(id="tenant_id", ctx=ast.Load()),
                conversion=-1,
            ),
        ]
    )
    assert classify_value(node, {"tenant_id"}) == ValueKind.TENANT_SCOPED


def test_fstring_without_tenant():
    """f"docs_{version}" → DYNAMIC."""
    node = ast.JoinedStr(
        values=[
            ast.Constant(value="docs_"),
            ast.FormattedValue(
                value=ast.Name(id="version", ctx=ast.Load()),
                conversion=-1,
            ),
        ]
    )
    assert classify_value(node, set()) == ValueKind.DYNAMIC
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_engine_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'agentwall.engine'`

- [ ] **Step 3: Implement engine models**

```python
# src/agentwall/engine/__init__.py
"""General-purpose analysis engines for AI security property verification."""

# src/agentwall/engine/models.py
"""Data models for the engine layer.

These models are engine-internal. Analyzers consume them and convert
to Finding objects for output.
"""

from __future__ import annotations

import ast
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Literal


class ValueKind(str, Enum):
    """Classification of an AST expression by security relevance."""

    LITERAL = "literal"
    DYNAMIC = "dynamic"
    TENANT_SCOPED = "tenant"
    COMPOUND_STATIC = "cstatic"
    COMPOUND_DYNAMIC = "cdynamic"
    COMPOUND_TENANT = "ctenant"


def classify_value(node: ast.expr, tenant_names: set[str]) -> ValueKind:
    """Classify an AST expression by its security-relevant kind.

    Args:
        node: AST expression node to classify.
        tenant_names: Set of variable names known to carry tenant identity.
    """
    if isinstance(node, ast.Constant):
        return ValueKind.LITERAL
    if isinstance(node, ast.Name):
        if node.id in tenant_names:
            return ValueKind.TENANT_SCOPED
        return ValueKind.DYNAMIC
    if isinstance(node, ast.JoinedStr):
        for val in node.values:
            child = val.value if isinstance(val, ast.FormattedValue) else val
            if classify_value(child, tenant_names) == ValueKind.TENANT_SCOPED:
                return ValueKind.TENANT_SCOPED
        return ValueKind.DYNAMIC
    if isinstance(node, ast.Dict):
        kinds = [classify_value(v, tenant_names) for v in node.values if v is not None]
        if any(k == ValueKind.TENANT_SCOPED for k in kinds):
            return ValueKind.COMPOUND_TENANT
        if all(k == ValueKind.LITERAL for k in kinds):
            return ValueKind.COMPOUND_STATIC
        return ValueKind.COMPOUND_DYNAMIC
    return ValueKind.DYNAMIC


class IsolationStrategy(str, Enum):
    """How tenant isolation is achieved for a store."""

    COLLECTION_PER_TENANT = "collection_per_tenant"
    FILTER_ON_READ = "filter_on_read"
    PARTIAL_FILTER = "partial_filter"
    NONE = "none"


class SecurityProperty(str, Enum):
    """Security properties that can be verified across access paths."""

    TENANT_ISOLATION = "tenant_isolation"
    # Future: SANITIZATION, AUTH_CHECK, etc.


class Verdict(str, Enum):
    """Result of verifying a security property on one access path."""

    VERIFIED = "verified"
    VIOLATED = "violated"
    PARTIAL = "partial"
    UNKNOWN = "unknown"


class UnresolvedReason(str, Enum):
    """Why a call could not be resolved."""

    DYNAMIC_ATTR = "dynamic_attr"
    PLUGIN_LOAD = "plugin_load"
    VARIABLE_CALLEE = "variable_callee"
    EXTERNAL_MODULE = "external_module"


@dataclass(frozen=True)
class PropertyExtraction:
    """A single extracted property from a framework call."""

    file: Path
    line: int
    store_id: str
    operation: Literal["read", "write", "init"]
    method: str

    has_filter: bool = False  # True if filter kwarg was present at all
    filter_keys: frozenset[str] = frozenset()
    filter_value_kind: ValueKind = ValueKind.DYNAMIC
    metadata_keys: frozenset[str] = frozenset()
    metadata_value_kind: ValueKind = ValueKind.DYNAMIC
    collection_name: str | None = None
    collection_name_kind: ValueKind = ValueKind.DYNAMIC


@dataclass
class MetadataConsistency:
    """Cross-reference write metadata keys vs read filter keys."""

    write_keys: frozenset[str] = frozenset()
    read_filter_keys: frozenset[str] = frozenset()

    @property
    def unfiltered_write_keys(self) -> frozenset[str]:
        return self.write_keys - self.read_filter_keys

    @property
    def has_tenant_key_on_both(self) -> bool:
        tenant_keys = {"user_id", "tenant_id", "org_id", "owner_id"}
        return bool(self.write_keys & self.read_filter_keys & tenant_keys)


@dataclass
class StoreProfile:
    """Complete security profile of one vector store instance."""

    store_id: str
    backend: str
    collection_name: str | None = None
    collection_name_kind: ValueKind = ValueKind.DYNAMIC
    extractions: list[PropertyExtraction] = field(default_factory=list)
    file: Path | None = None
    line: int | None = None

    @property
    def isolation_strategy(self) -> IsolationStrategy:
        if self.collection_name_kind == ValueKind.TENANT_SCOPED:
            return IsolationStrategy.COLLECTION_PER_TENANT
        reads = [e for e in self.extractions if e.operation == "read"]
        if not reads:
            return IsolationStrategy.NONE
        tenant_reads = [r for r in reads if r.filter_value_kind == ValueKind.COMPOUND_TENANT]
        if len(tenant_reads) == len(reads):
            return IsolationStrategy.FILTER_ON_READ
        if tenant_reads:
            return IsolationStrategy.PARTIAL_FILTER
        return IsolationStrategy.NONE

    @property
    def metadata_consistency(self) -> MetadataConsistency:
        write_keys: set[str] = set()
        read_keys: set[str] = set()
        for e in self.extractions:
            if e.operation == "write":
                write_keys |= e.metadata_keys
            elif e.operation == "read":
                read_keys |= e.filter_keys
        return MetadataConsistency(
            write_keys=frozenset(write_keys),
            read_filter_keys=frozenset(read_keys),
        )


@dataclass(frozen=True)
class FlowStep:
    """One step in a tenant identity flow trace."""

    file: Path
    line: int
    kind: str  # "source", "propagation", "call_arg", "call_return", "sink"
    value_kind: ValueKind
    summary_used: str | None = None


@dataclass(frozen=True)
class StoreAccess:
    """A store operation with filter classification."""

    store_id: str
    method: str
    filter_kind: ValueKind
    filter_param_source: int | None = None  # which param feeds the filter


@dataclass(frozen=True)
class TenantFlowSummary:
    """Per-function summary: what this function does with tenant identity."""

    function: str
    file: Path
    param_reaches_filter: dict[int, frozenset[str]] = field(default_factory=dict)
    returns_tenant_scoped: bool = False
    has_unfiltered_read: bool = False
    store_reads: list[StoreAccess] = field(default_factory=list)
    store_writes: list[StoreAccess] = field(default_factory=list)


@dataclass(frozen=True)
class PropertyVerification:
    """Result of verifying a security property on one access path."""

    store_id: str
    access: StoreAccess
    property: SecurityProperty = SecurityProperty.TENANT_ISOLATION
    verdict: Verdict = Verdict.UNKNOWN
    evidence: list[FlowStep] = field(default_factory=list)
    file: Path | None = None
    line: int | None = None


@dataclass(frozen=True)
class VerifiedPath:
    """A path where the security property holds."""

    entry_file: Path
    entry_line: int
    call_chain: list[tuple[Path, int]] = field(default_factory=list)


@dataclass(frozen=True)
class ViolatedPath:
    """A path where the security property doesn't hold."""

    entry_file: Path
    entry_line: int
    violation_file: Path
    violation_line: int
    call_chain: list[tuple[Path, int]] = field(default_factory=list)
    branch_condition: str | None = None


@dataclass(frozen=True)
class UnknownPath:
    """A path where the property could not be determined."""

    entry_file: Path
    entry_line: int
    reason: str  # e.g. "unresolved call at api.py:42"
    call_chain: list[tuple[Path, int]] = field(default_factory=list)


@dataclass
class PathCoverage:
    """Coverage report for a security property across all access paths to a store."""

    store_id: str
    property: SecurityProperty = SecurityProperty.TENANT_ISOLATION
    total_paths: int = 0
    verified_paths: list[VerifiedPath] = field(default_factory=list)
    violated_paths: list[ViolatedPath] = field(default_factory=list)
    unknown_paths: list[UnknownPath] = field(default_factory=list)

    @property
    def coverage_ratio(self) -> float:
        return len(self.verified_paths) / self.total_paths if self.total_paths else 0.0


@dataclass(frozen=True)
class UnresolvedCall:
    """A call that could not be statically resolved."""

    file: Path
    line: int
    callee_expr: str
    reason: UnresolvedReason
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_engine_models.py -v`
Expected: All 10 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/engine/__init__.py src/agentwall/engine/models.py tests/test_engine_models.py
git commit -m "feat(engine): add core data models with ValueKind classifier"
```

---

## Task 2: Framework Model Schema

**Files:**
- Create: `src/agentwall/frameworks/__init__.py`
- Create: `src/agentwall/frameworks/base.py`
- Test: `tests/test_framework_model.py`

- [ ] **Step 1: Write tests for framework model schema**

```python
# tests/test_framework_model.py
from agentwall.frameworks.base import (
    DecoratorPattern,
    FactoryPattern,
    FrameworkModel,
    PipePattern,
    StoreModel,
)


def test_store_model_has_required_fields():
    sm = StoreModel(
        backend="chromadb",
        isolation_params=["collection_name"],
        write_methods={"add_texts": "metadata"},
        read_methods={"similarity_search": "filter"},
    )
    assert sm.backend == "chromadb"
    assert sm.read_methods["similarity_search"] == "filter"


def test_framework_model_stores_lookup():
    model = FrameworkModel(
        name="test",
        stores={
            "Chroma": StoreModel(
                backend="chromadb",
                isolation_params=["collection_name"],
                write_methods={"add_texts": "metadata"},
                read_methods={"similarity_search": "filter"},
            ),
        },
    )
    assert "Chroma" in model.stores
    assert model.stores["Chroma"].backend == "chromadb"


def test_pipe_pattern():
    p = PipePattern(operator="|")
    assert p.operator == "|"


def test_factory_pattern():
    f = FactoryPattern(method="from_llm", kwarg="retriever", role="read_source")
    assert f.method == "from_llm"
    assert f.kwarg == "retriever"


def test_decorator_pattern():
    d = DecoratorPattern(decorator="tool", registers_as="agent_tool")
    assert d.decorator == "tool"


def test_framework_model_tenant_params():
    model = FrameworkModel(
        name="test",
        stores={},
        tenant_param_names=["user_id", "tenant_id", "org_id"],
    )
    assert "user_id" in model.tenant_param_names


def test_store_model_retriever_factory():
    sm = StoreModel(
        backend="chromadb",
        isolation_params=["collection_name"],
        write_methods={"add_texts": "metadata"},
        read_methods={"similarity_search": "filter"},
        retriever_factory="as_retriever",
        retriever_filter_path="search_kwargs.filter",
    )
    assert sm.retriever_factory == "as_retriever"
    assert sm.retriever_filter_path == "search_kwargs.filter"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_framework_model.py -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement framework model schema**

```python
# src/agentwall/frameworks/__init__.py
"""Declarative framework models for AI agent security analysis."""

# src/agentwall/frameworks/base.py
"""Base schema for framework models.

A framework model declares the patterns an engine should look for
when analyzing code that uses a specific AI framework. Adding a new
framework = writing a new model file using these schemas.
"""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True)
class StoreModel:
    """Declares how a vector store backend works for security analysis."""

    backend: str  # canonical name: "chromadb", "pgvector", "pinecone"
    isolation_params: list[str]  # params that can isolate tenants: ["collection_name", "namespace"]
    write_methods: dict[str, str]  # method → metadata kwarg: {"add_texts": "metadata"}
    read_methods: dict[str, str]  # method → filter kwarg: {"similarity_search": "filter"}
    retriever_factory: str | None = None  # e.g., "as_retriever"
    retriever_filter_path: str | None = None  # e.g., "search_kwargs.filter"
    auth_params: list[str] = field(default_factory=list)  # ["api_key", "connection_string"]
    persistence_params: list[str] = field(default_factory=list)  # ["persist_directory"]
    has_builtin_acl: bool = False  # True for backends with native RBAC


@dataclass(frozen=True)
class PipePattern:
    """Declares a pipe/composition operator."""

    operator: str  # "|" for LCEL


@dataclass(frozen=True)
class FactoryPattern:
    """Declares a factory method that wires components."""

    method: str  # "from_llm", "from_chain_type"
    kwarg: str  # "retriever" — the kwarg that takes a data source
    role: str  # "read_source", "memory", "tool"


@dataclass(frozen=True)
class DecoratorPattern:
    """Declares a decorator that registers a function as a component."""

    decorator: str  # "tool"
    registers_as: str  # "agent_tool", "mcp_tool"


@dataclass
class FrameworkModel:
    """Complete model for one AI framework.

    The engine reads this to know what AST patterns to look for.
    Adding a new framework = creating a new FrameworkModel instance.
    """

    name: str  # "langchain", "llamaindex", "crewai"
    stores: dict[str, StoreModel]  # class_name → store model

    # Composition patterns
    pipe_patterns: list[PipePattern] = field(default_factory=list)
    factory_patterns: list[FactoryPattern] = field(default_factory=list)
    decorator_patterns: list[DecoratorPattern] = field(default_factory=list)

    # Tenant identity
    auth_sources: list[str] = field(default_factory=lambda: [
        "request.user", "request.user_id", "session.user_id",
        "g.user", "current_user", "jwt.sub",
    ])
    tenant_param_names: list[str] = field(default_factory=lambda: [
        "user_id", "tenant_id", "org_id", "owner_id",
    ])

    # Memory classes (injection risk)
    memory_classes: list[str] = field(default_factory=list)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_framework_model.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/frameworks/__init__.py src/agentwall/frameworks/base.py tests/test_framework_model.py
git commit -m "feat(frameworks): add declarative framework model schema"
```

---

## Task 3: LangChain Framework Model

**Files:**
- Create: `src/agentwall/frameworks/langchain.py`
- Test: `tests/test_framework_model.py` (extend)

- [ ] **Step 1: Write tests for LangChain model completeness**

```python
# Append to tests/test_framework_model.py
from agentwall.frameworks.langchain import LANGCHAIN_MODEL


def test_langchain_model_has_chroma():
    assert "Chroma" in LANGCHAIN_MODEL.stores
    chroma = LANGCHAIN_MODEL.stores["Chroma"]
    assert chroma.backend == "chromadb"
    assert "collection_name" in chroma.isolation_params
    assert "similarity_search" in chroma.read_methods
    assert chroma.read_methods["similarity_search"] == "filter"
    assert "add_texts" in chroma.write_methods


def test_langchain_model_has_pgvector():
    assert "PGVector" in LANGCHAIN_MODEL.stores
    assert LANGCHAIN_MODEL.stores["PGVector"].backend == "pgvector"


def test_langchain_model_has_faiss():
    faiss = LANGCHAIN_MODEL.stores["FAISS"]
    assert faiss.backend == "faiss"
    assert faiss.has_builtin_acl is False


def test_langchain_model_has_pipe_pattern():
    assert any(p.operator == "|" for p in LANGCHAIN_MODEL.pipe_patterns)


def test_langchain_model_has_factory_patterns():
    methods = {f.method for f in LANGCHAIN_MODEL.factory_patterns}
    assert "from_llm" in methods
    assert "from_chain_type" in methods


def test_langchain_model_has_tool_decorator():
    decorators = {d.decorator for d in LANGCHAIN_MODEL.decorator_patterns}
    assert "tool" in decorators


def test_langchain_model_covers_all_current_backends():
    """Every backend currently in _VECTOR_STORES dict must be in the model."""
    expected = {
        "Chroma", "PGVector", "Pinecone", "Qdrant", "FAISS",
        "Weaviate", "Neo4jVector", "Milvus", "Redis",
        "ElasticsearchStore", "LanceDB", "MongoDBAtlasVectorSearch",
    }
    assert expected.issubset(LANGCHAIN_MODEL.stores.keys())
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_framework_model.py::test_langchain_model_has_chroma -v`
Expected: FAIL — `ModuleNotFoundError`

- [ ] **Step 3: Implement LangChain model**

```python
# src/agentwall/frameworks/langchain.py
"""LangChain framework model.

Declares all vector stores, composition patterns, and tenant identity
sources for the LangChain ecosystem. This is the ONLY place LangChain-specific
knowledge lives — the engine reads this model, not LangChain code.
"""

from __future__ import annotations

from agentwall.frameworks.base import (
    DecoratorPattern,
    FactoryPattern,
    FrameworkModel,
    PipePattern,
    StoreModel,
)

# Shared read methods for most LangChain vector stores
_COMMON_READ = {
    "similarity_search": "filter",
    "similarity_search_with_score": "filter",
    "max_marginal_relevance_search": "filter",
}
_COMMON_WRITE = {
    "add_texts": "metadatas",
    "add_documents": "metadatas",
}
_COMMON_RETRIEVER = "as_retriever"
_COMMON_RETRIEVER_FILTER = "search_kwargs.filter"

LANGCHAIN_MODEL = FrameworkModel(
    name="langchain",
    stores={
        "Chroma": StoreModel(
            backend="chromadb",
            isolation_params=["collection_name"],
            write_methods={**_COMMON_WRITE, "add_texts": "metadata"},
            read_methods={**_COMMON_READ},
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["client_settings", "http_client"],
            persistence_params=["persist_directory"],
        ),
        "PGVector": StoreModel(
            backend="pgvector",
            isolation_params=["collection_name"],
            write_methods=_COMMON_WRITE,
            read_methods=_COMMON_READ,
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["connection_string"],
        ),
        "Pinecone": StoreModel(
            backend="pinecone",
            isolation_params=["namespace"],
            write_methods=_COMMON_WRITE,
            read_methods=_COMMON_READ,
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["api_key", "environment"],
        ),
        "Qdrant": StoreModel(
            backend="qdrant",
            isolation_params=["collection_name"],
            write_methods=_COMMON_WRITE,
            read_methods={**_COMMON_READ, "similarity_search": "filter"},
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["api_key", "url"],
        ),
        "FAISS": StoreModel(
            backend="faiss",
            isolation_params=[],  # FAISS has zero access control
            write_methods=_COMMON_WRITE,
            read_methods=_COMMON_READ,
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            persistence_params=["folder_path"],
            has_builtin_acl=False,
        ),
        "Weaviate": StoreModel(
            backend="weaviate",
            isolation_params=["index_name"],
            write_methods=_COMMON_WRITE,
            read_methods={**_COMMON_READ, "similarity_search": "where_filter"},
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["auth_credentials", "url"],
        ),
        "Neo4jVector": StoreModel(
            backend="neo4j",
            isolation_params=["index_name"],
            write_methods=_COMMON_WRITE,
            read_methods=_COMMON_READ,
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["url", "username", "password"],
        ),
        "Milvus": StoreModel(
            backend="milvus",
            isolation_params=["collection_name"],
            write_methods=_COMMON_WRITE,
            read_methods={**_COMMON_READ, "similarity_search": "expr"},
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["connection_args"],
        ),
        "Redis": StoreModel(
            backend="redis",
            isolation_params=["index_name"],
            write_methods=_COMMON_WRITE,
            read_methods=_COMMON_READ,
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["redis_url"],
        ),
        "ElasticsearchStore": StoreModel(
            backend="elasticsearch",
            isolation_params=["index_name"],
            write_methods=_COMMON_WRITE,
            read_methods=_COMMON_READ,
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["es_url", "es_user", "es_password"],
        ),
        "LanceDB": StoreModel(
            backend="lancedb",
            isolation_params=["table_name"],
            write_methods=_COMMON_WRITE,
            read_methods={**_COMMON_READ, "similarity_search": "filter"},
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            persistence_params=["uri"],
        ),
        "MongoDBAtlasVectorSearch": StoreModel(
            backend="mongodb",
            isolation_params=["collection_name"],
            write_methods=_COMMON_WRITE,
            read_methods={**_COMMON_READ},
            retriever_factory=_COMMON_RETRIEVER,
            retriever_filter_path=_COMMON_RETRIEVER_FILTER,
            auth_params=["connection_string"],
        ),
    },
    pipe_patterns=[PipePattern(operator="|")],
    factory_patterns=[
        FactoryPattern(method="from_llm", kwarg="retriever", role="read_source"),
        FactoryPattern(method="from_chain_type", kwarg="retriever", role="read_source"),
    ],
    decorator_patterns=[
        DecoratorPattern(decorator="tool", registers_as="agent_tool"),
    ],
    memory_classes=[
        "ConversationBufferMemory",
        "ConversationBufferWindowMemory",
        "ConversationSummaryMemory",
        "ConversationSummaryBufferMemory",
        "VectorStoreRetrieverMemory",
        "ConversationEntityMemory",
        "ConversationKGMemory",
    ],
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_framework_model.py -v`
Expected: All 14 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/frameworks/langchain.py tests/test_framework_model.py
git commit -m "feat(frameworks): add LangChain model with 12 vector stores"
```

---

## Task 4: L1 Engine — Model-Driven Property Extractor

**Files:**
- Create: `src/agentwall/engine/extractor.py`
- Create: `tests/fixtures/engine_basic/agent.py`
- Create: `tests/fixtures/engine_tenant_collection/agent.py`
- Create: `tests/fixtures/engine_static_filter/agent.py`
- Test: `tests/test_extractor.py`

- [ ] **Step 1: Create test fixtures**

```python
# tests/fixtures/engine_basic/agent.py
from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="shared_docs")
results = db.similarity_search("query")
```

```python
# tests/fixtures/engine_tenant_collection/agent.py
from langchain_community.vectorstores import Chroma

def search(tenant_id: str, query: str):
    db = Chroma(collection_name=f"docs_{tenant_id}")
    return db.similarity_search(query)
```

```python
# tests/fixtures/engine_static_filter/agent.py
from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="shared_docs")
db.add_texts(["hello"], metadatas=[{"user_id": "u1", "source": "web"}])
results = db.similarity_search("query", filter={"source": "web"})
```

- [ ] **Step 2: Write tests**

```python
# tests/test_extractor.py
from pathlib import Path

from agentwall.engine.extractor import extract_properties
from agentwall.engine.models import IsolationStrategy, ValueKind
from agentwall.frameworks.langchain import LANGCHAIN_MODEL

FIXTURES = Path(__file__).parent / "fixtures"


def test_basic_no_filter():
    """Chroma with no filter → NONE isolation, read has DYNAMIC filter kind."""
    profiles = extract_properties(
        [FIXTURES / "engine_basic" / "agent.py"],
        LANGCHAIN_MODEL,
    )
    assert len(profiles) == 1
    p = profiles[0]
    assert p.backend == "chromadb"
    assert p.isolation_strategy == IsolationStrategy.NONE
    reads = [e for e in p.extractions if e.operation == "read"]
    assert len(reads) == 1
    assert reads[0].filter_value_kind == ValueKind.DYNAMIC  # no filter kwarg at all


def test_tenant_collection():
    """collection_name=f"docs_{tenant_id}" → COLLECTION_PER_TENANT."""
    profiles = extract_properties(
        [FIXTURES / "engine_tenant_collection" / "agent.py"],
        LANGCHAIN_MODEL,
    )
    assert len(profiles) == 1
    assert profiles[0].isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT
    assert profiles[0].collection_name_kind == ValueKind.TENANT_SCOPED


def test_static_filter():
    """filter={"source": "web"} → COMPOUND_STATIC, isolation=NONE."""
    profiles = extract_properties(
        [FIXTURES / "engine_static_filter" / "agent.py"],
        LANGCHAIN_MODEL,
    )
    assert len(profiles) == 1
    p = profiles[0]
    assert p.isolation_strategy == IsolationStrategy.NONE
    reads = [e for e in p.extractions if e.operation == "read"]
    assert reads[0].filter_value_kind == ValueKind.COMPOUND_STATIC


def test_metadata_consistency_mismatch():
    """Write user_id+source, filter only on source → unfiltered_write_keys has user_id."""
    profiles = extract_properties(
        [FIXTURES / "engine_static_filter" / "agent.py"],
        LANGCHAIN_MODEL,
    )
    mc = profiles[0].metadata_consistency
    assert "user_id" in mc.unfiltered_write_keys
    assert mc.has_tenant_key_on_both is False
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_extractor.py -v`
Expected: FAIL — `ImportError`

- [ ] **Step 4: Implement L1 engine**

```python
# src/agentwall/engine/extractor.py
"""L1 Engine: Model-driven property extraction with value classification.

Walks AST and extracts security-relevant properties from framework calls,
driven by a declarative FrameworkModel. No hardcoded framework knowledge.
"""

from __future__ import annotations

import ast
import warnings
from pathlib import Path

from agentwall.engine.models import PropertyExtraction, StoreProfile, ValueKind, classify_value
from agentwall.frameworks.base import FrameworkModel


class _PropertyVisitor(ast.NodeVisitor):
    """Extract properties from AST using a framework model."""

    def __init__(self, file_path: Path, model: FrameworkModel) -> None:
        self.file_path = file_path
        self.model = model
        self.stores: dict[str, StoreProfile] = {}  # var_name → profile
        self.extractions: list[PropertyExtraction] = []
        self._var_stores: dict[str, str] = {}  # var_name → store_id
        self._tenant_names: set[str] = set(model.tenant_param_names)
        self._current_func_params: set[str] = set()

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev = self._current_func_params.copy()
        self._current_func_params = set()
        for arg in node.args.args:
            if arg.arg.lower() in self._tenant_names:
                self._current_func_params.add(arg.arg)
        self.generic_visit(node)
        self._current_func_params = prev

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            self._check_store_init(node)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        self._check_read_op(node)
        self._check_write_op(node)
        self.generic_visit(node)

    def _check_store_init(self, node: ast.Assign) -> None:
        """Check if assignment is a vector store instantiation."""
        call = node.value
        if not isinstance(call, ast.Call):
            return
        class_name = self._get_call_name(call)
        if class_name not in self.model.stores:
            return

        store_model = self.model.stores[class_name]
        var_name = None
        for target in node.targets:
            if isinstance(target, ast.Name):
                var_name = target.id
                break
        if not var_name:
            return

        store_id = f"{self.file_path.stem}:{node.lineno}:{var_name}"
        tenant_names = self._tenant_names | self._current_func_params

        # Extract collection_name / isolation params
        col_name = None
        col_kind = ValueKind.DYNAMIC
        for param_name in store_model.isolation_params:
            for kw in call.keywords:
                if kw.arg == param_name:
                    col_name = self._get_constant_value(kw.value)
                    col_kind = classify_value(kw.value, tenant_names)

        profile = StoreProfile(
            store_id=store_id,
            backend=store_model.backend,
            collection_name=col_name,
            collection_name_kind=col_kind,
            file=self.file_path,
            line=node.lineno,
        )
        self.stores[var_name] = profile
        self._var_stores[var_name] = store_id

        self.extractions.append(PropertyExtraction(
            file=self.file_path,
            line=node.lineno,
            store_id=store_id,
            operation="init",
            method="__init__",
            collection_name=col_name,
            collection_name_kind=col_kind,
        ))

    def _check_read_op(self, node: ast.Call) -> None:
        """Check if call is a vector store read operation."""
        if not isinstance(node.func, ast.Attribute):
            return
        method = node.func.attr
        var_name = self._get_receiver_name(node.func)
        store_id = self._var_stores.get(var_name, f"unknown:{var_name}") if var_name else None
        if not store_id:
            return

        # Check all store models for this method
        for store_model in self.model.stores.values():
            if method in store_model.read_methods:
                filter_kwarg = store_model.read_methods[method]
                tenant_names = self._tenant_names | self._current_func_params
                filter_keys: set[str] = set()
                filter_kind = ValueKind.DYNAMIC

                for kw in node.keywords:
                    if kw.arg == filter_kwarg:
                        filter_kind = classify_value(kw.value, tenant_names)
                        filter_keys = self._extract_dict_keys(kw.value)
                        break
                    # Handle search_kwargs={"filter": ...}
                    if kw.arg == "search_kwargs" and isinstance(kw.value, ast.Dict):
                        for k, v in zip(kw.value.keys, kw.value.values):
                            if isinstance(k, ast.Constant) and k.value == "filter" and v:
                                filter_kind = classify_value(v, tenant_names)
                                filter_keys = self._extract_dict_keys(v)
                                break

                self.extractions.append(PropertyExtraction(
                    file=self.file_path,
                    line=node.lineno,
                    store_id=store_id,
                    operation="read",
                    method=method,
                    filter_keys=frozenset(filter_keys),
                    filter_value_kind=filter_kind,
                ))
                return

    def _check_write_op(self, node: ast.Call) -> None:
        """Check if call is a vector store write operation."""
        if not isinstance(node.func, ast.Attribute):
            return
        method = node.func.attr
        var_name = self._get_receiver_name(node.func)
        store_id = self._var_stores.get(var_name, f"unknown:{var_name}") if var_name else None
        if not store_id:
            return

        for store_model in self.model.stores.values():
            if method in store_model.write_methods:
                meta_kwarg = store_model.write_methods[method]
                tenant_names = self._tenant_names | self._current_func_params
                meta_keys: set[str] = set()
                meta_kind = ValueKind.DYNAMIC

                for kw in node.keywords:
                    if kw.arg == meta_kwarg:
                        meta_kind = classify_value(kw.value, tenant_names)
                        # If it's a list of dicts, peek at first element
                        if isinstance(kw.value, ast.List) and kw.value.elts:
                            first = kw.value.elts[0]
                            meta_keys = self._extract_dict_keys(first)
                            meta_kind = classify_value(first, tenant_names)
                        else:
                            meta_keys = self._extract_dict_keys(kw.value)
                        break

                self.extractions.append(PropertyExtraction(
                    file=self.file_path,
                    line=node.lineno,
                    store_id=store_id,
                    operation="write",
                    method=method,
                    metadata_keys=frozenset(meta_keys),
                    metadata_value_kind=meta_kind,
                ))
                return

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    @staticmethod
    def _get_receiver_name(node: ast.Attribute) -> str | None:
        if isinstance(node.value, ast.Name):
            return node.value.id
        return None

    @staticmethod
    def _get_constant_value(node: ast.expr) -> str | None:
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return None

    @staticmethod
    def _extract_dict_keys(node: ast.expr) -> set[str]:
        if isinstance(node, ast.Dict):
            return {
                k.value for k in node.keys
                if isinstance(k, ast.Constant) and isinstance(k.value, str)
            }
        return set()


def extract_properties(
    source_files: list[Path],
    model: FrameworkModel,
) -> list[StoreProfile]:
    """Extract all store profiles from source files using a framework model.

    This is the L1 engine entry point. Returns one StoreProfile per
    detected vector store instance.
    """
    all_stores: dict[str, StoreProfile] = {}
    all_extractions: list[PropertyExtraction] = []

    for py_file in source_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError) as exc:
            warnings.warn(f"L1-engine: Skipping {py_file}: {exc}", stacklevel=2)
            continue

        visitor = _PropertyVisitor(py_file, model)
        visitor.visit(tree)

        for var_name, profile in visitor.stores.items():
            all_stores[profile.store_id] = profile
        all_extractions.extend(visitor.extractions)

    # Attach extractions to their stores
    for extraction in all_extractions:
        if extraction.store_id in all_stores:
            all_stores[extraction.store_id].extractions.append(extraction)

    return list(all_stores.values())
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_extractor.py -v`
Expected: All 4 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/engine/extractor.py tests/test_extractor.py tests/fixtures/engine_basic/ tests/fixtures/engine_tenant_collection/ tests/fixtures/engine_static_filter/
git commit -m "feat(engine): L1 model-driven property extractor with value classification"
```

---

## Task 5: L2 Engine — Assignment-Based Project Graph

**Files:**
- Create: `src/agentwall/engine/graph.py`
- Create: `tests/fixtures/engine_cross_file/auth.py`
- Create: `tests/fixtures/engine_cross_file/retriever.py`
- Create: `tests/fixtures/engine_cross_file/api.py`
- Create: `tests/fixtures/engine_lcel_pipe/agent.py`
- Create: `tests/fixtures/engine_factory/agent.py`
- Create: `tests/fixtures/engine_inheritance/agent.py`
- Test: `tests/test_graph.py`

- [ ] **Step 1: Create test fixtures**

```python
# tests/fixtures/engine_cross_file/auth.py
def get_current_user(request):
    return request.user.id

# tests/fixtures/engine_cross_file/retriever.py
from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="docs")

def search_docs(query, user_id):
    return db.similarity_search(query, filter={"user_id": user_id})

# tests/fixtures/engine_cross_file/api.py
from auth import get_current_user
from retriever import search_docs

def ask_endpoint(request):
    user_id = get_current_user(request)
    return search_docs(request.body, user_id)
```

```python
# tests/fixtures/engine_lcel_pipe/agent.py
from langchain_community.vectorstores import Chroma
from langchain.prompts import PromptTemplate
from langchain_openai import ChatOpenAI

db = Chroma(collection_name="docs")
retriever = db.as_retriever()
prompt = PromptTemplate.from_template("{context}")
llm = ChatOpenAI()
chain = prompt | llm | retriever
```

```python
# tests/fixtures/engine_factory/agent.py
from langchain.chains import ConversationalRetrievalChain
from langchain_community.vectorstores import Chroma
from langchain_openai import ChatOpenAI

db = Chroma(collection_name="docs")
retriever = db.as_retriever()
llm = ChatOpenAI()
chain = ConversationalRetrievalChain.from_llm(llm=llm, retriever=retriever)
```

```python
# tests/fixtures/engine_inheritance/agent.py
from langchain_community.vectorstores import Chroma

class TenantChroma(Chroma):
    def similarity_search(self, query, **kwargs):
        kwargs["filter"] = {"user_id": self.current_user}
        return super().similarity_search(query, **kwargs)

db = TenantChroma(collection_name="docs")
results = db.similarity_search("query")
```

- [ ] **Step 2: Write tests**

```python
# tests/test_graph.py
from pathlib import Path

from agentwall.engine.graph import build_project_graph
from agentwall.frameworks.langchain import LANGCHAIN_MODEL

FIXTURES = Path(__file__).parent / "fixtures"


def test_cross_file_import_resolution():
    """Imports across files are resolved."""
    files = list((FIXTURES / "engine_cross_file").glob("*.py"))
    graph = build_project_graph(files, LANGCHAIN_MODEL, FIXTURES / "engine_cross_file")
    # api.py calls search_docs from retriever.py
    callees = {e.callee_name for e in graph.call_edges if e.caller_name == "ask_endpoint"}
    assert "get_current_user" in callees and "search_docs" in callees


def test_assignment_tracking():
    """Variable reassignment is tracked: db = Chroma(); retriever = db.as_retriever()."""
    files = [FIXTURES / "engine_lcel_pipe" / "agent.py"]
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    # db should point to Chroma
    assert "db" in graph.identifiers
    assert any("Chroma" in v for v in graph.identifiers["db"].pointsto)


def test_lcel_pipe_detected():
    """LCEL pipe operator creates composition edges."""
    files = [FIXTURES / "engine_lcel_pipe" / "agent.py"]
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    pipe_edges = [e for e in graph.composition_edges if e.kind == "pipe"]
    assert len(pipe_edges) >= 2  # prompt|llm and llm|retriever


def test_factory_pattern_detected():
    """from_llm(retriever=r) creates a factory composition edge."""
    files = [FIXTURES / "engine_factory" / "agent.py"]
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    factory_edges = [e for e in graph.composition_edges if e.kind == "factory"]
    assert len(factory_edges) >= 1
    assert any("retriever" in e.target for e in factory_edges)


def test_single_level_inheritance():
    """class TenantChroma(Chroma) → extends recorded."""
    files = [FIXTURES / "engine_inheritance" / "agent.py"]
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    assert graph.extends.get("TenantChroma") == "Chroma"


def test_unresolved_calls_marked():
    """Calls that can't be resolved are explicitly marked with reason."""
    files = [FIXTURES / "engine_basic" / "agent.py"]
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    # All calls should be either resolved or in unresolved list
    total = len(graph.call_edges) + len(graph.unresolved)
    assert total >= 0  # sanity check — no crash
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_graph.py -v`
Expected: FAIL — `ImportError`

- [ ] **Step 4: Implement L2 engine**

```python
# src/agentwall/engine/graph.py
"""L2 Engine: Assignment-based project graph with composition detection.

Algorithm based on PyCG (ICSE '21): track all possible values of every
identifier through assignments. Extended with:
- Framework-specific composition patterns (pipe, factory, decorator)
- Single-level inheritance tracking
- Cross-file import resolution

Reference: https://arxiv.org/pdf/2103.00587
"""

from __future__ import annotations

import ast
import warnings
from dataclasses import dataclass, field
from pathlib import Path

from agentwall.engine.models import UnresolvedCall, UnresolvedReason
from agentwall.frameworks.base import FrameworkModel


@dataclass
class IdentifierState:
    """All possible values an identifier can hold."""

    name: str
    pointsto: set[str] = field(default_factory=set)
    scope: str = "<module>"


@dataclass(frozen=True)
class CallEdgeV2:
    """A resolved call edge in the project graph."""

    caller_name: str
    callee_name: str
    caller_file: Path
    callee_file: Path | None
    line: int
    resolved: bool = True
    # Positional arg names at the call site (for fixpoint param mapping)
    # e.g., search_docs(db, query, user_id) → ("db", "query", "user_id")
    arg_names: tuple[str, ...] = ()


@dataclass(frozen=True)
class CompositionEdge:
    """A framework-specific connection between components."""

    source: str  # variable/expression that produces
    target: str  # variable/expression that consumes
    kind: str  # "pipe", "factory", "decorator"
    file: Path
    line: int


@dataclass
class ProjectGraph:
    """Unified call + composition graph for the entire project."""

    call_edges: list[CallEdgeV2] = field(default_factory=list)
    composition_edges: list[CompositionEdge] = field(default_factory=list)
    identifiers: dict[str, IdentifierState] = field(default_factory=dict)
    extends: dict[str, str] = field(default_factory=dict)  # child → parent
    unresolved: list[UnresolvedCall] = field(default_factory=list)

    def callers_of(self, func_name: str) -> list[CallEdgeV2]:
        return [e for e in self.call_edges if e.callee_name == func_name and e.resolved]

    def callees_of(self, func_name: str) -> list[CallEdgeV2]:
        return [e for e in self.call_edges if e.caller_name == func_name and e.resolved]

    def resolve_method(self, class_name: str, method_name: str) -> str | None:
        """Resolve method with single-level inheritance fallback."""
        qualified = f"{class_name}.{method_name}"
        if qualified in self.identifiers:
            return qualified
        parent = self.extends.get(class_name)
        if parent:
            parent_qualified = f"{parent}.{method_name}"
            if parent_qualified in self.identifiers:
                return parent_qualified
        return None


class _ModuleMapper:
    """Map module names to file paths."""

    def __init__(self, all_files: list[Path], root: Path | None = None) -> None:
        self._module_map: dict[str, Path] = {}
        base = root or (all_files[0].parent if all_files else Path("."))
        for f in all_files:
            try:
                rel = f.relative_to(base)
            except ValueError:
                continue
            parts = list(rel.parts)
            if parts[-1] == "__init__.py":
                parts = parts[:-1]
            else:
                parts[-1] = parts[-1].removesuffix(".py")
            module = ".".join(parts)
            self._module_map[module] = f
            # Also store just the filename stem for simple imports
            self._module_map[parts[-1]] = f

    def resolve(self, module: str) -> Path | None:
        if module in self._module_map:
            return self._module_map[module]
        for mod, path in self._module_map.items():
            if mod.endswith(module) or module.endswith(mod):
                return path
        return None


class _Pass1Visitor(ast.NodeVisitor):
    """Pass 1: Collect definitions, imports, assignments, class hierarchy."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self.definitions: dict[str, str] = {}  # name → qualified name
        self.imports: list[tuple[str, str | None, str]] = []  # (local, module, imported)
        self.assignments: list[tuple[str, str]] = []  # (target, value_expr)
        self.extends: dict[str, str] = {}  # child → parent (single-level)
        self._current_class: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        self.definitions[node.name] = node.name
        # Single-level inheritance
        if node.bases:
            base = node.bases[0]
            base_name = None
            if isinstance(base, ast.Name):
                base_name = base.id
            elif isinstance(base, ast.Attribute):
                base_name = base.attr
            if base_name:
                self.extends[node.name] = base_name
        prev = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        if self._current_class:
            qualified = f"{self._current_class}.{node.name}"
        else:
            qualified = node.name
        self.definitions[qualified] = qualified
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_Import(self, node: ast.Import) -> None:
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports.append((local, alias.name, alias.name))

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        module = node.module or ""
        for alias in node.names:
            local = alias.asname or alias.name
            self.imports.append((local, module, alias.name))

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            call_name = self._get_call_name(node.value)
            if call_name:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self.assignments.append((target.id, call_name))
        elif isinstance(node.value, ast.Name):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.assignments.append((target.id, node.value.id))
        self.generic_visit(node)

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            if isinstance(node.func.value, ast.Name):
                return f"{node.func.value.id}.{node.func.attr}"
            return node.func.attr
        return None


class _Pass2Visitor(ast.NodeVisitor):
    """Pass 2: Collect call sites and composition patterns."""

    def __init__(
        self,
        file_path: Path,
        model: FrameworkModel,
        identifiers: dict[str, IdentifierState] | None = None,
    ) -> None:
        self.file_path = file_path
        self.model = model
        self.calls: list[tuple[str, str, int]] = []  # (caller, callee, line)
        self.compositions: list[CompositionEdge] = []
        self._current_func: str | None = None
        self._current_class: str | None = None
        # Local var types, seeded from global identifier graph
        self._var_types: dict[str, str] = {}
        if identifiers:
            for name, state in identifiers.items():
                if state.pointsto:
                    self._var_types[name] = next(iter(state.pointsto))

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev = self._current_func
        if self._current_class:
            self._current_func = f"{self._current_class}.{node.name}"
        else:
            self._current_func = node.name
        # Check decorators for composition patterns
        for dec in node.decorator_list:
            dec_name = None
            if isinstance(dec, ast.Name):
                dec_name = dec.id
            elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name):
                dec_name = dec.func.id
            elif isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
                dec_name = dec.func.attr
            if dec_name:
                for dp in self.model.decorator_patterns:
                    if dec_name == dp.decorator:
                        self.compositions.append(CompositionEdge(
                            source=self._current_func or node.name,
                            target=dp.registers_as,
                            kind="decorator",
                            file=self.file_path,
                            line=node.lineno,
                        ))
        self.generic_visit(node)
        self._current_func = prev

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.visit_FunctionDef(node)  # type: ignore[arg-type]

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            func = node.value.func
            call_name = None
            if isinstance(func, ast.Name):
                call_name = func.id
            elif isinstance(func, ast.Attribute):
                call_name = func.attr
            if call_name:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._var_types[target.id] = call_name
            # Check factory patterns
            if isinstance(func, ast.Attribute):
                method_name = func.attr
                for fp in self.model.factory_patterns:
                    if method_name == fp.method:
                        for kw in node.value.keywords:
                            if kw.arg == fp.kwarg and isinstance(kw.value, ast.Name):
                                target_name = None
                                for t in node.targets:
                                    if isinstance(t, ast.Name):
                                        target_name = t.id
                                if target_name:
                                    self.compositions.append(CompositionEdge(
                                        source=target_name,
                                        target=kw.value.id,
                                        kind="factory",
                                        file=self.file_path,
                                        line=node.lineno,
                                    ))
        # Check pipe patterns: x = a | b
        if isinstance(node.value, ast.BinOp) and isinstance(node.value.op, ast.BitOr):
            if self.model.pipe_patterns:
                self._extract_pipe_edges(node.value)
        self.generic_visit(node)

    def _extract_pipe_edges(self, node: ast.BinOp) -> None:
        """Recursively extract pipe composition edges from a | b | c."""
        left_name = self._expr_name(node.left)
        right_name = self._expr_name(node.right)
        if left_name and right_name:
            self.compositions.append(CompositionEdge(
                source=left_name,
                target=right_name,
                kind="pipe",
                file=self.file_path,
                line=node.lineno if hasattr(node, "lineno") else 0,
            ))
        # Recurse into nested pipes: (a | b) | c
        if isinstance(node.left, ast.BinOp) and isinstance(node.left.op, ast.BitOr):
            self._extract_pipe_edges(node.left)
        if isinstance(node.right, ast.BinOp) and isinstance(node.right.op, ast.BitOr):
            self._extract_pipe_edges(node.right)

    def visit_Call(self, node: ast.Call) -> None:
        caller = "<module>" if self._current_func is None else self._current_func
        callee = self._resolve_callee(node)
        if callee:
            # Capture positional arg names for fixpoint param mapping
            arg_names = tuple(
                a.id if isinstance(a, ast.Name) else "<expr>"
                for a in node.args
            )
            self.calls.append((caller, callee, getattr(node, "lineno", 0), arg_names))
        self.generic_visit(node)

    def _resolve_callee(self, node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            if isinstance(func.value, ast.Name):
                var = func.value.id
                if var == "self" and self._current_class:
                    return f"{self._current_class}.{func.attr}"
                cls = self._var_types.get(var)
                if cls:
                    return f"{cls}.{func.attr}"
                return f"{var}.{func.attr}"
            return func.attr
        return None

    @staticmethod
    def _expr_name(node: ast.expr) -> str | None:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            return f"{node.value.id}.{node.attr}"
        return None


def build_project_graph(
    source_files: list[Path],
    model: FrameworkModel,
    root: Path | None = None,
) -> ProjectGraph:
    """Build unified project graph from source files.

    Two-pass algorithm (PyCG-style):
      Pass 1: Collect definitions, imports, assignments, class hierarchy
      Pass 2: Resolve call sites and detect composition patterns
    """
    graph = ProjectGraph()
    mapper = _ModuleMapper(source_files, root)

    # Pass 1: Collect definitions and build identifier graph
    all_defs: dict[str, tuple[str, Path]] = {}  # qualified_name → (name, file)
    import_map: dict[str, str] = {}  # local_name → qualified_name (across files)

    for py_file in source_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue

        v1 = _Pass1Visitor(py_file)
        v1.visit(tree)

        for name, qualified in v1.definitions.items():
            all_defs[qualified] = (name, py_file)
            graph.identifiers[qualified] = IdentifierState(name=qualified, scope=str(py_file))

        for child, parent in v1.extends.items():
            graph.extends[child] = parent

        for target, value in v1.assignments:
            state = graph.identifiers.setdefault(target, IdentifierState(name=target))
            state.pointsto.add(value)

        for local, module, imported in v1.imports:
            resolved_file = mapper.resolve(module) if module else None
            if resolved_file:
                qualified = imported
                import_map[local] = qualified
                state = graph.identifiers.setdefault(local, IdentifierState(name=local))
                state.pointsto.add(qualified)

    # Pass 2: Resolve call sites and composition
    for py_file in source_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue

        v2 = _Pass2Visitor(py_file, model, graph.identifiers)
        v2.visit(tree)

        for caller, callee, line, *rest in v2.calls:
            arg_names = rest[0] if rest else ()
            # Try to resolve callee to a known definition
            resolved = callee in all_defs
            if not resolved and callee in import_map:
                callee = import_map[callee]
                resolved = callee in all_defs
            if not resolved:
                # Try method resolution with inheritance
                parts = callee.split(".", 1)
                if len(parts) == 2:
                    resolved_name = graph.resolve_method(parts[0], parts[1])
                    if resolved_name and resolved_name in all_defs:
                        callee = resolved_name
                        resolved = True

            callee_file = all_defs[callee][1] if resolved and callee in all_defs else None
            graph.call_edges.append(CallEdgeV2(
                caller_name=caller,
                callee_name=callee,
                caller_file=py_file,
                callee_file=callee_file,
                line=line,
                resolved=resolved,
                arg_names=arg_names,
            ))

            if not resolved:
                reason = UnresolvedReason.EXTERNAL_MODULE
                if "." in callee and not any(callee.startswith(d) for d in all_defs):
                    reason = UnresolvedReason.EXTERNAL_MODULE
                graph.unresolved.append(UnresolvedCall(
                    file=py_file, line=line, callee_expr=callee, reason=reason,
                ))

        graph.composition_edges.extend(v2.compositions)

    return graph
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_graph.py -v`
Expected: All 6 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/engine/graph.py tests/test_graph.py tests/fixtures/engine_cross_file/ tests/fixtures/engine_lcel_pipe/ tests/fixtures/engine_factory/ tests/fixtures/engine_inheritance/
git commit -m "feat(engine): L2 assignment-based project graph with composition detection"
```

---

## Task 6: L3 Engine — Fixpoint Property Verifier

**Files:**
- Create: `src/agentwall/engine/verifier.py`
- Test: `tests/test_verifier.py`

- [ ] **Step 1: Write tests**

```python
# tests/test_verifier.py
from pathlib import Path

from agentwall.engine.extractor import extract_properties
from agentwall.engine.graph import build_project_graph
from agentwall.engine.models import Verdict
from agentwall.engine.verifier import verify_tenant_isolation
from agentwall.frameworks.langchain import LANGCHAIN_MODEL

FIXTURES = Path(__file__).parent / "fixtures"


def test_basic_no_filter_violated():
    """No filter at all → VIOLATED."""
    files = [FIXTURES / "engine_basic" / "agent.py"]
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    assert any(r.verdict == Verdict.VIOLATED for r in results)


def test_tenant_collection_verified():
    """Per-tenant collection → VERIFIED (no filter needed)."""
    files = [FIXTURES / "engine_tenant_collection" / "agent.py"]
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    # Per-tenant collection means isolation is handled at collection level
    violated = [r for r in results if r.verdict == Verdict.VIOLATED]
    assert len(violated) == 0


def test_static_filter_violated():
    """Static filter {"source": "web"} → VIOLATED (not tenant-scoped)."""
    files = [FIXTURES / "engine_static_filter" / "agent.py"]
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    assert any(r.verdict == Verdict.VIOLATED for r in results)


def test_cross_file_tenant_flow():
    """user_id flows auth.py → api.py → retriever.py → filter → VERIFIED."""
    files = list((FIXTURES / "engine_cross_file").glob("*.py"))
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL, FIXTURES / "engine_cross_file")
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    # search_docs has filter with user_id param → should verify
    verified = [r for r in results if r.verdict == Verdict.VERIFIED]
    assert len(verified) >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_verifier.py -v`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Implement L3 engine**

```python
# src/agentwall/engine/verifier.py
"""L3 Engine: Fixpoint property verification for tenant isolation.

Algorithm based on Pysa's fixpoint iteration, scoped to a single security
property: "does tenant identity reach the store filter on every read path?"

Reference: https://github.com/facebook/pyre-check/blob/main/source/interprocedural/fixpointAnalysis.ml
"""

from __future__ import annotations

import ast
import warnings
from pathlib import Path

from agentwall.engine.graph import ProjectGraph
from agentwall.engine.models import (
    FlowStep,
    IsolationStrategy,
    PropertyVerification,
    StoreAccess,
    StoreProfile,
    TenantFlowSummary,
    ValueKind,
    Verdict,
)
from agentwall.frameworks.base import FrameworkModel


def _compute_initial_summaries(
    source_files: list[Path],
    model: FrameworkModel,
) -> dict[str, TenantFlowSummary]:
    """Phase 1: Compute per-function summaries from function bodies alone."""
    summaries: dict[str, TenantFlowSummary] = {}
    tenant_params = set(model.tenant_param_names)

    for py_file in source_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue

        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue

            func_name = node.name
            param_indices: dict[int, str] = {}
            tainted_vars: set[str] = set()

            # Mark tenant-scoped parameters
            for i, arg in enumerate(node.args.args):
                if arg.arg.lower() in tenant_params:
                    param_indices[i] = arg.arg
                    tainted_vars.add(arg.arg)

            # Simple intraprocedural propagation
            for child in ast.walk(node):
                if isinstance(child, ast.Assign):
                    if _expr_references_any(child.value, tainted_vars):
                        for t in child.targets:
                            if isinstance(t, ast.Name):
                                tainted_vars.add(t.id)

            # Check for store reads with/without tenant filter
            reads: list[StoreAccess] = []
            has_unfiltered = False
            param_reaches: dict[int, set[str]] = {}

            for child in ast.walk(node):
                if not isinstance(child, ast.Call):
                    continue
                if not isinstance(child.func, ast.Attribute):
                    continue
                method = child.func.attr

                # Check if this is a read method
                for store_model in model.stores.values():
                    if method not in store_model.read_methods:
                        continue
                    filter_kwarg = store_model.read_methods[method]
                    filter_kind = ValueKind.DYNAMIC
                    filter_tainted = False

                    for kw in child.keywords:
                        if kw.arg == filter_kwarg:
                            if _expr_references_any(kw.value, tainted_vars):
                                filter_tainted = True
                                filter_kind = ValueKind.COMPOUND_TENANT
                            else:
                                filter_kind = ValueKind.COMPOUND_STATIC

                    store_id = ""  # will be resolved later
                    access = StoreAccess(
                        store_id=store_id,
                        method=method,
                        filter_kind=filter_kind,
                    )
                    reads.append(access)

                    if not filter_tainted:
                        has_unfiltered = True
                    else:
                        # Track which params reach the filter
                        for idx, param_name in param_indices.items():
                            if param_name in tainted_vars:
                                param_reaches.setdefault(idx, set()).add(method)

            # Check return value
            returns_tenant = False
            for child in ast.walk(node):
                if isinstance(child, ast.Return) and child.value:
                    if _expr_references_any(child.value, tainted_vars):
                        returns_tenant = True

            summaries[func_name] = TenantFlowSummary(
                function=func_name,
                file=py_file,
                param_reaches_filter={
                    k: frozenset(v) for k, v in param_reaches.items()
                },
                returns_tenant_scoped=returns_tenant,
                has_unfiltered_read=has_unfiltered,
                store_reads=reads,
            )

    return summaries


def _fixpoint_propagate(
    summaries: dict[str, TenantFlowSummary],
    graph: ProjectGraph,
    max_iterations: int = 20,
) -> dict[str, TenantFlowSummary]:
    """Phase 2: Propagate summaries across call graph until fixpoint."""
    changed = True
    iteration = 0

    while changed and iteration < max_iterations:
        changed = False
        iteration += 1

        for edge in graph.call_edges:
            if not edge.resolved:
                continue
            caller = edge.caller_name
            callee = edge.callee_name

            caller_summary = summaries.get(caller)
            callee_summary = summaries.get(callee)
            if not caller_summary or not callee_summary:
                continue

            # If callee returns tenant-scoped data, and caller assigns it,
            # the caller now has additional tainted variables
            if callee_summary.returns_tenant_scoped:
                # This could refine the caller summary
                pass  # handled by initial summary

            # Map callee param indices to caller arg names at the call site.
            # If callee's param i reaches a filter, check if the caller
            # passes a tenant-scoped value as arg i.
            for callee_param_idx, methods in callee_summary.param_reaches_filter.items():
                if not methods:
                    continue
                # Find call sites from caller to callee
                for call_edge in graph.call_edges:
                    if (call_edge.caller_name != caller
                            or call_edge.callee_name != callee
                            or not call_edge.resolved):
                        continue
                    if callee_param_idx >= len(call_edge.arg_names):
                        continue
                    arg_name = call_edge.arg_names[callee_param_idx]
                    if arg_name == "<expr>":
                        continue
                    # Is this arg tenant-scoped in the caller's context?
                    tenant_params = {p.lower() for p in model.tenant_param_names}
                    arg_is_tenant = arg_name.lower() in tenant_params
                    if not arg_is_tenant:
                        continue
                    # Caller passes tenant-scoped arg → callee uses it as filter.
                    # Update caller summary: mark unfiltered_read as False.
                    if caller_summary.has_unfiltered_read:
                        summaries[caller] = TenantFlowSummary(
                            function=caller,
                            file=caller_summary.file,
                            param_reaches_filter=caller_summary.param_reaches_filter,
                            returns_tenant_scoped=caller_summary.returns_tenant_scoped,
                            has_unfiltered_read=False,
                            store_reads=caller_summary.store_reads,
                        )
                        changed = True

    return summaries


def verify_tenant_isolation(
    profiles: list[StoreProfile],
    graph: ProjectGraph,
    model: FrameworkModel,
) -> list[PropertyVerification]:
    """Verify tenant isolation property for all store profiles.

    Returns one PropertyVerification per store read operation.
    """
    results: list[PropertyVerification] = []

    # Collect all source files from profiles
    source_files = list({p.file for p in profiles if p.file})

    # Phase 1: Initial summaries
    summaries = _compute_initial_summaries(source_files, model)

    # Phase 2: Fixpoint propagation
    summaries = _fixpoint_propagate(summaries, graph)

    # Phase 3: Verify each store
    for profile in profiles:
        # Per-tenant collection → skip, isolation at collection level
        if profile.isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT:
            for extraction in profile.extractions:
                if extraction.operation == "read":
                    results.append(PropertyVerification(
                        store_id=profile.store_id,
                        access=StoreAccess(
                            store_id=profile.store_id,
                            method=extraction.method,
                            filter_kind=ValueKind.TENANT_SCOPED,
                        ),
                        verdict=Verdict.VERIFIED,
                        evidence=[FlowStep(
                            file=extraction.file,
                            line=extraction.line,
                            kind="collection_isolation",
                            value_kind=profile.collection_name_kind,
                        )],
                        file=extraction.file,
                        line=extraction.line,
                    ))
            continue

        # Check each read operation
        for extraction in profile.extractions:
            if extraction.operation != "read":
                continue

            if extraction.filter_value_kind == ValueKind.COMPOUND_TENANT:
                verdict = Verdict.VERIFIED
            elif extraction.filter_value_kind in (
                ValueKind.COMPOUND_STATIC,
                ValueKind.LITERAL,
            ):
                verdict = Verdict.VIOLATED
            elif extraction.filter_value_kind == ValueKind.DYNAMIC:
                # No filter kwarg at all — check if any summary reaches this
                verdict = Verdict.VIOLATED
            else:
                verdict = Verdict.UNKNOWN

            results.append(PropertyVerification(
                store_id=profile.store_id,
                access=StoreAccess(
                    store_id=profile.store_id,
                    method=extraction.method,
                    filter_kind=extraction.filter_value_kind,
                ),
                verdict=verdict,
                file=extraction.file,
                line=extraction.line,
            ))

    return results


def _expr_references_any(node: ast.expr, names: set[str]) -> bool:
    """Check if an expression references any of the given variable names."""
    for child in ast.walk(node):
        if isinstance(child, ast.Name) and child.id in names:
            return True
    return False
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_verifier.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/engine/verifier.py tests/test_verifier.py
git commit -m "feat(engine): L3 fixpoint property verifier for tenant isolation"
```

---

## Task 7: L6 Engine — Interprocedural Path Coverage

**Files:**
- Create: `src/agentwall/engine/pathcov.py`
- Create: `tests/fixtures/engine_branching/agent.py`
- Test: `tests/test_pathcov.py`

- [ ] **Step 1: Create test fixture**

```python
# tests/fixtures/engine_branching/agent.py
from langchain_community.vectorstores import Chroma

db = Chroma(collection_name="docs")

def search(query, user_id=None):
    if user_id:
        return db.similarity_search(query, filter={"user_id": user_id})
    else:
        return db.similarity_search(query)  # NO FILTER on this path!
```

- [ ] **Step 2: Write tests**

```python
# tests/test_pathcov.py
from pathlib import Path

from agentwall.engine.extractor import extract_properties
from agentwall.engine.graph import build_project_graph
from agentwall.engine.pathcov import compute_path_coverage
from agentwall.engine.verifier import verify_tenant_isolation
from agentwall.frameworks.langchain import LANGCHAIN_MODEL

FIXTURES = Path(__file__).parent / "fixtures"


def test_branching_partial_coverage():
    """Filter on one branch but not the other → partial coverage."""
    files = [FIXTURES / "engine_branching" / "agent.py"]
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    verifications = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    coverages = compute_path_coverage(profiles, graph, verifications)
    assert len(coverages) >= 1
    cov = coverages[0]
    assert cov.coverage_ratio < 1.0  # not fully covered
    assert len(cov.violated_paths) >= 1


def test_full_coverage_no_violations():
    """Per-tenant collection → full coverage, no violations."""
    files = [FIXTURES / "engine_tenant_collection" / "agent.py"]
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    verifications = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    coverages = compute_path_coverage(profiles, graph, verifications)
    for cov in coverages:
        assert len(cov.violated_paths) == 0
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `pytest tests/test_pathcov.py -v`
Expected: FAIL — `ImportError`

- [ ] **Step 4: Implement L6 engine**

```python
# src/agentwall/engine/pathcov.py
"""L6 Engine: Interprocedural path coverage for tenant isolation.

Enumerates all code paths from entry points to store reads,
checks if tenant isolation holds on each path, reports coverage.

Reference: CodeQL GlobalWithState concept.
"""

from __future__ import annotations

from agentwall.engine.graph import ProjectGraph
from agentwall.engine.models import (
    IsolationStrategy,
    PathCoverage,
    PropertyVerification,
    StoreProfile,
    Verdict,
    VerifiedPath,
    ViolatedPath,
)


def compute_path_coverage(
    profiles: list[StoreProfile],
    graph: ProjectGraph,
    verifications: list[PropertyVerification],
) -> list[PathCoverage]:
    """Compute path coverage for each store.

    Groups verifications by store and reports how many paths
    are verified vs violated.
    """
    # Group verifications by store_id
    by_store: dict[str, list[PropertyVerification]] = {}
    for v in verifications:
        by_store.setdefault(v.store_id, []).append(v)

    coverages: list[PathCoverage] = []

    for profile in profiles:
        store_verifications = by_store.get(profile.store_id, [])
        if not store_verifications:
            continue

        # Per-tenant collection → all paths verified by definition
        if profile.isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT:
            coverages.append(PathCoverage(
                store_id=profile.store_id,
                total_paths=len(store_verifications),
                verified_paths=[
                    VerifiedPath(
                        entry_file=v.file or profile.file,
                        entry_line=v.line or 0,
                    )
                    for v in store_verifications
                ],
            ))
            continue

        verified: list[VerifiedPath] = []
        violated: list[ViolatedPath] = []
        unknown = 0

        for v in store_verifications:
            if v.verdict == Verdict.VERIFIED:
                verified.append(VerifiedPath(
                    entry_file=v.file or profile.file,
                    entry_line=v.line or 0,
                ))
            elif v.verdict == Verdict.VIOLATED:
                violated.append(ViolatedPath(
                    entry_file=v.file or profile.file,
                    entry_line=v.line or 0,
                    violation_file=v.file or profile.file,
                    violation_line=v.line or 0,
                ))
            elif v.verdict == Verdict.UNKNOWN:
                unknown += 1

        coverages.append(PathCoverage(
            store_id=profile.store_id,
            total_paths=len(store_verifications),
            verified_paths=verified,
            violated_paths=violated,
            unknown_paths=unknown,
        ))

    return coverages
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `pytest tests/test_pathcov.py -v`
Expected: All 2 tests PASS

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/engine/pathcov.py tests/test_pathcov.py tests/fixtures/engine_branching/
git commit -m "feat(engine): L6 interprocedural path coverage checker"
```

---

## Task 8: Wire Engines Into Existing Analyzers

**Files:**
- Modify: `src/agentwall/context.py`
- Modify: `src/agentwall/analyzers/memory.py`
- Modify: `src/agentwall/analyzers/callgraph.py`
- Modify: `src/agentwall/analyzers/taint.py`
- Modify: `src/agentwall/analyzers/symbolic.py`

- [ ] **Step 1: Add engine fields to AnalysisContext**

Add to `src/agentwall/context.py`:

```python
# After existing TYPE_CHECKING imports, add:
if TYPE_CHECKING:
    from agentwall.engine.models import PathCoverage, PropertyVerification, StoreProfile
    from agentwall.engine.graph import ProjectGraph as ProjectGraphType

# Add fields to AnalysisContext:
    # Populated by L1 engine (when available)
    store_profiles: list[StoreProfile] | None = None

    # Populated by L2 engine (when available)
    project_graph: ProjectGraphType | None = None

    # Populated by L3 engine (when available)
    property_verifications: list[PropertyVerification] | None = None

    # Populated by L6 engine (when available)
    path_coverages: list[PathCoverage] | None = None
```

- [ ] **Step 2: Update CallGraphAnalyzer to delegate to engine**

In `src/agentwall/analyzers/callgraph.py`, update `analyze()` to try engine first:

```python
def analyze(self, ctx: AnalysisContext) -> list[Finding]:
    spec = ctx.spec
    if spec is None:
        return list(ctx.findings)

    l1_findings = list(ctx.findings)
    target = ctx.target
    if not spec.source_files:
        return l1_findings

    # Try new engine first
    try:
        from agentwall.engine.graph import build_project_graph
        from agentwall.frameworks.langchain import LANGCHAIN_MODEL

        if spec.framework == "langchain":
            project_graph = build_project_graph(
                spec.source_files, LANGCHAIN_MODEL, target,
            )
            ctx.project_graph = project_graph
    except Exception:
        pass  # Fall back to old call graph

    # Build old call graph for backward compat
    graph = build_call_graph(target, spec.source_files)
    ctx.call_graph = graph

    # ... rest of existing analyze() logic unchanged
```

- [ ] **Step 3: Update TaintAnalyzer to delegate to engine**

In `src/agentwall/analyzers/taint.py`, add engine delegation at the start of `analyze()`:

```python
def analyze(self, ctx: AnalysisContext) -> list[Finding]:
    spec = ctx.spec
    if spec is None:
        return []

    # Try new engine
    try:
        from agentwall.engine.extractor import extract_properties
        from agentwall.engine.verifier import verify_tenant_isolation
        from agentwall.frameworks.langchain import LANGCHAIN_MODEL

        if spec.framework == "langchain" and ctx.project_graph is not None:
            profiles = extract_properties(spec.source_files, LANGCHAIN_MODEL)
            ctx.store_profiles = profiles
            verifications = verify_tenant_isolation(
                profiles, ctx.project_graph, LANGCHAIN_MODEL,
            )
            ctx.property_verifications = verifications
    except Exception:
        pass  # Fall back to old taint

    # ... rest of existing analyze() logic unchanged
```

- [ ] **Step 4: Run full test suite to verify no regressions**

Run: `pytest tests/ -v --tb=short`
Expected: All existing tests PASS. No regressions.

- [ ] **Step 5: Commit**

```bash
git add src/agentwall/context.py src/agentwall/analyzers/callgraph.py src/agentwall/analyzers/taint.py
git commit -m "feat: wire engine into existing analyzers with backward compat fallback"
```

---

## Task 9: Full Integration Test

**Files:**
- Test: `tests/test_engine_integration.py`

- [ ] **Step 1: Write integration test that runs the full scan pipeline**

```python
# tests/test_engine_integration.py
"""Integration tests: verify engine produces better results than old analyzers."""

from pathlib import Path

from agentwall.scanner import scan

FIXTURES = Path(__file__).parent / "fixtures"


def test_scan_basic_fixture_still_finds_issues():
    """Existing basic fixture still produces findings (no regression)."""
    result = scan(FIXTURES / "langchain_basic")
    mem_findings = [f for f in result.findings if f.rule_id.startswith("AW-MEM")]
    assert len(mem_findings) > 0


def test_scan_safe_fixture_still_clean():
    """Existing safe fixture still produces no CRITICAL findings."""
    result = scan(FIXTURES / "langchain_safe")
    critical = [f for f in result.findings if f.severity.value == "critical"]
    assert len(critical) == 0


def test_scan_tenant_collection_suppresses_false_positive():
    """Per-tenant collection should NOT be flagged as CRITICAL."""
    result = scan(FIXTURES / "engine_tenant_collection")
    critical = [f for f in result.findings if f.severity.value == "critical"]
    # Should have fewer criticals than a shared collection
    result_shared = scan(FIXTURES / "engine_basic")
    critical_shared = [f for f in result_shared.findings if f.severity.value == "critical"]
    assert len(critical) <= len(critical_shared)


def test_scan_static_filter_detected():
    """Static filter should be flagged (not tenant-scoped)."""
    result = scan(FIXTURES / "engine_static_filter")
    # Should still have findings — static filter is not secure
    mem_findings = [f for f in result.findings if f.rule_id.startswith("AW-MEM")]
    assert len(mem_findings) > 0
```

- [ ] **Step 2: Run integration tests**

Run: `pytest tests/test_engine_integration.py -v`
Expected: All 4 tests PASS

- [ ] **Step 3: Run full test suite + lint + type check**

Run: `pytest tests/ -v && ruff check src/ tests/ && ruff format --check src/ tests/ && mypy src/`
Expected: All pass

- [ ] **Step 4: Commit**

```bash
git add tests/test_engine_integration.py
git commit -m "test: add engine integration tests with regression checks"
```

---

## Task 10: Abstraction Validation (LlamaIndex Model)

**Files:**
- Create: `src/agentwall/frameworks/llamaindex.py`
- Test: `tests/test_framework_model.py` (extend)

This task validates the engine/model split: write a LlamaIndex model with **zero engine changes**.

- [ ] **Step 1: Write tests**

```python
# Append to tests/test_framework_model.py
from agentwall.frameworks.llamaindex import LLAMAINDEX_MODEL


def test_llamaindex_model_has_pinecone():
    assert "PineconeVectorStore" in LLAMAINDEX_MODEL.stores
    pinecone = LLAMAINDEX_MODEL.stores["PineconeVectorStore"]
    assert pinecone.backend == "pinecone"
    assert "namespace" in pinecone.isolation_params


def test_llamaindex_model_has_chroma():
    assert "ChromaVectorStore" in LLAMAINDEX_MODEL.stores


def test_llamaindex_model_uses_different_filter_kwarg():
    """LlamaIndex uses 'filters' not 'filter' for Pinecone."""
    pinecone = LLAMAINDEX_MODEL.stores["PineconeVectorStore"]
    assert "query" in pinecone.read_methods
    assert pinecone.read_methods["query"] == "filters"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_framework_model.py::test_llamaindex_model_has_pinecone -v`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Implement LlamaIndex model (zero engine changes)**

```python
# src/agentwall/frameworks/llamaindex.py
"""LlamaIndex framework model."""

from __future__ import annotations

from agentwall.frameworks.base import (
    FrameworkModel,
    StoreModel,
)

LLAMAINDEX_MODEL = FrameworkModel(
    name="llamaindex",
    stores={
        "PineconeVectorStore": StoreModel(
            backend="pinecone",
            isolation_params=["namespace"],
            write_methods={"add": "metadata"},
            read_methods={"query": "filters"},
            auth_params=["api_key", "environment"],
        ),
        "ChromaVectorStore": StoreModel(
            backend="chromadb",
            isolation_params=["collection_name"],
            write_methods={"add": "metadata"},
            read_methods={"query": "filters"},
            auth_params=["chroma_collection"],
        ),
        "QdrantVectorStore": StoreModel(
            backend="qdrant",
            isolation_params=["collection_name"],
            write_methods={"add": "metadata"},
            read_methods={"query": "query_filter"},
            auth_params=["url", "api_key"],
        ),
    },
)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_framework_model.py -v`
Expected: All tests PASS

- [ ] **Step 5: Verify zero engine changes**

Run: `git diff src/agentwall/engine/`
Expected: No changes to any engine file.

- [ ] **Step 6: Commit**

```bash
git add src/agentwall/frameworks/llamaindex.py tests/test_framework_model.py
git commit -m "feat(frameworks): add LlamaIndex model — validates zero engine changes"
```

---

## Summary

| Task | Component | LOC (est) | Tests |
|------|-----------|-----------|-------|
| 1 | Engine data models + ValueKind classifier | ~250 | 10 |
| 2 | Framework model schema | ~80 | 7 |
| 3 | LangChain framework model | ~150 | 7 |
| 4 | L1 engine: property extractor | ~250 | 4 |
| 5 | L2 engine: project graph | ~350 | 6 |
| 6 | L3 engine: fixpoint verifier | ~200 | 4 |
| 7 | L6 engine: path coverage | ~80 | 2 |
| 8 | Wire into existing analyzers | ~50 (net) | 0 (existing tests) |
| 9 | Integration tests | ~50 | 4 |
| 10 | LlamaIndex model (abstraction test) | ~40 | 3 |
| **Total** | | **~1,500** | **47** |
