"""Core data models."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    MEMORY = "memory"
    TOOL = "tool"


class ConfidenceLevel(str, Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


CONFIDENCE_RANK: dict[ConfidenceLevel, int] = {
    ConfidenceLevel.HIGH: 0,
    ConfidenceLevel.MEDIUM: 1,
    ConfidenceLevel.LOW: 2,
}


class ASMConfidence(str, Enum):
    """Confidence level for ASM nodes and edges."""

    CONFIRMED = "confirmed"
    INFERRED = "inferred"
    UNKNOWN = "unknown"


ASM_CONFIDENCE_RANK: dict[ASMConfidence, int] = {
    ASMConfidence.CONFIRMED: 0,
    ASMConfidence.INFERRED: 1,
    ASMConfidence.UNKNOWN: 2,
}


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    category: Category
    description: str
    file: Path | None = None
    line: int | None = None
    fix: str | None = None
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH
    layer: str | None = None  # which analysis layer produced this
    file_context: str | None = None  # e.g. "test file", "example"
    evidence_path: list[dict[str, object]] | None = None  # ASM path witness
    proof_strength: str | None = None  # "confirmed" | "possible" | "uncertain"


class ToolSpec(BaseModel):
    name: str
    description: str | None = None
    is_destructive: bool = False
    accepts_code_execution: bool = False
    has_approval_gate: bool = False
    has_user_scope_check: bool = False
    source_file: Path | None = None
    source_line: int | None = None


class MemoryConfig(BaseModel):
    backend: str  # "chroma", "pgvector", "pinecone", etc.
    has_tenant_isolation: bool = False
    has_metadata_filter_on_retrieval: bool = False
    has_metadata_on_write: bool = False
    sanitizes_retrieved_content: bool = False
    has_injection_risk: bool = False
    collection_name: str | None = None
    source_file: Path | None = None
    source_line: int | None = None


# ── ASM models (V4) ────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Provenance:
    """Source location for an ASM node."""

    file: Path
    line: int
    col: int
    symbol: str  # "ClassName.method" or "function_name"
    end_line: int | None = None  # end of enclosing scope (for trigger edge scoping)


@dataclass(frozen=True)
class EntryPoint:
    """An entry point into the application (route, job, CLI command)."""

    id: str
    kind: str  # "http_route", "background_job", "cli_command", "cron"
    provenance: Provenance
    auth: str  # "authenticated", "unauthenticated", "unknown"
    auth_mechanism: str | None
    user_id_source: str | None
    confidence: ASMConfidence


@dataclass(frozen=True)
class WriteOp:
    """A write operation to a vector store."""

    id: str
    provenance: Provenance
    store_id: str  # links to Store.id
    method: str  # "add_documents", "add_texts"
    metadata_keys: frozenset[str]  # keys written as metadata
    confidence: ASMConfidence


@dataclass(frozen=True)
class ReadOp:
    """A read/query operation on a vector store."""

    id: str
    provenance: Provenance
    store_id: str  # links to Store.id
    method: str  # "similarity_search", "as_retriever"
    filter_keys: frozenset[str]  # keys used in filter kwarg
    has_filter: bool
    confidence: ASMConfidence


@dataclass(frozen=True)
class Store:
    """A vector store instance."""

    id: str
    provenance: Provenance
    backend: str  # "chroma", "pgvector", "faiss"
    collection_name: str | None
    collection_name_is_static: bool
    confidence: ASMConfidence


@dataclass(frozen=True)
class ContextSink:
    """Where retrieved content flows (LLM prompt, API response, etc.)."""

    id: str
    provenance: Provenance
    kind: str  # "llm_context", "api_response", "tool_input"
    sanitized: bool
    confidence: ASMConfidence


@dataclass(frozen=True)
class Edge:
    """A directed relationship between two ASM nodes."""

    source_id: str
    target_id: str
    kind: str  # "triggers", "writes_to", "reads_from", "guarded_by", "assembles_into"
    confidence: ASMConfidence
    provenance: Provenance


@dataclass
class ApplicationModel:
    """Graph-based application security model."""

    entry_points: list[EntryPoint] = field(default_factory=list)
    write_ops: list[WriteOp] = field(default_factory=list)
    stores: list[Store] = field(default_factory=list)
    read_ops: list[ReadOp] = field(default_factory=list)
    sinks: list[ContextSink] = field(default_factory=list)
    edges: list[Edge] = field(default_factory=list)
    unresolved: list[Provenance] = field(default_factory=list)


class AgentSpec(BaseModel):
    model_config = {"arbitrary_types_allowed": True}

    framework: str
    source_files: list[Path] = Field(default_factory=list)
    tools: list[ToolSpec] = Field(default_factory=list)
    memory_configs: list[MemoryConfig] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)
    asm: ApplicationModel | None = None


class ScanResult(BaseModel):
    target: Path
    framework: str | None
    findings: list[Finding] = Field(default_factory=list)
    scanned_files: int = 0
    errors: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result


# ── Call Graph models (L2) ───────────────────────────────────────────────────


@dataclass(frozen=True)
class FunctionRef:
    """Reference to a function/method in a specific file."""

    file: Path
    name: str  # qualified: "ClassName.method" or "function_name"
    lineno: int = 0


@dataclass(frozen=True)
class CallEdge:
    """An edge in the inter-procedural call graph."""

    caller: FunctionRef
    callee: FunctionRef
    call_site_line: int = 0
    resolved: bool = True  # True if statically resolved


@dataclass
class CallGraph:
    """Inter-procedural call graph."""

    edges: list[CallEdge] = field(default_factory=list)
    unresolved: list[tuple[Path, int]] = field(default_factory=list)

    def callers_of(self, func_name: str) -> list[CallEdge]:
        return [e for e in self.edges if e.callee.name == func_name]

    def callees_of(self, func_name: str) -> list[CallEdge]:
        return [e for e in self.edges if e.caller.name == func_name]

    def reachable_from(self, func_name: str, visited: set[str] | None = None) -> set[str]:
        """Return all functions reachable from func_name (forward traversal)."""
        if visited is None:
            visited = set()
        if func_name in visited:
            return visited
        visited.add(func_name)
        for edge in self.callees_of(func_name):
            self.reachable_from(edge.callee.name, visited)
        return visited


# ── Taint models (L3) ───────────────────────────────────────────────────────


@dataclass(frozen=True)
class TaintSource:
    """A source of user identity data."""

    name: str  # e.g. "request.user", "user_id"
    file: Path
    lineno: int


@dataclass(frozen=True)
class TaintSink:
    """A sink where user identity should reach (filter kwarg)."""

    name: str  # e.g. "similarity_search.filter"
    file: Path
    lineno: int


@dataclass
class TaintResult:
    """Result of taint analysis for a single source-sink pair."""

    source: TaintSource
    sink: TaintSink
    reaches: bool  # True if source data reaches the sink
    path: list[str] = field(default_factory=list)  # variable chain


# ── Scan configuration ──────────────────────────────────────────────────────


@dataclass
class ScanConfig:
    """Configuration for which analysis layers to run."""

    layers: set[str] = field(default_factory=lambda: {"L0", "L1", "L2", "L3", "L4", "L5", "L6"})
    dynamic: bool = False  # L7 — runtime instrumentation
    llm_assist: bool = False  # L8 — LLM confidence scoring
    asm_shadow: bool = False  # ASM findings logged but not included in output
    shadow_layers: set[str] = field(default_factory=set)
    semgrep_rules_dir: Path | None = None  # custom semgrep rules
    target: Path = field(default_factory=lambda: Path("."))

    def __post_init__(self) -> None:
        if self.asm_shadow and "ASM" not in self.shadow_layers:
            self.shadow_layers = self.shadow_layers | {"ASM"}

    @classmethod
    def default(cls) -> ScanConfig:
        return cls()

    @classmethod
    def fast(cls) -> ScanConfig:
        """CI-friendly: L0-L2 only."""
        return cls(layers={"L0", "L1", "L2"})

    @classmethod
    def full(cls) -> ScanConfig:
        """Full audit: all static layers."""
        return cls(layers={"L0", "L1", "L2", "L3", "L4", "L5", "L6"})
