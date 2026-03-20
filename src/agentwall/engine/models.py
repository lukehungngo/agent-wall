"""Data models for the engine layer.

These models are engine-internal. Analyzers consume them and convert
to Finding objects for output.
"""

from __future__ import annotations

import ast
import builtins
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


class SecurityProperty(str, Enum):
    """Security properties that can be verified across access paths."""

    TENANT_ISOLATION = "tenant_isolation"


class IsolationStrategy(str, Enum):
    """How tenant isolation is achieved for a store."""

    COLLECTION_PER_TENANT = "collection_per_tenant"
    FILTER_ON_READ = "filter_on_read"
    PARTIAL_FILTER = "partial_filter"
    NONE = "none"


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


def classify_value(node: ast.expr, tenant_names: set[str]) -> ValueKind:
    """Classify an AST expression by its security-relevant kind.

    Args:
        node: AST expression node to classify.
        tenant_names: Set of variable names known to carry tenant identity.

    Returns:
        LITERAL if node is a constant.
        TENANT_SCOPED if node is a Name whose id is in tenant_names,
            or an f-string that embeds a tenant-scoped variable.
        COMPOUND_TENANT if node is a dict with any tenant-scoped value.
        COMPOUND_STATIC if node is a dict with all literal values.
        COMPOUND_DYNAMIC if node is a dict with any dynamic (non-tenant) value.
        DYNAMIC for all other cases.
    """
    if isinstance(node, ast.Constant):
        return ValueKind.LITERAL

    if isinstance(node, ast.Name):
        if node.id in tenant_names:
            return ValueKind.TENANT_SCOPED
        return ValueKind.DYNAMIC

    if isinstance(node, ast.JoinedStr):
        for part in node.values:
            if (
                isinstance(part, ast.FormattedValue)
                and classify_value(part.value, tenant_names) == ValueKind.TENANT_SCOPED
            ):
                return ValueKind.TENANT_SCOPED
        return ValueKind.DYNAMIC

    if isinstance(node, ast.Dict):
        # Skip None values (** unpacking has value=None for the key slot)
        kinds = [classify_value(v, tenant_names) for v in node.values if v is not None]
        if any(k == ValueKind.TENANT_SCOPED for k in kinds):
            return ValueKind.COMPOUND_TENANT
        if kinds and all(k == ValueKind.LITERAL for k in kinds):
            return ValueKind.COMPOUND_STATIC
        return ValueKind.COMPOUND_DYNAMIC

    return ValueKind.DYNAMIC


@dataclass(frozen=True)
class PropertyExtraction:
    """A single extracted property from a framework call."""

    file: Path
    line: int
    store_id: str
    operation: Literal["read", "write", "init"]
    method: str

    has_filter: bool = False
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
        """Keys written to metadata that are never used as read filters."""
        return self.write_keys - self.read_filter_keys

    @property
    def has_tenant_key_on_both(self) -> bool:
        """True if a known tenant identity key appears in both writes and read filters."""
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
        """Determine how (or whether) this store isolates tenant data."""
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
        """Aggregate metadata keys written vs filter keys read across all extractions."""
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
    """Per-function summary of how tenant identity flows through it."""

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
    """A path where the security property does not hold."""

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
    reason: str
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

    @builtins.property
    def coverage_ratio(self) -> float:
        """Fraction of total_paths that are verified. Returns 0.0 if no paths."""
        if not self.total_paths:
            return 0.0
        return len(self.verified_paths) / self.total_paths


@dataclass(frozen=True)
class UnresolvedCall:
    """A call that could not be statically resolved."""

    file: Path
    line: int
    callee_expr: str
    reason: UnresolvedReason
