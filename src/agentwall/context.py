"""AnalysisContext — shared mutable state flowing through the analysis pipeline.

Each analyzer reads what it needs from ctx, may write intermediate results
for downstream analyzers, and returns findings. The depends_on metadata
on each analyzer declares which fields it expects to be populated.

WARNING: Analyzer ordering is load-bearing. The registry topologically sorts
by depends_on. Do not reorder or parallelize without verifying data dependencies.
"""

from __future__ import annotations

from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Protocol, runtime_checkable

from agentwall.models import Finding, ScanConfig

if TYPE_CHECKING:
    from agentwall.engine.graph import ProjectGraph
    from agentwall.engine.models import PathCoverage, PropertyVerification, StoreProfile
    from agentwall.models import AgentSpec, CallGraph, Severity, TaintResult, VersionModifier


@dataclass
class AnalysisContext:
    """Shared state that flows through the analysis pipeline."""

    target: Path
    config: ScanConfig

    # Populated by L0+L1 (adapter)
    spec: AgentSpec | None = None

    # Populated by L2 (call graph), consumed by L3 and L6
    call_graph: CallGraph | None = None

    # Populated by L3 (taint), consumed by L6
    taint_results: list[TaintResult] | None = None

    # Populated before analyzers run
    source_files: list[Path] = field(default_factory=list)

    # Populated by L0-versions analyzer
    version_modifiers: dict[str, VersionModifier] = field(default_factory=dict)

    # Populated by L1 engine
    store_profiles: list[StoreProfile] | None = None

    # Populated by L2 engine
    project_graph: ProjectGraph | None = None

    # Populated by L3 engine
    property_verifications: list[PropertyVerification] | None = None

    # Populated by L6 engine
    path_coverages: list[PathCoverage] | None = None

    # Accumulated findings from all layers
    findings: list[Finding] = field(default_factory=list)

    # Errors from failed layers (non-fatal)
    errors: list[str] = field(default_factory=list)

    def should_suppress(self, rule_id: str) -> bool:
        """Check if any version modifier suppresses this rule."""
        return any(rule_id in m.suppress for m in self.version_modifiers.values())

    def severity_override(self, rule_id: str) -> Severity | None:
        """Get severity override from version modifiers. Most-severe-wins."""
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


@runtime_checkable
class Analyzer(Protocol):
    """Protocol that all analyzers must satisfy.

    - name: layer identifier (e.g. "L1", "L2", "ASM")
    - depends_on: layers that must run before this one
    - analyze(ctx): read from ctx, optionally write to ctx, return findings
    """

    name: str
    depends_on: Sequence[str]
    replace: bool
    opt_in: bool
    framework_agnostic: bool

    def analyze(self, ctx: AnalysisContext) -> list[Finding]: ...
