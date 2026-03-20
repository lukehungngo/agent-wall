"""Memory security analyzer — AW-MEM-001 through AW-MEM-005."""

from __future__ import annotations

from collections.abc import Sequence

from agentwall.context import AnalysisContext
from agentwall.models import ConfidenceLevel, Finding, MemoryConfig
from agentwall.rules import AW_MEM_001, AW_MEM_002, AW_MEM_003, AW_MEM_004, AW_MEM_005, RuleDef

# Memory class backends — these are LangChain conversation memory, not vector stores.
# They get MEM-004 (injection risk) but NOT MEM-005 (which targets vector store retrieval).
_MEMORY_CLASS_BACKENDS = frozenset(
    [
        "conversation_buffer",
        "conversation_buffer_window",
        "conversation_summary",
        "conversation_summary_buffer",
        "vectorstore_retriever",
        "conversation_entity",
        "conversation_kg",
    ]
)


def _finding_from_rule(
    rule: RuleDef,
    mc: MemoryConfig,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        fix=rule.fix,
        file=mc.source_file,
        line=mc.source_line,
        confidence=confidence,
    )


class MemoryAnalyzer:
    """Fire memory-related rules against an AgentSpec."""

    name: str = "L1-memory"
    depends_on: Sequence[str] = ()
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = False

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        spec = ctx.spec
        if spec is None:
            return []
        findings: list[Finding] = []
        for mc in spec.memory_configs:
            findings.extend(self._check(mc))
        return findings

    def _check(self, mc: MemoryConfig) -> list[Finding]:
        findings: list[Finding] = []

        is_memory_class = mc.backend in _MEMORY_CLASS_BACKENDS
        no_isolation = not mc.has_tenant_isolation
        no_filter = not mc.has_metadata_filter_on_retrieval
        no_write_meta = not mc.has_metadata_on_write

        # AW-MEM-001: no isolation AND no retrieval filter (vector stores only)
        # HIGH confidence — direct pattern match (no filter kwarg observed)
        if not is_memory_class and no_isolation and no_filter:
            findings.append(_finding_from_rule(AW_MEM_001, mc, ConfidenceLevel.HIGH))

        # AW-MEM-002: has write metadata BUT no retrieval filter (false sense of security)
        # HIGH confidence — concrete mismatch between write and read paths
        if not is_memory_class and mc.has_metadata_on_write and no_filter:
            findings.append(_finding_from_rule(AW_MEM_002, mc, ConfidenceLevel.HIGH))

        # AW-MEM-003: no access control at all (vector stores only)
        # MEDIUM confidence — inferred from missing config (wrapper may exist)
        if not is_memory_class and no_isolation and no_write_meta and no_filter:
            findings.append(_finding_from_rule(AW_MEM_003, mc, ConfidenceLevel.MEDIUM))

        # AW-MEM-004: known injection patterns (memory classes, unvalidated writes)
        # HIGH confidence — direct evidence of injection risk
        if mc.has_injection_risk:
            findings.append(_finding_from_rule(AW_MEM_004, mc, ConfidenceLevel.HIGH))

        # AW-MEM-005: no sanitization on retrieved memory before context injection
        # Only fires for vector stores (memory classes already get MEM-004).
        # Only fires when we have evidence of a retrieval path (not just store instantiation).
        # MEDIUM confidence — absence of sanitization is heuristic
        if not is_memory_class and not mc.sanitizes_retrieved_content:
            findings.append(_finding_from_rule(AW_MEM_005, mc, ConfidenceLevel.MEDIUM))

        return findings
