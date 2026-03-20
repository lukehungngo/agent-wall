"""Memory security analyzer — AW-MEM-001 through AW-MEM-005."""

from __future__ import annotations

from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import ConfidenceLevel, Finding, MemoryConfig, Severity
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
        engine_isolation = self._get_engine_isolation(ctx)
        findings: list[Finding] = []
        for mc in spec.memory_configs:
            findings.extend(self._check(mc, engine_isolation))
        return findings

    @staticmethod
    def _get_engine_isolation(ctx: AnalysisContext) -> dict[str, str]:
        """Get isolation strategy per backend from engine store profiles."""
        result: dict[str, str] = {}
        profiles = getattr(ctx, "store_profiles", None)
        if not profiles:
            return result
        try:
            for profile in profiles:
                result[profile.backend] = profile.isolation_strategy.value
        except Exception:  # noqa: BLE001
            pass
        return result

    def _check(
        self, mc: MemoryConfig, engine_isolation: dict[str, str] | None = None
    ) -> list[Finding]:
        findings: list[Finding] = []

        is_memory_class = mc.backend in _MEMORY_CLASS_BACKENDS
        no_isolation = not mc.has_tenant_isolation
        no_filter = not mc.has_metadata_filter_on_retrieval
        no_write_meta = not mc.has_metadata_on_write

        # AW-MEM-001: no isolation AND no retrieval filter (vector stores only)
        # HIGH confidence — direct pattern match (no filter kwarg observed)
        if not is_memory_class and no_isolation and no_filter:
            iso = (engine_isolation or {}).get(mc.backend, "")
            if iso == "filter_on_read":
                pass  # suppressed — engine confirmed all reads carry tenant filter
            elif iso == "collection_per_tenant":
                f = _finding_from_rule(AW_MEM_001, mc, ConfidenceLevel.LOW)
                findings.append(
                    Finding(
                        rule_id=f.rule_id,
                        title=f.title,
                        severity=Severity.MEDIUM,
                        category=f.category,
                        description=f.description
                        + " (downgraded: engine detected per-tenant collection isolation)",
                        fix=f.fix,
                        file=f.file,
                        line=f.line,
                        confidence=ConfidenceLevel.LOW,
                    )
                )
            else:
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
        # Only fires when there's a confirmed retrieval path in the file.
        # Suppress for write-only stores and constructor-only files.
        if not is_memory_class and not mc.sanitizes_retrieved_content:
            has_retrieval = self._file_has_retrieval(mc.source_file)
            if has_retrieval:
                findings.append(_finding_from_rule(AW_MEM_005, mc, ConfidenceLevel.MEDIUM))

        return findings

    @staticmethod
    def _file_has_retrieval(source_file: Path | None) -> bool:
        """Check if a file contains any vector store retrieval method call."""
        if source_file is None:
            return True  # fail open — assume retrieval exists
        try:
            import ast as _ast

            from agentwall.patterns import RETRIEVAL_METHODS

            source = source_file.read_text(encoding="utf-8")
            tree = _ast.parse(source)
            for node in _ast.walk(tree):
                if isinstance(node, _ast.Attribute) and node.attr in RETRIEVAL_METHODS:
                    return True
            return False
        except Exception:  # noqa: BLE001
            return True  # fail open on parse errors
