"""Memory security analyzer — AW-MEM-001 through AW-MEM-005."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.engine.isolation_evidence import (
    classify_isolation,
    collect_evidence,
    project_has_web_framework,
)
from agentwall.models import ConfidenceLevel, Finding, MemoryConfig
from agentwall.rules import AW_MEM_001, AW_MEM_002, AW_MEM_003, AW_MEM_004, AW_MEM_005, RuleDef

_VECTORSTORE_IMPORTS: dict[str, str] = {
    "chromadb": "chroma",
    "faiss": "faiss",
    "pinecone": "pinecone",
    "qdrant_client": "qdrant",
    "pymilvus": "milvus",
    "weaviate": "weaviate",
}

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
    framework_agnostic: bool = True

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        spec = ctx.spec
        if spec is None or not spec.memory_configs:
            # No adapter or adapter found no memory configs — use AST fallback
            return self._analyze_agnostic(ctx)
        engine_isolation = self._get_engine_isolation(ctx)
        # Compute web framework presence once for the entire scan.
        has_web_framework = project_has_web_framework(ctx)
        findings: list[Finding] = []
        for mc in spec.memory_configs:
            findings.extend(
                self._check(mc, ctx, engine_isolation, has_web_framework=has_web_framework)
            )
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
        self,
        mc: MemoryConfig,
        ctx: AnalysisContext,
        engine_isolation: dict[str, str] | None = None,
        *,
        has_web_framework: bool = False,
    ) -> list[Finding]:
        findings: list[Finding] = []

        is_memory_class = mc.backend in _MEMORY_CLASS_BACKENDS
        no_isolation = not mc.has_tenant_isolation
        no_filter = not mc.has_metadata_filter_on_retrieval
        no_write_meta = not mc.has_metadata_on_write

        # AW-MEM-001: no isolation AND no retrieval filter (vector stores only)
        # Severity is determined by evidence strength, not hardcoded.
        if not is_memory_class and no_isolation and no_filter:
            evidence = collect_evidence(
                mc, ctx, engine_isolation, has_web_framework=has_web_framework
            )
            severity, confidence, reason = classify_isolation(evidence)
            findings.append(
                Finding(
                    rule_id=AW_MEM_001.rule_id,
                    title=AW_MEM_001.title,
                    severity=severity,
                    category=AW_MEM_001.category,
                    description=f"{AW_MEM_001.description} [{reason}]",
                    fix=AW_MEM_001.fix,
                    file=mc.source_file,
                    line=mc.source_line,
                    confidence=confidence,
                )
            )

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

    def _analyze_agnostic(self, ctx: AnalysisContext) -> list[Finding]:
        """AST-based fallback when no framework adapter produced a spec."""
        configs = self._extract_memory_configs_from_ast(ctx.source_files)
        if not configs:
            return []
        engine_isolation = self._get_engine_isolation(ctx)
        has_web_framework = project_has_web_framework(ctx)
        findings: list[Finding] = []
        for mc in configs:
            findings.extend(
                self._check(mc, ctx, engine_isolation, has_web_framework=has_web_framework)
            )
        return findings

    @staticmethod
    def _extract_memory_configs_from_ast(source_files: Sequence[Path]) -> list[MemoryConfig]:
        """Walk source files for vectorstore import patterns and build synthetic configs."""
        seen: set[tuple[str, Path]] = set()
        configs: list[MemoryConfig] = []
        for path in source_files:
            try:
                source = path.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(path))
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue
            for node in ast.walk(tree):
                module: str | None = None
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        top = alias.name.split(".")[0]
                        if top in _VECTORSTORE_IMPORTS:
                            module = top
                            break
                elif isinstance(node, ast.ImportFrom) and node.module:
                    top = node.module.split(".")[0]
                    if top in _VECTORSTORE_IMPORTS:
                        module = top
                if module is None:
                    continue
                backend = _VECTORSTORE_IMPORTS[module]
                key = (backend, path)
                if key in seen:
                    continue
                seen.add(key)
                configs.append(
                    MemoryConfig(
                        backend=backend,
                        source_file=path,
                        source_line=getattr(node, "lineno", 1),
                    )
                )
        return configs

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
