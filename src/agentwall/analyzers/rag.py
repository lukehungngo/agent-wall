"""L1-rag analyzer — detect RAG pipeline security issues."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import Finding
from agentwall.patterns import (
    RAG_DELIMITER_PATTERNS,
    RETRIEVAL_METHODS,
    UNTRUSTED_SOURCE_CALLS,
    VECTOR_STORE_AUTH_KWARGS,
    VECTOR_STORE_NETWORK_CLIENTS,
)
from agentwall.rules import AW_RAG_001, AW_RAG_002, AW_RAG_003, AW_RAG_004

_LOCAL_PERSIST_METHODS: frozenset[str] = frozenset({"save_local", "load_local"})


class RAGAnalyzer:
    """Detect RAG pipeline security issues."""

    name: str = "L1-rag"
    depends_on: Sequence[str] = ("L0-versions",)
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = False

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for source_file in ctx.source_files:
            try:
                source = source_file.read_text()
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue
            findings.extend(self._check_file(ctx, tree, source_file, source))
        return findings

    def _check_file(
        self,
        ctx: AnalysisContext,
        tree: ast.Module,
        path: Path,
        source: str,
    ) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_calls(ctx, tree, path))
        findings.extend(self._check_delimiters(ctx, tree, path, source))
        return findings

    # ------------------------------------------------------------------
    # Call-level checks: AW-RAG-003, AW-RAG-004, AW-RAG-002
    # ------------------------------------------------------------------

    def _check_calls(self, ctx: AnalysisContext, tree: ast.Module, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _get_call_name(node)

            # AW-RAG-003: local persistence (save_local, load_local)
            if call_name in _LOCAL_PERSIST_METHODS:
                finding = _make_finding(
                    ctx,
                    AW_RAG_003,
                    path,
                    node,
                    f"Call to {call_name}() — unencrypted local persistence. "
                    f"{AW_RAG_003.description}",
                )
                if finding:
                    findings.append(finding)

            # AW-RAG-003: persist_directory keyword
            for kw in node.keywords:
                if kw.arg == "persist_directory":
                    finding = _make_finding(
                        ctx,
                        AW_RAG_003,
                        path,
                        node,
                        f"persist_directory= kwarg — unencrypted local persistence. "
                        f"{AW_RAG_003.description}",
                    )
                    if finding:
                        findings.append(finding)

            # AW-RAG-004: network client without auth
            if call_name and call_name in VECTOR_STORE_NETWORK_CLIENTS:
                kwarg_names = {kw.arg for kw in node.keywords if kw.arg}
                if not kwarg_names & VECTOR_STORE_AUTH_KWARGS:
                    finding = _make_finding(
                        ctx,
                        AW_RAG_004,
                        path,
                        node,
                        f"{call_name}() called without auth kwargs. {AW_RAG_004.description}",
                    )
                    if finding:
                        findings.append(finding)

            # AW-RAG-002: ingestion from untrusted source
            if call_name in {"add_texts", "add_documents"} and _file_has_untrusted_source(tree):
                finding = _make_finding(
                    ctx,
                    AW_RAG_002,
                    path,
                    node,
                    AW_RAG_002.description,
                )
                if finding:
                    findings.append(finding)

        return findings

    # ------------------------------------------------------------------
    # File-level check: AW-RAG-001 (missing delimiters)
    # ------------------------------------------------------------------

    def _check_delimiters(
        self,
        ctx: AnalysisContext,
        tree: ast.Module,
        path: Path,
        source: str,
    ) -> list[Finding]:
        has_retrieval = any(m in source for m in RETRIEVAL_METHODS)
        if not has_retrieval:
            return []
        has_delimiter = any(d in source for d in RAG_DELIMITER_PATTERNS)
        if has_delimiter:
            return []

        # Look for f-string usage (JoinedStr nodes)
        for node in ast.walk(tree):
            if isinstance(node, ast.JoinedStr):
                finding = _make_finding(
                    ctx,
                    AW_RAG_001,
                    path,
                    node,
                    AW_RAG_001.description,
                )
                if finding:
                    return [finding]  # one per file
                break
        return []


# ── helpers ──────────────────────────────────────────────────────────────────


def _get_call_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None


def _get_qualified_name(node: ast.Call) -> str | None:
    if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
        return f"{node.func.value.id}.{node.func.attr}"
    return None


def _file_has_untrusted_source(tree: ast.Module) -> bool:
    """Return True if the file contains any call from UNTRUSTED_SOURCE_CALLS."""
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        qualified = _get_qualified_name(node)
        if qualified and qualified in UNTRUSTED_SOURCE_CALLS:
            return True
        name = _get_call_name(node)
        if name and name in UNTRUSTED_SOURCE_CALLS:
            return True
    return False


def _make_finding(
    ctx: AnalysisContext,
    rule: object,
    path: Path,
    node: ast.AST,
    description: str,
) -> Finding | None:
    """Create a Finding if the rule is not suppressed. Applies severity override."""
    from agentwall.rules import RuleDef

    assert isinstance(rule, RuleDef)
    if ctx.should_suppress(rule.rule_id):
        return None
    sev = ctx.severity_override(rule.rule_id) or rule.severity
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=sev,
        category=rule.category,
        description=description,
        file=path,
        line=getattr(node, "lineno", None),
        fix=rule.fix,
        layer="L1",
    )
