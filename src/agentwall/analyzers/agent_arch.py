"""L2-agent analyzer — detect agent architecture security issues."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import ConfidenceLevel, Finding, Severity
from agentwall.patterns import DESTRUCTIVE_KEYWORDS, SANITIZE_NAMES
from agentwall.rules import AW_AGT_001, AW_AGT_003, AW_AGT_004, RuleDef


class AgentArchAnalyzer:
    """Detect agent architecture security issues."""

    name: str = "L2-agent"
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
        has_sanitize = any(name in source for name in SANITIZE_NAMES)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = _get_call_name(node)

            # AW-AGT-001: AgentExecutor(tools=variable)
            if call_name == "AgentExecutor":
                self._check_tool_inheritance(ctx, node, path, findings)

            # AW-AGT-004: .add_texts() / .add_documents() / .save_context()
            # in same file that has .invoke() / .run() — without sanitization
            if (
                call_name in {"add_texts", "add_documents", "save_context"}
                and _file_has_llm_call(tree)
                and not has_sanitize
                and not ctx.should_suppress(AW_AGT_004.rule_id)
            ):
                sev = _resolve_severity(ctx, AW_AGT_004)
                findings.append(
                    Finding(
                        rule_id=AW_AGT_004.rule_id,
                        title=AW_AGT_004.title,
                        severity=sev,
                        category=AW_AGT_004.category,
                        description=AW_AGT_004.description,
                        file=path,
                        line=getattr(node, "lineno", None),
                        fix=AW_AGT_004.fix,
                        layer="L2",
                    )
                )

        # AW-AGT-003: mixed read+destructive tools without approval
        self._check_mixed_tools(ctx, tree, path, source, findings)

        return findings

    @staticmethod
    def _check_tool_inheritance(
        ctx: AnalysisContext,
        node: ast.Call,
        path: Path,
        findings: list[Finding],
    ) -> None:
        for kw in node.keywords:
            if (
                kw.arg == "tools"
                and isinstance(kw.value, ast.Name)
                and not ctx.should_suppress(AW_AGT_001.rule_id)
            ):
                sev = _resolve_severity(ctx, AW_AGT_001)
                findings.append(
                    Finding(
                        rule_id=AW_AGT_001.rule_id,
                        title=AW_AGT_001.title,
                        severity=sev,
                        category=AW_AGT_001.category,
                        description=(
                            f"AgentExecutor(tools={kw.value.id})"
                            f" -- full tool set inherited."
                            f" {AW_AGT_001.description}"
                        ),
                        file=path,
                        line=getattr(node, "lineno", None),
                        fix=AW_AGT_001.fix,
                        layer="L2",
                    )
                )

    @staticmethod
    def _check_mixed_tools(
        ctx: AnalysisContext,
        tree: ast.Module,
        path: Path,
        source: str,
        findings: list[Finding],
    ) -> None:
        tool_names = _get_tool_names(tree)
        has_read = any(
            not any(dk in name.lower() for dk in DESTRUCTIVE_KEYWORDS) for name in tool_names
        )
        has_destructive = any(
            any(dk in name.lower() for dk in DESTRUCTIVE_KEYWORDS) for name in tool_names
        )
        source_lower = source.lower()
        needs_flag = (
            has_read
            and has_destructive
            and len(tool_names) >= 2
            and "approval" not in source_lower
            and "confirm" not in source_lower
            and not ctx.should_suppress(AW_AGT_003.rule_id)
        )
        if not needs_flag:
            return
        sev = _resolve_severity(ctx, AW_AGT_003)
        findings.append(
            Finding(
                rule_id=AW_AGT_003.rule_id,
                title=AW_AGT_003.title,
                severity=sev,
                category=AW_AGT_003.category,
                description=AW_AGT_003.description,
                file=path,
                line=1,
                fix=AW_AGT_003.fix,
                layer="L2",
                confidence=ConfidenceLevel.MEDIUM,
            )
        )


def _resolve_severity(ctx: AnalysisContext, rule: RuleDef) -> Severity:
    return ctx.severity_override(rule.rule_id) or rule.severity


def _file_has_llm_call(tree: ast.Module) -> bool:
    """Check if file contains .invoke() or .run() calls."""
    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _get_call_name(node)
            if name in {"invoke", "run", "predict", "generate"}:
                return True
    return False


def _get_tool_names(tree: ast.Module) -> list[str]:
    """Get names of @tool decorated functions."""
    names: list[str] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            is_tool = (isinstance(dec, ast.Name) and dec.id == "tool") or (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Name)
                and dec.func.id == "tool"
            )
            if is_tool:
                names.append(node.name)
    return names


def _get_call_name(node: ast.Call) -> str | None:
    """Extract the simple name from a call node."""
    if isinstance(node.func, ast.Name):
        return node.func.id
    if isinstance(node.func, ast.Attribute):
        return node.func.attr
    return None
