"""L1-secrets analyzer — detect hardcoded secrets and context logging."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import Finding
from agentwall.patterns import CONTEXT_VAR_NAMES, SECRET_KWARG_NAMES, SECRET_PREFIXES
from agentwall.rules import AW_SEC_001, AW_SEC_003


class SecretsAnalyzer:
    """Detect hardcoded secrets and sensitive context logging."""

    name: str = "L1-secrets"
    depends_on: Sequence[str] = ("L0-versions",)
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = True

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for source_file in ctx.source_files:
            try:
                tree = ast.parse(source_file.read_text())
            except (SyntaxError, UnicodeDecodeError):
                continue
            findings.extend(self._check_file(ctx, tree, source_file))
        return findings

    def _check_file(self, ctx: AnalysisContext, tree: ast.Module, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            # Check string constants for secret prefixes
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for prefix in SECRET_PREFIXES:
                    if node.value.startswith(prefix) and len(node.value) > len(prefix) + 4:
                        if not ctx.should_suppress(AW_SEC_001.rule_id):
                            sev = ctx.severity_override(AW_SEC_001.rule_id) or AW_SEC_001.severity
                            findings.append(
                                Finding(
                                    rule_id=AW_SEC_001.rule_id,
                                    title=AW_SEC_001.title,
                                    severity=sev,
                                    category=AW_SEC_001.category,
                                    description=f"String with prefix {prefix!r} found. {AW_SEC_001.description}",
                                    file=path,
                                    line=getattr(node, "lineno", None),
                                    fix=AW_SEC_001.fix,
                                    layer="L1",
                                )
                            )
                        break  # one finding per string

            # Check keyword arguments (api_key="...", token="...", etc.)
            if (
                isinstance(node, ast.keyword)
                and node.arg in SECRET_KWARG_NAMES
                and isinstance(node.value, ast.Constant)
                and isinstance(node.value.value, str)
                and not ctx.should_suppress(AW_SEC_001.rule_id)
            ):
                sev = ctx.severity_override(AW_SEC_001.rule_id) or AW_SEC_001.severity
                findings.append(
                    Finding(
                        rule_id=AW_SEC_001.rule_id,
                        title=AW_SEC_001.title,
                        severity=sev,
                        category=AW_SEC_001.category,
                        description=f"Secret passed as {node.arg!r} kwarg. {AW_SEC_001.description}",
                        file=path,
                        line=getattr(node, "lineno", None),
                        fix=AW_SEC_001.fix,
                        layer="L1",
                    )
                )

            # Check for logging/print of context variables
            if isinstance(node, ast.Call):
                func_name = self._get_call_name(node)
                if func_name and self._is_logging_call(func_name):
                    for arg in node.args:
                        if self._references_context_var(arg):
                            if not ctx.should_suppress(AW_SEC_003.rule_id):
                                sev = (
                                    ctx.severity_override(AW_SEC_003.rule_id) or AW_SEC_003.severity
                                )
                                findings.append(
                                    Finding(
                                        rule_id=AW_SEC_003.rule_id,
                                        title=AW_SEC_003.title,
                                        severity=sev,
                                        category=AW_SEC_003.category,
                                        description=AW_SEC_003.description,
                                        file=path,
                                        line=getattr(node, "lineno", None),
                                        fix=AW_SEC_003.fix,
                                        layer="L1",
                                    )
                                )
                            break
        return findings

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    @staticmethod
    def _is_logging_call(name: str) -> bool:
        return name in {"debug", "info", "warning", "error", "critical", "print", "log"}

    @staticmethod
    def _references_context_var(node: ast.expr) -> bool:
        """Return True only when a context var's *content* would be logged.

        Suppressed (returns False):
        - Call wrapping the var: ``len(messages)``, ``type(messages)`` — metadata
        - Attribute access on the var: ``context.function.name`` — metadata

        Fires (returns True):
        - Direct Name: ``messages``
        - f-string with direct Name: ``f"payload: {messages}"``
        - Subscript: ``messages[-1]`` — content access by index
        - BinOp with direct ref: recurse both sides
        """
        return SecretsAnalyzer._is_content_reference(node)

    @staticmethod
    def _is_content_reference(node: ast.expr) -> bool:
        """Recursive helper — True when the node exposes context var content."""
        if isinstance(node, ast.Name):
            return node.id in CONTEXT_VAR_NAMES

        if isinstance(node, ast.Call):
            # Only check the func expression itself (e.g. chained calls like
            # messages.copy()), NOT the arguments — args are metadata extraction.
            return SecretsAnalyzer._is_content_reference(node.func)

        if isinstance(node, ast.Attribute):
            # Attribute access reads metadata from the object, not its content.
            return False

        if isinstance(node, ast.Subscript):
            # messages[-1] is a content reference; recurse on the container.
            return SecretsAnalyzer._is_content_reference(node.value)

        if isinstance(node, ast.BinOp):
            return SecretsAnalyzer._is_content_reference(
                node.left
            ) or SecretsAnalyzer._is_content_reference(node.right)

        if isinstance(node, ast.JoinedStr):
            # f-string: check each interpolated value node.
            for value in node.values:
                if isinstance(value, ast.FormattedValue) and SecretsAnalyzer._is_content_reference(value.value):
                    return True
            return False

        return False
