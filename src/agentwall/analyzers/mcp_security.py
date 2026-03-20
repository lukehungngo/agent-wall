"""L1-mcp analyzer — detect MCP security issues."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import Finding
from agentwall.patterns import MCP_IMPORTS, MCP_SHELL_CALLS, SECRET_PREFIXES
from agentwall.rules import AW_MCP_001, AW_MCP_002, AW_MCP_003


class MCPSecurityAnalyzer:
    """Detect MCP server security issues."""

    name: str = "L1-mcp"
    depends_on: Sequence[str] = ("L0-versions",)
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = True

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for source_file in ctx.source_files:
            try:
                source = source_file.read_text()
                tree = ast.parse(source)
            except (SyntaxError, UnicodeDecodeError):
                continue
            if not self._has_mcp_import(tree):
                continue
            findings.extend(self._check_file(ctx, tree, source_file))
        return findings

    def _has_mcp_import(self, tree: ast.Module) -> bool:
        """Check if file imports any MCP package."""
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if any(
                        alias.name == imp or alias.name.startswith(imp + ".") for imp in MCP_IMPORTS
                    ):
                        return True
            if (
                isinstance(node, ast.ImportFrom)
                and node.module
                and any(
                    node.module == imp or node.module.startswith(imp + ".") for imp in MCP_IMPORTS
                )
            ):
                return True
        return False

    def _check_file(self, ctx: AnalysisContext, tree: ast.Module, path: Path) -> list[Finding]:
        findings: list[Finding] = []

        for node in ast.walk(tree):
            # Detect Server() instantiation (AW-MCP-001)
            if isinstance(node, ast.Call):
                call_name = self._get_call_name(node)
                if call_name == "Server" and not ctx.should_suppress(AW_MCP_001.rule_id):
                    sev = ctx.severity_override(AW_MCP_001.rule_id) or AW_MCP_001.severity
                    findings.append(
                        Finding(
                            rule_id=AW_MCP_001.rule_id,
                            title=AW_MCP_001.title,
                            severity=sev,
                            category=AW_MCP_001.category,
                            description=AW_MCP_001.description,
                            file=path,
                            line=getattr(node, "lineno", None),
                            fix=AW_MCP_001.fix,
                            layer="L1",
                        )
                    )

            # Detect hardcoded tokens in MCP files (AW-MCP-002)
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                for prefix in SECRET_PREFIXES:
                    if (
                        node.value.startswith(prefix)
                        and len(node.value) > len(prefix) + 4
                        and not ctx.should_suppress(AW_MCP_002.rule_id)
                    ):
                        sev = ctx.severity_override(AW_MCP_002.rule_id) or AW_MCP_002.severity
                        findings.append(
                            Finding(
                                rule_id=AW_MCP_002.rule_id,
                                title=AW_MCP_002.title,
                                severity=sev,
                                category=AW_MCP_002.category,
                                description=AW_MCP_002.description,
                                file=path,
                                line=getattr(node, "lineno", None),
                                fix=AW_MCP_002.fix,
                                layer="L1",
                            )
                        )
                        break

        # Check for shell calls inside decorated tool functions (AW-MCP-003)
        for node in ast.walk(tree):
            if isinstance(
                node, (ast.FunctionDef, ast.AsyncFunctionDef)
            ) and self._is_tool_decorated(node):
                for child in ast.walk(node):
                    if isinstance(child, ast.Call):
                        call_name = self._get_qualified_name(child)
                        if (
                            call_name
                            and call_name in MCP_SHELL_CALLS
                            and not ctx.should_suppress(AW_MCP_003.rule_id)
                        ):
                            sev = ctx.severity_override(AW_MCP_003.rule_id) or AW_MCP_003.severity
                            findings.append(
                                Finding(
                                    rule_id=AW_MCP_003.rule_id,
                                    title=AW_MCP_003.title,
                                    severity=sev,
                                    category=AW_MCP_003.category,
                                    description=AW_MCP_003.description,
                                    file=path,
                                    line=getattr(child, "lineno", None),
                                    fix=AW_MCP_003.fix,
                                    layer="L1",
                                )
                            )
        return findings

    @staticmethod
    def _get_call_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Name):
            return node.func.id
        if isinstance(node.func, ast.Attribute):
            return node.func.attr
        return None

    @staticmethod
    def _get_qualified_name(node: ast.Call) -> str | None:
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        if isinstance(node.func, ast.Name):
            return node.func.id
        return None

    @staticmethod
    def _is_tool_decorated(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Check if function has @server.tool() or similar decorator."""
        for dec in node.decorator_list:
            if (
                isinstance(dec, ast.Call)
                and isinstance(dec.func, ast.Attribute)
                and dec.func.attr == "tool"
            ):
                return True
            if isinstance(dec, ast.Attribute) and dec.attr == "tool":
                return True
        return False
