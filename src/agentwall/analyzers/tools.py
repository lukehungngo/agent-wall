"""Tool security analyzer — AW-TOOL-001..005."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import ConfidenceLevel, Finding, ToolSpec
from agentwall.rules import AW_TOOL_001, AW_TOOL_002, AW_TOOL_003, AW_TOOL_004, AW_TOOL_005, RuleDef

_TOOL_LIMIT = 15

_EXEC_CALLS: frozenset[str] = frozenset({"exec", "eval", "compile"})
_SUBPROCESS_ATTRS: frozenset[str] = frozenset({"run", "call", "Popen", "check_output", "check_call"})
_DESTRUCTIVE_KW: frozenset[str] = frozenset({
    "delete", "remove", "drop", "destroy", "kill", "purge", "erase", "wipe", "truncate",
})


def _finding_from_rule(
    rule: RuleDef,
    tool: ToolSpec,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        fix=rule.fix,
        file=tool.source_file,
        line=tool.source_line,
        confidence=confidence,
    )


def _finding_from_rule_no_loc(
    rule: RuleDef,
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        fix=rule.fix,
        confidence=confidence,
    )


class ToolAnalyzer:
    """Fire tool-related rules against an AgentSpec."""

    name: str = "L1-tools"
    depends_on: Sequence[str] = ()
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = True

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        spec = ctx.spec
        if spec is None or not spec.tools:
            # No adapter or adapter found no tools — use AST fallback
            return self._analyze_agnostic(ctx)
        findings: list[Finding] = []
        for tool in spec.tools:
            findings.extend(self._check_tool(tool))
        if len(spec.tools) > _TOOL_LIMIT:
            # LOW confidence — tool count is heuristic
            findings.append(_finding_from_rule_no_loc(AW_TOOL_005, ConfidenceLevel.LOW))
        return findings

    def _analyze_agnostic(self, ctx: AnalysisContext) -> list[Finding]:
        """AST-based fallback when no framework adapter is available."""
        tools = self._extract_tools_from_ast(ctx.source_files)
        if not tools:
            return []
        findings: list[Finding] = []
        for tool in tools:
            findings.extend(self._check_tool(tool))
        if len(tools) > _TOOL_LIMIT:
            findings.append(_finding_from_rule_no_loc(AW_TOOL_005, ConfidenceLevel.LOW))
        return findings

    @staticmethod
    def _extract_tools_from_ast(source_files: list[Path]) -> list[ToolSpec]:
        """Walk source files' ASTs and build synthetic ToolSpec objects."""
        tools: list[ToolSpec] = []
        for fpath in source_files:
            try:
                source = fpath.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(fpath))
            except (SyntaxError, UnicodeDecodeError, OSError):
                continue

            for node in ast.walk(tree):
                if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    continue

                # Check for @tool decorator
                has_tool_decorator = any(
                    (isinstance(dec, ast.Name) and dec.id == "tool")
                    or (isinstance(dec, ast.Call) and isinstance(dec.func, ast.Name) and dec.func.id == "tool")
                    or (isinstance(dec, ast.Attribute) and dec.attr == "tool")
                    for dec in node.decorator_list
                )

                # Check body for exec/eval/compile and subprocess calls
                has_code_exec = any(
                    isinstance(child, ast.Call) and (
                        (isinstance(child.func, ast.Name) and child.func.id in _EXEC_CALLS)
                        or (isinstance(child.func, ast.Attribute) and child.func.attr in _SUBPROCESS_ATTRS)
                    )
                    for child in ast.walk(node)
                )

                # Only create ToolSpec if decorated or contains dangerous calls
                if not has_tool_decorator and not has_code_exec:
                    continue

                func_name = node.name
                is_destructive = any(kw in func_name.lower() for kw in _DESTRUCTIVE_KW)

                tools.append(
                    ToolSpec(
                        name=func_name,
                        description=ast.get_docstring(node),
                        is_destructive=is_destructive,
                        accepts_code_execution=has_code_exec,
                        source_file=fpath,
                        source_line=node.lineno,
                    )
                )
        return tools

    def _check_tool(self, tool: ToolSpec) -> list[Finding]:
        findings: list[Finding] = []

        # AW-TOOL-001: destructive without approval gate
        # HIGH confidence — direct pattern match
        if tool.is_destructive and not tool.has_approval_gate:
            findings.append(_finding_from_rule(AW_TOOL_001, tool, ConfidenceLevel.HIGH))

        # AW-TOOL-002: accepts code/shell execution
        # HIGH confidence — direct pattern match
        if tool.accepts_code_execution:
            findings.append(_finding_from_rule(AW_TOOL_002, tool, ConfidenceLevel.HIGH))

        # AW-TOOL-003: destructive without user scope check
        # MEDIUM confidence — scope check may exist outside visible code
        if tool.is_destructive and not tool.has_user_scope_check:
            findings.append(_finding_from_rule(AW_TOOL_003, tool, ConfidenceLevel.MEDIUM))

        # AW-TOOL-004: no description
        # HIGH confidence — absence is directly observable
        if not tool.description:
            findings.append(_finding_from_rule(AW_TOOL_004, tool, ConfidenceLevel.HIGH))

        return findings
