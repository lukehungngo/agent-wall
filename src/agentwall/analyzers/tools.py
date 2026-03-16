"""Tool security analyzer — AW-TOOL-001..005."""

from __future__ import annotations

from agentwall.models import AgentSpec, Finding, ToolSpec
from agentwall.rules import AW_TOOL_001, AW_TOOL_002, AW_TOOL_003, AW_TOOL_004, AW_TOOL_005, RuleDef

_TOOL_LIMIT = 15


def _finding_from_rule(rule: RuleDef, tool: ToolSpec) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        fix=rule.fix,
        file=tool.source_file,
        line=tool.source_line,
    )


def _finding_from_rule_no_loc(rule: RuleDef) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        fix=rule.fix,
    )


class ToolAnalyzer:
    """Fire tool-related rules against an AgentSpec."""

    def analyze(self, spec: AgentSpec) -> list[Finding]:
        findings: list[Finding] = []
        for tool in spec.tools:
            findings.extend(self._check_tool(tool))
        if len(spec.tools) > _TOOL_LIMIT:
            findings.append(_finding_from_rule_no_loc(AW_TOOL_005))
        return findings

    def _check_tool(self, tool: ToolSpec) -> list[Finding]:
        findings: list[Finding] = []

        # AW-TOOL-001: destructive without approval gate
        if tool.is_destructive and not tool.has_approval_gate:
            findings.append(_finding_from_rule(AW_TOOL_001, tool))

        # AW-TOOL-002: accepts code/shell execution
        if tool.accepts_code_execution:
            findings.append(_finding_from_rule(AW_TOOL_002, tool))

        # AW-TOOL-003: destructive without user scope check
        if tool.is_destructive and not tool.has_user_scope_check:
            findings.append(_finding_from_rule(AW_TOOL_003, tool))

        # AW-TOOL-004: no description
        if not tool.description:
            findings.append(_finding_from_rule(AW_TOOL_004, tool))

        return findings
