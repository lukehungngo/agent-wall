"""Tool security analyzer — AW-TOOL-001..005."""

from __future__ import annotations

from agentwall.models import AgentSpec, ConfidenceLevel, Finding, ToolSpec
from agentwall.rules import AW_TOOL_001, AW_TOOL_002, AW_TOOL_003, AW_TOOL_004, AW_TOOL_005, RuleDef

_TOOL_LIMIT = 15


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

    def analyze(self, spec: AgentSpec) -> list[Finding]:
        findings: list[Finding] = []
        for tool in spec.tools:
            findings.extend(self._check_tool(tool))
        if len(spec.tools) > _TOOL_LIMIT:
            # LOW confidence — tool count is heuristic
            findings.append(_finding_from_rule_no_loc(AW_TOOL_005, ConfidenceLevel.LOW))
        return findings

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
