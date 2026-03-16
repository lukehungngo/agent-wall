"""Tests for ToolAnalyzer."""

from __future__ import annotations

from agentwall.analyzers.tools import ToolAnalyzer
from agentwall.models import AgentSpec, Severity, ToolSpec


def _spec(*tools: ToolSpec) -> AgentSpec:
    return AgentSpec(framework="langchain", tools=list(tools))


class TestToolAnalyzerTOOL001:
    def test_fires_destructive_no_gate(self) -> None:
        tool = ToolSpec(name="delete_file", is_destructive=True, has_approval_gate=False)
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-001" in rule_ids

    def test_severity_is_high(self) -> None:
        tool = ToolSpec(name="delete_file", is_destructive=True)
        findings = ToolAnalyzer().analyze(_spec(tool))
        f = next(f for f in findings if f.rule_id == "AW-TOOL-001")
        assert f.severity == Severity.HIGH

    def test_does_not_fire_when_gate_present(self) -> None:
        tool = ToolSpec(name="delete_file", is_destructive=True, has_approval_gate=True)
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-001" not in rule_ids


class TestToolAnalyzerTOOL002:
    def test_fires_for_code_execution(self) -> None:
        tool = ToolSpec(name="run_shell", accepts_code_execution=True)
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-002" in rule_ids

    def test_does_not_fire_for_safe_tool(self) -> None:
        tool = ToolSpec(name="search_web", description="Search the web", accepts_code_execution=False)
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-002" not in rule_ids


class TestToolAnalyzerTOOL003:
    def test_fires_destructive_no_scope_check(self) -> None:
        tool = ToolSpec(name="delete_file", is_destructive=True, has_user_scope_check=False)
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-003" in rule_ids

    def test_does_not_fire_when_scope_check_present(self) -> None:
        tool = ToolSpec(
            name="delete_file",
            is_destructive=True,
            has_user_scope_check=True,
            has_approval_gate=True,
        )
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-003" not in rule_ids


class TestToolAnalyzerTOOL004:
    def test_fires_when_no_description(self) -> None:
        tool = ToolSpec(name="mystery_tool", description=None)
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-004" in rule_ids

    def test_fires_when_empty_description(self) -> None:
        tool = ToolSpec(name="mystery_tool", description="")
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-004" in rule_ids

    def test_does_not_fire_with_description(self) -> None:
        tool = ToolSpec(name="search_web", description="Searches the web.")
        findings = ToolAnalyzer().analyze(_spec(tool))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-004" not in rule_ids


class TestToolAnalyzerTOOL005:
    def test_fires_when_more_than_15_tools(self) -> None:
        tools = [ToolSpec(name=f"tool_{i}", description="desc") for i in range(16)]
        findings = ToolAnalyzer().analyze(AgentSpec(framework="langchain", tools=tools))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-005" in rule_ids

    def test_does_not_fire_for_15_or_fewer(self) -> None:
        tools = [ToolSpec(name=f"tool_{i}", description="desc") for i in range(15)]
        findings = ToolAnalyzer().analyze(AgentSpec(framework="langchain", tools=tools))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-TOOL-005" not in rule_ids


class TestToolAnalyzerNoFindingsOnSafe:
    def test_safe_tool_no_findings(self) -> None:
        tool = ToolSpec(
            name="get_user_data",
            description="Returns data scoped to the requesting user.",
            is_destructive=False,
            accepts_code_execution=False,
            has_approval_gate=False,
            has_user_scope_check=True,
        )
        findings = ToolAnalyzer().analyze(_spec(tool))
        assert findings == []
