"""Tests for the L2-agent (AgentArchAnalyzer)."""

from __future__ import annotations

from pathlib import Path

from agentwall.adapters.langchain import LangChainAdapter
from agentwall.analyzers.agent_arch import AgentArchAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"


class TestAgentArchAnalyzer:
    def test_name_and_flags(self) -> None:
        assert AgentArchAnalyzer.name == "L2-agent"
        assert AgentArchAnalyzer.framework_agnostic is False

    def test_detects_inherited_tools(self) -> None:
        fixture = FIXTURES / "agent_unsafe"
        spec = LangChainAdapter().parse(fixture)
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            spec=spec,
            source_files=list(fixture.glob("*.py")),
        )
        findings = AgentArchAnalyzer().analyze(ctx)
        agt_001 = [f for f in findings if f.rule_id == "AW-AGT-001"]
        assert len(agt_001) >= 1

    def test_detects_llm_output_to_memory(self) -> None:
        fixture = FIXTURES / "agent_unsafe"
        spec = LangChainAdapter().parse(fixture)
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            spec=spec,
            source_files=list(fixture.glob("*.py")),
        )
        findings = AgentArchAnalyzer().analyze(ctx)
        agt_004 = [f for f in findings if f.rule_id == "AW-AGT-004"]
        assert len(agt_004) >= 1

    def test_detects_mixed_read_destructive_tools(self) -> None:
        fixture = FIXTURES / "agent_unsafe"
        spec = LangChainAdapter().parse(fixture)
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            spec=spec,
            source_files=list(fixture.glob("*.py")),
        )
        findings = AgentArchAnalyzer().analyze(ctx)
        agt_003 = [f for f in findings if f.rule_id == "AW-AGT-003"]
        assert len(agt_003) >= 1

    def test_no_findings_in_clean_file(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 42\n")
        spec = LangChainAdapter().parse(tmp_path)
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            spec=spec,
            source_files=[tmp_path / "app.py"],
        )
        findings = AgentArchAnalyzer().analyze(ctx)
        assert findings == []

    def test_skips_unparseable_file(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.py"
        bad.write_text("def foo(:\n")  # syntax error
        spec = LangChainAdapter().parse(tmp_path)
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            spec=spec,
            source_files=[bad],
        )
        findings = AgentArchAnalyzer().analyze(ctx)
        assert findings == []

    def test_suppression_respected(self) -> None:
        """If version modifier suppresses AW-AGT-001, no finding emitted."""
        from agentwall.models import VersionModifier

        fixture = FIXTURES / "agent_unsafe"
        spec = LangChainAdapter().parse(fixture)
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            spec=spec,
            source_files=list(fixture.glob("*.py")),
            version_modifiers={"test": VersionModifier(library="test", suppress=["AW-AGT-001"])},
        )
        findings = AgentArchAnalyzer().analyze(ctx)
        agt_001 = [f for f in findings if f.rule_id == "AW-AGT-001"]
        assert len(agt_001) == 0
