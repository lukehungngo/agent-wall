from pathlib import Path

from agentwall.analyzers.mcp_security import MCPSecurityAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"


class TestMCPSecurityAnalyzer:
    def test_name_and_flags(self) -> None:
        assert MCPSecurityAnalyzer.name == "L1-mcp"
        assert MCPSecurityAnalyzer.framework_agnostic is True

    def test_detects_mcp_server_without_auth(self) -> None:
        fixture = FIXTURES / "mcp_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = MCPSecurityAnalyzer().analyze(ctx)
        mcp_001 = [f for f in findings if f.rule_id == "AW-MCP-001"]
        assert len(mcp_001) >= 1

    def test_detects_hardcoded_token(self) -> None:
        fixture = FIXTURES / "mcp_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = MCPSecurityAnalyzer().analyze(ctx)
        mcp_002 = [f for f in findings if f.rule_id == "AW-MCP-002"]
        assert len(mcp_002) >= 1

    def test_detects_shell_in_tool(self) -> None:
        fixture = FIXTURES / "mcp_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = MCPSecurityAnalyzer().analyze(ctx)
        mcp_003 = [f for f in findings if f.rule_id == "AW-MCP-003"]
        assert len(mcp_003) >= 1

    def test_no_findings_without_mcp(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("import flask\napp = flask.Flask(__name__)\n")
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "app.py"],
        )
        findings = MCPSecurityAnalyzer().analyze(ctx)
        assert findings == []
