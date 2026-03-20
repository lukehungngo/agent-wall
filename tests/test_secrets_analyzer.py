from pathlib import Path

from agentwall.analyzers.secrets import SecretsAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"


class TestSecretsAnalyzer:
    def test_name_and_flags(self) -> None:
        assert SecretsAnalyzer.name == "L1-secrets"
        assert SecretsAnalyzer.framework_agnostic is True

    def test_detects_hardcoded_secret(self) -> None:
        fixture = FIXTURES / "secrets_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SecretsAnalyzer().analyze(ctx)
        sec_001 = [f for f in findings if f.rule_id == "AW-SEC-001"]
        assert len(sec_001) >= 2  # sk- and AKIA prefixes

    def test_detects_context_logging(self) -> None:
        fixture = FIXTURES / "secrets_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SecretsAnalyzer().analyze(ctx)
        sec_003 = [f for f in findings if f.rule_id == "AW-SEC-003"]
        assert len(sec_003) >= 1

    def test_no_findings_in_clean_file(self, tmp_path: Path) -> None:
        (tmp_path / "clean.py").write_text("x = 42\nprint(x)\n")
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "clean.py"],
        )
        findings = SecretsAnalyzer().analyze(ctx)
        assert findings == []
