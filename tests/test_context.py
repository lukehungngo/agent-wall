"""Tests for AnalysisContext and Analyzer protocol."""

from pathlib import Path

from agentwall.context import AnalysisContext, Analyzer
from agentwall.models import Category, Finding, ScanConfig, Severity, VersionModifier


class TestAnalysisContext:
    def test_creates_with_defaults(self) -> None:
        ctx = AnalysisContext(target=Path("/tmp"), config=ScanConfig.default())
        assert ctx.spec is None
        assert ctx.call_graph is None
        assert ctx.taint_results is None
        assert ctx.findings == []
        assert ctx.errors == []

    def test_findings_mutable(self) -> None:
        ctx = AnalysisContext(target=Path("/tmp"), config=ScanConfig.default())
        ctx.findings.append(
            Finding(
                rule_id="TEST",
                title="t",
                severity=Severity.CRITICAL,
                category=Category.MEMORY,
                description="t",
            )
        )
        assert len(ctx.findings) == 1

    def test_source_files_default_empty(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        assert ctx.source_files == []


class TestContextVersionModifiers:
    def test_should_suppress_empty(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        assert not ctx.should_suppress("AW-MEM-001")

    def test_should_suppress_match(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        ctx.version_modifiers["chromadb"] = VersionModifier(
            library="chromadb", suppress=["AW-MEM-001"]
        )
        assert ctx.should_suppress("AW-MEM-001")
        assert not ctx.should_suppress("AW-MEM-002")

    def test_severity_override_upgrade(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        ctx.version_modifiers["chromadb"] = VersionModifier(
            library="chromadb", upgrade={"AW-MEM-003": Severity.HIGH}
        )
        assert ctx.severity_override("AW-MEM-003") == Severity.HIGH
        assert ctx.severity_override("AW-MEM-001") is None

    def test_severity_override_most_severe_wins(self) -> None:
        ctx = AnalysisContext(target=Path("."), config=ScanConfig())
        ctx.version_modifiers["lib_a"] = VersionModifier(
            library="lib_a", downgrade={"AW-MEM-001": Severity.LOW}
        )
        ctx.version_modifiers["lib_b"] = VersionModifier(
            library="lib_b", upgrade={"AW-MEM-001": Severity.HIGH}
        )
        assert ctx.severity_override("AW-MEM-001") == Severity.HIGH


class TestAnalyzerProtocol:
    def test_concrete_class_satisfies_protocol(self) -> None:
        """A class with all protocol fields satisfies Analyzer."""

        class FakeAnalyzer:
            name = "FAKE"
            depends_on: list[str] = []
            replace: bool = False
            opt_in: bool = False
            framework_agnostic: bool = False

            def analyze(self, ctx: AnalysisContext) -> list[Finding]:
                return []

        analyzer: Analyzer = FakeAnalyzer()
        result = analyzer.analyze(AnalysisContext(target=Path("/tmp"), config=ScanConfig.default()))
        assert result == []
