"""End-to-end scanner tests."""

from __future__ import annotations

from pathlib import Path

from agentwall.models import ConfidenceLevel, Finding, Severity
from agentwall.scanner import _apply_file_context, _classify_file_context, _sort_findings, scan

FIXTURES = Path(__file__).parent / "fixtures"


class TestScannerUnsafe:
    def test_returns_at_least_one_critical(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe")
        assert any(f.severity == Severity.CRITICAL for f in result.findings)

    def test_findings_sorted_critical_first(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe")
        assert result.findings, "Expected findings"
        sevs = [f.severity for f in result.findings]
        # CRITICAL should appear before HIGH/MEDIUM etc.
        order = [Severity.CRITICAL, Severity.HIGH, Severity.MEDIUM, Severity.LOW, Severity.INFO]
        last_rank = -1
        for sev in sevs:
            rank = order.index(sev)
            assert rank >= last_rank, f"Findings not sorted: {sevs}"
            last_rank = rank

    def test_framework_detected_as_langchain(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe")
        assert result.framework == "langchain"

    def test_scanned_files_count(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe")
        assert result.scanned_files >= 1


class TestScannerSafe:
    def test_no_critical_findings(self) -> None:
        result = scan(FIXTURES / "langchain_safe")
        assert not any(f.severity == Severity.CRITICAL for f in result.findings)


class TestScannerBasic:
    def test_mem001_triggered_for_unfiltered_retrieval(self) -> None:
        result = scan(FIXTURES / "langchain_basic")
        rule_ids = [f.rule_id for f in result.findings]
        assert "AW-MEM-001" in rule_ids


class TestScannerFrameworkOverride:
    def test_unsupported_framework_returns_error(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe", framework="crewai")
        assert result.errors

    def test_langchain_override_works(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe", framework="langchain")
        assert result.framework == "langchain"
        assert result.findings


class TestFileContextClassification:
    def test_test_directory(self) -> None:
        assert _classify_file_context(Path("tests/test_agent.py")) == "test file"

    def test_test_prefix(self) -> None:
        assert _classify_file_context(Path("src/test_utils.py")) == "test file"

    def test_test_suffix(self) -> None:
        assert _classify_file_context(Path("src/agent_test.py")) == "test file"

    def test_example_directory(self) -> None:
        assert _classify_file_context(Path("examples/demo.py")) == "example"

    def test_example_extension(self) -> None:
        assert _classify_file_context(Path("config.example")) == "example"

    def test_docs_directory(self) -> None:
        assert _classify_file_context(Path("docs/guide.py")) == "example"

    def test_production_file(self) -> None:
        assert _classify_file_context(Path("src/agent.py")) is None

    def test_none_path(self) -> None:
        assert _classify_file_context(None) is None

    # Negative cases — production files must NOT be classified
    def test_contest_handler_not_test(self) -> None:
        assert _classify_file_context(Path("src/contest_handler.py")) is None

    def test_latest_config_not_test(self) -> None:
        assert _classify_file_context(Path("src/latest_config.py")) is None

    def test_backtest_not_test(self) -> None:
        assert _classify_file_context(Path("src/backtest.py")) is None

    def test_protest_not_test(self) -> None:
        assert _classify_file_context(Path("src/protest_handler.py")) is None

    def test_example_utils_not_example(self) -> None:
        assert _classify_file_context(Path("src/example_utils.py")) is None


class TestConfidenceCapping:
    def _make_finding(
        self,
        file: Path | None = None,
        confidence: ConfidenceLevel = ConfidenceLevel.HIGH,
    ) -> Finding:
        from agentwall.models import Category

        return Finding(
            rule_id="AW-MEM-001",
            title="Test",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="Test",
            file=file,
            confidence=confidence,
        )

    def test_caps_test_file_to_low(self) -> None:
        f = self._make_finding(file=Path("tests/test_agent.py"), confidence=ConfidenceLevel.HIGH)
        result = _apply_file_context([f])
        assert result[0].confidence == ConfidenceLevel.LOW
        assert result[0].file_context == "test file"

    def test_caps_example_to_low(self) -> None:
        f = self._make_finding(file=Path("examples/demo.py"), confidence=ConfidenceLevel.MEDIUM)
        result = _apply_file_context([f])
        assert result[0].confidence == ConfidenceLevel.LOW
        assert result[0].file_context == "example"

    def test_keeps_low_as_low(self) -> None:
        f = self._make_finding(file=Path("tests/test_agent.py"), confidence=ConfidenceLevel.LOW)
        result = _apply_file_context([f])
        assert result[0].confidence == ConfidenceLevel.LOW

    def test_no_cap_for_production(self) -> None:
        f = self._make_finding(file=Path("src/agent.py"), confidence=ConfidenceLevel.HIGH)
        result = _apply_file_context([f])
        assert result[0].confidence == ConfidenceLevel.HIGH
        assert result[0].file_context is None


class TestSecondarySort:
    def _make_finding(self, severity: Severity, confidence: ConfidenceLevel) -> Finding:
        from agentwall.models import Category

        return Finding(
            rule_id="AW-MEM-001",
            title="Test",
            severity=severity,
            category=Category.MEMORY,
            description="Test",
            confidence=confidence,
        )

    def test_sorts_by_confidence_within_severity(self) -> None:
        findings = [
            self._make_finding(Severity.HIGH, ConfidenceLevel.LOW),
            self._make_finding(Severity.HIGH, ConfidenceLevel.HIGH),
            self._make_finding(Severity.HIGH, ConfidenceLevel.MEDIUM),
        ]
        sorted_f = _sort_findings(findings)
        assert sorted_f[0].confidence == ConfidenceLevel.HIGH
        assert sorted_f[1].confidence == ConfidenceLevel.MEDIUM
        assert sorted_f[2].confidence == ConfidenceLevel.LOW

    def test_severity_takes_precedence(self) -> None:
        findings = [
            self._make_finding(Severity.MEDIUM, ConfidenceLevel.HIGH),
            self._make_finding(Severity.CRITICAL, ConfidenceLevel.LOW),
        ]
        sorted_f = _sort_findings(findings)
        assert sorted_f[0].severity == Severity.CRITICAL
        assert sorted_f[1].severity == Severity.MEDIUM
