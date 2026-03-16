"""End-to-end scanner tests."""

from __future__ import annotations

from pathlib import Path

from agentwall.models import Severity
from agentwall.scanner import scan

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
