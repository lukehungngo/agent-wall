"""Tests for L7 RuntimePatcher."""

from __future__ import annotations

from agentwall.runtime.patcher import (
    RuntimeReport,
    RuntimeViolation,
    get_report,
    reset_report,
)


class TestRuntimeReport:
    def test_empty_report(self) -> None:
        report = RuntimeReport()
        assert report.violations == []
        assert report.total_calls == 0
        assert report.to_findings() == []

    def test_violation_to_finding(self) -> None:
        violation = RuntimeViolation(
            method="similarity_search",
            file="agent.py",
            line=10,
            kwargs={"query": "test"},
        )
        report = RuntimeReport(violations=[violation], total_calls=1)
        findings = report.to_findings()
        assert len(findings) == 1
        assert findings[0].rule_id == "AW-MEM-001"
        assert findings[0].layer == "L7"
        assert findings[0].severity.value == "high"

    def test_multiple_violations(self) -> None:
        violations = [
            RuntimeViolation(method="similarity_search", file="a.py", line=1, kwargs={}),
            RuntimeViolation(method="similarity_search", file="b.py", line=2, kwargs={}),
        ]
        report = RuntimeReport(violations=violations, total_calls=3, filtered_calls=1)
        findings = report.to_findings()
        assert len(findings) == 2

    def test_reset_report(self) -> None:
        reset_report()
        report = get_report()
        assert report.total_calls == 0
        assert report.violations == []
