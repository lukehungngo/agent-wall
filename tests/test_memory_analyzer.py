"""Tests for MemoryAnalyzer."""

from __future__ import annotations

from agentwall.analyzers.memory import MemoryAnalyzer
from agentwall.models import AgentSpec, MemoryConfig, Severity


def _spec(mc: MemoryConfig) -> AgentSpec:
    return AgentSpec(framework="langchain", memory_configs=[mc])


class TestMemoryAnalyzerMEM001:
    def test_fires_when_no_isolation_no_filter(self) -> None:
        mc = MemoryConfig(backend="chroma")
        findings = MemoryAnalyzer().analyze(_spec(mc))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-MEM-001" in rule_ids

    def test_severity_is_critical(self) -> None:
        mc = MemoryConfig(backend="chroma")
        findings = MemoryAnalyzer().analyze(_spec(mc))
        mem001 = next(f for f in findings if f.rule_id == "AW-MEM-001")
        assert mem001.severity == Severity.CRITICAL

    def test_does_not_fire_when_filter_present(self) -> None:
        mc = MemoryConfig(backend="chroma", has_metadata_filter_on_retrieval=True)
        findings = MemoryAnalyzer().analyze(_spec(mc))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-MEM-001" not in rule_ids


class TestMemoryAnalyzerMEM002:
    def test_fires_when_write_meta_but_no_retrieval_filter(self) -> None:
        mc = MemoryConfig(backend="chroma", has_metadata_on_write=True)
        findings = MemoryAnalyzer().analyze(_spec(mc))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-MEM-002" in rule_ids

    def test_does_not_fire_when_retrieval_filter_also_present(self) -> None:
        mc = MemoryConfig(
            backend="chroma",
            has_metadata_on_write=True,
            has_metadata_filter_on_retrieval=True,
        )
        findings = MemoryAnalyzer().analyze(_spec(mc))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-MEM-002" not in rule_ids


class TestMemoryAnalyzerMEM003:
    def test_fires_when_no_access_control_at_all(self) -> None:
        mc = MemoryConfig(backend="chroma")
        findings = MemoryAnalyzer().analyze(_spec(mc))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-MEM-003" in rule_ids

    def test_does_not_fire_when_write_meta_present(self) -> None:
        mc = MemoryConfig(backend="chroma", has_metadata_on_write=True)
        findings = MemoryAnalyzer().analyze(_spec(mc))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-MEM-003" not in rule_ids

    def test_does_not_fire_on_safe_config(self) -> None:
        mc = MemoryConfig(
            backend="chroma",
            has_tenant_isolation=True,
            has_metadata_filter_on_retrieval=True,
            has_metadata_on_write=True,
        )
        findings = MemoryAnalyzer().analyze(_spec(mc))
        assert findings == []


class TestMemoryAnalyzerCoFiring:
    def test_mem001_and_mem002_both_fire_on_write_meta_no_filter(self) -> None:
        # The "false sense of security" pattern: metadata on write but no retrieval filter.
        # Both AW-MEM-001 (no isolation) and AW-MEM-002 (write/retrieval mismatch) must fire.
        mc = MemoryConfig(backend="chroma", has_metadata_on_write=True)
        findings = MemoryAnalyzer().analyze(_spec(mc))
        rule_ids = [f.rule_id for f in findings]
        assert "AW-MEM-001" in rule_ids
        assert "AW-MEM-002" in rule_ids


class TestMemoryAnalyzerNoFindingsOnSafe:
    def test_fully_safe_config_no_findings(self) -> None:
        mc = MemoryConfig(
            backend="chroma",
            has_tenant_isolation=True,
            has_metadata_filter_on_retrieval=True,
            has_metadata_on_write=True,
        )
        findings = MemoryAnalyzer().analyze(_spec(mc))
        assert findings == []

    def test_empty_spec_returns_empty(self) -> None:
        spec = AgentSpec(framework="langchain")
        findings = MemoryAnalyzer().analyze(spec)
        assert findings == []
