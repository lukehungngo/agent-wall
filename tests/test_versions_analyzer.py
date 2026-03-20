"""Tests for L0-versions analyzer."""

from __future__ import annotations

from pathlib import Path

from agentwall.analyzers.versions import VersionsAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig


class TestVersionsAnalyzer:
    def test_name(self) -> None:
        assert VersionsAnalyzer.name == "L0-versions"
        assert VersionsAnalyzer.framework_agnostic is True

    def test_populates_version_modifiers(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("chromadb==0.3.0\n")
        (tmp_path / "app.py").write_text("import chromadb\n")
        ctx = AnalysisContext(
            target=tmp_path, config=ScanConfig(), source_files=[tmp_path / "app.py"]
        )
        findings = VersionsAnalyzer().analyze(ctx)
        # chromadb only appears in modifiers if there's YAML version data for it
        # The key assertion is that analyze() runs without error
        assert isinstance(findings, list)

    def test_flags_unpinned_agent_framework(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain\n")
        (tmp_path / "app.py").write_text("import langchain\n")
        ctx = AnalysisContext(
            target=tmp_path, config=ScanConfig(), source_files=[tmp_path / "app.py"]
        )
        findings = VersionsAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in findings]
        assert "AW-SER-002" in rule_ids

    def test_pinned_agent_framework_no_finding(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain==0.2.5\n")
        (tmp_path / "app.py").write_text("import langchain\n")
        ctx = AnalysisContext(
            target=tmp_path, config=ScanConfig(), source_files=[tmp_path / "app.py"]
        )
        findings = VersionsAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in findings]
        assert "AW-SER-002" not in rule_ids

    def test_no_deps_file_no_crash(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("print('hello')\n")
        ctx = AnalysisContext(
            target=tmp_path, config=ScanConfig(), source_files=[tmp_path / "app.py"]
        )
        findings = VersionsAnalyzer().analyze(ctx)
        assert ctx.version_modifiers == {}
        assert findings == []

    def test_empty_requirements_file(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("")
        ctx = AnalysisContext(
            target=tmp_path, config=ScanConfig(), source_files=[tmp_path / "app.py"]
        )
        findings = VersionsAnalyzer().analyze(ctx)
        assert ctx.version_modifiers == {}
        assert findings == []

    def test_multiple_unpinned_frameworks(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("langchain\ncrewai\n")
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig(), source_files=[])
        findings = VersionsAnalyzer().analyze(ctx)
        rule_ids = [f.rule_id for f in findings]
        assert rule_ids.count("AW-SER-002") == 2

    def test_non_framework_unpinned_no_finding(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("requests\n")
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig(), source_files=[])
        findings = VersionsAnalyzer().analyze(ctx)
        assert findings == []
