"""Tests for terminal, JSON, SARIF, agent-json, and patch reporters."""

from __future__ import annotations

import io
import json
from pathlib import Path

from rich.console import Console

from agentwall.models import Category, ConfidenceLevel, Finding, ScanResult, Severity
from agentwall.reporters.agent_json import AgentJsonReporter, build_agent_json
from agentwall.reporters.json_reporter import JsonReporter
from agentwall.reporters.patch import PatchReporter, build_patch
from agentwall.reporters.sarif import SarifReporter, build_sarif
from agentwall.reporters.terminal import TerminalReporter


def _make_result(findings: list[Finding] | None = None) -> ScanResult:
    return ScanResult(
        target=Path("/fake/project"),
        framework="langchain",
        findings=findings or [],
        scanned_files=3,
    )


def _make_finding(
    rule_id: str = "AW-MEM-001",
    severity: Severity = Severity.CRITICAL,
    file: Path | None = Path("/fake/agent.py"),
    line: int | None = 42,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="Test finding",
        severity=severity,
        category=Category.MEMORY,
        description="Test description",
        fix="Test fix",
        file=file,
        line=line,
    )


class TestTerminalReporter:
    def test_render_no_findings(self) -> None:
        console = Console(file=None, force_terminal=True, width=120)
        reporter = TerminalReporter(console=console)
        result = _make_result()
        # Should not raise
        reporter.render(result)

    def test_render_with_findings(self) -> None:
        console = Console(file=None, force_terminal=True, width=120)
        reporter = TerminalReporter(console=console)
        result = _make_result(
            [
                _make_finding(severity=Severity.CRITICAL),
                _make_finding(rule_id="AW-TOOL-001", severity=Severity.HIGH),
                _make_finding(rule_id="AW-MEM-005", severity=Severity.MEDIUM),
            ]
        )
        reporter.render(result)

    def test_render_finding_no_file(self) -> None:
        console = Console(file=None, force_terminal=True, width=120)
        reporter = TerminalReporter(console=console)
        result = _make_result([_make_finding(file=None, line=None)])
        reporter.render(result)

    def test_render_finding_no_fix(self) -> None:
        console = Console(file=None, force_terminal=True, width=120)
        reporter = TerminalReporter(console=console)
        f = Finding(
            rule_id="AW-MEM-001",
            title="No fix",
            severity=Severity.HIGH,
            category=Category.MEMORY,
            description="Desc",
        )
        result = _make_result([f])
        reporter.render(result)

    def test_render_shows_confidence_inline(self) -> None:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=200)
        reporter = TerminalReporter(console=console)
        f = _make_finding(severity=Severity.HIGH)
        f = f.model_copy(update={"confidence": ConfidenceLevel.MEDIUM})
        result = _make_result([f])
        reporter.render(result)
        output = buf.getvalue()
        assert "Confidence: Medium" in output

    def test_render_dual_axis_summary(self) -> None:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=200)
        reporter = TerminalReporter(console=console)
        result = _make_result(
            [
                _make_finding(severity=Severity.CRITICAL, file=Path("/fake/a.py"), line=1),
                _make_finding(
                    rule_id="AW-TOOL-001", severity=Severity.HIGH, file=Path("/fake/b.py"), line=2
                ).model_copy(update={"confidence": ConfidenceLevel.MEDIUM}),
            ]
        )
        reporter.render(result)
        output = buf.getvalue()
        assert "by severity:" in output
        assert "by confidence:" in output
        assert "2 findings" in output

    def test_render_shows_file_context_tag(self) -> None:
        buf = io.StringIO()
        console = Console(file=buf, force_terminal=False, width=200)
        reporter = TerminalReporter(console=console)
        f = _make_finding().model_copy(update={"file_context": "test file"})
        result = _make_result([f])
        reporter.render(result)
        output = buf.getvalue()
        assert "test file" in output


class TestJsonReporter:
    def test_render_creates_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        reporter = JsonReporter()
        result = _make_result([_make_finding()])
        reporter.render(result, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert "findings" in data
        assert len(data["findings"]) == 1

    def test_render_empty_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        reporter = JsonReporter()
        result = _make_result()
        reporter.render(result, out)
        data = json.loads(out.read_text())
        assert data["findings"] == []

    def test_json_round_trip(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        reporter = JsonReporter()
        result = _make_result(
            [
                _make_finding(severity=Severity.CRITICAL),
                _make_finding(rule_id="AW-TOOL-002", severity=Severity.MEDIUM),
            ]
        )
        reporter.render(result, out)
        data = json.loads(out.read_text())
        assert data["framework"] == "langchain"
        assert data["scanned_files"] == 3
        assert len(data["findings"]) == 2


class TestSarifReporter:
    def test_render_creates_valid_sarif(self, tmp_path: Path) -> None:
        out = tmp_path / "report.sarif"
        reporter = SarifReporter()
        result = _make_result([_make_finding()])
        reporter.render(result, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"
        assert "$schema" in data
        assert len(data["runs"]) == 1

    def test_sarif_has_rules(self) -> None:
        result = _make_result([_make_finding()])
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        driver = runs[0]["tool"]["driver"]  # type: ignore[index]
        rules = driver["rules"]  # type: ignore[index]
        assert len(rules) == 10  # 5 MEM + 5 TOOL rules

    def test_sarif_results_map_to_findings(self) -> None:
        findings = [
            _make_finding(severity=Severity.CRITICAL),
            _make_finding(rule_id="AW-TOOL-001", severity=Severity.HIGH),
        ]
        result = _make_result(findings)
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        results = runs[0]["results"]  # type: ignore[index]
        assert len(results) == 2
        assert results[0]["ruleId"] == "AW-MEM-001"  # type: ignore[index]
        assert results[1]["ruleId"] == "AW-TOOL-001"  # type: ignore[index]

    def test_sarif_severity_mapping(self) -> None:
        result = _make_result(
            [
                _make_finding(severity=Severity.CRITICAL),
                _make_finding(rule_id="AW-MEM-005", severity=Severity.MEDIUM),
                _make_finding(rule_id="AW-TOOL-004", severity=Severity.LOW),
            ]
        )
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        results = runs[0]["results"]  # type: ignore[index]
        assert results[0]["level"] == "error"  # type: ignore[index]
        assert results[1]["level"] == "warning"  # type: ignore[index]
        assert results[2]["level"] == "note"  # type: ignore[index]

    def test_sarif_finding_with_location(self) -> None:
        result = _make_result([_make_finding(file=Path("src/agent.py"), line=10)])
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        results = runs[0]["results"]  # type: ignore[index]
        locations = results[0]["locations"]  # type: ignore[index]
        assert len(locations) == 1
        phys = locations[0]["physicalLocation"]
        assert phys["artifactLocation"]["uri"] == "src/agent.py"
        assert phys["region"]["startLine"] == 10

    def test_sarif_finding_without_file(self) -> None:
        result = _make_result([_make_finding(file=None, line=None)])
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        results = runs[0]["results"]  # type: ignore[index]
        assert "locations" not in results[0]  # type: ignore[index]

    def test_sarif_empty_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "report.sarif"
        reporter = SarifReporter()
        result = _make_result()
        reporter.render(result, out)
        data = json.loads(out.read_text())
        runs = data["runs"]
        assert runs[0]["results"] == []

    def test_sarif_properties_bag(self) -> None:
        finding = _make_finding()
        finding = finding.model_copy(update={"layer": "L1"})
        result = _make_result([finding])
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        props = runs[0]["results"][0]["properties"]  # type: ignore[index]
        assert props["agentwall:confidence"] == "high"
        assert props["agentwall:fix"] == "Test fix"
        assert props["agentwall:layer"] == "L1"

    def test_sarif_invocation(self) -> None:
        result = _make_result()
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        invocations = runs[0]["invocations"]  # type: ignore[index]
        assert invocations[0]["executionSuccessful"] is True

    def test_sarif_extension_properties(self) -> None:
        finding = _make_finding(file=Path("src/agent.py"), line=10)
        result = _make_result([finding])
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        props = runs[0]["results"][0]["properties"]  # type: ignore[index]
        assert (
            props["agentwall:verification_command"]
            == "agentwall verify --finding AW-MEM-001 src/agent.py"
        )
        assert props["agentwall:attack_vector"] == "AW-ATK-MEM-001"

    def test_sarif_version_from_module(self) -> None:
        from agentwall import __version__

        result = _make_result()
        sarif = build_sarif(result)
        runs = sarif["runs"]
        assert isinstance(runs, list)
        driver = runs[0]["tool"]["driver"]  # type: ignore[index]
        assert driver["version"] == __version__


class TestAgentJsonReporter:
    def test_render_creates_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        reporter = AgentJsonReporter()
        result = _make_result([_make_finding()])
        reporter.render(result, out)
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["scanner"] == "agentwall"
        assert data["total_findings"] == 1

    def test_agent_json_structure(self) -> None:
        result = _make_result([_make_finding()])
        data = build_agent_json(result)
        assert data["schema_version"] == "1.0"
        from agentwall import __version__

        assert data["scanner_version"] == __version__
        assert data["framework"] == "langchain"
        assert data["scanned_files"] == 3

    def test_agent_json_finding_fields(self) -> None:
        finding = _make_finding(
            rule_id="AW-MEM-001",
            severity=Severity.CRITICAL,
            file=Path("src/agent.py"),
            line=10,
        )
        result = _make_result([finding])
        data = build_agent_json(result)
        f = data["findings"]
        assert isinstance(f, list)
        entry = f[0]
        assert entry["rule_id"] == "AW-MEM-001"
        assert entry["severity"] == "critical"
        assert entry["confidence"] == "high"
        assert entry["file"] == "src/agent.py"
        assert entry["line"] == 10
        assert entry["fix_suggestion"] == "Test fix"
        assert entry["framework_detected"] == "langchain"
        assert entry["affected_component"] == "memory_store"
        assert entry["attack_vector_id"] == "AW-ATK-MEM-001"
        assert "remediation_hint" in entry

    def test_agent_json_tool_finding(self) -> None:
        finding = Finding(
            rule_id="AW-TOOL-001",
            title="Tool finding",
            severity=Severity.HIGH,
            category=Category.TOOL,
            description="Tool desc",
            fix="Tool fix",
        )
        result = _make_result([finding])
        data = build_agent_json(result)
        entry = data["findings"]
        assert isinstance(entry, list)
        assert entry[0]["affected_component"] == "tool_registration"
        assert entry[0]["attack_vector_id"] == "AW-ATK-AGT-001"

    def test_agent_json_finding_no_file(self) -> None:
        result = _make_result([_make_finding(file=None, line=None)])
        data = build_agent_json(result)
        entry = data["findings"]
        assert isinstance(entry, list)
        assert entry[0]["file"] is None
        assert entry[0]["line"] is None

    def test_agent_json_empty_findings(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        reporter = AgentJsonReporter()
        result = _make_result()
        reporter.render(result, out)
        data = json.loads(out.read_text())
        assert data["findings"] == []
        assert data["total_findings"] == 0

    def test_agent_json_severity_counts(self) -> None:
        result = _make_result(
            [
                _make_finding(severity=Severity.CRITICAL),
                _make_finding(rule_id="AW-TOOL-001", severity=Severity.HIGH),
                _make_finding(rule_id="AW-MEM-005", severity=Severity.HIGH),
            ]
        )
        data = build_agent_json(result)
        counts = data["severity_counts"]
        assert isinstance(counts, dict)
        assert counts["critical"] == 1
        assert counts["high"] == 2

    def test_agent_json_confidence_counts(self) -> None:
        result = _make_result(
            [
                _make_finding(severity=Severity.CRITICAL),
                _make_finding(rule_id="AW-TOOL-001", severity=Severity.HIGH).model_copy(
                    update={"confidence": ConfidenceLevel.MEDIUM}
                ),
                _make_finding(rule_id="AW-MEM-005", severity=Severity.MEDIUM).model_copy(
                    update={"confidence": ConfidenceLevel.LOW}
                ),
            ]
        )
        data = build_agent_json(result)
        counts = data["confidence_counts"]
        assert isinstance(counts, dict)
        assert counts["high"] == 1
        assert counts["medium"] == 1
        assert counts["low"] == 1

    def test_agent_json_file_context(self) -> None:
        f = _make_finding().model_copy(update={"file_context": "test file"})
        result = _make_result([f])
        data = build_agent_json(result)
        entry = data["findings"]
        assert isinstance(entry, list)
        assert entry[0]["file_context"] == "test file"

    def test_agent_json_unknown_rule_fallback(self) -> None:
        finding = Finding(
            rule_id="AW-CUSTOM-999",
            title="Custom",
            severity=Severity.LOW,
            category=Category.MEMORY,
            description="Custom desc",
        )
        result = _make_result([finding])
        data = build_agent_json(result)
        entry = data["findings"]
        assert isinstance(entry, list)
        assert entry[0]["attack_vector_id"] is None
        assert entry[0]["remediation_hint"] == "Review and fix manually."

    def test_agent_json_detection_layer(self) -> None:
        finding = _make_finding()
        finding = finding.model_copy(update={"layer": "L1"})
        result = _make_result([finding])
        data = build_agent_json(result)
        entry = data["findings"]
        assert isinstance(entry, list)
        assert entry[0]["detection_layer"] == "L1"

    def test_agent_json_verification_field(self) -> None:
        finding = _make_finding(file=Path("src/agent.py"))
        result = _make_result([finding])
        data = build_agent_json(result)
        entry = data["findings"]
        assert isinstance(entry, list)
        assert entry[0]["verification"] == "agentwall verify --finding AW-MEM-001 src/agent.py"

    def test_agent_json_false_positive_hint(self) -> None:
        finding = _make_finding()
        result = _make_result([finding])
        data = build_agent_json(result)
        entry = data["findings"]
        assert isinstance(entry, list)
        hint = entry[0]["false_positive_hint"]
        assert isinstance(hint, str)
        assert len(hint) > 0

    def test_agent_json_related_findings(self) -> None:
        """Findings sharing the same rule_id should appear as related."""
        f1 = _make_finding(file=Path("a.py"), line=1)
        f2 = _make_finding(file=Path("b.py"), line=5)
        f3 = _make_finding(rule_id="AW-TOOL-001", file=Path("c.py"), line=10)
        result = _make_result([f1, f2, f3])
        data = build_agent_json(result)
        findings = data["findings"]
        assert isinstance(findings, list)
        # f1 should list f2 as related (same rule_id), not f3
        related_0 = findings[0]["related_findings"]
        assert isinstance(related_0, list)
        assert len(related_0) == 1
        assert related_0[0]["file"] == "b.py"
        # f3 (different rule) should have no related
        related_2 = findings[2]["related_findings"]
        assert isinstance(related_2, list)
        assert len(related_2) == 0

    def test_agent_json_no_file_verification(self) -> None:
        finding = _make_finding(file=None, line=None)
        result = _make_result([finding])
        data = build_agent_json(result)
        entry = data["findings"]
        assert isinstance(entry, list)
        assert entry[0]["verification"] == "agentwall verify --finding AW-MEM-001 ."


class TestPatchReporter:
    def test_render_creates_file(self, tmp_path: Path) -> None:
        out = tmp_path / "report.patch"
        reporter = PatchReporter()
        result = _make_result([_make_finding()])
        reporter.render(result, out)
        assert out.exists()

    def test_patch_manual_for_unfixable(self) -> None:
        finding = _make_finding(rule_id="AW-MEM-005")
        result = _make_result([finding])
        patch = build_patch(result)
        assert "AW-MEM-005" in patch
        assert "manual intervention" in patch

    def test_patch_manual_for_no_file(self) -> None:
        finding = _make_finding(file=None, line=None, rule_id="AW-TOOL-005")
        result = _make_result([finding])
        patch = build_patch(result)
        assert "AW-TOOL-005" in patch
        assert "manual intervention" in patch

    def test_patch_auto_fix_mem001(self, tmp_path: Path) -> None:
        # Create a source file with an unfixed similarity_search call
        src = tmp_path / "agent.py"
        src.write_text(
            "docs = vectorstore.similarity_search(query)\n",
            encoding="utf-8",
        )
        finding = Finding(
            rule_id="AW-MEM-001",
            title="No tenant isolation",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="No filter",
            fix="Add filter",
            file=src,
            line=1,
        )
        result = _make_result([finding])
        patch = build_patch(result)
        assert "---" in patch
        assert "+++" in patch
        assert "user_id" in patch

    def test_patch_auto_fix_mem001_with_args(self, tmp_path: Path) -> None:
        src = tmp_path / "agent.py"
        src.write_text(
            "docs = vectorstore.similarity_search(query, k=5)\n",
            encoding="utf-8",
        )
        finding = Finding(
            rule_id="AW-MEM-001",
            title="No tenant isolation",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="No filter",
            fix="Add filter",
            file=src,
            line=1,
        )
        result = _make_result([finding])
        patch = build_patch(result)
        assert "user_id" in patch
        assert "k=5" in patch

    def test_patch_auto_fix_retriever(self, tmp_path: Path) -> None:
        src = tmp_path / "agent.py"
        src.write_text(
            "retriever = vectorstore.as_retriever()\n",
            encoding="utf-8",
        )
        finding = Finding(
            rule_id="AW-MEM-001",
            title="No tenant isolation",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="No filter",
            fix="Add filter",
            file=src,
            line=1,
        )
        result = _make_result([finding])
        patch = build_patch(result)
        assert "user_id" in patch
        assert "search_kwargs" in patch

    def test_patch_unreadable_file(self) -> None:
        finding = Finding(
            rule_id="AW-MEM-001",
            title="No tenant isolation",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="No filter",
            fix="Add filter",
            file=Path("/nonexistent/file.py"),
            line=1,
        )
        result = _make_result([finding])
        patch = build_patch(result)
        assert "manual intervention" in patch

    def test_patch_empty_findings(self) -> None:
        result = _make_result()
        patch = build_patch(result)
        assert patch == ""

    def test_patch_finding_line_out_of_range(self, tmp_path: Path) -> None:
        src = tmp_path / "agent.py"
        src.write_text("x = 1\n", encoding="utf-8")
        finding = Finding(
            rule_id="AW-MEM-001",
            title="No tenant isolation",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="No filter",
            fix="Add filter",
            file=src,
            line=999,
        )
        result = _make_result([finding])
        patch = build_patch(result)
        assert "manual intervention" in patch

    def test_patch_finding_no_line(self, tmp_path: Path) -> None:
        src = tmp_path / "agent.py"
        src.write_text("docs = vectorstore.similarity_search(query)\n", encoding="utf-8")
        finding = Finding(
            rule_id="AW-MEM-001",
            title="No tenant isolation",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="No filter",
            fix="Add filter",
            file=src,
            line=None,
        )
        result = _make_result([finding])
        patch = build_patch(result)
        assert "manual intervention" in patch

    def test_patch_nested_parens_falls_back_to_manual(self, tmp_path: Path) -> None:
        """Nested parens like get_k(config) should fall back to manual comment."""
        src = tmp_path / "agent.py"
        src.write_text(
            "docs = vectorstore.similarity_search(query, k=get_k(config))\n",
            encoding="utf-8",
        )
        finding = Finding(
            rule_id="AW-MEM-001",
            title="No tenant isolation",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="No filter",
            fix="Add filter",
            file=src,
            line=1,
        )
        result = _make_result([finding])
        patch = build_patch(result)
        assert "manual intervention" in patch
        # Should NOT produce a broken diff
        assert "---" not in patch

    def test_patch_applies_cleanly(self, tmp_path: Path) -> None:
        """Generate a patch and validate it applies cleanly."""
        src = tmp_path / "agent.py"
        source_code = "docs = vectorstore.similarity_search(query)\n"
        src.write_text(source_code, encoding="utf-8")
        finding = Finding(
            rule_id="AW-MEM-001",
            title="No tenant isolation",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="No filter",
            fix="Add filter",
            file=src,
            line=1,
        )
        result = _make_result([finding])
        patch_text = build_patch(result)

        # Validate the unified diff format programmatically
        assert patch_text.startswith("---"), "Patch should start with --- header"
        lines = patch_text.splitlines()
        assert any(line.startswith("+++") for line in lines), "Patch should have +++ header"
        assert any(line.startswith("@@") for line in lines), "Patch should have @@ hunk header"
        assert any(line.startswith("-") and not line.startswith("---") for line in lines), (
            "Patch should have removed lines"
        )
        assert any(line.startswith("+") and not line.startswith("+++") for line in lines), (
            "Patch should have added lines"
        )

        # Verify the patch content makes sense: the added line should have user_id filter
        added_lines = [ln for ln in lines if ln.startswith("+") and not ln.startswith("+++")]
        assert any("user_id" in ln for ln in added_lines)

        # Try applying with `patch` if available, otherwise skip gracefully
        import shutil
        import subprocess

        if shutil.which("patch") is not None:
            proc = subprocess.run(
                ["patch", "-p1", "--dry-run"],
                input=patch_text,
                capture_output=True,
                text=True,
                cwd="/",
            )
            assert proc.returncode == 0, f"Patch failed to apply: {proc.stdout}\n{proc.stderr}"
