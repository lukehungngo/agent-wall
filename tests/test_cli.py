"""Tests for the CLI."""

from __future__ import annotations

import json
from pathlib import Path

from typer.testing import CliRunner

from agentwall.cli import app

runner = CliRunner()

FIXTURES = Path(__file__).parent / "fixtures"


class TestCliScan:
    def test_scan_unsafe_exits_1(self) -> None:
        result = runner.invoke(app, ["scan", str(FIXTURES / "langchain_unsafe")])
        assert result.exit_code == 1

    def test_scan_safe_exits_0(self) -> None:
        result = runner.invoke(
            app, ["scan", str(FIXTURES / "langchain_safe"), "--fail-on", "critical"]
        )
        assert result.exit_code == 0

    def test_scan_nonexistent_exits_2(self) -> None:
        result = runner.invoke(app, ["scan", "/nonexistent/path"])
        assert result.exit_code == 2
        assert "does not exist" in result.output

    def test_scan_invalid_fail_on_exits_2(self) -> None:
        result = runner.invoke(
            app, ["scan", str(FIXTURES / "langchain_basic"), "--fail-on", "bogus"]
        )
        assert result.exit_code == 2

    def test_scan_fail_on_none_exits_0(self) -> None:
        result = runner.invoke(
            app, ["scan", str(FIXTURES / "langchain_unsafe"), "--fail-on", "none"]
        )
        assert result.exit_code == 0

    def test_scan_fast_mode(self) -> None:
        result = runner.invoke(
            app, ["scan", str(FIXTURES / "langchain_basic"), "--fast", "--fail-on", "none"]
        )
        assert result.exit_code == 0
        assert "AgentWall" in result.output

    def test_scan_custom_layers(self) -> None:
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES / "langchain_basic"), "--layers", "L0,L1", "--fail-on", "none"],
        )
        assert result.exit_code == 0

    def test_scan_invalid_layer_exits_2(self) -> None:
        result = runner.invoke(app, ["scan", str(FIXTURES / "langchain_basic"), "--layers", "L99"])
        assert result.exit_code == 2
        assert "unknown layers" in result.output

    def test_scan_json_output(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES / "langchain_basic"), "--output", str(out), "--fail-on", "none"],
        )
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_framework_override(self) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                str(FIXTURES / "langchain_basic"),
                "--framework",
                "langchain",
                "--fail-on",
                "none",
            ],
        )
        assert result.exit_code == 0

    def test_scan_unsupported_framework_exits_2(self) -> None:
        result = runner.invoke(
            app, ["scan", str(FIXTURES / "langchain_basic"), "--framework", "crewai"]
        )
        assert result.exit_code == 2

    def test_scan_format_sarif(self, tmp_path: Path) -> None:
        out = tmp_path / "report.sarif"
        result = runner.invoke(
            app,
            [
                "scan",
                str(FIXTURES / "langchain_basic"),
                "--format",
                "sarif",
                "--output",
                str(out),
                "--fail-on",
                "none",
            ],
        )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["version"] == "2.1.0"

    def test_scan_format_agent_json(self, tmp_path: Path) -> None:
        out = tmp_path / "report.json"
        result = runner.invoke(
            app,
            [
                "scan",
                str(FIXTURES / "langchain_basic"),
                "--format",
                "agent-json",
                "--output",
                str(out),
                "--fail-on",
                "none",
            ],
        )
        assert result.exit_code == 0
        assert out.exists()
        data = json.loads(out.read_text())
        assert data["scanner"] == "agentwall"

    def test_scan_format_patch(self, tmp_path: Path) -> None:
        out = tmp_path / "report.patch"
        result = runner.invoke(
            app,
            [
                "scan",
                str(FIXTURES / "langchain_basic"),
                "--format",
                "patch",
                "--output",
                str(out),
                "--fail-on",
                "none",
            ],
        )
        assert result.exit_code == 0
        assert out.exists()

    def test_scan_invalid_format_exits_2(self) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                str(FIXTURES / "langchain_basic"),
                "--format",
                "xml",
            ],
        )
        assert result.exit_code == 2
        assert "--format must be one of" in result.output


    def test_scan_confidence_filter_high(self) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                str(FIXTURES / "langchain_unsafe"),
                "--confidence",
                "high",
                "--format",
                "json",
                "--fail-on",
                "none",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        # All remaining findings should have high confidence
        for f in data["findings"]:
            assert f["confidence"] == "high"

    def test_scan_confidence_filter_all(self) -> None:
        result = runner.invoke(
            app,
            [
                "scan",
                str(FIXTURES / "langchain_unsafe"),
                "--confidence",
                "all",
                "--fail-on",
                "none",
            ],
        )
        assert result.exit_code == 0

    def test_scan_confidence_invalid_exits_2(self) -> None:
        result = runner.invoke(
            app,
            ["scan", str(FIXTURES / "langchain_basic"), "--confidence", "bogus"],
        )
        assert result.exit_code == 2
        assert "--confidence must be one of" in result.output


class TestCliVerify:
    def test_verify_finding_present(self) -> None:
        result = runner.invoke(
            app,
            [
                "verify",
                "--finding",
                "AW-MEM-001",
                str(FIXTURES / "langchain_unsafe"),
            ],
        )
        assert result.exit_code == 1
        assert "FAIL" in result.output

    def test_verify_finding_resolved(self) -> None:
        result = runner.invoke(
            app,
            [
                "verify",
                "--finding",
                "AW-MEM-001",
                str(FIXTURES / "langchain_safe"),
            ],
        )
        assert result.exit_code == 0
        assert "PASS" in result.output

    def test_verify_unknown_rule(self) -> None:
        result = runner.invoke(
            app,
            [
                "verify",
                "--finding",
                "AW-FAKE-999",
                str(FIXTURES / "langchain_basic"),
            ],
        )
        assert result.exit_code == 2
        assert "unknown rule ID" in result.output

    def test_verify_nonexistent_path(self) -> None:
        result = runner.invoke(
            app,
            [
                "verify",
                "--finding",
                "AW-MEM-001",
                "/nonexistent/path",
            ],
        )
        assert result.exit_code == 2
        assert "does not exist" in result.output

    def test_verify_json_format_pass(self) -> None:
        result = runner.invoke(
            app,
            [
                "verify",
                "--finding",
                "AW-MEM-001",
                str(FIXTURES / "langchain_safe"),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 0
        data = json.loads(result.output)
        assert data["status"] == "PASS"
        assert data["finding_count"] == 0

    def test_verify_json_format_fail(self) -> None:
        result = runner.invoke(
            app,
            [
                "verify",
                "--finding",
                "AW-MEM-001",
                str(FIXTURES / "langchain_unsafe"),
                "--format",
                "json",
            ],
        )
        assert result.exit_code == 1
        data = json.loads(result.output)
        assert data["status"] == "FAIL"
        assert data["finding_count"] >= 1


class TestCliVersion:
    def test_version_output(self) -> None:
        result = runner.invoke(app, ["version"])
        assert result.exit_code == 0
        assert "AgentWall v" in result.output
