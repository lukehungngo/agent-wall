"""End-to-end scanner tests."""

from __future__ import annotations

from pathlib import Path

from agentwall.models import Category, ConfidenceLevel, Finding, ScanConfig, Severity
from agentwall.postprocess import (
    apply_file_context,
    classify_file_context,
    dedup,
    sort,
)
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
    def test_unsupported_framework_returns_warning_not_error(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe", framework="crewai")
        assert not result.errors, "unsupported framework should not populate errors"
        assert not result.findings
        assert result.warnings
        assert "unsupported" in result.warnings[0].lower() or "undetected" in result.warnings[0].lower()

    def test_langchain_override_works(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe", framework="langchain")
        assert result.framework == "langchain"
        assert result.findings


class TestFileContextClassification:
    def test_test_directory(self) -> None:
        assert classify_file_context(Path("tests/test_agent.py")) == "test file"

    def test_test_prefix(self) -> None:
        assert classify_file_context(Path("src/test_utils.py")) == "test file"

    def test_test_suffix(self) -> None:
        assert classify_file_context(Path("src/agent_test.py")) == "test file"

    def test_example_directory(self) -> None:
        assert classify_file_context(Path("examples/demo.py")) == "example"

    def test_example_extension(self) -> None:
        assert classify_file_context(Path("config.example")) == "example"

    def test_docs_directory(self) -> None:
        assert classify_file_context(Path("docs/guide.py")) == "example"

    def test_production_file(self) -> None:
        assert classify_file_context(Path("src/agent.py")) is None

    def test_none_path(self) -> None:
        assert classify_file_context(None) is None

    # Negative cases — production files must NOT be classified
    def test_contest_handler_not_test(self) -> None:
        assert classify_file_context(Path("src/contest_handler.py")) is None

    def test_latest_config_not_test(self) -> None:
        assert classify_file_context(Path("src/latest_config.py")) is None

    def test_backtest_not_test(self) -> None:
        assert classify_file_context(Path("src/backtest.py")) is None

    def test_protest_not_test(self) -> None:
        assert classify_file_context(Path("src/protest_handler.py")) is None

    def test_example_utils_not_example(self) -> None:
        assert classify_file_context(Path("src/example_utils.py")) is None


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
        result = apply_file_context([f])
        assert result[0].confidence == ConfidenceLevel.LOW
        assert result[0].file_context == "test file"

    def test_caps_example_to_low(self) -> None:
        f = self._make_finding(file=Path("examples/demo.py"), confidence=ConfidenceLevel.MEDIUM)
        result = apply_file_context([f])
        assert result[0].confidence == ConfidenceLevel.LOW
        assert result[0].file_context == "example"

    def test_keeps_low_as_low(self) -> None:
        f = self._make_finding(file=Path("tests/test_agent.py"), confidence=ConfidenceLevel.LOW)
        result = apply_file_context([f])
        assert result[0].confidence == ConfidenceLevel.LOW

    def test_no_cap_for_production(self) -> None:
        f = self._make_finding(file=Path("src/agent.py"), confidence=ConfidenceLevel.HIGH)
        result = apply_file_context([f])
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
        sorted_f = sort(findings)
        assert sorted_f[0].confidence == ConfidenceLevel.HIGH
        assert sorted_f[1].confidence == ConfidenceLevel.MEDIUM
        assert sorted_f[2].confidence == ConfidenceLevel.LOW

    def test_severity_takes_precedence(self) -> None:
        findings = [
            self._make_finding(Severity.MEDIUM, ConfidenceLevel.HIGH),
            self._make_finding(Severity.CRITICAL, ConfidenceLevel.LOW),
        ]
        sorted_f = sort(findings)
        assert sorted_f[0].severity == Severity.CRITICAL
        assert sorted_f[1].severity == Severity.MEDIUM


# ── ASM Integration ─────────────────────────────────────────────────────


class TestASMIntegration:
    def test_asm_findings_in_shadow_mode_not_in_output(self) -> None:
        config = ScanConfig.default()
        config.asm_shadow = True
        result = scan(FIXTURES / "asm_lifecycle", config=config)
        asm_findings = [f for f in result.findings if f.layer == "ASM"]
        assert len(asm_findings) == 0

    def test_asm_findings_included_when_not_shadow(self) -> None:
        result = scan(FIXTURES / "asm_lifecycle")
        asm_findings = [f for f in result.findings if f.layer == "ASM"]
        assert len(asm_findings) >= 1

    def test_fast_mode_skips_asm(self) -> None:
        config = ScanConfig.fast()
        result = scan(FIXTURES / "asm_lifecycle", config=config)
        asm_findings = [f for f in result.findings if f.layer == "ASM"]
        assert len(asm_findings) == 0

    def test_asm_safe_no_tenant_isolation_findings(self) -> None:
        result = scan(FIXTURES / "asm_safe")
        tenant_findings = [
            f for f in result.findings
            if f.layer == "ASM" and f.rule_id in ("AW-MEM-001", "AW-MEM-002", "AW-MEM-003")
        ]
        assert len(tenant_findings) == 0

    def test_existing_l1_findings_still_present(self) -> None:
        result = scan(FIXTURES / "langchain_unsafe")
        l1_findings = [f for f in result.findings if f.layer == "L1"]
        assert len(l1_findings) >= 1


# ── ASM Dedup ───────────────────────────────────────────────────────────


class TestASMDedup:
    def _finding(
        self, layer: str, proof: str | None = None, line: int = 10
    ) -> Finding:
        return Finding(
            rule_id="AW-MEM-001",
            title="Test",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="Test",
            file=Path("app.py"),
            line=line,
            layer=layer,
            proof_strength=proof,
            evidence_path=[{"type": "Store"}] if proof else None,
        )

    def test_asm_confirmed_replaces_l1(self) -> None:
        l1 = self._finding("L1")
        asm = self._finding("ASM", proof="confirmed")
        result = dedup([l1, asm])
        assert len(result) == 1
        assert result[0].layer == "ASM"

    def test_l1_kept_when_asm_uncertain(self) -> None:
        l1 = self._finding("L1")
        asm = self._finding("ASM", proof="uncertain")
        result = dedup([l1, asm])
        assert len(result) == 1
        assert result[0].layer == "L1"

    def test_both_kept_on_different_lines(self) -> None:
        l1 = self._finding("L1", line=10)
        asm = self._finding("ASM", proof="confirmed", line=20)
        result = dedup([l1, asm])
        assert len(result) == 2


# ── Registry Resolver ─────────────────────────────────────────────────────


class TestResolveOrder:
    def test_respects_depends_on(self) -> None:
        from agentwall.scanner import _resolve_order

        class FakeL1:
            name = "L1"
            depends_on: tuple[str, ...] = ()

        class FakeL3:
            name = "L3"
            depends_on = ("L2",)

        class FakeL2:
            name = "L2"
            depends_on = ("L1",)

        result = _resolve_order([FakeL3, FakeL1, FakeL2], enabled={"L1", "L2", "L3"})
        names = [cls.name for cls in result]
        assert names.index("L1") < names.index("L2")
        assert names.index("L2") < names.index("L3")

    def test_filters_by_enabled_layers(self) -> None:
        from agentwall.scanner import _resolve_order

        class FakeL1:
            name = "L1"
            depends_on: tuple[str, ...] = ()

        class FakeL2:
            name = "L2"
            depends_on = ("L1",)

        result = _resolve_order([FakeL1, FakeL2], enabled={"L1"})
        names = [cls.name for cls in result]
        assert "L2" not in names

    def test_auto_includes_transitive_deps(self) -> None:
        from agentwall.scanner import _resolve_order

        class FakeL1:
            name = "L1"
            depends_on: tuple[str, ...] = ()

        class FakeL2:
            name = "L2"
            depends_on = ("L1",)

        class FakeL3:
            name = "L3"
            depends_on = ("L2",)

        result = _resolve_order([FakeL1, FakeL2, FakeL3], enabled={"L3"})
        names = [cls.name for cls in result]
        assert "L2" in names
        assert "L1" in names

    def test_asm_runs_after_l2(self) -> None:
        from agentwall.scanner import _resolve_order

        class FakeL1:
            name = "L1-memory"
            depends_on: tuple[str, ...] = ()

        class FakeL2:
            name = "L2"
            depends_on = ("L1-memory",)

        class FakeASM:
            name = "ASM"
            depends_on = ("L2",)

        result = _resolve_order([FakeASM, FakeL1, FakeL2], enabled={"ASM", "L2", "L1-memory"})
        names = [cls.name for cls in result]
        assert names.index("L2") < names.index("ASM")

    def test_l6_runs_after_l3(self) -> None:
        from agentwall.scanner import _resolve_order

        class FakeL2:
            name = "L2"
            depends_on: tuple[str, ...] = ()

        class FakeL3:
            name = "L3"
            depends_on = ("L2",)

        class FakeL6:
            name = "L6"
            depends_on = ("L3",)

        result = _resolve_order([FakeL6, FakeL2, FakeL3], enabled={"L2", "L3", "L6"})
        names = [cls.name for cls in result]
        assert names.index("L3") < names.index("L6")

    def test_raises_on_dependency_cycle(self) -> None:
        import pytest

        from agentwall.scanner import _resolve_order

        class FakeA:
            name = "A"
            depends_on = ("B",)

        class FakeB:
            name = "B"
            depends_on = ("A",)

        with pytest.raises(ValueError, match="cycle"):
            _resolve_order([FakeA, FakeB], enabled={"A", "B"})
