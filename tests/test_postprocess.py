"""Tests for finding post-processing: dedup, file context, sort."""

from pathlib import Path

from agentwall.models import Category, ConfidenceLevel, Finding, Severity


class TestClassifyFileContext:
    def test_test_directory(self) -> None:
        from agentwall.postprocess import classify_file_context

        assert classify_file_context(Path("tests/test_foo.py")) == "test file"

    def test_example_directory(self) -> None:
        from agentwall.postprocess import classify_file_context

        assert classify_file_context(Path("examples/demo.py")) == "example"

    def test_regular_file(self) -> None:
        from agentwall.postprocess import classify_file_context

        assert classify_file_context(Path("src/app.py")) is None

    def test_none_path(self) -> None:
        from agentwall.postprocess import classify_file_context

        assert classify_file_context(None) is None


def _make_finding(
    rule_id: str = "AW-MEM-001",
    severity: Severity = Severity.CRITICAL,
    file: str | None = "app.py",
    line: int | None = 10,
    layer: str | None = "L1",
    proof_strength: str | None = None,
) -> Finding:
    return Finding(
        rule_id=rule_id,
        title="test",
        severity=severity,
        category=Category.MEMORY,
        description="test",
        file=Path(file) if file else None,
        line=line,
        layer=layer,
        proof_strength=proof_strength,
    )


class TestDedupFindings:
    def test_no_duplicates_unchanged(self) -> None:
        from agentwall.postprocess import dedup

        findings = [_make_finding(line=1), _make_finding(line=2)]
        assert len(dedup(findings)) == 2

    def test_asm_confirmed_replaces_l1(self) -> None:
        from agentwall.postprocess import dedup

        l1 = _make_finding(layer="L1")
        asm = _make_finding(layer="ASM", proof_strength="confirmed")
        result = dedup([l1, asm])
        assert len(result) == 1
        assert result[0].layer == "ASM"

    def test_l1_replaces_asm_uncertain(self) -> None:
        from agentwall.postprocess import dedup

        l1 = _make_finding(layer="L1")
        asm = _make_finding(layer="ASM", proof_strength="uncertain")
        result = dedup([l1, asm])
        assert len(result) == 1
        assert result[0].layer == "L1"


class TestSortFindings:
    def test_critical_before_high(self) -> None:
        from agentwall.postprocess import sort

        high = _make_finding(severity=Severity.HIGH)
        crit = _make_finding(severity=Severity.CRITICAL)
        result = sort([high, crit])
        assert result[0].severity == Severity.CRITICAL

    def test_same_severity_sorts_by_confidence(self) -> None:
        from agentwall.postprocess import sort

        low_conf = _make_finding(severity=Severity.HIGH)
        low_conf = low_conf.model_copy(update={"confidence": ConfidenceLevel.LOW})
        high_conf = _make_finding(severity=Severity.HIGH)
        high_conf = high_conf.model_copy(update={"confidence": ConfidenceLevel.HIGH})
        result = sort([low_conf, high_conf])
        assert result[0].confidence == ConfidenceLevel.HIGH


class TestApplyFileContext:
    def test_test_file_gets_context_tag(self) -> None:
        from agentwall.postprocess import apply_file_context

        f = _make_finding(file="tests/test_app.py")
        result = apply_file_context([f])
        assert result[0].file_context == "test file"

    def test_test_file_confidence_capped_to_low(self) -> None:
        from agentwall.postprocess import apply_file_context

        f = _make_finding(file="tests/test_app.py")
        result = apply_file_context([f])
        assert result[0].confidence == ConfidenceLevel.LOW
