"""Finding post-processing: dedup, file context classification, sorting."""

from __future__ import annotations

from pathlib import Path

from agentwall.models import (
    CONFIDENCE_RANK,
    ConfidenceLevel,
    Finding,
    Severity,
)

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

_TEST_DIRS = frozenset({"tests", "test"})
_EXAMPLE_DIRS = frozenset({"examples", "example", "docs"})


def classify_file_context(file_path: Path | None) -> str | None:
    """Classify a file path as test/example context, or None."""
    if file_path is None:
        return None
    name = file_path.name
    parts = file_path.parts
    if any(p in _TEST_DIRS for p in parts) or name.startswith("test_") or name.endswith("_test.py"):
        return "test file"
    if any(p in _EXAMPLE_DIRS for p in parts) or name.endswith(".example"):
        return "example"
    return None


def apply_file_context(findings: list[Finding]) -> list[Finding]:
    """Tag findings with file context and cap confidence for test/example files."""
    result: list[Finding] = []
    for f in findings:
        ctx = classify_file_context(f.file)
        if ctx is not None:
            updates: dict[str, object] = {"file_context": ctx}
            if f.confidence != ConfidenceLevel.LOW:
                updates["confidence"] = ConfidenceLevel.LOW
            result.append(f.model_copy(update=updates))
        else:
            result.append(f)
    return result


def sort(findings: list[Finding]) -> list[Finding]:
    """Sort findings by severity (CRITICAL first), then confidence."""
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK[f.severity], CONFIDENCE_RANK[f.confidence]),
    )


def dedup(findings: list[Finding]) -> list[Finding]:
    """Remove duplicate findings (same rule_id + file + line).

    When ASM and L1 both fire on the same location:
    - ASM with confirmed/possible proof replaces L1
    - L1 replaces ASM with uncertain proof
    """
    grouped: dict[tuple[str, str | None, int | None], list[Finding]] = {}
    for f in findings:
        key = (f.rule_id, str(f.file) if f.file else None, f.line)
        grouped.setdefault(key, []).append(f)

    result: list[Finding] = []
    for group in grouped.values():
        if len(group) == 1:
            result.append(group[0])
            continue
        asm = [f for f in group if f.layer == "ASM"]
        non_asm = [f for f in group if f.layer != "ASM"]
        if asm and non_asm:
            best_asm = asm[0]
            if best_asm.proof_strength in ("confirmed", "possible"):
                result.append(best_asm)
            else:
                result.append(non_asm[0])
        else:
            result.append(group[0])
    return result
