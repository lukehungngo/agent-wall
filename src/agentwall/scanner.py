"""Scanner orchestrator — ties together all analysis layers."""

from __future__ import annotations

import logging
import warnings
from pathlib import Path

from agentwall.adapters.langchain import LangChainAdapter
from agentwall.analyzers.asm import ASMAnalyzer
from agentwall.analyzers.callgraph import CallGraphAnalyzer
from agentwall.analyzers.config import ConfigAuditor
from agentwall.analyzers.memory import MemoryAnalyzer
from agentwall.analyzers.semgrep import SemgrepAnalyzer
from agentwall.analyzers.symbolic import SymbolicAnalyzer
from agentwall.analyzers.taint import TaintAnalyzer
from agentwall.analyzers.tools import ToolAnalyzer
from agentwall.detector import auto_detect_framework
from agentwall.models import (
    CONFIDENCE_RANK,
    ConfidenceLevel,
    Finding,
    ScanConfig,
    ScanResult,
    Severity,
)

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}

# Directory components that indicate test context
_TEST_DIRS = frozenset({"tests", "test"})
# Directory components that indicate example/docs context
_EXAMPLE_DIRS = frozenset({"examples", "example", "docs"})


def _classify_file_context(file_path: Path | None) -> str | None:
    """Classify a file path as test/example context, or None."""
    if file_path is None:
        return None
    name = file_path.name
    parts = file_path.parts

    # Test file: directory is tests/test, or filename starts with test_ or ends with _test.py
    if (
        any(p in _TEST_DIRS for p in parts)
        or name.startswith("test_")
        or name.endswith("_test.py")
    ):
        return "test file"

    # Example/docs: directory is examples/example/docs, or filename ends with .example
    if any(p in _EXAMPLE_DIRS for p in parts) or name.endswith(".example"):
        return "example"

    return None


def _apply_file_context(findings: list[Finding]) -> list[Finding]:
    """Tag findings with file context and cap confidence for test/example files."""
    result: list[Finding] = []
    for f in findings:
        ctx = _classify_file_context(f.file)
        if ctx is not None:
            updates: dict[str, object] = {"file_context": ctx}
            # Cap confidence at LOW for test/example files
            if f.confidence != ConfidenceLevel.LOW:
                updates["confidence"] = ConfidenceLevel.LOW
            result.append(f.model_copy(update=updates))
        else:
            result.append(f)
    return result


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(
        findings,
        key=lambda f: (_SEVERITY_RANK[f.severity], CONFIDENCE_RANK[f.confidence]),
    )


def _dedup_findings(findings: list[Finding]) -> list[Finding]:
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


def scan(
    target: Path,
    framework: str | None = None,
    config: ScanConfig | None = None,
) -> ScanResult:
    """Run a full scan on *target* and return a ScanResult.

    Analysis layers (all additive — higher layers refine, not replace):
        L0  Regex / Import Matching         (framework detection)
        L1  Single-File AST Visitor         (kwarg inspection)
        L2  Inter-Procedural Call Graph     (cross-file resolution)
        L3  Taint Analysis                  (source → sink flow)
        L4  Config Auditing                 (infra misconfiguration)
        L5  Semgrep Rules                   (declarative patterns)
        L6  Symbolic / Abstract Interp.     (path-sensitive)
        L7  Runtime Instrumentation         (dynamic, opt-in)
        L8  LLM-Assisted Confidence         (ambiguity resolver)
    """
    if config is None:
        config = ScanConfig.default()

    layers = config.layers

    # ── L0: Framework detection ──────────────────────────────────────────
    detected = framework or auto_detect_framework(target)

    if detected != "langchain":
        return ScanResult(
            target=target,
            framework=detected,
            errors=[f"Unsupported or undetected framework: {detected!r}"],
        )

    # ── L1: Single-file AST analysis ────────────────────────────────────
    adapter = LangChainAdapter()
    spec = adapter.parse(target)

    all_findings: list[Finding] = []

    if "L1" in layers:
        memory_findings = MemoryAnalyzer().analyze(spec)
        tool_findings = ToolAnalyzer().analyze(spec)
        # Tag L1 findings
        for f in memory_findings + tool_findings:
            if f.layer is None:
                all_findings.append(f.model_copy(update={"layer": "L1"}))
            else:
                all_findings.append(f)

    # ── L2: Call graph analysis ──────────────────────────────────────────
    if "L2" in layers and spec.source_files:
        try:
            l2 = CallGraphAnalyzer()
            all_findings = l2.analyze(spec, list(all_findings), target)
        except Exception as exc:
            warnings.warn(f"L2 analysis failed: {exc}", stacklevel=2)

    # ── L3: Taint analysis ──────────────────────────────────────────────
    if "L3" in layers and spec.source_files:
        try:
            l3_findings = TaintAnalyzer().analyze(spec)
            all_findings.extend(l3_findings)
        except Exception as exc:
            warnings.warn(f"L3 analysis failed: {exc}", stacklevel=2)

    # ── L4: Config auditing ─────────────────────────────────────────────
    if "L4" in layers:
        try:
            config_findings = ConfigAuditor().analyze(target)
            all_findings.extend(config_findings)
        except Exception as exc:
            warnings.warn(f"L4 analysis failed: {exc}", stacklevel=2)

    # ── L5: Semgrep rules ───────────────────────────────────────────────
    if "L5" in layers:
        try:
            l5 = SemgrepAnalyzer(custom_rules_dir=config.semgrep_rules_dir)
            all_findings.extend(l5.analyze(target))
        except Exception as exc:
            warnings.warn(f"L5 analysis failed: {exc}", stacklevel=2)

    # ── L6: Symbolic analysis ───────────────────────────────────────────
    if "L6" in layers and spec.source_files:
        try:
            l6_findings = SymbolicAnalyzer().analyze(spec)
            all_findings.extend(l6_findings)
        except Exception as exc:
            warnings.warn(f"L6 analysis failed: {exc}", stacklevel=2)

    # ── ASM: Application Security Model queries ────────────────────────
    # Run ASM when the model was built AND at least one layer beyond L0-L2 is
    # enabled (ASM graph queries need the richer analysis context).
    if spec.asm is not None and not layers.issubset({"L0", "L1", "L2"}):
        try:
            asm_findings = ASMAnalyzer().analyze(spec.asm)
            if config.asm_shadow:
                logger = logging.getLogger("agentwall.asm")
                for f in asm_findings:
                    logger.debug(
                        "ASM shadow: %s %s at %s:%s",
                        f.rule_id, f.title, f.file, f.line,
                    )
            else:
                all_findings.extend(asm_findings)
        except Exception as exc:
            warnings.warn(f"ASM analysis failed: {exc}", stacklevel=2)

    # ── L7: Runtime instrumentation ─────────────────────────────────────
    if config.dynamic:
        try:
            from agentwall.runtime.patcher import run_with_instrumentation

            report = run_with_instrumentation(target)
            all_findings.extend(report.to_findings())
        except Exception as exc:
            warnings.warn(f"L7 runtime analysis failed: {exc}", stacklevel=2)

    # ── L8: LLM confidence scoring ──────────────────────────────────────
    if config.llm_assist:
        try:
            from agentwall.analyzers.confidence import ConfidenceScorer

            scorer = ConfidenceScorer(allow_local_llm=True, allow_api=False)
            all_findings = scorer.apply_scores(all_findings)
        except Exception as exc:
            warnings.warn(f"L8 confidence scoring failed: {exc}", stacklevel=2)

    # ── Finalize ────────────────────────────────────────────────────────
    all_findings = _dedup_findings(all_findings)
    all_findings = _apply_file_context(all_findings)
    all_findings = _sort_findings(all_findings)

    return ScanResult(
        target=target,
        framework=detected,
        findings=all_findings,
        scanned_files=len(spec.source_files),
    )
