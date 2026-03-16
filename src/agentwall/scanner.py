"""Scanner orchestrator — ties together adapter, analyzers, and result."""

from __future__ import annotations

from pathlib import Path

from agentwall.adapters.langchain import LangChainAdapter
from agentwall.analyzers.memory import MemoryAnalyzer
from agentwall.analyzers.tools import ToolAnalyzer
from agentwall.detector import auto_detect_framework
from agentwall.models import Finding, ScanResult, Severity

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


def _sort_findings(findings: list[Finding]) -> list[Finding]:
    return sorted(findings, key=lambda f: _SEVERITY_RANK[f.severity])


def scan(target: Path, framework: str | None = None) -> ScanResult:
    """Run a full scan on *target* and return a ScanResult."""
    detected = framework or auto_detect_framework(target)

    if detected != "langchain":
        return ScanResult(
            target=target,
            framework=detected,
            errors=[f"Unsupported or undetected framework: {detected!r}"],
        )

    adapter = LangChainAdapter()
    spec = adapter.parse(target)

    memory_findings = MemoryAnalyzer().analyze(spec)
    tool_findings = ToolAnalyzer().analyze(spec)
    all_findings = _sort_findings(memory_findings + tool_findings)

    return ScanResult(
        target=target,
        framework=detected,
        findings=all_findings,
        scanned_files=len(spec.source_files),
    )
