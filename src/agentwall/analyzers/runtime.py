"""L7 — Runtime Instrumentation analyzer wrapper."""

from __future__ import annotations

from collections.abc import Sequence

from agentwall.context import AnalysisContext
from agentwall.models import Finding


class RuntimeAnalyzer:
    """Thin registry wrapper around runtime instrumentation (L7)."""

    name: str = "L7"
    depends_on: Sequence[str] = ("L1-memory", "L1-tools")
    replace: bool = False
    opt_in: bool = True
    framework_agnostic: bool = False

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        from agentwall.runtime.patcher import run_with_instrumentation

        report = run_with_instrumentation(ctx.target)
        return report.to_findings()
