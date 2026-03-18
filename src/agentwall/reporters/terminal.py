"""Rich terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from agentwall.models import ConfidenceLevel, Finding, ScanResult, Severity

_SEVERITY_STYLES: dict[Severity, str] = {
    Severity.CRITICAL: "bold red",
    Severity.HIGH: "red",
    Severity.MEDIUM: "yellow",
    Severity.LOW: "blue",
    Severity.INFO: "dim",
}

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
]

_CONFIDENCE_STYLES: dict[ConfidenceLevel, str] = {
    ConfidenceLevel.HIGH: "bold",
    ConfidenceLevel.MEDIUM: "",
    ConfidenceLevel.LOW: "dim",
}

_CONFIDENCE_ORDER = [ConfidenceLevel.HIGH, ConfidenceLevel.MEDIUM, ConfidenceLevel.LOW]


class TerminalReporter:
    def __init__(self, console: Console | None = None) -> None:
        self.console = console or Console()

    def render(self, result: ScanResult) -> None:
        c = self.console
        c.print()
        c.print("[bold]AgentWall v0.1.0[/bold] — Memory Security Scanner")
        c.print(
            f"Scanning: [cyan]{result.target}[/cyan]  "
            f"Framework: [green]{result.framework or 'unknown'}[/green]  "
            f"Files: {result.scanned_files}  "
            f"Findings: {len(result.findings)}"
        )
        c.print()

        by_sev = result.by_severity
        for sev in _SEVERITY_ORDER:
            group = by_sev.get(sev, [])
            if not group:
                continue
            style = _SEVERITY_STYLES[sev]
            label = f" {sev.value.upper()} ({len(group)}) "
            c.rule(Text(label, style=style))
            c.print()
            for finding in group:
                self._render_finding(finding, style)
            c.print()

        if not result.findings:
            c.print("[bold green]No findings.[/bold green]")
            return

        # Dual-axis summary
        sev_counts = dict.fromkeys(_SEVERITY_ORDER, 0)
        conf_counts = dict.fromkeys(_CONFIDENCE_ORDER, 0)
        for f in result.findings:
            sev_counts[f.severity] += 1
            conf_counts[f.confidence] += 1

        sev_parts = "  ".join(
            f"{s.value.upper()}: {n}" for s, n in sev_counts.items() if n
        )
        conf_parts = "  ".join(
            f"{cl.value.upper()}: {n}" for cl, n in conf_counts.items() if n
        )

        c.print(f"{len(result.findings)} findings")
        c.print(f"  by severity:    {sev_parts}")
        c.print(f"  by confidence:  {conf_parts}")

    def _render_finding(self, finding: Finding, style: str) -> None:
        c = self.console
        conf_style = _CONFIDENCE_STYLES[finding.confidence]
        conf_label = finding.confidence.value.capitalize()
        if conf_style:
            conf_text = f"[{conf_style}]Confidence: {conf_label}[/{conf_style}]"
        else:
            conf_text = f"Confidence: {conf_label}"
        ctx_tag = f"  [dim]({finding.file_context})[/dim]" if finding.file_context else ""
        c.print(
            f"  [{style}]{finding.rule_id}[/{style}]  {finding.title}"
            f"  {conf_text}{ctx_tag}"
        )
        if finding.file is not None:
            loc = f"{finding.file}"
            if finding.line is not None:
                loc += f":{finding.line}"
            c.print(f"  File: [dim]{loc}[/dim]")
        c.print(f"  {finding.description}")
        if finding.fix:
            c.print(f"  [dim]Fix: {finding.fix}[/dim]")
        c.print()
