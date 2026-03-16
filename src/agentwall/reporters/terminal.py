"""Rich terminal reporter."""

from __future__ import annotations

from rich.console import Console
from rich.text import Text

from agentwall.models import Finding, ScanResult, Severity

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

    def _render_finding(self, finding: Finding, style: str) -> None:
        c = self.console
        c.print(f"  [{style}]{finding.rule_id}[/{style}]  {finding.title}")
        if finding.file is not None:
            loc = f"{finding.file}"
            if finding.line is not None:
                loc += f":{finding.line}"
            c.print(f"  File: [dim]{loc}[/dim]")
        c.print(f"  {finding.description}")
        if finding.fix:
            c.print(f"  [dim]Fix: {finding.fix}[/dim]")
        c.print()
