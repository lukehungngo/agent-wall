"""AgentWall CLI."""

from __future__ import annotations

from pathlib import Path

import typer

from agentwall.models import Severity
from agentwall.reporters.json_reporter import JsonReporter
from agentwall.reporters.terminal import TerminalReporter
from agentwall.scanner import scan as run_scan

app = typer.Typer(
    name="agentwall",
    help="Memory security scanner for AI agents.",
    add_completion=False,
    no_args_is_help=True,
)


@app.callback()
def _root() -> None:
    pass

_SEVERITY_MAP: dict[str, Severity | None] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "none": None,
}

_SEVERITY_RANK: dict[Severity, int] = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Target directory to scan."),  # noqa: B008
    framework: str | None = typer.Option(None, "--framework", "-f", help="Force framework."),  # noqa: B008
    output: Path | None = typer.Option(None, "--output", "-o", help="JSON output file."),  # noqa: B008
    fail_on: str = typer.Option("high", "--fail-on", help="Severity threshold: critical|high|medium|low|none"),  # noqa: B008
) -> None:
    """Scan an agent directory for memory and tool security issues."""
    if not path.exists():
        typer.echo(f"Error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    if fail_on not in _SEVERITY_MAP:
        typer.echo(f"Error: --fail-on must be one of {list(_SEVERITY_MAP)}", err=True)
        raise typer.Exit(2)

    result = run_scan(target=path, framework=framework)

    if result.errors and not result.findings:
        typer.echo(f"Scan error: {result.errors[0]}", err=True)
        raise typer.Exit(2)

    TerminalReporter().render(result)

    if output is not None:
        JsonReporter().render(result, output)
        typer.echo(f"JSON report written to {output}")

    threshold = _SEVERITY_MAP[fail_on]
    if threshold is None:
        raise typer.Exit(0)

    threshold_rank = _SEVERITY_RANK[threshold]
    triggered = any(
        _SEVERITY_RANK[f.severity] <= threshold_rank for f in result.findings
    )
    raise typer.Exit(1 if triggered else 0)
