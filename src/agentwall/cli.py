"""AgentWall CLI."""

from __future__ import annotations

from pathlib import Path

import typer

from agentwall.models import CONFIDENCE_RANK, ConfidenceLevel, ScanConfig, ScanResult, Severity
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

_STATIC_LAYERS = {"L0", "L1", "L2", "L3", "L4", "L5", "L6"}

_VALID_FORMATS = {"terminal", "json", "sarif", "agent-json", "patch"}

_CONFIDENCE_MAP: dict[str, ConfidenceLevel | None] = {
    "high": ConfidenceLevel.HIGH,
    "medium": ConfidenceLevel.MEDIUM,
    "low": ConfidenceLevel.LOW,
    "all": None,
}



def _print_formatted_output(result: ScanResult, fmt: str) -> None:
    """Print formatted output to stdout."""
    import json

    if fmt == "json":
        typer.echo(result.model_dump_json(indent=2))
    elif fmt == "sarif":
        from agentwall.reporters.sarif import build_sarif

        typer.echo(json.dumps(build_sarif(result), indent=2))
    elif fmt == "agent-json":
        from agentwall.reporters.agent_json import build_agent_json

        typer.echo(json.dumps(build_agent_json(result), indent=2))
    elif fmt == "patch":
        from agentwall.reporters.patch import build_patch

        typer.echo(build_patch(result))


def _write_formatted_output(result: ScanResult, fmt: str, output: Path) -> None:
    """Write scan result to file in the specified format."""
    if fmt == "json":
        from agentwall.reporters.json_reporter import JsonReporter

        JsonReporter().render(result, output)
    elif fmt == "sarif":
        from agentwall.reporters.sarif import SarifReporter

        SarifReporter().render(result, output)
    elif fmt == "agent-json":
        from agentwall.reporters.agent_json import AgentJsonReporter

        AgentJsonReporter().render(result, output)
    elif fmt == "patch":
        from agentwall.reporters.patch import PatchReporter

        PatchReporter().render(result, output)
    else:
        from agentwall.reporters.json_reporter import JsonReporter

        JsonReporter().render(result, output)


@app.command()
def scan(
    path: Path = typer.Argument(..., help="Target directory to scan."),  # noqa: B008
    framework: str | None = typer.Option(None, "--framework", "-f", help="Force framework."),  # noqa: B008
    output: Path | None = typer.Option(None, "--output", "-o", help="Output file path."),  # noqa: B008
    fmt: str = typer.Option(
        "terminal", "--format", help="Output format: terminal|json|sarif|agent-json|patch"
    ),  # noqa: B008
    fail_on: str = typer.Option(
        "high", "--fail-on", help="Severity threshold: critical|high|medium|low|none"
    ),  # noqa: B008
    layers: str | None = typer.Option(
        None, "--layers", help="Comma-separated layers to run (e.g. L0,L1,L2). Default: all static."
    ),  # noqa: B008
    dynamic: bool = typer.Option(False, "--dynamic", help="Enable L7 runtime instrumentation."),  # noqa: B008
    llm_assist: bool = typer.Option(
        False, "--llm-assist", help="Enable L8 LLM confidence scoring."
    ),  # noqa: B008
    fast: bool = typer.Option(False, "--fast", help="Fast mode: L0-L2 only."),  # noqa: B008
    confidence: str = typer.Option(
        "all", "--confidence", help="Minimum confidence: high|medium|low|all"
    ),  # noqa: B008
) -> None:
    """Scan an agent directory for memory and tool security issues."""
    if not path.exists():
        typer.echo(f"Error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    if fail_on not in _SEVERITY_MAP:
        typer.echo(f"Error: --fail-on must be one of {list(_SEVERITY_MAP)}", err=True)
        raise typer.Exit(2)

    if fmt not in _VALID_FORMATS:
        typer.echo(f"Error: --format must be one of {sorted(_VALID_FORMATS)}", err=True)
        raise typer.Exit(2)

    if confidence not in _CONFIDENCE_MAP:
        typer.echo(f"Error: --confidence must be one of {list(_CONFIDENCE_MAP)}", err=True)
        raise typer.Exit(2)

    # Build scan config
    if fast:
        config = ScanConfig.fast()
    elif layers:
        layer_set = {part.strip().upper() for part in layers.split(",")}
        invalid = layer_set - _STATIC_LAYERS
        if invalid:
            typer.echo(f"Error: unknown layers: {invalid}. Valid: {_STATIC_LAYERS}", err=True)
            raise typer.Exit(2)
        config = ScanConfig(layers=layer_set)
    else:
        config = ScanConfig.default()

    config.dynamic = dynamic
    config.llm_assist = llm_assist

    result = run_scan(target=path, framework=framework, config=config)

    if result.errors and not result.findings:
        typer.echo(f"Scan error: {result.errors[0]}", err=True)
        raise typer.Exit(2)

    # Filter by confidence threshold
    conf_threshold = _CONFIDENCE_MAP[confidence]
    if conf_threshold is not None:
        threshold_rank = CONFIDENCE_RANK[conf_threshold]
        result.findings = [
            f for f in result.findings if CONFIDENCE_RANK[f.confidence] <= threshold_rank
        ]

    # Terminal output or formatted output
    if fmt == "terminal":
        TerminalReporter().render(result)
        if output is not None:
            # --format=terminal with --output: write JSON to file
            _write_formatted_output(result, "json", output)
            typer.echo(f"JSON report written to {output}")
    elif output is not None:
        _write_formatted_output(result, fmt, output)
        typer.echo(f"{fmt.upper()} report written to {output}")
    else:
        # Non-terminal format without --output: print to stdout
        _print_formatted_output(result, fmt)

    threshold = _SEVERITY_MAP[fail_on]
    if threshold is None:
        raise typer.Exit(0)

    threshold_rank = _SEVERITY_RANK[threshold]
    triggered = any(_SEVERITY_RANK[f.severity] <= threshold_rank for f in result.findings)
    raise typer.Exit(1 if triggered else 0)


@app.command()
def verify(
    finding: str = typer.Option(..., "--finding", help="Rule ID to verify (e.g. AW-MEM-001)."),  # noqa: B008
    path: Path = typer.Argument(".", help="Target directory to scan."),  # noqa: B008
    fmt: str = typer.Option("terminal", "--format", help="Output format: terminal|json"),  # noqa: B008
) -> None:
    """Re-scan targeting a specific rule to verify if a finding is resolved."""
    from agentwall.rules import ALL_RULES

    if not path.exists():
        typer.echo(f"Error: path does not exist: {path}", err=True)
        raise typer.Exit(2)

    if finding not in ALL_RULES:
        typer.echo(f"Error: unknown rule ID: {finding}. Valid: {sorted(ALL_RULES)}", err=True)
        raise typer.Exit(2)

    # Run a fast scan (L0 + L1 only) for quick verification
    config = ScanConfig.fast()
    result = run_scan(target=path, config=config)

    if result.errors and not result.findings:
        typer.echo(f"Scan error: {result.errors[0]}", err=True)
        raise typer.Exit(2)

    # Filter to only the target rule
    matching = [f for f in result.findings if f.rule_id == finding]

    if fmt == "json":
        import json

        output = {
            "rule_id": finding,
            "status": "FAIL" if matching else "PASS",
            "finding_count": len(matching),
            "findings": [f.model_dump(mode="json") for f in matching],
        }
        typer.echo(json.dumps(output, indent=2, default=str))
    else:
        if matching:
            typer.echo(f"FAIL: {finding} still present ({len(matching)} finding(s))")
            for f in matching:
                loc = ""
                if f.file:
                    loc = f"  {f.file}"
                    if f.line:
                        loc += f":{f.line}"
                typer.echo(f"  - {f.description}{loc}")
        else:
            typer.echo(f"PASS: {finding} resolved")

    raise typer.Exit(1 if matching else 0)


@app.command()
def version() -> None:
    """Show AgentWall version."""
    from agentwall import __version__

    typer.echo(f"AgentWall v{__version__}")
