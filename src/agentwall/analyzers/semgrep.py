"""L5 — Semgrep Integration.

Runs bundled Semgrep rules against the target codebase and converts
output to AgentWall findings. Gracefully degrades if semgrep is not installed.
"""

from __future__ import annotations

import json
import subprocess
import warnings
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import Category, ConfidenceLevel, Finding, Severity

# Bundled rules directory
_RULES_DIR = Path(__file__).parent.parent / "semgrep_rules"

# Semgrep severity → AgentWall severity
_SEVERITY_MAP: dict[str, Severity] = {
    "ERROR": Severity.HIGH,
    "WARNING": Severity.MEDIUM,
    "INFO": Severity.LOW,
}

# Category mapping from semgrep metadata
_CATEGORY_MAP: dict[str, Category] = {
    "memory": Category.MEMORY,
    "tool": Category.TOOL,
    "config": Category.MEMORY,  # config findings are memory-adjacent
}


def _semgrep_available() -> bool:
    """Check if the semgrep binary is available."""
    try:
        result = subprocess.run(
            ["semgrep", "--version"],
            capture_output=True,
            text=True,
            timeout=10,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


def _parse_semgrep_output(raw: str) -> list[dict[str, object]]:
    """Parse semgrep JSON output into a list of result dicts."""
    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        return []

    if not isinstance(data, dict):
        return []

    results = data.get("results", [])
    if not isinstance(results, list):
        return []

    return results  # type: ignore[return-value,unused-ignore]


def _result_to_finding(result: dict[str, object]) -> Finding | None:
    """Convert a single semgrep result to an AgentWall Finding."""
    check_id = result.get("check_id", "")
    if not isinstance(check_id, str):
        return None

    extra = result.get("extra", {})
    if not isinstance(extra, dict):
        extra = {}

    metadata = extra.get("metadata", {})
    if not isinstance(metadata, dict):
        metadata = {}

    message = extra.get("message", "")
    if not isinstance(message, str):
        message = str(message)

    severity_str = extra.get("severity", "WARNING")
    if not isinstance(severity_str, str):
        severity_str = "WARNING"
    severity = _SEVERITY_MAP.get(severity_str, Severity.MEDIUM)

    category_str = metadata.get("category", "memory")
    if not isinstance(category_str, str):
        category_str = "memory"
    category = _CATEGORY_MAP.get(category_str, Category.MEMORY)

    # Extract rule ID from metadata or check_id
    rule_id = metadata.get("agentwall-id", check_id)
    if not isinstance(rule_id, str):
        rule_id = str(rule_id)

    # Extract file and line
    path_str = result.get("path", "")
    start = result.get("start", {})
    line = start.get("line", 1) if isinstance(start, dict) else 1

    confidence_str = metadata.get("confidence", "MEDIUM")
    if not isinstance(confidence_str, str):
        confidence_str = "MEDIUM"
    confidence_map = {
        "HIGH": ConfidenceLevel.HIGH,
        "MEDIUM": ConfidenceLevel.MEDIUM,
        "LOW": ConfidenceLevel.LOW,
    }
    confidence = confidence_map.get(confidence_str, ConfidenceLevel.MEDIUM)

    return Finding(
        rule_id=rule_id,
        title=check_id.replace("-", " ").replace("_", " "),
        severity=severity,
        category=category,
        description=message.strip(),
        file=Path(str(path_str)) if path_str else None,
        line=int(line) if isinstance(line, int) else 1,
        fix=metadata.get("fix"),  # type: ignore[arg-type,unused-ignore]
        confidence=confidence,
        layer="L5",
    )


class SemgrepAnalyzer:
    """L5 analyzer: run Semgrep rules and convert to AgentWall findings."""

    def __init__(self, custom_rules_dir: Path | None = None) -> None:
        self.rules_dirs: list[Path] = [_RULES_DIR]
        if custom_rules_dir and custom_rules_dir.exists():
            self.rules_dirs.append(custom_rules_dir)

    name: str = "L5"
    depends_on: Sequence[str] = ()
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = False

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Run semgrep and return findings. Returns empty list if semgrep not installed."""
        target = ctx.target
        if not _semgrep_available():
            warnings.warn(
                "semgrep not installed — L5 analysis skipped. Install with: pip install semgrep",
                stacklevel=2,
            )
            return []

        # Pick up custom rules from config (not just __init__)
        custom = getattr(ctx.config, "semgrep_rules_dir", None)
        if custom and custom not in self.rules_dirs and custom.exists():
            self.rules_dirs.append(custom)

        findings: list[Finding] = []
        for rules_dir in self.rules_dirs:
            if not rules_dir.exists():
                continue
            findings.extend(self._run_semgrep(target, rules_dir))
        return findings

    def _run_semgrep(self, target: Path, rules_dir: Path) -> list[Finding]:
        """Execute semgrep with the given rules directory."""
        try:
            result = subprocess.run(
                [
                    "semgrep",
                    "--config",
                    str(rules_dir),
                    "--json",
                    "--quiet",
                    "--no-git-ignore",
                    str(target),
                ],
                capture_output=True,
                text=True,
                timeout=120,
            )
        except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
            warnings.warn(f"L5: semgrep execution failed: {exc}", stacklevel=2)
            return []

        results = _parse_semgrep_output(result.stdout)
        findings: list[Finding] = []
        for r in results:
            finding = _result_to_finding(r)
            if finding:
                findings.append(finding)
        return findings
