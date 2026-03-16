"""SARIF 2.1.0 reporter — stub."""

from __future__ import annotations

from pathlib import Path

from agentwall.models import ScanResult


class SarifReporter:
    """SARIF 2.1.0 output — coming in week 3."""

    def render(self, result: ScanResult, output: Path) -> None:
        raise NotImplementedError("SARIF reporter coming in week 3")
