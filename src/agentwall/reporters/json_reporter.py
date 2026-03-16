"""JSON reporter — exports ScanResult to a file."""

from __future__ import annotations

from pathlib import Path

from agentwall.models import ScanResult


class JsonReporter:
    def render(self, result: ScanResult, output: Path) -> None:
        output.write_text(result.model_dump_json(indent=2), encoding="utf-8")
