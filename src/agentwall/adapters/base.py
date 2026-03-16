"""AbstractAdapter Protocol — all adapters implement this interface."""

from __future__ import annotations

from pathlib import Path
from typing import Protocol

from agentwall.models import AgentSpec


class AbstractAdapter(Protocol):
    """Parse a target directory into a normalised AgentSpec."""

    def parse(self, target: Path) -> AgentSpec:
        ...
