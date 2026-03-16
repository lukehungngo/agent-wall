# /new-probe

Scaffold a new memory backend probe.

## Steps

1. Create `src/agentwall/probes/<backend_name>.py` using this template:

```python
"""<BackendName> memory probe.

Checks for cross-user memory isolation failures in <BackendName>-based agents.
Optional live probing requires: pip install agentwall[<backend_name>]
"""
from __future__ import annotations

import ast
from pathlib import Path
from typing import TYPE_CHECKING

from agentwall.models import Finding, Severity, Category
from agentwall.probes.base import ProbeResult

if TYPE_CHECKING:
    from agentwall.models import MemoryConfig


BACKEND_NAME = "<backend_name>"
OPTIONAL_DEP = "<sdk_package_name>"

# ── Static patterns to detect ────────────────────────────────────────────────
# Query call that indicates unsafe access (no filter argument)
UNSAFE_QUERY_CALLS = {"<method_name>"}  # e.g. {"query", "similarity_search"}
REQUIRED_FILTER_ARG = "<filter_arg_name>"  # e.g. "where", "filter", "namespace"


def detect_static(files: list[Path]) -> list[Finding]:
    """AST-based analysis. No SDK import required."""
    findings: list[Finding] = []
    for path in files:
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
            tree = ast.parse(source)
        except SyntaxError:
            continue
        findings.extend(_check_file(tree, path))
    return findings


def probe_live(config: MemoryConfig) -> list[Finding]:
    """Live connection test. Requires optional SDK."""
    import importlib.util
    if importlib.util.find_spec(OPTIONAL_DEP) is None:
        return []  # SDK not installed, skip silently
    # TODO: implement live probe
    return []


def _check_file(tree: ast.AST, path: Path) -> list[Finding]:
    findings: list[Finding] = []
    # TODO: implement AST checks
    return findings
```

2. Register in `src/agentwall/probes/__init__.py`:
```python
from agentwall.probes.<backend_name> import detect_static, probe_live
PROBE_REGISTRY["<backend_name>"] = {"static": detect_static, "live": probe_live}
```

3. Add optional dep to `pyproject.toml`:
```toml
[project.optional-dependencies]
<backend_name> = ["<sdk_package>>=<min_version>"]
```

4. Add test fixture in `tests/fixtures/` with unsafe + safe patterns.

5. Update CLAUDE.md Rules Reference and Probe Build Priority.
