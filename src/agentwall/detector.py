"""Auto-detect the agent framework used in a target directory."""

from __future__ import annotations

import ast
from collections import Counter
from pathlib import Path

_FRAMEWORK_SIGNATURES: dict[str, list[str]] = {
    "langchain": ["langchain", "langchain_core", "langchain_community", "langgraph"],
    "openai_agents": ["openai_agents", "agents"],
    "crewai": ["crewai"],
    "autogen": ["autogen", "pyautogen"],
}

# Directories that are never part of the primary source — skip entirely.
_SKIP_DIRS: frozenset[str] = frozenset(
    {
        "examples",
        "example",
        "docs",
        "doc",
        "tests",
        "test",
        "benchmarks",
        "bench",
        "scripts",
        "migrations",
        "node_modules",
        ".venv",
        "venv",
        ".git",
        "__pycache__",
        "sdks",
        "vendor",
    }
)


def _source_files(target: Path) -> list[Path]:
    """Yield .py files, skipping non-source directories."""
    results: list[Path] = []
    for py_file in target.rglob("*.py"):
        # Skip if any path component is a known non-source dir.
        if any(part in _SKIP_DIRS for part in py_file.relative_to(target).parts):
            continue
        results.append(py_file)
    return results


def auto_detect_framework(target: Path) -> str | None:
    """
    Return the most-prevalent framework name detected in *target*, or None.

    Strategy:
    1. Check pyproject.toml dependencies first — most reliable signal.
    2. Score all source .py files (excluding examples/, tests/, etc.).
    3. Return the framework with the highest import count.
       Ties broken by _FRAMEWORK_SIGNATURES key order (langchain first).
    """
    # -- 1. pyproject.toml dependency check (authoritative) --
    pyproject = target / "pyproject.toml"
    if pyproject.exists():
        content = pyproject.read_text()
        for framework, markers in _FRAMEWORK_SIGNATURES.items():
            if any(m in content for m in markers):
                return framework

    # -- 2. Score source files --
    scores: Counter[str] = Counter()

    for py_file in _source_files(target):
        try:
            tree = ast.parse(py_file.read_text(), filename=str(py_file))
        except SyntaxError:
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import | ast.ImportFrom):
                module = (
                    node.module
                    if isinstance(node, ast.ImportFrom)
                    else ".".join(alias.name for alias in node.names)
                )
                if not module:
                    continue
                for framework, markers in _FRAMEWORK_SIGNATURES.items():
                    if any(module.startswith(m) for m in markers):
                        scores[framework] += 1

    if not scores:
        return None

    return scores.most_common(1)[0][0]
