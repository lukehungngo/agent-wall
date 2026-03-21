"""Project scoping — detect when the scan target IS a framework/vector-store library.

When the target is a library (e.g., scanning the langchain repo itself), all source
files are library code by definition. MEM-001 findings in library code route to
Tier 2 (INFO) — the library provides the API, isolation is the caller's job.
"""

from __future__ import annotations

import ast
import configparser
import re
import sys
from pathlib import Path

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

# Canonical package names of frameworks and vector-store SDKs that AgentWall
# scans FOR. If the project declares itself AS one of these, it's a library.
# Names are normalized: lowercased, hyphens → underscores.
_SELF_LIBRARY_NAMES: frozenset[str] = frozenset(
    {
        # Frameworks (from detector._FRAMEWORK_SIGNATURES)
        "langchain",
        "langchain_core",
        "langchain_community",
        "langchain_openai",
        "langchain_experimental",
        "langgraph",
        "llama_index",
        "llama_index_core",
        "llama_hub",
        "llamaindex",
        "llamahub",
        "openai_agents",
        "crewai",
        "autogen",
        "pyautogen",
        "pydantic_ai",
        "graphrag",
        "dspy",
        "semantic_kernel",
        # Vector store SDKs (from memory._VECTORSTORE_IMPORTS)
        "chromadb",
        "faiss_cpu",
        "faiss_gpu",
        "pinecone",
        "pinecone_client",
        "qdrant_client",
        "pymilvus",
        "weaviate",
        "weaviate_client",
    }
)


def _normalize_name(name: str) -> str:
    """PEP 503 normalization: lowercase, replace [-_.] with underscore."""
    return re.sub(r"[-_. ]+", "_", name.strip()).lower()


def _read_pyproject_name(target: Path) -> str | None:
    """Extract package name from pyproject.toml [project] or [tool.poetry]."""
    pyproject = target / "pyproject.toml"
    if not pyproject.exists():
        return None
    try:
        with pyproject.open("rb") as f:
            data = tomllib.load(f)
        # PEP 621: [project].name
        name = data.get("project", {}).get("name")
        if name:
            return str(name)
        # Poetry: [tool.poetry].name
        name = data.get("tool", {}).get("poetry", {}).get("name")
        if name:
            return str(name)
    except Exception:  # noqa: BLE001 — fail safe on malformed files
        pass
    return None


def _read_setup_cfg_name(target: Path) -> str | None:
    """Extract package name from setup.cfg [metadata].name."""
    setup_cfg = target / "setup.cfg"
    if not setup_cfg.exists():
        return None
    try:
        parser = configparser.ConfigParser()
        parser.read(setup_cfg)
        return parser.get("metadata", "name", fallback=None)
    except Exception:  # noqa: BLE001
        return None


def _read_setup_py_name(target: Path) -> str | None:
    """Extract package name from setup.py setup(name='...') call.

    Uses AST parsing only — never executes setup.py.
    """
    setup_py = target / "setup.py"
    if not setup_py.exists():
        return None
    try:
        source = setup_py.read_text(encoding="utf-8")
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if (
                isinstance(node, ast.Call)
                and isinstance(node.func, ast.Name)
                and node.func.id == "setup"
            ):
                for kw in node.keywords:
                    if kw.arg == "name" and isinstance(kw.value, ast.Constant):
                        return str(kw.value.value)
    except Exception:  # noqa: BLE001
        pass
    return None


def _has_framework_module_layout(target: Path) -> bool:
    """Secondary signal: top-level directory matches a known framework module name.

    Only fires when NO metadata file exists (pyproject.toml/setup.cfg/setup.py).
    Requires BOTH a matching package dir AND a library marker file (setup.py,
    setup.cfg, or MANIFEST.in) to avoid false positives on user apps that
    have a framework module installed/vendored locally.

    Catches monorepos or renamed packages where metadata doesn't match.
    """
    # Require at least one library-marker file — otherwise this is likely
    # a user app with a coincidentally named directory.
    has_library_marker = any(
        (target / f).exists() for f in ("setup.py", "setup.cfg", "MANIFEST.in")
    )
    if not has_library_marker:
        return False

    for child in target.iterdir():
        if (
            child.is_dir()
            and _normalize_name(child.name) in _SELF_LIBRARY_NAMES
            and (child / "__init__.py").exists()
        ):
            return True
    # Also check src/ layout: src/chromadb/__init__.py
    src = target / "src"
    if src.is_dir():
        for child in src.iterdir():
            if (
                child.is_dir()
                and _normalize_name(child.name) in _SELF_LIBRARY_NAMES
                and (child / "__init__.py").exists()
            ):
                return True
    return False


def is_self_library_project(target: Path) -> bool:
    """Detect if the scan target IS a known framework or vector-store library.

    Uses two signals (either sufficient):
    1. Package metadata: pyproject.toml/setup.cfg/setup.py name matches a known
       framework or vector-store SDK.
    2. Module layout: a top-level Python package directory matches a known name
       (catches monorepos or renamed packages).
    """
    # Signal 1: package name from metadata files
    for reader in (_read_pyproject_name, _read_setup_cfg_name, _read_setup_py_name):
        name = reader(target)
        if name is not None:
            # Found a name — check if it's a known library. If not, don't
            # fall through to module layout (the project is named, just not a library).
            return _normalize_name(name) in _SELF_LIBRARY_NAMES

    # Signal 2: module layout (no metadata found — try directory structure)
    return _has_framework_module_layout(target)
