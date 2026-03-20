"""L7 — Runtime Instrumentation.

Monkey-patches vector store retrieval methods to detect unfiltered calls
at runtime. Designed to be used with the target's test suite.

Usage:
    agentwall scan ./project --dynamic
    agentwall scan ./project --dynamic --test

This module patches `similarity_search`, `get_relevant_documents`, and
other retrieval methods at import time. It logs every retrieval call
and flags any that lack a filter.
"""

from __future__ import annotations

import importlib
import inspect
import logging
import sys
import warnings
from collections.abc import Callable
from dataclasses import dataclass, field
from functools import wraps
from pathlib import Path
from types import ModuleType
from typing import Any

from agentwall.models import Category, ConfidenceLevel, Finding, Severity
from agentwall.patterns import FILTER_KWARGS

logger = logging.getLogger("agentwall.runtime")

# Methods to patch
_PATCH_TARGETS: dict[str, list[str]] = {
    # module_path: [method_names]
    "langchain_community.vectorstores.chroma": [
        "similarity_search",
        "similarity_search_with_score",
    ],
    "langchain_community.vectorstores.pgvector": ["similarity_search"],
    "langchain_community.vectorstores.pinecone": ["similarity_search"],
    "langchain_community.vectorstores.qdrant": ["similarity_search"],
    "langchain_community.vectorstores.faiss": ["similarity_search"],
    "langchain_community.vectorstores.weaviate": ["similarity_search"],
    "langchain_community.vectorstores.neo4j_vector": ["similarity_search"],
    "langchain_community.vectorstores.milvus": ["similarity_search"],
    "langchain_community.vectorstores.redis": ["similarity_search"],
}


@dataclass
class RuntimeViolation:
    """A detected unfiltered retrieval call at runtime."""

    method: str
    file: str
    line: int
    kwargs: dict[str, Any]


@dataclass
class RuntimeReport:
    """Aggregated results from runtime instrumentation."""

    violations: list[RuntimeViolation] = field(default_factory=list)
    total_calls: int = 0
    filtered_calls: int = 0

    def to_findings(self) -> list[Finding]:
        """Convert runtime violations to AgentWall findings."""
        findings: list[Finding] = []
        for v in self.violations:
            findings.append(
                Finding(
                    rule_id="AW-MEM-001",
                    title=f"Runtime: unfiltered {v.method}() call",
                    severity=Severity.CRITICAL,
                    category=Category.MEMORY,
                    description=(
                        f"At runtime, {v.method}() was called without a filter kwarg "
                        f"at {v.file}:{v.line}. This is a confirmed cross-tenant "
                        "data leakage vector."
                    ),
                    file=Path(v.file) if v.file != "<unknown>" else None,
                    line=v.line if v.line > 0 else None,
                    fix="Add filter={'user_id': user_id} to this retrieval call.",
                    confidence=ConfidenceLevel.HIGH,
                    layer="L7",
                )
            )
        return findings


# Global report instance
_report = RuntimeReport()


def get_report() -> RuntimeReport:
    """Get the current runtime report."""
    return _report


def reset_report() -> None:
    """Reset the runtime report for a new scan."""
    global _report
    _report = RuntimeReport()


def _make_wrapper(
    original: Callable[..., Any],
    method_name: str,
) -> Callable[..., Any]:
    """Create a wrapper that checks for filter kwargs before calling original."""

    @wraps(original)
    def wrapper(*args: Any, **kwargs: Any) -> Any:
        _report.total_calls += 1

        has_filter = any(k in kwargs for k in FILTER_KWARGS)
        if "search_kwargs" in kwargs:
            sk = kwargs["search_kwargs"]
            if isinstance(sk, dict) and "filter" in sk:
                has_filter = True

        if has_filter:
            _report.filtered_calls += 1
        else:
            # Get caller info
            frame = inspect.currentframe()
            caller_frame = frame.f_back if frame else None
            caller_file = "<unknown>"
            caller_line = 0
            if caller_frame:
                caller_file = caller_frame.f_code.co_filename
                caller_line = caller_frame.f_lineno

            violation = RuntimeViolation(
                method=method_name,
                file=caller_file,
                line=caller_line,
                kwargs=dict(kwargs),
            )
            _report.violations.append(violation)
            logger.warning(
                "AW-MEM-001: %s() called without filter at %s:%d",
                method_name,
                caller_file,
                caller_line,
            )

        return original(*args, **kwargs)

    return wrapper


def _try_import(module_path: str) -> ModuleType | None:
    """Try to import a module, return None if not available."""
    try:
        return importlib.import_module(module_path)
    except (ImportError, ModuleNotFoundError):
        return None


def patch_all() -> int:
    """Patch all known vector store methods. Returns number of patches applied."""
    reset_report()
    patches_applied = 0
    for module_path, methods in _PATCH_TARGETS.items():
        module = _try_import(module_path)
        if module is None:
            continue

        # Find the class in the module that has these methods
        for name, obj in inspect.getmembers(module, inspect.isclass):
            for method_name in methods:
                original = getattr(obj, method_name, None)
                if original is None:
                    continue
                if hasattr(original, "_agentwall_patched"):
                    continue

                wrapped = _make_wrapper(original, f"{name}.{method_name}")
                wrapped._agentwall_patched = True  # type: ignore[attr-defined]
                setattr(obj, method_name, wrapped)
                patches_applied += 1
                logger.info("Patched %s.%s", name, method_name)

    if patches_applied == 0:
        warnings.warn(
            "L7: No vector store SDKs found to patch. "
            "Install the relevant SDK (e.g., pip install agentwall[chroma]) "
            "for runtime instrumentation.",
            stacklevel=2,
        )

    return patches_applied


def unpatch_all() -> None:
    """Remove all patches. Not strictly needed but useful for testing."""
    for module_path, methods in _PATCH_TARGETS.items():
        module = _try_import(module_path)
        if module is None:
            continue
        for _name, obj in inspect.getmembers(module, inspect.isclass):
            for method_name in methods:
                func = getattr(obj, method_name, None)
                if func and hasattr(func, "__wrapped__"):
                    setattr(obj, method_name, func.__wrapped__)


def run_with_instrumentation(
    target: Path,
    test_command: list[str] | None = None,
) -> RuntimeReport:
    """Run the target's test suite with instrumentation and return the report.

    Runs a subprocess that imports the patcher, executes the test suite, then
    serializes the report to a temp file which the parent reads back.
    """
    import json as _json
    import os
    import subprocess
    import tempfile

    reset_report()

    # Create temp file atomically via mkstemp (avoids TOCTOU)
    fd, report_path = tempfile.mkstemp(suffix=".json", prefix="agentwall_l7_report_")
    os.close(fd)

    # Build the test args for the subprocess
    if test_command is None:
        test_args = ["-m", "pytest", str(target), "-x", "--tb=no", "-q"]
    elif test_command[0] == sys.executable:
        test_args = test_command[1:]
    else:
        test_args = test_command

    # Pass report path via env var to avoid embedding in script string
    env = os.environ.copy()
    env["AGENTWALL_L7_REPORT"] = report_path

    # The subprocess script: patch, run tests, serialize report
    script = """\
import sys, os, json

report_path = os.environ["AGENTWALL_L7_REPORT"]

# Patch vector store methods
from agentwall.runtime.patcher import patch_all, get_report

patches = patch_all()
if patches == 0:
    with open(report_path, "w") as f:
        json.dump({"violations": [], "total_calls": 0, "filtered_calls": 0}, f)
    sys.exit(0)

# Run the test suite
test_args = json.loads(os.environ.get("AGENTWALL_L7_TEST_ARGS", "[]"))
if test_args and test_args[0] == "-m":
    import runpy
    sys.argv = test_args[1:]
    try:
        runpy.run_module(test_args[1], run_name="__main__", alter_sys=True)
    except SystemExit:
        pass
else:
    import subprocess as sp
    sp.run([sys.executable] + test_args, cwd=os.environ.get("AGENTWALL_L7_CWD", "."))

# Serialize report
report = get_report()
data = {
    "violations": [
        {"method": v.method, "file": v.file, "line": v.line}
        for v in report.violations
    ],
    "total_calls": report.total_calls,
    "filtered_calls": report.filtered_calls,
}
with open(report_path, "w") as f:
    json.dump(data, f)
"""

    env["AGENTWALL_L7_TEST_ARGS"] = _json.dumps(test_args)
    env["AGENTWALL_L7_CWD"] = str(target)

    try:
        proc = subprocess.run(
            [sys.executable, "-c", script],
            capture_output=True,
            text=True,
            timeout=300,
            cwd=str(target),
            env=env,
        )

        # Read back the report
        report_file = Path(report_path)
        if report_file.exists() and report_file.stat().st_size > 0:
            raw = _json.loads(report_file.read_text())
            result = RuntimeReport(
                total_calls=raw.get("total_calls", 0),
                filtered_calls=raw.get("filtered_calls", 0),
            )
            for v in raw.get("violations", []):
                result.violations.append(
                    RuntimeViolation(
                        method=v["method"],
                        file=v["file"],
                        line=v["line"],
                        kwargs={},
                    )
                )
            return result

        # Subprocess ran but produced no report — instrumentation failed
        warnings.warn(
            f"L7: Subprocess completed (rc={proc.returncode}) but produced no report. "
            f"stderr: {proc.stderr[:200] if proc.stderr else '(empty)'}",
            stacklevel=2,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError) as exc:
        warnings.warn(f"L7: Test execution failed: {exc}", stacklevel=2)
    finally:
        Path(report_path).unlink(missing_ok=True)

    return RuntimeReport()  # empty report — distinguishable from success via caller warning
