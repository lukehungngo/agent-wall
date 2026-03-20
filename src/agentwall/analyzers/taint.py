"""L3 — Taint Analysis.

Track whether user identity flows from request entry point to retrieval filter.
Answers: "does data from request.user actually reach the filter parameter?"
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import (
    Category,
    ConfidenceLevel,
    Finding,
    Severity,
    TaintResult,
    TaintSink,
    TaintSource,
)
from agentwall.patterns import SIMPLE_SOURCE_NAMES, SINK_METHODS, SOURCE_PATTERNS


@dataclass
class _TaintState:
    """Track tainted variables through a file."""

    tainted_vars: set[str] = field(default_factory=set)
    sources: list[TaintSource] = field(default_factory=list)
    sinks: list[TaintSink] = field(default_factory=list)
    flows: list[TaintResult] = field(default_factory=list)
    static_filter_sinks: set[int] = field(
        default_factory=set
    )  # line numbers of sinks with static filters


class _TaintVisitor(ast.NodeVisitor):
    """AST visitor that tracks taint flow through a file."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self.state = _TaintState()
        self._current_func: str | None = None
        # Per-function source tracking to avoid cross-function false pairing
        self._func_sources: list[TaintSource] = []

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev_func = self._current_func
        prev_tainted = self.state.tainted_vars.copy()
        prev_func_sources = self._func_sources
        self._current_func = node.name
        self._func_sources = []
        self._check_params_for_sources(node)
        self.generic_visit(node)
        self._current_func = prev_func
        self.state.tainted_vars = prev_tainted
        self._func_sources = prev_func_sources

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        prev_func = self._current_func
        prev_tainted = self.state.tainted_vars.copy()
        prev_func_sources = self._func_sources
        self._current_func = node.name
        self._func_sources = []
        self._check_params_for_sources(node)
        self.generic_visit(node)
        self._current_func = prev_func
        self.state.tainted_vars = prev_tainted
        self._func_sources = prev_func_sources

    def _check_params_for_sources(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Mark function parameters named user_id, tenant_id, etc. as tainted."""
        for arg in node.args.args:
            if arg.arg.lower() in SIMPLE_SOURCE_NAMES:
                self.state.tainted_vars.add(arg.arg)
                src = TaintSource(
                    name=arg.arg,
                    file=self.file_path,
                    lineno=node.lineno,
                )
                self.state.sources.append(src)
                self._func_sources.append(src)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Track taint propagation through assignments."""
        # Check if RHS contains any tainted variable
        rhs_tainted = self._expr_is_tainted(node.value)

        # Check if RHS is a source pattern (e.g., x = request.user)
        rhs_is_source = self._expr_is_source(node.value)

        if rhs_tainted or rhs_is_source:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.state.tainted_vars.add(target.id)
                    if rhs_is_source:
                        src = TaintSource(
                            name=target.id,
                            file=self.file_path,
                            lineno=node.lineno,
                        )
                        self.state.sources.append(src)
                        self._func_sources.append(src)

        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Check if tainted data reaches a sink (filter kwarg)."""
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in SINK_METHODS:
            expected_kwarg = SINK_METHODS[func.attr]
            kwarg_found = False
            for kw in node.keywords:
                if kw.arg == expected_kwarg:
                    kwarg_found = True
                    sink = TaintSink(
                        name=f"{func.attr}.{expected_kwarg}",
                        file=self.file_path,
                        lineno=node.lineno,
                    )
                    self.state.sinks.append(sink)
                    if self._expr_is_tainted(kw.value):
                        # Find the specific source that taints this expression
                        source = self._find_taint_source(kw.value)
                        if source:
                            self.state.flows.append(
                                TaintResult(
                                    source=source,
                                    sink=sink,
                                    reaches=True,
                                )
                            )
                    else:
                        # kwarg exists but not tainted — static filter value
                        self.state.static_filter_sinks.add(node.lineno)

            # Retrieval call exists but filter kwarg is missing entirely
            if not kwarg_found:
                sink = TaintSink(
                    name=f"{func.attr}.{expected_kwarg}",
                    file=self.file_path,
                    lineno=node.lineno,
                )
                self.state.sinks.append(sink)
                if self._func_sources:
                    self.state.flows.append(
                        TaintResult(
                            source=self._func_sources[0],
                            sink=sink,
                            reaches=False,
                        )
                    )

        self.generic_visit(node)

    def _find_taint_source(self, node: ast.expr) -> TaintSource | None:
        """Find the specific source that taints an expression, scoped to current function."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.state.tainted_vars:
                # Prefer function-scoped sources
                for source in self._func_sources:
                    if source.name == child.id:
                        return source
                # Fall back to file-level sources (e.g., module-level assignments)
                for source in self.state.sources:
                    if source.name == child.id:
                        return source
        return None

    def _expr_is_tainted(self, node: ast.expr) -> bool:
        """Check if an expression references any tainted variable."""
        for child in ast.walk(node):
            if isinstance(child, ast.Name) and child.id in self.state.tainted_vars:
                return True
        return False

    def _expr_is_source(self, node: ast.expr) -> bool:
        """Check if expression matches a source pattern like request.user."""
        src = self._expr_to_str(node)
        if not src:
            return False
        return any(src.endswith(pat) or pat.endswith(src) for pat in SOURCE_PATTERNS)

    def _expr_to_str(self, node: ast.expr) -> str | None:
        """Convert simple attribute access to dotted string."""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            base = self._expr_to_str(node.value)
            if base:
                return f"{base}.{node.attr}"
        return None


class TaintAnalyzer:
    """L3 analyzer: track user identity flow from source to sink."""

    name: str = "L3"
    depends_on: Sequence[str] = ("L2",)
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = False

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Run taint analysis across all source files."""
        spec = ctx.spec
        if spec is None:
            return []

        _call_graph = ctx.call_graph  # available for cross-file taint (v1.0)  # noqa: F841

        findings: list[Finding] = []

        all_sources: list[TaintSource] = []
        all_sinks: list[TaintSink] = []
        all_flows: list[TaintResult] = []
        static_filter_lines: set[tuple[Path, int]] = set()

        for py_file in spec.source_files:
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (OSError, SyntaxError) as exc:
                warnings.warn(f"L3: Skipping {py_file}: {exc}", stacklevel=2)
                continue

            visitor = _TaintVisitor(py_file)
            visitor.visit(tree)

            all_sources.extend(visitor.state.sources)
            all_sinks.extend(visitor.state.sinks)
            all_flows.extend(visitor.state.flows)
            for lineno in visitor.state.static_filter_sinks:
                static_filter_lines.add((py_file, lineno))

        # Analyze flows: if source exists but never reaches any sink → finding
        if all_sources and all_sinks:
            unreached = [f for f in all_flows if not f.reaches]
            for flow in unreached:
                findings.append(
                    Finding(
                        rule_id="AW-MEM-001",
                        title="User identity does not reach retrieval filter",
                        severity=Severity.CRITICAL,
                        category=Category.MEMORY,
                        description=(
                            f"User identity from '{flow.source.name}' "
                            f"(at {flow.source.file.name}:{flow.source.lineno}) "
                            f"does not flow into the retrieval filter "
                            f"at {flow.sink.file.name}:{flow.sink.lineno}. "
                            "The vector store query is not scoped to the current user."
                        ),
                        file=flow.sink.file,
                        line=flow.sink.lineno,
                        fix="Pass the user identity through to the filter kwarg.",
                        confidence=ConfidenceLevel.HIGH,
                        layer="L3",
                    )
                )

        # If sources exist but no sinks at all (no retrieval filter kwarg anywhere)
        if all_sources and not all_sinks:
            for mc in spec.memory_configs:
                if not mc.has_metadata_filter_on_retrieval:
                    findings.append(
                        Finding(
                            rule_id="AW-MEM-001",
                            title="User identity available but no filter sink found",
                            severity=Severity.CRITICAL,
                            category=Category.MEMORY,
                            description=(
                                "User identity sources detected but no retrieval filter "
                                "uses them. Vector store queries are not tenant-scoped."
                            ),
                            file=mc.source_file,
                            line=mc.source_line,
                            fix="Add filter={'user_id': user_id} to all retrieval calls.",
                            confidence=ConfidenceLevel.HIGH,
                            layer="L3",
                        )
                    )

        # If sinks have static filter values (filter kwarg present but not tainted)
        reached_flows = [f for f in all_flows if f.reaches]
        if static_filter_lines and all_sources and not reached_flows:
            for sink in all_sinks:
                if (sink.file, sink.lineno) not in static_filter_lines:
                    continue
                findings.append(
                    Finding(
                        rule_id="AW-MEM-002",
                        title="Filter exists but does not contain user identity",
                        severity=Severity.HIGH,
                        category=Category.MEMORY,
                        description=(
                            f"Retrieval filter at {sink.file.name}:{sink.lineno} "
                            "contains only static values — not scoped to the current user. "
                            "This is a false sense of security."
                        ),
                        file=sink.file,
                        line=sink.lineno,
                        fix="Ensure the filter contains a user-scoped value like user_id.",
                        confidence=ConfidenceLevel.MEDIUM,
                        layer="L3",
                    )
                )

        # Write taint results to context for downstream analyzers (L6)
        ctx.taint_results = all_flows

        return findings
