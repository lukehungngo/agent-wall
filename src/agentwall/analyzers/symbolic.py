"""L6 — Symbolic / Abstract Interpretation.

Path-sensitive analysis using a simple lattice to determine if a filter
is applied on ALL code paths, not just some.

Lattice:
       TOP (unknown)
      /           \\
  FILTERED    UNFILTERED
      \\           /
      BOTTOM (unreachable)
"""

from __future__ import annotations

import ast
import warnings
from collections.abc import Sequence
from enum import Enum, auto

from agentwall.context import AnalysisContext
from agentwall.models import (
    Category,
    ConfidenceLevel,
    Finding,
    Severity,
)
from agentwall.patterns import FILTER_KWARGS, RETRIEVAL_METHODS


class FilterState(Enum):
    """Abstract state for filter analysis."""

    TOP = auto()  # unknown — not yet determined
    FILTERED = auto()  # filter applied on this path
    UNFILTERED = auto()  # no filter on this path
    BOTTOM = auto()  # unreachable


def _join(a: FilterState, b: FilterState) -> FilterState:
    """Join two states at a merge point (e.g., after if/else)."""
    if a == b:
        return a
    if a == FilterState.BOTTOM:
        return b
    if b == FilterState.BOTTOM:
        return a
    if a == FilterState.TOP or b == FilterState.TOP:
        return FilterState.TOP
    # FILTERED + UNFILTERED → TOP (mixed paths)
    return FilterState.TOP


class _PathAnalyzer(ast.NodeVisitor):
    """Analyze a function body for path-sensitive filter application."""

    def __init__(self) -> None:
        self.state: FilterState = FilterState.BOTTOM
        self.has_retrieval: bool = False
        self.branch_results: list[FilterState] = []

    def analyze_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> FilterState:
        """Analyze all paths through a function, return final state."""
        self.state = FilterState.BOTTOM
        self.has_retrieval = False
        self._analyze_body(node.body)
        return self.state

    def _analyze_body(self, stmts: list[ast.stmt]) -> None:
        """Analyze a sequence of statements."""
        for stmt in stmts:
            self._analyze_stmt(stmt)

    def _analyze_stmt(self, stmt: ast.stmt) -> None:
        """Analyze a single statement."""
        if isinstance(stmt, ast.If):
            self._analyze_if(stmt)
        elif isinstance(stmt, ast.For | ast.While):
            self._analyze_loop(stmt)
        elif isinstance(stmt, ast.Try):
            self._analyze_try(stmt)
        elif isinstance(stmt, ast.With | ast.AsyncWith):
            self._analyze_body(stmt.body)
        elif (
            isinstance(stmt, ast.Expr | ast.Assign | ast.AugAssign)
            and isinstance(stmt.value, ast.Call)
        ) or (isinstance(stmt, ast.Return) and isinstance(getattr(stmt, "value", None), ast.Call)):
            self._analyze_call(stmt.value)  # type: ignore[arg-type]

    def _analyze_if(self, node: ast.If) -> None:
        """Analyze if/elif/else branches — join states at merge point."""
        # Save state before branches
        pre_state = self.state

        # Analyze 'then' branch
        self.state = pre_state
        self._analyze_body(node.body)
        then_state = self.state

        # Analyze 'else' branch
        self.state = pre_state
        if node.orelse:
            self._analyze_body(node.orelse)
        else:
            # No else → the pre-state persists on the else path
            pass
        else_state = self.state

        # Join both branches
        self.state = _join(then_state, else_state)

    def _analyze_loop(self, node: ast.For | ast.While) -> None:
        """Analyze loop body — conservative: use TOP if retrieval in loop."""
        pre_state = self.state
        self._analyze_body(node.body)
        loop_state = self.state
        # Loop might execute 0 times, so join with pre-state
        self.state = _join(pre_state, loop_state)

    def _analyze_try(self, node: ast.Try) -> None:
        """Analyze try/except — join all branches."""
        pre_state = self.state
        self._analyze_body(node.body)
        try_state = self.state

        handler_states: list[FilterState] = []
        for handler in node.handlers:
            self.state = pre_state
            self._analyze_body(handler.body)
            handler_states.append(self.state)

        combined = try_state
        for hs in handler_states:
            combined = _join(combined, hs)

        if node.orelse:
            self.state = try_state
            self._analyze_body(node.orelse)
            combined = _join(combined, self.state)

        if node.finalbody:
            self.state = combined
            self._analyze_body(node.finalbody)
            combined = _join(combined, self.state)

        self.state = combined

    def _analyze_call(self, node: ast.Call) -> None:
        """Check if a call is a retrieval with or without filter."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        if func.attr not in RETRIEVAL_METHODS:
            return

        self.has_retrieval = True

        # Check for filter kwarg
        has_filter = False
        for kw in node.keywords:
            if kw.arg in FILTER_KWARGS:
                has_filter = True
            if kw.arg == "search_kwargs" and isinstance(kw.value, ast.Dict):
                for key in kw.value.keys:
                    if isinstance(key, ast.Constant) and key.value == "filter":
                        has_filter = True

        new_state = FilterState.FILTERED if has_filter else FilterState.UNFILTERED
        self.state = _join(self.state, new_state)


class SymbolicAnalyzer:
    """L6 analyzer: path-sensitive filter analysis."""

    name: str = "L6"
    depends_on: Sequence[str] = ("L3",)
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = False

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Analyze all functions for path-dependent filter application."""
        spec = ctx.spec
        if spec is None:
            return []

        # NEW: Try new engine (non-breaking)
        try:
            from agentwall.engine.pathcov import compute_path_coverage

            if (
                ctx.store_profiles is not None
                and ctx.project_graph is not None
                and ctx.property_verifications is not None
            ):
                coverages = compute_path_coverage(
                    ctx.store_profiles,
                    ctx.project_graph,
                    ctx.property_verifications,
                )
                ctx.path_coverages = coverages
        except Exception:
            pass

        _taint_results = (
            ctx.taint_results
        )  # available for taint-aware path analysis (v1.0)  # noqa: F841

        findings: list[Finding] = []

        for py_file in spec.source_files:
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (OSError, SyntaxError) as exc:
                warnings.warn(f"L6: Skipping {py_file}: {exc}", stacklevel=2)
                continue

            for node in ast.walk(tree):
                if not isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                    continue

                analyzer = _PathAnalyzer()
                final_state = analyzer.analyze_function(node)

                if not analyzer.has_retrieval:
                    continue

                if final_state == FilterState.UNFILTERED:
                    findings.append(
                        Finding(
                            rule_id="AW-MEM-001",
                            title=f"No filter on any path in {node.name}()",
                            severity=Severity.HIGH,
                            category=Category.MEMORY,
                            description=(
                                f"Function '{node.name}' performs vector store retrieval "
                                "without a filter on all code paths."
                            ),
                            file=py_file,
                            line=node.lineno,
                            fix="Add filter= to all retrieval calls in this function.",
                            confidence=ConfidenceLevel.MEDIUM,
                            layer="L6",
                        )
                    )
                elif final_state == FilterState.TOP:
                    # Mixed: some paths filtered, some not
                    findings.append(
                        Finding(
                            rule_id="AW-MEM-001",
                            title=f"Filter missing on some paths in {node.name}()",
                            severity=Severity.HIGH,
                            category=Category.MEMORY,
                            description=(
                                f"Function '{node.name}' has vector store retrieval "
                                "with a filter on some code paths but not all. "
                                "At least one execution path lacks tenant scoping."
                            ),
                            file=py_file,
                            line=node.lineno,
                            fix="Ensure filter= is applied on ALL branches.",
                            confidence=ConfidenceLevel.MEDIUM,
                            layer="L6",
                        )
                    )

        return findings
