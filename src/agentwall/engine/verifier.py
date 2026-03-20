"""L3 engine: fixpoint property verifier for tenant isolation.

Implements a three-phase algorithm inspired by Pysa's fixpoint approach:

  Phase 1 — _compute_initial_summaries: intraprocedural taint analysis.
             For each function in each source file, determine which params
             reach a store filter and whether any unfiltered store reads exist.

  Phase 2 — _fixpoint_propagate: interprocedural refinement.
             Iterate call edges until no summaries change (max_iterations cap).
             If a callee param reaches a filter and the caller passes a tenant-
             named arg at that position, the caller's read is transitively safe.

  Phase 3 — _verify_profiles: emit PropertyVerification per store read.
             COLLECTION_PER_TENANT → VERIFIED.
             COMPOUND_TENANT filter → VERIFIED.
             COMPOUND_STATIC / LITERAL filter → VIOLATED (not tenant-scoped).
             Missing filter → VIOLATED.
             Anything else → UNKNOWN.

Never executes user code. All analysis via ast.parse() only.
"""

from __future__ import annotations

import ast
import logging
import warnings
from dataclasses import replace
from pathlib import Path

from agentwall.engine.graph import ProjectGraph
from agentwall.engine.models import (
    IsolationStrategy,
    PropertyVerification,
    SecurityProperty,
    StoreAccess,
    StoreProfile,
    TenantFlowSummary,
    ValueKind,
    Verdict,
    classify_value,
)
from agentwall.frameworks.base import FrameworkModel

logger = logging.getLogger(__name__)

# ── Public API ─────────────────────────────────────────────────────────────────


def verify_tenant_isolation(
    profiles: list[StoreProfile],
    graph: ProjectGraph,
    model: FrameworkModel,
) -> list[PropertyVerification]:
    """Verify tenant isolation for each store profile.

    Args:
        profiles: Store profiles produced by extract_properties.
        graph: Project call graph produced by build_project_graph.
        model: Framework model declaring tenant param names and store contracts.

    Returns:
        One PropertyVerification per read extraction across all profiles.
        Profiles with no read extractions produce no results.
        Never raises.
    """
    if not profiles:
        return []

    # Collect all source files mentioned across profiles for Phase 1 analysis.
    source_files: list[Path] = _collect_source_files(profiles)

    # Phase 1: intraprocedural summaries.
    summaries = _compute_initial_summaries(source_files, model)

    # Phase 2: fixpoint interprocedural refinement.
    summaries = _fixpoint_propagate(summaries, graph, model)

    # Phase 3: verdict per store profile.
    return _verify_profiles(profiles, summaries, model)


# ── Phase 1 ───────────────────────────────────────────────────────────────────


def _collect_source_files(profiles: list[StoreProfile]) -> list[Path]:
    """Return deduplicated source files mentioned in any profile."""
    seen: set[Path] = set()
    result: list[Path] = []
    for p in profiles:
        if p.file is not None and p.file not in seen:
            seen.add(p.file)
            result.append(p.file)
        for e in p.extractions:
            if e.file not in seen:
                seen.add(e.file)
                result.append(e.file)
    return result


def _compute_initial_summaries(
    source_files: list[Path],
    model: FrameworkModel,
) -> dict[str, TenantFlowSummary]:
    """Produce per-function TenantFlowSummary from intraprocedural analysis.

    Args:
        source_files: Python files to analyse.
        model: Framework model with tenant_param_names and store method maps.

    Returns:
        Mapping from function qualified name to its flow summary.
        Module-level code uses the key '<module>'.
    """
    summaries: dict[str, TenantFlowSummary] = {}

    for path in source_files:
        try:
            source = path.read_text(encoding="utf-8")
        except OSError as exc:
            warnings.warn(f"Cannot read {path}: {exc}", stacklevel=2)
            continue

        try:
            tree = ast.parse(source, filename=str(path))
        except SyntaxError as exc:
            warnings.warn(f"Syntax error in {path}: {exc}", stacklevel=2)
            continue

        visitor = _SummaryVisitor(file_path=path, model=model)
        visitor.visit(tree)

        for func_name, summary in visitor.summaries.items():
            summaries[func_name] = summary

    return summaries


# ── Phase 2 ───────────────────────────────────────────────────────────────────


def _fixpoint_propagate(
    summaries: dict[str, TenantFlowSummary],
    graph: ProjectGraph,
    model: FrameworkModel,
    max_iterations: int = 20,
) -> dict[str, TenantFlowSummary]:
    """Iterate call edges until summaries stabilize.

    For each call edge where:
      - The callee summary has param_reaches_filter entries
      - The caller passes a tenant-named arg at one of those param positions

    The caller's has_unfiltered_read is set to False (the read is safe via
    the callee).

    Args:
        summaries: Initial per-function summaries from Phase 1.
        graph: Project call graph with resolved call edges.
        model: Framework model with tenant_param_names.
        max_iterations: Maximum fixpoint iterations before stopping.

    Returns:
        Updated summaries dict (same keys, potentially updated values).
    """
    tenant_names = set(model.tenant_param_names)

    for _iteration in range(max_iterations):
        changed = False

        for edge in graph.call_edges:
            if not edge.resolved:
                continue

            callee_summary = summaries.get(edge.callee_name)
            caller_summary = summaries.get(edge.caller_name)

            if callee_summary is None or caller_summary is None:
                continue

            if not callee_summary.param_reaches_filter:
                continue

            # Check each param index that reaches a filter in the callee.
            for param_idx in callee_summary.param_reaches_filter:
                if param_idx >= len(edge.arg_names):
                    continue
                arg_name = edge.arg_names[param_idx]
                if arg_name in tenant_names and caller_summary.has_unfiltered_read:
                    # Caller passes a tenant-scoped arg to a filter-reaching param.
                    updated = replace(caller_summary, has_unfiltered_read=False)
                    summaries[edge.caller_name] = updated
                    changed = True

        if not changed:
            break

    return summaries


# ── Phase 3 ───────────────────────────────────────────────────────────────────


def _verify_profiles(
    profiles: list[StoreProfile],
    summaries: dict[str, TenantFlowSummary],
    model: FrameworkModel,  # noqa: ARG001 — reserved for future use
) -> list[PropertyVerification]:
    """Emit one PropertyVerification per read extraction per profile.

    Decision rules (in priority order):
      1. COLLECTION_PER_TENANT isolation strategy → VERIFIED (no filter needed).
      2. filter_value_kind == COMPOUND_TENANT → VERIFIED.
      3. filter_value_kind in (COMPOUND_STATIC, LITERAL) → VIOLATED.
      4. has_filter == False → VIOLATED (no filter at all).
      5. All other cases → UNKNOWN.
    """
    results: list[PropertyVerification] = []

    for profile in profiles:
        reads = [e for e in profile.extractions if e.operation == "read"]
        if not reads:
            continue

        is_collection_isolated = (
            profile.isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT
        )

        for extraction in reads:
            access = StoreAccess(
                store_id=profile.store_id,
                method=extraction.method,
                filter_kind=extraction.filter_value_kind,
            )

            if is_collection_isolated or extraction.filter_value_kind == ValueKind.COMPOUND_TENANT:
                verdict = Verdict.VERIFIED
            elif (
                extraction.filter_value_kind
                in (
                    ValueKind.COMPOUND_STATIC,
                    ValueKind.LITERAL,
                )
                or not extraction.has_filter
            ):
                verdict = Verdict.VIOLATED
            else:
                verdict = Verdict.UNKNOWN

            results.append(
                PropertyVerification(
                    store_id=profile.store_id,
                    access=access,
                    property=SecurityProperty.TENANT_ISOLATION,
                    verdict=verdict,
                    file=extraction.file,
                    line=extraction.line,
                )
            )

    return results


# ── Internal AST visitor for Phase 1 ──────────────────────────────────────────


class _SummaryVisitor(ast.NodeVisitor):
    """Walk a single file producing per-function TenantFlowSummary objects."""

    def __init__(self, file_path: Path, model: FrameworkModel) -> None:
        self._file = file_path
        self._model = model

        # All store read method names from the model (across all store types).
        self._read_methods: set[str] = {
            method for store in model.stores.values() for method in store.read_methods
        }

        # Maps store method name → filter kwarg name.
        self._filter_kwarg_for: dict[str, str] = {}
        for store in model.stores.values():
            for method, kwarg in store.read_methods.items():
                if method not in self._filter_kwarg_for:
                    self._filter_kwarg_for[method] = kwarg

        # Tenant param names from model.
        self._tenant_param_names: set[str] = set(model.tenant_param_names)

        # Summaries collected for this file.
        self.summaries: dict[str, TenantFlowSummary] = {}

        # Current function context.
        self._current_func: str | None = None
        self._current_params: list[str] = []
        # Tainted variable names in the current scope.
        self._tainted: set[str] = set()
        # Per-function: param index → set of store_ids whose filters it reaches.
        self._param_reaches: dict[int, frozenset[str]] = {}
        self._has_unfiltered_read: bool = False

    # ── Scope management ──────────────────────────────────────────────────────

    def _enter_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        # Save outer context.
        outer_func = self._current_func
        outer_params = self._current_params
        outer_tainted = self._tainted.copy()
        outer_reaches = self._param_reaches
        outer_unfiltered = self._has_unfiltered_read

        # Set up new scope.
        params = [arg.arg for arg in node.args.args]
        self._current_func = node.name
        self._current_params = params
        self._tainted = {p for p in params if p in self._tenant_param_names}
        self._param_reaches = {}
        self._has_unfiltered_read = False

        self.generic_visit(node)

        # Emit summary for this function.
        self.summaries[node.name] = TenantFlowSummary(
            function=node.name,
            file=self._file,
            param_reaches_filter=dict(self._param_reaches),
            has_unfiltered_read=self._has_unfiltered_read,
        )

        # Restore outer context.
        self._current_func = outer_func
        self._current_params = outer_params
        self._tainted = outer_tainted
        self._param_reaches = outer_reaches
        self._has_unfiltered_read = outer_unfiltered

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._enter_function(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:  # noqa: N802
        self._enter_function(node)

    # ── Assignment: propagate taint ───────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        """If RHS references a tainted name, taint the LHS variable."""
        if _expr_references_any(node.value, self._tainted):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self._tainted.add(target.id)
        self.generic_visit(node)

    # ── Call: detect store reads ──────────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        """Detect store.method(...) calls and classify filter taint."""
        if isinstance(node.func, ast.Attribute):
            method = node.func.attr
            if method in self._read_methods:
                self._analyze_read_call(node, method)
        self.generic_visit(node)

    def _analyze_read_call(self, call: ast.Call, method: str) -> None:
        """Classify the filter argument of a read call and update summaries."""
        filter_kwarg = self._filter_kwarg_for.get(method)
        if filter_kwarg is None:
            self._has_unfiltered_read = True
            return

        filter_node: ast.expr | None = None
        for kw in call.keywords:
            if kw.arg == filter_kwarg:
                filter_node = kw.value
                break

        if filter_node is None:
            self._has_unfiltered_read = True
            return

        kind = classify_value(filter_node, self._tainted)
        if kind == ValueKind.COMPOUND_TENANT:
            # Record which params reach this filter.
            self._record_param_reaches_filter(filter_node)
        else:
            self._has_unfiltered_read = True

    def _record_param_reaches_filter(self, filter_node: ast.expr) -> None:
        """Record which function params contribute to a tenant-scoped filter."""
        tainted_vars = _collect_name_refs(filter_node) & self._tainted

        for idx, param_name in enumerate(self._current_params):
            if param_name in tainted_vars:
                existing = self._param_reaches.get(idx, frozenset())
                self._param_reaches[idx] = existing | frozenset(["_filter"])


# ── Pure AST helpers ──────────────────────────────────────────────────────────


def _expr_references_any(node: ast.expr, names: set[str]) -> bool:
    """Return True if node references any name in the given set."""
    return any(isinstance(child, ast.Name) and child.id in names for child in ast.walk(node))


def _collect_name_refs(node: ast.expr) -> set[str]:
    """Return all Name ids referenced anywhere inside node."""
    return {child.id for child in ast.walk(node) if isinstance(child, ast.Name)}
