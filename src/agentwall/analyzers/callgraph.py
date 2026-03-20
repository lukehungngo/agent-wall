"""L2 — Inter-Procedural Call Graph.

Builds a lightweight call graph across files using AST-only analysis.
Resolves direct imports, class method calls, and traces filter application
through call chains to confirm or dismiss L1 findings.
"""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import (
    CallEdge,
    CallGraph,
    ConfidenceLevel,
    Finding,
    FunctionRef,
    MemoryConfig,
    Severity,
)
from agentwall.patterns import FILTER_KWARGS, RETRIEVAL_METHODS
from agentwall.rules import RuleDef


def _finding_from_rule(rule: RuleDef, mc: MemoryConfig, *, layer: str = "L2") -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        fix=rule.fix,
        file=mc.source_file,
        line=mc.source_line,
        layer=layer,
    )


class _DefinitionCollector(ast.NodeVisitor):
    """Collect all function and class definitions in a file."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self.functions: dict[str, FunctionRef] = {}
        self.classes: dict[str, dict[str, FunctionRef]] = {}
        self._current_class: str | None = None

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev = self._current_class
        self._current_class = node.name
        self.classes[node.name] = {}
        self.generic_visit(node)
        self._current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._register_func(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._register_func(node)
        self.generic_visit(node)

    def _register_func(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        if self._current_class:
            qualified = f"{self._current_class}.{node.name}"
            ref = FunctionRef(file=self.file_path, name=qualified, lineno=node.lineno)
            self.classes[self._current_class][node.name] = ref
        else:
            ref = FunctionRef(file=self.file_path, name=node.name, lineno=node.lineno)
        self.functions[ref.name] = ref


class _ImportResolver:
    """Resolve import statements to file paths."""

    def __init__(self, target: Path, all_files: list[Path]) -> None:
        self.target = target
        # Build module → file mapping
        self._module_map: dict[str, Path] = {}
        for f in all_files:
            try:
                rel = f.relative_to(target)
            except ValueError:
                continue
            # Convert path to module: src/agentwall/cli.py → src.agentwall.cli
            parts = list(rel.parts)
            if parts[-1] == "__init__.py":
                parts = parts[:-1]
            else:
                parts[-1] = parts[-1].removesuffix(".py")
            module = ".".join(parts)
            self._module_map[module] = f

    def resolve(self, module: str | None) -> Path | None:
        if not module:
            return None
        # Try exact match first
        if module in self._module_map:
            return self._module_map[module]
        # Try prefix match (e.g. "foo.bar" might match "foo/bar.py")
        for mod, path in self._module_map.items():
            if mod.endswith(module) or module.endswith(mod):
                return path
        return None


class _CallSiteCollector(ast.NodeVisitor):
    """Collect all call sites in a file."""

    def __init__(self, file_path: Path) -> None:
        self.file_path = file_path
        self.calls: list[tuple[str, str | None, int]] = []  # (caller, callee, line)
        self._current_func: str | None = None
        self._current_class: str | None = None
        # Track variable types via assignments
        self._var_types: dict[str, str] = {}  # var_name → class_name

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        prev = self._current_class
        self._current_class = node.name
        self.generic_visit(node)
        self._current_class = prev

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        prev = self._current_func
        if self._current_class:
            self._current_func = f"{self._current_class}.{node.name}"
        else:
            self._current_func = node.name
        self.generic_visit(node)
        self._current_func = prev

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        prev = self._current_func
        if self._current_class:
            self._current_func = f"{self._current_class}.{node.name}"
        else:
            self._current_func = node.name
        self.generic_visit(node)
        self._current_func = prev

    def visit_Assign(self, node: ast.Assign) -> None:
        # Track x = ClassName(...) assignments for method resolution
        if isinstance(node.value, ast.Call):
            func = node.value.func
            class_name = None
            if isinstance(func, ast.Name):
                class_name = func.id
            elif isinstance(func, ast.Attribute):
                class_name = func.attr
            if class_name and node.targets:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        self._var_types[target.id] = class_name
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        caller = "<module>" if self._current_func is None else self._current_func

        callee = self._resolve_callee(node)
        if callee:
            self.calls.append((caller, callee, node.lineno))
        self.generic_visit(node)

    def _resolve_callee(self, node: ast.Call) -> str | None:
        func = node.func
        if isinstance(func, ast.Name):
            return func.id
        if isinstance(func, ast.Attribute):
            # x.method() — try to resolve x to a class
            if isinstance(func.value, ast.Name):
                var_name = func.value.id
                if var_name == "self" and self._current_class:
                    return f"{self._current_class}.{func.attr}"
                class_name = self._var_types.get(var_name)
                if class_name:
                    return f"{class_name}.{func.attr}"
                return f"{var_name}.{func.attr}"
            return func.attr
        return None


class _FilterChecker(ast.NodeVisitor):
    """Check if a function applies a filter to retrieval calls."""

    def __init__(self) -> None:
        self.has_filter = False
        self.has_retrieval = False

    def visit_Call(self, node: ast.Call) -> None:
        func = node.func
        if isinstance(func, ast.Attribute) and func.attr in RETRIEVAL_METHODS:
            self.has_retrieval = True
            for kw in node.keywords:
                if kw.arg in FILTER_KWARGS:
                    self.has_filter = True
                if kw.arg == "search_kwargs" and isinstance(kw.value, ast.Dict):
                    for key in kw.value.keys:
                        if isinstance(key, ast.Constant) and key.value == "filter":
                            self.has_filter = True
        self.generic_visit(node)


def build_call_graph(target: Path, source_files: list[Path]) -> CallGraph:
    """Build an inter-procedural call graph from source files."""
    graph = CallGraph()
    all_defs: dict[str, FunctionRef] = {}
    class_defs: dict[str, dict[str, FunctionRef]] = {}
    # TODO: wire _ImportResolver into call site resolution for cross-file imports

    # Phase 1: collect all definitions
    for py_file in source_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue
        collector = _DefinitionCollector(py_file)
        collector.visit(tree)
        all_defs.update(collector.functions)
        class_defs.update(collector.classes)

    # Phase 2: collect call sites and build edges
    for py_file in source_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue
        call_collector = _CallSiteCollector(py_file)
        call_collector.visit(tree)

        for caller_name, callee_name, lineno in call_collector.calls:
            if callee_name is None:
                graph.unresolved.append((py_file, lineno))
                continue

            caller_ref = all_defs.get(
                caller_name, FunctionRef(file=py_file, name=caller_name, lineno=0)
            )

            # Try to resolve callee
            callee_ref = all_defs.get(callee_name)
            if callee_ref is None:
                # Try class method lookup
                parts = callee_name.split(".", 1)
                if len(parts) == 2:
                    cls, method = parts
                    if cls in class_defs and method in class_defs[cls]:
                        callee_ref = class_defs[cls][method]

            if callee_ref:
                graph.edges.append(
                    CallEdge(
                        caller=caller_ref,
                        callee=callee_ref,
                        call_site_line=lineno,
                        resolved=True,
                    )
                )
            else:
                graph.edges.append(
                    CallEdge(
                        caller=caller_ref,
                        callee=FunctionRef(file=py_file, name=callee_name, lineno=0),
                        call_site_line=lineno,
                        resolved=False,
                    )
                )

    return graph


def _function_has_filter(func_name: str, source_files: list[Path]) -> bool:
    """Check if any function with this name applies a filter in its body."""
    for py_file in source_files:
        try:
            source = py_file.read_text(encoding="utf-8")
            tree = ast.parse(source, filename=str(py_file))
        except (OSError, SyntaxError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef):
                qualified = node.name
                if qualified == func_name or func_name.endswith(f".{qualified}"):
                    checker = _FilterChecker()
                    checker.visit(node)
                    if checker.has_filter:
                        return True
    return False


class CallGraphAnalyzer:
    """L2 analyzer: use call graph to confirm/dismiss L1 findings."""

    name: str = "L2"
    depends_on: Sequence[str] = ("L1-memory", "L1-tools")
    replace: bool = True
    opt_in: bool = False
    framework_agnostic: bool = False

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        """Refine L1 findings using call graph analysis.

        For each AW-MEM-001 finding, check if any caller in the chain
        applies a filter. If found, downgrade to INFO.
        """
        spec = ctx.spec
        if spec is None:
            return list(ctx.findings)
        l1_findings = list(ctx.findings)
        target = ctx.target
        if not spec.source_files:
            return l1_findings

        graph = build_call_graph(target, spec.source_files)
        ctx.call_graph = graph
        refined: list[Finding] = []

        for finding in l1_findings:
            if finding.rule_id != "AW-MEM-001":
                refined.append(finding)
                continue

            # Check if any function in the call chain applies a filter
            filter_found_upstream = False

            # Find retrieval call sites
            for edge in graph.edges:
                if not edge.resolved:
                    continue
                callee = edge.callee.name
                # Check if callee is a retrieval method
                for method in RETRIEVAL_METHODS:
                    if callee.endswith(f".{method}") or callee == method:
                        # Check all callers of this edge
                        caller = edge.caller.name
                        if _function_has_filter(caller, spec.source_files):
                            filter_found_upstream = True
                            break
                if filter_found_upstream:
                    break

            if filter_found_upstream:
                # Downgrade — filter applied via wrapper
                refined.append(
                    finding.model_copy(
                        update={
                            "severity": Severity.LOW,
                            "description": (
                                finding.description
                                + " [L2: filter may be applied via wrapper function]"
                            ),
                            "confidence": ConfidenceLevel.MEDIUM,
                            "layer": "L2",
                        }
                    )
                )
            else:
                # Confirm as CRITICAL
                refined.append(
                    finding.model_copy(
                        update={
                            "description": (
                                finding.description + " [L2: confirmed — no filter in call chain]"
                            ),
                            "layer": "L2",
                        }
                    )
                )

        return refined
