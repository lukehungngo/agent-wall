"""L1 model-driven property extractor.

Walks AST of source files using a FrameworkModel to identify vector store
instantiations, reads, and writes. Produces StoreProfile objects annotated
with ValueKind classifications for downstream security analysis.

Never executes user code. All analysis via ast.parse() only.
"""

from __future__ import annotations

import ast
import logging
import warnings
from pathlib import Path

from agentwall.engine.models import (
    PropertyExtraction,
    StoreProfile,
    ValueKind,
    classify_value,
)
from agentwall.frameworks.base import FrameworkModel, StoreModel

logger = logging.getLogger(__name__)

# Synthetic store_id counter is scoped per-visitor run; we use file+line as
# a natural unique key so no global counter is required.


def extract_properties(source_files: list[Path], model: FrameworkModel) -> list[StoreProfile]:
    """Extract StoreProfiles from a list of source files using a framework model.

    Args:
        source_files: Absolute paths to Python source files to analyse.
        model: Declarative framework model that describes store classes and
            their isolation/filter/metadata contracts.

    Returns:
        One StoreProfile per store instantiation found across all files.
        Files that cannot be read or parsed are skipped with a warning.
        Never raises.
    """
    profiles: dict[str, StoreProfile] = {}

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

        visitor = _PropertyVisitor(file_path=path, model=model)
        visitor.visit(tree)

        for store_id, profile in visitor.profiles.items():
            profiles[store_id] = profile

    return list(profiles.values())


# ── Internal visitor ──────────────────────────────────────────────────────────


class _PropertyVisitor(ast.NodeVisitor):
    """Stateful AST visitor that extracts store properties from one file."""

    def __init__(self, file_path: Path, model: FrameworkModel) -> None:
        self._file = file_path
        self._model = model

        # Active tenant-scoped names in the current scope.
        # Module-level: populated from model.tenant_param_names if a matching
        # variable is assigned.  Function-level: augmented by param names.
        self._tenant_names: set[str] = set()

        # var name → store_id (for method call matching)
        self._var_to_store_id: dict[str, str] = {}
        # var name → StoreModel
        self._var_to_store_model: dict[str, StoreModel] = {}

        # Collected profiles for this file.
        self.profiles: dict[str, StoreProfile] = {}

    # ── Scope-aware function traversal ───────────────────────────────────────

    def _visit_function(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        """Visit a function, temporarily augmenting tenant_names with its params."""
        param_names = {arg.arg for arg in node.args.args}
        tenant_param_names = set(self._model.tenant_param_names)
        new_tenant_names = param_names & tenant_param_names

        saved = self._tenant_names.copy()
        self._tenant_names = self._tenant_names | new_tenant_names

        self.generic_visit(node)

        self._tenant_names = saved

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:  # noqa: N802
        self._visit_function(node)

    def visit_AsyncFunctionDef(  # noqa: N802
        self, node: ast.AsyncFunctionDef
    ) -> None:
        self._visit_function(node)

    # ── Store instantiation ───────────────────────────────────────────────────

    def visit_Assign(self, node: ast.Assign) -> None:  # noqa: N802
        """Detect `var = StoreClass(...)` and record a StoreProfile."""
        if isinstance(node.value, ast.Call):
            self._try_record_store(node, node.value)
        self.generic_visit(node)

    def _try_record_store(self, assign: ast.Assign, call: ast.Call) -> None:
        class_name = _get_call_name(call)
        if class_name not in self._model.stores:
            return

        store_model = self._model.stores[class_name]

        # Use file + line as a unique store id.
        store_id = f"{class_name}:{self._file}:{assign.lineno}"

        # Extract first isolation param (e.g. collection_name).
        col_name: str | None = None
        col_kind = ValueKind.DYNAMIC

        if store_model.isolation_params:
            param = store_model.isolation_params[0]
            val_node = _find_kwarg(call, param)
            if val_node is not None:
                col_kind = classify_value(val_node, self._tenant_names)
                if isinstance(val_node, ast.Constant) and isinstance(val_node.value, str):
                    col_name = val_node.value

        # Determine variable name(s) being assigned.
        for target in assign.targets:
            var_name = _target_name(target)
            if var_name is not None:
                self._var_to_store_id[var_name] = store_id
                self._var_to_store_model[var_name] = store_model

        profile = StoreProfile(
            store_id=store_id,
            backend=store_model.backend,
            collection_name=col_name,
            collection_name_kind=col_kind,
            file=self._file,
            line=assign.lineno,
        )
        self.profiles[store_id] = profile

    # ── Method calls (reads / writes) ─────────────────────────────────────────

    def visit_Call(self, node: ast.Call) -> None:  # noqa: N802
        """Detect store.method(...) calls and record PropertyExtraction."""
        if isinstance(node.func, ast.Attribute):
            receiver = _get_receiver_name(node.func)
            method = node.func.attr

            if receiver is not None and receiver in self._var_to_store_id:
                store_id = self._var_to_store_id[receiver]
                store_model = self._var_to_store_model[receiver]
                profile = self.profiles.get(store_id)
                if profile is not None:
                    extraction = self._make_extraction(node, store_id, store_model, method)
                    if extraction is not None:
                        profile.extractions.append(extraction)

        self.generic_visit(node)

    def _make_extraction(
        self,
        call: ast.Call,
        store_id: str,
        store_model: StoreModel,
        method: str,
    ) -> PropertyExtraction | None:
        if method in store_model.read_methods:
            return self._make_read_extraction(call, store_id, store_model, method)
        if method in store_model.write_methods:
            return self._make_write_extraction(call, store_id, store_model, method)
        return None

    def _make_read_extraction(
        self,
        call: ast.Call,
        store_id: str,
        store_model: StoreModel,
        method: str,
    ) -> PropertyExtraction:
        filter_kwarg = store_model.read_methods[method]
        filter_node = _find_kwarg(call, filter_kwarg)

        if filter_node is None:
            return PropertyExtraction(
                file=self._file,
                line=call.lineno,
                store_id=store_id,
                operation="read",
                method=method,
                has_filter=False,
                filter_value_kind=ValueKind.DYNAMIC,
            )

        filter_kind = classify_value(filter_node, self._tenant_names)
        filter_keys = frozenset(_extract_dict_keys(filter_node))

        return PropertyExtraction(
            file=self._file,
            line=call.lineno,
            store_id=store_id,
            operation="read",
            method=method,
            has_filter=True,
            filter_keys=filter_keys,
            filter_value_kind=filter_kind,
        )

    def _make_write_extraction(
        self,
        call: ast.Call,
        store_id: str,
        store_model: StoreModel,
        method: str,
    ) -> PropertyExtraction:
        meta_kwarg = store_model.write_methods[method]
        meta_node = _find_kwarg(call, meta_kwarg)

        meta_keys: frozenset[str] = frozenset()
        meta_kind = ValueKind.DYNAMIC

        if meta_node is not None:
            # metadatas=[{...}]  → unwrap single-element list
            actual_node = _unwrap_list(meta_node)
            meta_kind = classify_value(actual_node, self._tenant_names)
            meta_keys = frozenset(_extract_dict_keys(actual_node))

        return PropertyExtraction(
            file=self._file,
            line=call.lineno,
            store_id=store_id,
            operation="write",
            method=method,
            metadata_keys=meta_keys,
            metadata_value_kind=meta_kind,
        )


# ── Pure helper functions ─────────────────────────────────────────────────────


def _get_call_name(call: ast.Call) -> str:
    """Return the bare callable name from an ast.Call node."""
    func = call.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


def _get_receiver_name(attr: ast.Attribute) -> str | None:
    """Return the variable name that is the receiver of an attribute access."""
    if isinstance(attr.value, ast.Name):
        return attr.value.id
    return None


def _find_kwarg(call: ast.Call, name: str) -> ast.expr | None:
    """Return the value of keyword argument `name` in a Call, or None."""
    for kw in call.keywords:
        if kw.arg == name:
            return kw.value
    return None


def _extract_dict_keys(node: ast.expr) -> list[str]:
    """Return string literal keys from an ast.Dict node."""
    if not isinstance(node, ast.Dict):
        return []
    keys: list[str] = []
    for key in node.keys:
        if isinstance(key, ast.Constant) and isinstance(key.value, str):
            keys.append(key.value)
    return keys


def _unwrap_list(node: ast.expr) -> ast.expr:
    """If node is a single-element ast.List, return that element; else node."""
    if isinstance(node, ast.List) and len(node.elts) == 1:
        return node.elts[0]
    return node


def _target_name(target: ast.expr) -> str | None:
    """Return the simple name if target is a Name node, else None."""
    if isinstance(target, ast.Name):
        return target.id
    return None
