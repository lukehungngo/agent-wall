"""Extract entry points (HTTP routes, background jobs) from AST."""

from __future__ import annotations

import ast
from pathlib import Path

from agentwall.models import ASMConfidence, EntryPoint, Provenance

# HTTP method decorators (FastAPI and Flask)
_HTTP_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})

# Background job decorators
_JOB_DECORATORS = frozenset({"task", "shared_task"})

# Auth dependency patterns (FastAPI Depends)
_AUTH_PATTERNS = frozenset({
    "get_current_user", "get_current_active_user", "get_user",
    "require_auth", "require_login", "auth_required",
    "current_user", "authenticated",
})


class _Counter:
    """Per-invocation counter for deterministic IDs."""

    def __init__(self, prefix: str = "ep") -> None:
        self._prefix = prefix
        self._value = 0

    def next_id(self) -> str:
        self._value += 1
        return f"{self._prefix}-{self._value}"


def extract_entry_points(
    tree: ast.Module, file: Path, *, counter: _Counter,
) -> list[EntryPoint]:
    """Extract entry points from an AST module."""
    ctr = counter
    results: list[EntryPoint] = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            ep = _check_function(node, file, ctr)
            if ep is not None:
                results.append(ep)
    return results


def _check_function(
    node: ast.FunctionDef | ast.AsyncFunctionDef, file: Path, ctr: _Counter,
) -> EntryPoint | None:
    for dec in node.decorator_list:
        result = _check_decorator(dec, node, file, ctr)
        if result is not None:
            return result
    return None


def _check_decorator(
    dec: ast.expr,
    node: ast.FunctionDef | ast.AsyncFunctionDef,
    file: Path,
    ctr: _Counter,
) -> EntryPoint | None:
    # FastAPI/Flask: @app.get("/path"), @router.post("/path"), @app.route("/path")
    if isinstance(dec, ast.Call) and isinstance(dec.func, ast.Attribute):
        method = dec.func.attr
        if method in _HTTP_METHODS or method == "route":
            auth, mechanism, user_source = _detect_auth(node)
            return EntryPoint(
                id=ctr.next_id(),
                kind="http_route",
                provenance=Provenance(
                    file=file, line=node.lineno, col=node.col_offset,
                    symbol=node.name,
                    end_line=getattr(node, "end_lineno", None),
                ),
                auth=auth,
                auth_mechanism=mechanism,
                user_id_source=user_source,
                confidence=ASMConfidence.CONFIRMED,
            )

    # Celery: @celery.task, @app.task, @shared_task
    dec_name = _get_decorator_name(dec)
    if dec_name in _JOB_DECORATORS:
        return EntryPoint(
            id=ctr.next_id(),
            kind="background_job",
            provenance=Provenance(
                file=file, line=node.lineno, col=node.col_offset,
                symbol=node.name,
                end_line=getattr(node, "end_lineno", None),
            ),
            auth="unauthenticated",
            auth_mechanism=None,
            user_id_source=None,
            confidence=ASMConfidence.CONFIRMED,
        )

    return None


def _get_decorator_name(dec: ast.expr) -> str | None:
    if isinstance(dec, ast.Name):
        return dec.id
    if isinstance(dec, ast.Attribute):
        return dec.attr
    if isinstance(dec, ast.Call):
        return _get_decorator_name(dec.func)
    return None


def _detect_auth(
    node: ast.FunctionDef | ast.AsyncFunctionDef,
) -> tuple[str, str | None, str | None]:
    """Detect auth from function parameters (FastAPI Depends pattern)."""
    for arg in node.args.defaults + [d for d in node.args.kw_defaults if d is not None]:
        if isinstance(arg, ast.Call):
            func_name = _get_decorator_name(arg.func)
            if func_name == "Depends" and arg.args:
                dep_name = _get_decorator_name(arg.args[0])
                if dep_name and dep_name.lower() in _AUTH_PATTERNS:
                    param_name = _find_param_with_default(node, arg)
                    return "authenticated", f"Depends({dep_name})", param_name
    return "unknown", None, None


def _find_param_with_default(
    node: ast.FunctionDef | ast.AsyncFunctionDef, default: ast.expr
) -> str | None:
    args = node.args
    n_defaults = len(args.defaults)
    n_args = len(args.args)
    for i, d in enumerate(args.defaults):
        if d is default:
            arg_idx = n_args - n_defaults + i
            if arg_idx < n_args:
                return args.args[arg_idx].arg
    for i, kw_default in enumerate(args.kw_defaults):
        if kw_default is not None and kw_default is default:
            return args.kwonlyargs[i].arg
    return None
