"""Extract context sinks — where retrieval results flow into LLM prompts."""

from __future__ import annotations

import ast
from pathlib import Path

from agentwall.models import ASMConfidence, ContextSink, Provenance

_RETRIEVAL_METHODS = frozenset({
    "similarity_search", "similarity_search_with_score",
    "max_marginal_relevance_search", "as_retriever",
    "get_relevant_documents",
})

_LLM_METHODS = frozenset({
    "invoke", "ainvoke", "predict", "apredict",
    "call", "__call__", "run", "arun",
    "generate", "agenerate",
})

_SANITIZE_NAMES = frozenset({
    "sanitize", "sanitise", "clean", "strip_tags", "escape",
    "filter_content", "scrub", "bleach", "clean_text",
    "sanitize_output", "sanitize_content",
})


class _Counter:
    """Per-invocation counter for deterministic IDs."""

    def __init__(self, prefix: str = "sink") -> None:
        self._prefix = prefix
        self._value = 0

    def next_id(self) -> str:
        self._value += 1
        return f"{self._prefix}-{self._value}"


def extract_context_sinks(
    tree: ast.Module, file: Path, *, counter: _Counter,
) -> list[ContextSink]:
    """Extract context sinks from an AST module.

    Tracks variables assigned from retrieval calls, then checks if those
    variables (or derivatives) flow into LLM invocations.
    """
    ctr = counter
    retrieval_vars: set[str] = set()
    sanitized_vars: set[str] = set()
    derived_vars: set[str] = set()
    sinks: list[ContextSink] = []

    # Pass 1: Find retrieval assignments
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign) and isinstance(node.value, ast.Call):
            func = node.value.func
            if isinstance(func, ast.Attribute) and func.attr in _RETRIEVAL_METHODS:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        retrieval_vars.add(target.id)

    if not retrieval_vars:
        return []

    # Pass 2: Find derived variables and sanitization
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        # Track variables derived from retrieval vars
        for name in _names_in_expr(node.value):
            if name in retrieval_vars or name in derived_vars:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        derived_vars.add(target.id)
                break

        # Track sanitization
        if isinstance(node.value, ast.Call):
            func_name = _get_func_name(node.value.func)
            if func_name and func_name.lower() in _SANITIZE_NAMES:
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        sanitized_vars.add(target.id)

    tainted = retrieval_vars | derived_vars

    # Pass 3: Find LLM calls that consume tainted vars
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func = node.func
        if not (isinstance(func, ast.Attribute) and func.attr in _LLM_METHODS):
            continue

        call_names: set[str] = set()
        for arg in node.args:
            call_names |= _names_in_expr(arg)
        for kw in node.keywords:
            call_names |= _names_in_expr(kw.value)

        if call_names & tainted:
            is_sanitized = bool(call_names & sanitized_vars)
            sinks.append(ContextSink(
                id=ctr.next_id(),
                provenance=Provenance(
                    file=file, line=node.lineno, col=node.col_offset,
                    symbol=_get_func_name(func) or "llm",
                ),
                kind="llm_context",
                sanitized=is_sanitized,
                confidence=ASMConfidence.INFERRED,
            ))

    return sinks


def _names_in_expr(node: ast.expr) -> set[str]:
    names: set[str] = set()
    for child in ast.walk(node):
        if isinstance(child, ast.Name):
            names.add(child.id)
    return names


def _get_func_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None
