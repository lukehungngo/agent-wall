"""LlamaIndex adapter -- AST-based parser for LlamaIndex agent code."""

from __future__ import annotations

import ast
import warnings
from pathlib import Path

from agentwall.detector import _SKIP_DIRS
from agentwall.models import (
    AgentSpec,
    MemoryConfig,
    ToolSpec,
)
from agentwall.patterns import (
    CODE_EXEC_CALLS,
    CODE_EXEC_KEYWORDS,
    DESTRUCTIVE_KEYWORDS,
)

# LlamaIndex vector store class names to normalised backend identifiers.
_VECTOR_STORES: dict[str, str] = {
    "VectorStoreIndex": "vectorstoreindex",
    "SimpleVectorStore": "simplevectorstore",
    "PineconeVectorStore": "pinecone",
    "ChromaVectorStore": "chromadb",
    "QdrantVectorStore": "qdrant",
}

# LlamaIndex memory classes that persist conversation history.
_MEMORY_CLASSES: dict[str, str] = {
    "ChatMemoryBuffer": "chat_memory_buffer",
    "VectorMemory": "vector_memory",
}

# LlamaIndex tool class names.
_TOOL_CLASSES: frozenset[str] = frozenset({
    "FunctionTool",
    "QueryEngineTool",
    "ToolSpec",
})

# Methods that produce a retrieval path.
_RETRIEVAL_METHODS: frozenset[str] = frozenset({
    "as_query_engine",
    "as_retriever",
    "query",
    "retrieve",
})


class _LlamaIndexVisitor(ast.NodeVisitor):
    """AST visitor for a single Python file -- extracts LlamaIndex patterns."""

    def __init__(self, source_file: Path) -> None:
        self.source_file = source_file
        self.tools: list[ToolSpec] = []
        self.memory_configs: list[MemoryConfig] = []
        # Track vector store instances for retrieval resolution.
        self._vs_instances: dict[str, MemoryConfig] = {}

    # -- Function / async function: check for tool registration ----------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self.generic_visit(node)

    # -- Assignments: vector store, memory, tool instantiation -----------------

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            var_name: str | None = None
            if node.targets and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id
            self._check_vectorstore_call(node.value, node.lineno, var_name)
            self._check_memory_class_call(node.value, node.lineno)
            self._check_tool_call(node.value, node.lineno)
        self.generic_visit(node)

    # -- Bare expression calls (e.g. query_engine.query(...)) ------------------

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            self._check_retrieval_call(node.value)
        self.generic_visit(node)

    # -- General Call visitor for method calls ---------------------------------

    def visit_Call(self, node: ast.Call) -> None:
        self._check_retrieval_call(node)
        self.generic_visit(node)

    # -- Helpers ---------------------------------------------------------------

    def _check_vectorstore_call(
        self, call: ast.Call, lineno: int, var_name: str | None = None
    ) -> None:
        """Detect VectorStoreIndex(...), ChromaVectorStore(...), etc."""
        class_name = _get_call_name(call)
        if class_name is None:
            return

        # Handle Class.from_documents(...) and Class.from_defaults(...)
        if class_name in {"from_documents", "from_defaults"}:
            class_name = _get_chained_class(call)

        if class_name not in _VECTOR_STORES:
            return

        backend = _VECTOR_STORES[class_name]
        coll_name = _get_keyword_str(call, "collection_name")
        mc = MemoryConfig(
            backend=backend,
            collection_name=coll_name,
            source_file=self.source_file,
            source_line=lineno,
        )
        self.memory_configs.append(mc)
        if var_name:
            self._vs_instances[var_name] = mc

    def _check_memory_class_call(self, call: ast.Call, lineno: int) -> None:
        """Detect ChatMemoryBuffer(...), VectorMemory(...)."""
        class_name = _get_call_name(call)
        if class_name is None:
            return

        # Handle Class.from_defaults(...)
        if class_name == "from_defaults":
            class_name = _get_chained_class(call)

        if class_name not in _MEMORY_CLASSES:
            return

        backend = _MEMORY_CLASSES[class_name]
        mc = MemoryConfig(
            backend=backend,
            has_injection_risk=True,
            source_file=self.source_file,
            source_line=lineno,
        )
        self.memory_configs.append(mc)

    def _check_tool_call(self, call: ast.Call, lineno: int) -> None:
        """Detect FunctionTool.from_defaults(...), QueryEngineTool.from_defaults(...)."""
        class_name = _get_call_name(call)
        if class_name is None:
            return

        # Handle Class.from_defaults(...)
        actual_class: str | None = class_name
        if class_name == "from_defaults":
            actual_class = _get_chained_class(call)

        if actual_class is None or actual_class not in _TOOL_CLASSES:
            return

        name = _get_keyword_str(call, "name") or actual_class
        desc = _get_keyword_str(call, "description")
        tool_spec = ToolSpec(
            name=name,
            description=desc,
            source_file=self.source_file,
            source_line=lineno,
            is_destructive=_name_is_destructive(name),
            accepts_code_execution=_name_accepts_code_exec(name)
            or _desc_accepts_code_exec(desc),
        )
        self.tools.append(tool_spec)

    def _check_retrieval_call(self, node: ast.Call) -> None:
        """Detect .as_query_engine(), .as_retriever(), .query() with filter check."""
        func = node.func
        if not isinstance(func, ast.Attribute):
            return
        method = func.attr
        if method not in _RETRIEVAL_METHODS:
            return

        has_filter = _call_has_filter_kwarg(node)
        instance_name = _get_name(func.value)
        mc = self._find_mc(instance_name)
        if mc is None:
            return

        if has_filter and not mc.has_metadata_filter_on_retrieval:
            mc_updated = mc.model_copy(
                update={
                    "has_metadata_filter_on_retrieval": True,
                    "has_tenant_isolation": True,
                }
            )
            idx = self.memory_configs.index(mc)
            self.memory_configs[idx] = mc_updated
            if instance_name:
                self._vs_instances[instance_name] = mc_updated

    def _find_mc(self, instance_name: str | None) -> MemoryConfig | None:
        if instance_name and instance_name in self._vs_instances:
            return self._vs_instances[instance_name]
        # Fallback: last memory config that is a vector store (not a memory class).
        vs_configs = [
            mc for mc in self.memory_configs if mc.backend in _VECTOR_STORES.values()
        ]
        return vs_configs[-1] if vs_configs else None


# -- Module-level helpers ------------------------------------------------------


def _get_name(node: ast.expr) -> str | None:
    """Extract a simple name from a Name or Attribute node."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _get_call_name(call: ast.Call) -> str | None:
    """Get the function/method name from a Call node."""
    return _get_name(call.func)


def _get_chained_class(call: ast.Call) -> str | None:
    """For SomeClass.from_defaults(...), extract 'SomeClass'."""
    if isinstance(call.func, ast.Attribute) and isinstance(
        call.func.value, ast.Name
    ):
        return call.func.value.id
    # SomeClass.from_defaults where SomeClass is itself an attribute (module.Class)
    if isinstance(call.func, ast.Attribute) and isinstance(
        call.func.value, ast.Attribute
    ):
        return call.func.value.attr
    return None


def _get_keyword_str(call: ast.Call, key: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    return None


def _call_has_filter_kwarg(node: ast.Call) -> bool:
    """Check for filters=, filter=, or query_filter= kwargs."""
    return any(kw.arg in {"filters", "filter", "query_filter"} for kw in node.keywords)


def _name_is_destructive(name: str) -> bool:
    low = name.lower()
    return any(kw in low for kw in DESTRUCTIVE_KEYWORDS)


def _name_accepts_code_exec(name: str) -> bool:
    low = name.lower()
    return any(kw in low for kw in CODE_EXEC_KEYWORDS)


def _desc_accepts_code_exec(desc: str | None) -> bool:
    if not desc:
        return False
    low = desc.lower()
    return any(kw in low for kw in CODE_EXEC_KEYWORDS)


def _body_has_code_exec(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name) and func.id in CODE_EXEC_CALLS:
                return True
            if isinstance(func, ast.Attribute) and func.attr in CODE_EXEC_CALLS:
                return True
    return False


# -- Adapter -------------------------------------------------------------------


class LlamaIndexAdapter:
    """Parse a LlamaIndex agent directory into an AgentSpec."""

    def parse(self, target: Path) -> AgentSpec:
        py_files = sorted(
            f
            for f in target.rglob("*.py")
            if not any(part in _SKIP_DIRS for part in f.relative_to(target).parts)
        )
        all_tools: list[ToolSpec] = []
        all_memory: list[MemoryConfig] = []
        scanned: list[Path] = []

        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (OSError, SyntaxError) as exc:
                warnings.warn(f"Skipping {py_file}: {exc}", stacklevel=2)
                continue

            visitor = _LlamaIndexVisitor(source_file=py_file)
            visitor.visit(tree)
            all_tools.extend(visitor.tools)
            all_memory.extend(visitor.memory_configs)
            scanned.append(py_file)

        return AgentSpec(
            framework="llamaindex",
            source_files=scanned,
            tools=all_tools,
            memory_configs=all_memory,
        )
