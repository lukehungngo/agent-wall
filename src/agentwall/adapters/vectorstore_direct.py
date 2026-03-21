"""VectorStore-direct adapter -- AST-based parser for raw vector store SDK usage."""

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
    DESTRUCTIVE_KEYWORDS,
)

# Map (module_or_class, constructor_name) → backend label.
# Handles both `chromadb.Client()` (Attribute) and `PersistentClient()` (Name).
_VECTORSTORE_CONSTRUCTORS: dict[str, str] = {
    # chromadb
    "Client": "chromadb",
    "PersistentClient": "chromadb",
    "HttpClient": "chromadb",
    # FAISS
    "IndexFlatL2": "faiss",
    "IndexIVFFlat": "faiss",
    # Pinecone
    "Index": "pinecone",
    "Pinecone": "pinecone",
    # Qdrant
    "QdrantClient": "qdrant",
    # Milvus
    "MilvusClient": "milvus",
    "Milvus": "milvus",
    # Weaviate
    "WeaviateClient": "weaviate",
}

# When the call is `module.Constructor()`, disambiguate by module prefix.
_MODULE_PREFIXES: dict[str, str] = {
    "chromadb": "chromadb",
    "faiss": "faiss",
    "pinecone": "pinecone",
    "weaviate": "weaviate",
}

# Standalone names that are unambiguous (no module prefix needed).
_UNAMBIGUOUS_NAMES: frozenset[str] = frozenset(
    {
        "PersistentClient",
        "QdrantClient",
        "MilvusClient",
        "Milvus",
        "WeaviateClient",
        "Pinecone",
        "IndexFlatL2",
        "IndexIVFFlat",
    }
)


class _VectorStoreDirectVisitor(ast.NodeVisitor):
    """AST visitor for a single Python file -- extracts raw vectorstore SDK patterns."""

    def __init__(self, source_file: Path) -> None:
        self.source_file = source_file
        self.tools: list[ToolSpec] = []
        self.memory_configs: list[MemoryConfig] = []

    # -- Assignments: detect constructor calls ---------------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            self._check_vectorstore_call(node.value, node.lineno)
        self.generic_visit(node)

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            self._check_vectorstore_call(node.value, node.lineno)
        self.generic_visit(node)

    # -- Function defs: detect eval/exec/subprocess ----------------------------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_code_exec_function(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_code_exec_function(node)
        self.generic_visit(node)

    # -- Helpers ---------------------------------------------------------------

    def _check_vectorstore_call(self, call: ast.Call, lineno: int) -> None:
        func = call.func

        # `module.Constructor()` — e.g. chromadb.PersistentClient()
        if isinstance(func, ast.Attribute):
            attr_name = func.attr
            module_name = _get_name(func.value)
            if attr_name in _VECTORSTORE_CONSTRUCTORS:
                # Verify module prefix matches expected backend
                if module_name and module_name in _MODULE_PREFIXES:
                    backend = _MODULE_PREFIXES[module_name]
                elif attr_name in _UNAMBIGUOUS_NAMES:
                    backend = _VECTORSTORE_CONSTRUCTORS[attr_name]
                else:
                    return
                coll_name = _get_keyword_str(call, "collection_name")
                self.memory_configs.append(
                    MemoryConfig(
                        backend=backend,
                        collection_name=coll_name,
                        source_file=self.source_file,
                        source_line=lineno,
                    )
                )
            # weaviate.connect_to_local()
            elif attr_name == "connect_to_local" and module_name == "weaviate":
                self.memory_configs.append(
                    MemoryConfig(
                        backend="weaviate",
                        source_file=self.source_file,
                        source_line=lineno,
                    )
                )

        # Bare `Constructor()` — e.g. PersistentClient() after `from chromadb import ...`
        elif isinstance(func, ast.Name) and func.id in _UNAMBIGUOUS_NAMES:
            backend = _VECTORSTORE_CONSTRUCTORS[func.id]
            coll_name = _get_keyword_str(call, "collection_name")
            self.memory_configs.append(
                MemoryConfig(
                    backend=backend,
                    collection_name=coll_name,
                    source_file=self.source_file,
                    source_line=lineno,
                )
            )

    def _check_code_exec_function(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """If function body contains eval/exec/subprocess, emit a ToolSpec."""
        if _body_has_code_exec(node):
            desc = ast.get_docstring(node)
            self.tools.append(
                ToolSpec(
                    name=node.name,
                    description=desc,
                    source_file=self.source_file,
                    source_line=node.lineno,
                    is_destructive=_name_is_destructive(node.name),
                    accepts_code_execution=True,
                )
            )


# -- Module-level helpers ------------------------------------------------------


def _get_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _get_keyword_str(call: ast.Call, key: str) -> str | None:
    for kw in call.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    return None


def _name_is_destructive(name: str) -> bool:
    low = name.lower()
    return any(kw in low for kw in DESTRUCTIVE_KEYWORDS)


def _body_has_code_exec(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name) and func.id in CODE_EXEC_CALLS:
                return True
            if isinstance(func, ast.Attribute):
                # Direct match: attr is eval/exec/subprocess
                if func.attr in CODE_EXEC_CALLS:
                    return True
                # Module call: subprocess.run(), subprocess.Popen(), etc.
                if isinstance(func.value, ast.Name) and func.value.id in CODE_EXEC_CALLS:
                    return True
    return False


# -- Adapter -------------------------------------------------------------------


class VectorStoreDirectAdapter:
    """Parse a directory with raw vector store SDK usage into an AgentSpec."""

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

            visitor = _VectorStoreDirectVisitor(source_file=py_file)
            visitor.visit(tree)
            all_tools.extend(visitor.tools)
            all_memory.extend(visitor.memory_configs)
            scanned.append(py_file)

        return AgentSpec(
            framework="vectorstore_direct",
            source_files=scanned,
            tools=all_tools,
            memory_configs=all_memory,
        )
