"""LangChain adapter — AST-based parser for LangChain agent code."""

from __future__ import annotations

import ast
import warnings
from pathlib import Path

from agentwall.detector import _SKIP_DIRS
from agentwall.extractors.context_sinks import _Counter as SinkCounter
from agentwall.extractors.context_sinks import extract_context_sinks
from agentwall.extractors.edge_linker import link_edges
from agentwall.extractors.entry_points import _Counter as EPCounter
from agentwall.extractors.entry_points import extract_entry_points
from agentwall.models import (
    AgentSpec,
    ApplicationModel,
    ASMConfidence,
    ContextSink,
    EntryPoint,
    MemoryConfig,
    Provenance,
    ReadOp,
    Store,
    ToolSpec,
    WriteOp,
)

# Vector store backend names to normalised identifiers
_VECTOR_STORES: dict[str, str] = {
    "Chroma": "chroma",
    "PGVector": "pgvector",
    "Pinecone": "pinecone",
    "Qdrant": "qdrant",
    "FAISS": "faiss",
    "Weaviate": "weaviate",
    "Neo4jVector": "neo4jvector",
    "Milvus": "milvus",
    "Redis": "redis",
    "ElasticVectorSearch": "elasticsearch",
    "LanceDB": "lancedb",
    "MongoDBAtlasVectorSearch": "mongodb",
}

# LangChain memory classes that store conversation history — inherently injection-risk
# because they persist user-supplied content that can be poisoned (MINJA, MemoryGraft)
_MEMORY_CLASSES: dict[str, str] = {
    "ConversationBufferMemory": "conversation_buffer",
    "ConversationBufferWindowMemory": "conversation_buffer_window",
    "ConversationSummaryMemory": "conversation_summary",
    "ConversationSummaryBufferMemory": "conversation_summary_buffer",
    "VectorStoreRetrieverMemory": "vectorstore_retriever",
    "ConversationEntityMemory": "conversation_entity",
    "ConversationKGMemory": "conversation_kg",
}

# Known sanitization function/method names (heuristic)
_SANITIZE_NAMES = frozenset(
    [
        "sanitize",
        "sanitise",
        "clean",
        "strip_tags",
        "escape",
        "filter_content",
        "scrub",
        "bleach",
        "clean_text",
        "sanitize_output",
        "sanitize_content",
    ]
)

# Tool names / keywords that indicate destructive behaviour
_DESTRUCTIVE_KEYWORDS = frozenset(
    ["delete", "remove", "drop", "rm", "write", "send", "post", "execute", "run"]
)

# AST call names / keywords that indicate code execution
_CODE_EXEC_CALLS = frozenset(["subprocess", "eval", "exec"])
_CODE_EXEC_KEYWORDS = frozenset(["shell", "exec", "eval", "subprocess", "code", "script", "sql"])

# All retrieval method names that indicate vector store queries
_RETRIEVAL_METHODS = frozenset(
    [
        "similarity_search",
        "similarity_search_with_score",
        "max_marginal_relevance_search",
        "as_retriever",
        "get_relevant_documents",
    ]
)


class _FileVisitor(ast.NodeVisitor):
    """AST visitor for a single Python file."""

    def __init__(self, source_file: Path) -> None:
        self.source_file = source_file
        self.tools: list[ToolSpec] = []
        self.memory_configs: list[MemoryConfig] = []
        # Track which vector store instances have filters on retrieval / write
        self._vs_instances: dict[str, MemoryConfig] = {}
        # decorator @tool targets
        self._tool_decorated_funcs: set[str] = set()
        # Track variables holding retrieved content (for sanitization detection)
        self._retrieval_vars: set[str] = set()
        # Track whether any sanitization was observed on retrieved content
        self._has_sanitization: bool = False
        # ASM tracking
        self._asm_stores: list[Store] = []
        self._asm_write_ops: list[WriteOp] = []
        self._asm_read_ops: list[ReadOp] = []
        self._vs_instance_store_ids: dict[str, str] = {}
        self._store_counter: int = 0
        self._op_counter: int = 0

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_tool_decorator(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_tool_decorator(node)
        self.generic_visit(node)

    def _check_tool_decorator(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> None:
        for dec in node.decorator_list:
            name = _get_name(dec)
            if name in {"tool", "langchain.tools.tool"}:
                self._tool_decorated_funcs.add(node.name)
                desc = ast.get_docstring(node)
                tool_spec = ToolSpec(
                    name=node.name,
                    description=desc,
                    source_file=self.source_file,
                    source_line=node.lineno,
                    is_destructive=_name_is_destructive(node.name),
                    accepts_code_execution=_body_has_code_exec(node),
                    has_user_scope_check=_body_has_user_scope_check(node),
                )
                self.tools.append(tool_spec)

    def visit_Assign(self, node: ast.Assign) -> None:
        """Detect vector store instantiation, memory classes, and tools=[ ] lists."""
        if isinstance(node.value, ast.Call):
            # Capture the variable name so _mark_retrieval can resolve it later.
            var_name: str | None = None
            if node.targets and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id
            self._check_vectorstore_call(node.value, node.lineno, var_name)
            self._check_memory_class_call(node.value, node.lineno, var_name)
            self._check_tool_class_call(node.value, node.lineno)
        self.generic_visit(node)

    def visit_ClassDef(self, node: ast.ClassDef) -> None:
        """Detect BaseTool subclasses."""
        base_names = {_get_name(b) for b in node.bases}
        if base_names & {"BaseTool", "StructuredTool"}:
            name = node.name
            desc = ast.get_docstring(node)
            tool_spec = ToolSpec(
                name=name,
                description=desc,
                source_file=self.source_file,
                source_line=node.lineno,
                is_destructive=_name_is_destructive(name),
                accepts_code_execution=_class_has_code_exec(node),
                has_user_scope_check=_class_has_user_scope_check(node),
            )
            self.tools.append(tool_spec)
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call) -> None:
        """Detect method calls on vector store instances."""
        func = node.func
        if isinstance(func, ast.Attribute):
            method = func.attr
            # Retrieval calls — all similarity search variants + retriever creation
            if method in _RETRIEVAL_METHODS:
                self._mark_retrieval(node, func)
            # add_texts / add_documents — write calls
            elif method in {"add_texts", "add_documents"}:
                self._mark_write(node, func)
        # Detect load_tools() calls
        func_name = _get_name(node.func)
        if func_name == "load_tools":
            self._handle_load_tools(node)
        self.generic_visit(node)

    # ── vector store helpers ──────────────────────────────────────────────────

    def _check_vectorstore_call(
        self, call: ast.Call, lineno: int, var_name: str | None = None
    ) -> None:
        class_name = _get_name(call.func)
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
        # Key by variable name (e.g. "vectorstore") for later retrieval resolution.
        if var_name:
            self._vs_instances[var_name] = mc
        self._vs_instances[backend] = mc  # fallback key by backend type

        # Emit ASM Store node
        coll_name_val, is_static = classify_collection_name(call)
        store_id = self._next_store_id()
        store_node = Store(
            id=store_id,
            provenance=Provenance(
                file=self.source_file, line=lineno, col=0, symbol=class_name,
            ),
            backend=backend,
            collection_name=coll_name_val,
            collection_name_is_static=is_static,
            confidence=ASMConfidence.CONFIRMED,
        )
        self._asm_stores.append(store_node)
        if var_name:
            self._vs_instance_store_ids[var_name] = store_id
        self._vs_instance_store_ids[backend] = store_id

    def _check_memory_class_call(
        self, call: ast.Call, lineno: int, var_name: str | None = None
    ) -> None:
        """Detect LangChain memory class instantiation (ConversationBufferMemory etc.)."""
        class_name = _get_name(call.func)
        if class_name not in _MEMORY_CLASSES:
            return
        backend = _MEMORY_CLASSES[class_name]
        mc = MemoryConfig(
            backend=backend,
            has_injection_risk=True,  # memory classes persist user input — injection vector
            source_file=self.source_file,
            source_line=lineno,
        )
        self.memory_configs.append(mc)
        if var_name:
            self._vs_instances[var_name] = mc

    def _mark_retrieval(self, node: ast.Call, func: ast.Attribute) -> None:
        has_filter = _call_has_filter_kwarg(node)
        instance_name = _get_name(func.value)

        # Emit ASM ReadOp node
        store_id = self._find_store_id(instance_name)
        if store_id:
            read_id = self._next_op_id("r")
            read_op = ReadOp(
                id=read_id,
                provenance=Provenance(
                    file=self.source_file, line=node.lineno, col=node.col_offset,
                    symbol=func.attr,
                ),
                store_id=store_id,
                method=func.attr,
                filter_keys=extract_dict_keys(node, "filter"),
                has_filter=has_filter,
                confidence=ASMConfidence.CONFIRMED,
            )
            self._asm_read_ops.append(read_op)

        mc = self._find_mc_by_instance(instance_name)
        if mc is None:
            return
        # Only upgrade to True — never downgrade. Once a filtered call is seen, keep it.
        # An unfiltered call on a config that already has a filtered call is a separate issue.
        if has_filter and not mc.has_metadata_filter_on_retrieval:
            mc_updated = mc.model_copy(
                update={"has_metadata_filter_on_retrieval": True, "has_tenant_isolation": True}
            )
            idx = self.memory_configs.index(mc)
            self.memory_configs[idx] = mc_updated
            self._vs_instances[mc.backend] = mc_updated
            if instance_name:
                self._vs_instances[instance_name] = mc_updated

    def _mark_write(self, node: ast.Call, func: ast.Attribute) -> None:
        has_meta = _call_has_metadata_kwarg(node)
        instance_name = _get_name(func.value)

        # Emit ASM WriteOp node
        store_id = self._find_store_id(instance_name)
        if store_id:
            write_id = self._next_op_id("w")
            write_op = WriteOp(
                id=write_id,
                provenance=Provenance(
                    file=self.source_file, line=node.lineno, col=node.col_offset,
                    symbol=func.attr,
                ),
                store_id=store_id,
                method=func.attr,
                metadata_keys=extract_dict_keys(node, "metadata"),
                confidence=ASMConfidence.CONFIRMED,
            )
            self._asm_write_ops.append(write_op)

        mc = self._find_mc_by_instance(instance_name)
        if mc is not None and has_meta and not mc.has_metadata_on_write:
            mc_updated = mc.model_copy(update={"has_metadata_on_write": True})
            idx = self.memory_configs.index(mc)
            self.memory_configs[idx] = mc_updated
            self._vs_instances[mc.backend] = mc_updated
            if instance_name:
                self._vs_instances[instance_name] = mc_updated

    def _handle_load_tools(self, node: ast.Call) -> None:
        """Detect load_tools(["tool_name", ...]) and register each tool."""
        if not node.args:
            return
        first_arg = node.args[0]
        if not isinstance(first_arg, ast.List):
            return
        for elt in first_arg.elts:
            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                name = elt.value
                self.tools.append(
                    ToolSpec(
                        name=name,
                        description=None,
                        source_file=self.source_file,
                        source_line=node.lineno,
                        is_destructive=_name_is_destructive(name),
                        accepts_code_execution=_name_accepts_code_exec(name),
                        has_user_scope_check=False,
                    )
                )

    def _find_mc_by_instance(self, instance_name: str | None) -> MemoryConfig | None:
        if not instance_name:
            return self.memory_configs[-1] if self.memory_configs else None
        # Try to match by instance name used in assignment
        return self._vs_instances.get(instance_name) or (
            self.memory_configs[-1] if self.memory_configs else None
        )

    # ── ASM helpers ──────────────────────────────────────────────────────────

    def _next_store_id(self) -> str:
        self._store_counter += 1
        return f"s-{self._store_counter}"

    def _next_op_id(self, prefix: str) -> str:
        self._op_counter += 1
        return f"{prefix}-{self._op_counter}"

    def _find_store_id(self, instance_name: str | None) -> str | None:
        if instance_name and instance_name in self._vs_instance_store_ids:
            return self._vs_instance_store_ids[instance_name]
        if self._asm_stores:
            return self._asm_stores[-1].id
        return None

    # ── Tool(name=...) helper ─────────────────────────────────────────────────

    def _check_tool_class_call(self, call: ast.Call, lineno: int) -> None:
        class_name = _get_name(call.func)
        if class_name not in {"Tool", "StructuredTool"}:
            return
        name = _get_keyword_str(call, "name") or "<unnamed>"
        desc = _get_keyword_str(call, "description")
        tool_spec = ToolSpec(
            name=name,
            description=desc,
            source_file=self.source_file,
            source_line=lineno,
            is_destructive=_name_is_destructive(name),
            accepts_code_execution=_name_accepts_code_exec(name) or _desc_accepts_code_exec(desc),
            has_user_scope_check=False,
        )
        self.tools.append(tool_spec)


# ── Module-level helpers ──────────────────────────────────────────────────────


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


def _call_has_filter_kwarg(node: ast.Call) -> bool:
    """Return True if the call has an effective user/tenant filter.

    - filter=<anything>         → True (explicit metadata filter)
    - search_kwargs={"filter":} → True (filter nested in search_kwargs dict)
    - search_kwargs={"k": 5}    → False (search_kwargs present but no filter key inside)
    """
    for kw in node.keywords:
        if kw.arg == "filter":
            return True
        if kw.arg == "search_kwargs" and isinstance(kw.value, ast.Dict):
            for key in kw.value.keys:
                if isinstance(key, ast.Constant) and key.value == "filter":
                    return True
    return False


def _call_has_metadata_kwarg(node: ast.Call) -> bool:
    return any(kw.arg == "metadata" for kw in node.keywords)


def extract_dict_keys(call: ast.Call, kwarg_name: str) -> frozenset[str]:
    """Extract string keys from a dict literal passed as a keyword argument."""
    for kw in call.keywords:
        if kw.arg == kwarg_name and isinstance(kw.value, ast.Dict):
            keys: list[str] = []
            for key in kw.value.keys:
                if isinstance(key, ast.Constant) and isinstance(key.value, str):
                    keys.append(key.value)
            return frozenset(keys)
    return frozenset()


def classify_collection_name(call: ast.Call) -> tuple[str | None, bool]:
    """Classify collection_name kwarg as (name, is_static).

    Returns (literal_string, True) for string constants,
    (None, False) for f-strings/variables/missing.
    """
    for kw in call.keywords:
        if kw.arg == "collection_name":
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value, True
            return None, False
    return None, False


def _body_has_code_exec(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Return True if the function body contains code-execution calls."""
    for child in ast.walk(node):
        if isinstance(child, ast.Call):
            func = child.func
            if isinstance(func, ast.Name) and func.id in _CODE_EXEC_CALLS:
                return True
            if isinstance(func, ast.Attribute) and func.attr in _CODE_EXEC_CALLS:
                return True
            # import subprocess; subprocess.run(...)
            if (
                isinstance(func, ast.Attribute)
                and isinstance(func.value, ast.Name)
                and func.value.id in _CODE_EXEC_CALLS
            ):
                return True
    return False


def _name_is_destructive(name: str) -> bool:
    low = name.lower()
    return any(kw in low for kw in _DESTRUCTIVE_KEYWORDS)


def _name_accepts_code_exec(name: str) -> bool:
    low = name.lower()
    return any(kw in low for kw in _CODE_EXEC_KEYWORDS)


def _desc_accepts_code_exec(desc: str | None) -> bool:
    if not desc:
        return False
    low = desc.lower()
    return any(kw in low for kw in _CODE_EXEC_KEYWORDS)


def _class_has_code_exec(node: ast.ClassDef) -> bool:
    """Return True if any method in the class body contains code-execution calls."""
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and _body_has_code_exec(item):
            return True
    return False


def _class_has_user_scope_check(node: ast.ClassDef) -> bool:
    """Return True if any method in the class body has a user scope check."""
    for item in node.body:
        if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and _body_has_user_scope_check(
            item
        ):
            return True
    return False


def _body_has_user_scope_check(node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
    """Heuristic: body raises PermissionError or checks user_id."""
    for child in ast.walk(node):
        if isinstance(child, ast.Raise):
            exc = child.exc
            if exc is not None and _get_name(exc) == "PermissionError":
                return True
            if isinstance(exc, ast.Call) and _get_name(exc.func) == "PermissionError":
                return True
        if isinstance(child, ast.Compare):
            for comp in ast.walk(child):
                if isinstance(comp, ast.Name) and "user" in comp.id.lower():
                    return True
    return False


def _track_retrieval_assignments(tree: ast.Module, visitor: _FileVisitor) -> None:
    """Find assignments like `docs = vs.similarity_search(...)` and track the var name."""
    retrieval_methods = _RETRIEVAL_METHODS
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if not isinstance(node.value, ast.Call):
            continue
        func = node.value.func
        if isinstance(func, ast.Attribute) and func.attr in retrieval_methods:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    visitor._retrieval_vars.add(target.id)


def _detect_sanitization(tree: ast.Module, visitor: _FileVisitor) -> None:
    """Detect if any sanitization function is called on retrieved content."""
    if not visitor._retrieval_vars:
        return
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        func_name = _get_name(node.func)
        if not func_name or func_name.lower() not in _SANITIZE_NAMES:
            continue
        for arg in node.args:
            if isinstance(arg, ast.Name) and arg.id in visitor._retrieval_vars:
                visitor._has_sanitization = True
                return


# ── Adapter ───────────────────────────────────────────────────────────────────


class LangChainAdapter:
    """Parse a LangChain agent directory into an AgentSpec."""

    def parse(self, target: Path) -> AgentSpec:
        py_files = sorted(
            f
            for f in target.rglob("*.py")
            if not any(part in _SKIP_DIRS for part in f.relative_to(target).parts)
        )
        all_tools: list[ToolSpec] = []
        all_memory: list[MemoryConfig] = []
        all_stores: list[Store] = []
        all_write_ops: list[WriteOp] = []
        all_read_ops: list[ReadOp] = []
        all_entry_points: list[EntryPoint] = []
        all_sinks: list[ContextSink] = []
        ep_counter = EPCounter("ep")
        sink_counter = SinkCounter("sink")
        scanned: list[Path] = []

        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (OSError, SyntaxError) as exc:
                warnings.warn(f"Skipping {py_file}: {exc}", stacklevel=2)
                continue

            visitor = _FileVisitor(source_file=py_file)
            visitor.visit(tree)
            # Track retrieval assignments at file level for sanitization detection
            _track_retrieval_assignments(tree, visitor)
            # Re-walk to detect sanitization after retrieval vars are known
            _detect_sanitization(tree, visitor)
            # Propagate sanitization info to memory configs
            if visitor._has_sanitization:
                visitor.memory_configs = [
                    mc.model_copy(update={"sanitizes_retrieved_content": True})
                    if not mc.sanitizes_retrieved_content
                    else mc
                    for mc in visitor.memory_configs
                ]
            all_tools.extend(visitor.tools)
            all_memory.extend(visitor.memory_configs)
            all_stores.extend(visitor._asm_stores)
            all_write_ops.extend(visitor._asm_write_ops)
            all_read_ops.extend(visitor._asm_read_ops)
            all_entry_points.extend(extract_entry_points(tree, py_file, counter=ep_counter))
            all_sinks.extend(extract_context_sinks(tree, py_file, counter=sink_counter))
            scanned.append(py_file)

        asm: ApplicationModel | None = None
        if all_stores or all_write_ops or all_read_ops or all_entry_points or all_sinks:
            asm_model = ApplicationModel(
                entry_points=all_entry_points,
                write_ops=all_write_ops,
                stores=all_stores,
                read_ops=all_read_ops,
                sinks=all_sinks,
            )
            asm_model.edges = link_edges(asm_model)
            asm = asm_model

        return AgentSpec(
            framework="langchain",
            source_files=scanned,
            tools=all_tools,
            memory_configs=all_memory,
            asm=asm,
        )
