"""AutoGen adapter -- AST-based parser for AutoGen agent code."""

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

# AutoGen can use LangChain vector stores -- detect same class names.
_VECTOR_STORES: dict[str, str] = {
    "Chroma": "chroma",
    "FAISS": "faiss",
    "Pinecone": "pinecone",
    "Qdrant": "qdrant",
    "PGVector": "pgvector",
}

_AGENT_CONSTRUCTORS: frozenset[str] = frozenset(
    {"ConversableAgent", "AssistantAgent", "UserProxyAgent", "GroupChatManager"}
)


class _AutoGenVisitor(ast.NodeVisitor):
    """AST visitor for a single Python file -- extracts AutoGen patterns."""

    def __init__(self, source_file: Path) -> None:
        self.source_file = source_file
        self.tools: list[ToolSpec] = []
        self.memory_configs: list[MemoryConfig] = []
        self.agent_count: int = 0
        self.chat_count: int = 0
        # Track variable names bound to agent constructors for decorator detection.
        self._agent_vars: set[str] = set()

    # -- Decorators: @agent.register_for_llm / register_for_execution ----------

    def visit_FunctionDef(self, node: ast.FunctionDef) -> None:
        self._check_register_decorators(node)
        self.generic_visit(node)

    def visit_AsyncFunctionDef(self, node: ast.AsyncFunctionDef) -> None:
        self._check_register_decorators(node)
        self.generic_visit(node)

    def _check_register_decorators(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef
    ) -> None:
        """Detect @agent.register_for_llm(...) and @agent.register_for_execution()."""
        has_register = False
        description: str | None = None

        for dec in node.decorator_list:
            name = _get_decorator_method(dec)
            if name in ("register_for_llm", "register_for_execution"):
                has_register = True
                # Extract description from register_for_llm(description=...)
                if name == "register_for_llm" and isinstance(dec, ast.Call):
                    desc = _get_keyword_str(dec, "description")
                    if desc is not None:
                        description = desc

        if has_register:
            # Prefer decorator description, fall back to docstring
            if description is None:
                description = ast.get_docstring(node)
            tool_spec = ToolSpec(
                name=node.name,
                description=description,
                source_file=self.source_file,
                source_line=node.lineno,
                is_destructive=_name_is_destructive(node.name),
                accepts_code_execution=_body_has_code_exec(node),
            )
            self.tools.append(tool_spec)

    # -- Assignments: agent constructors, vector stores -------------------------

    def visit_Assign(self, node: ast.Assign) -> None:
        if isinstance(node.value, ast.Call):
            var_name: str | None = None
            if node.targets and isinstance(node.targets[0], ast.Name):
                var_name = node.targets[0].id
            self._check_agent_call(node.value, var_name)
            self._check_vectorstore_call(node.value, node.lineno, var_name)
        self.generic_visit(node)

    def _check_agent_call(self, call: ast.Call, var_name: str | None) -> None:
        """Detect ConversableAgent/AssistantAgent/UserProxyAgent constructors."""
        class_name = _get_name(call.func)
        if class_name not in _AGENT_CONSTRUCTORS:
            return
        self.agent_count += 1
        if var_name is not None:
            self._agent_vars.add(var_name)

        # Extract tools from llm_config={"functions": [...]}
        for kw in call.keywords:
            if kw.arg == "llm_config" and isinstance(kw.value, ast.Dict):
                self._extract_llm_config_tools(kw.value, call)

    def _extract_llm_config_tools(
        self, config_dict: ast.Dict, call: ast.Call
    ) -> None:
        """Extract tool names from llm_config={"functions": [{"name": ...}]}."""
        for key, value in zip(config_dict.keys, config_dict.values, strict=False):
            if (
                isinstance(key, ast.Constant)
                and key.value == "functions"
                and isinstance(value, ast.List)
            ):
                for elt in value.elts:
                    if isinstance(elt, ast.Dict):
                        name = _get_dict_str(elt, "name")
                        desc = _get_dict_str(elt, "description")
                        if name:
                            tool_spec = ToolSpec(
                                name=name,
                                description=desc,
                                source_file=self.source_file,
                                source_line=call.lineno,
                                is_destructive=_name_is_destructive(name),
                            )
                            self.tools.append(tool_spec)

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

    # -- Expressions: register_function(), initiate_chat() ----------------------

    def visit_Expr(self, node: ast.Expr) -> None:
        if isinstance(node.value, ast.Call):
            self._check_register_function_call(node.value)
            self._check_initiate_chat(node.value)
        self.generic_visit(node)

    def _check_register_function_call(self, call: ast.Call) -> None:
        """Detect register_function(name=..., ...) calls."""
        func_name = _get_name(call.func)
        if func_name != "register_function":
            return
        name = _get_keyword_str(call, "name")
        desc = _get_keyword_str(call, "description")
        if name:
            tool_spec = ToolSpec(
                name=name,
                description=desc,
                source_file=self.source_file,
                source_line=call.lineno,
                is_destructive=_name_is_destructive(name),
            )
            self.tools.append(tool_spec)

    def _check_initiate_chat(self, call: ast.Call) -> None:
        """Detect agent.initiate_chat(...) calls."""
        func_name = _get_name(call.func)
        if func_name == "initiate_chat":
            self.chat_count += 1


# -- Module-level helpers ------------------------------------------------------


def _get_name(node: ast.expr) -> str | None:
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _get_decorator_method(node: ast.expr) -> str | None:
    """Extract method name from @obj.method or @obj.method(...)."""
    if isinstance(node, ast.Call):
        return _get_decorator_method(node.func)
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _get_keyword_str(call: ast.Call | ast.expr, key: str) -> str | None:
    if not isinstance(call, ast.Call):
        return None
    for kw in call.keywords:
        if kw.arg == key and isinstance(kw.value, ast.Constant):
            return str(kw.value.value)
    return None


def _get_dict_str(node: ast.Dict, key: str) -> str | None:
    """Extract a string value from a dict literal by key."""
    for k, v in zip(node.keys, node.values, strict=False):
        if isinstance(k, ast.Constant) and k.value == key and isinstance(v, ast.Constant):
            return str(v.value)
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
                if func.attr in CODE_EXEC_CALLS:
                    return True
                # subprocess.check_output(...) → value is Name("subprocess")
                if isinstance(func.value, ast.Name) and func.value.id in CODE_EXEC_CALLS:
                    return True
    return False


# -- Adapter -------------------------------------------------------------------


class AutoGenAdapter:
    """Parse an AutoGen agent directory into an AgentSpec."""

    def parse(self, target: Path) -> AgentSpec:
        py_files = sorted(
            f
            for f in target.rglob("*.py")
            if not any(part in _SKIP_DIRS for part in f.relative_to(target).parts)
        )
        all_tools: list[ToolSpec] = []
        all_memory: list[MemoryConfig] = []
        scanned: list[Path] = []
        total_agents = 0
        total_chats = 0

        for py_file in py_files:
            try:
                source = py_file.read_text(encoding="utf-8")
                tree = ast.parse(source, filename=str(py_file))
            except (OSError, SyntaxError) as exc:
                warnings.warn(f"Skipping {py_file}: {exc}", stacklevel=2)
                continue

            visitor = _AutoGenVisitor(source_file=py_file)
            visitor.visit(tree)
            all_tools.extend(visitor.tools)
            all_memory.extend(visitor.memory_configs)
            total_agents += visitor.agent_count
            total_chats += visitor.chat_count
            scanned.append(py_file)

        metadata: dict[str, object] = {}
        if total_agents:
            metadata["agent_count"] = total_agents
        if total_chats:
            metadata["chat_count"] = total_chats

        return AgentSpec(
            framework="autogen",
            source_files=scanned,
            tools=all_tools,
            memory_configs=all_memory,
            metadata=metadata,
        )
