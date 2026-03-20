"""Shared detection constants used across analyzers, adapters, and probes.

Single source of truth for method names, keyword sets, and filter parameters
that multiple modules need to agree on. Import from here — never redefine.
"""

from __future__ import annotations

# ── Retrieval methods that indicate a vector store query ─────────────────────

RETRIEVAL_METHODS: frozenset[str] = frozenset(
    [
        "similarity_search",
        "similarity_search_with_score",
        "max_marginal_relevance_search",
        "as_retriever",
        "get_relevant_documents",
    ]
)

# ── Filter kwargs that indicate tenant scoping ───────────────────────────────

FILTER_KWARGS: frozenset[str] = frozenset(["filter", "where", "where_document"])

# ── Taint sources: where user identity enters the system ─────────────────────

SOURCE_PATTERNS: list[str] = [
    # Attribute access patterns
    "request.user",
    "request.user_id",
    "request.headers",
    "session.user_id",
    "session.user",
    "g.user",
    "current_user",
    "auth.user",
    # Common parameter names
    "user_id",
    "tenant_id",
    "org_id",
    "owner_id",
    "user",
    "tenant",
    "owner",
]

SIMPLE_SOURCE_NAMES: frozenset[str] = frozenset(s for s in SOURCE_PATTERNS if "." not in s)

# ── Taint sinks: retrieval method → expected filter parameter ────────────────

SINK_METHODS: dict[str, str] = {
    "similarity_search": "filter",
    "similarity_search_with_score": "filter",
    "max_marginal_relevance_search": "filter",
    "as_retriever": "search_kwargs",
    "get_relevant_documents": "filter",
}

# ── Sanitization heuristics ──────────────────────────────────────────────────

SANITIZE_NAMES: frozenset[str] = frozenset(
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

# ── Destructive tool keywords ────────────────────────────────────────────────

DESTRUCTIVE_KEYWORDS: frozenset[str] = frozenset(
    ["delete", "remove", "drop", "rm", "write", "send", "post", "execute", "run"]
)

# ── Code execution detection ─────────────────────────────────────────────────

CODE_EXEC_CALLS: frozenset[str] = frozenset(["subprocess", "eval", "exec"])
CODE_EXEC_KEYWORDS: frozenset[str] = frozenset(
    ["shell", "exec", "eval", "subprocess", "code", "script", "sql"]
)

# ── Tenant identity keys ─────────────────────────────────────────────────────

TENANT_KEYS: frozenset[str] = frozenset({"user_id", "tenant_id", "org_id", "owner_id"})

# ── Secret detection ─────────────────────────────────────────────────────────

SECRET_PREFIXES: list[str] = [
    "sk-",
    "AKIA",
    "ghp_",
    "gho_",
    "ghu_",
    "ghs_",
    "ghr_",
    "xoxb-",
    "xoxp-",
    "xoxa-",
    "xoxr-",
    "Bearer ",
    "eyJ",
    "FLWSECK_",
    "sk_live_",
    "pk_live_",
    "rk_live_",
    "SG.",
    "key-",
]

SECRET_KWARG_NAMES: frozenset[str] = frozenset(
    {
        "api_key",
        "apikey",
        "secret",
        "token",
        "password",
        "passwd",
        "secret_key",
        "access_key",
        "auth_token",
        "private_key",
        "client_secret",
        "api_secret",
    }
)

SECRET_ENTROPY_MIN_LEN: int = 20
SECRET_ENTROPY_THRESHOLD: float = 4.5

# ── Context variable names (for logging detection) ──────────────────────────

CONTEXT_VAR_NAMES: frozenset[str] = frozenset(
    {
        "memory",
        "chat_history",
        "messages",
        "context",
        "conversation",
        "history",
        "chat_messages",
        "conversation_history",
        "message_history",
    }
)

# ── Unsafe deserialization ───────────────────────────────────────────────────

UNSAFE_DESER_CALLS: frozenset[str] = frozenset(
    {
        "pickle.load",
        "pickle.loads",
        "yaml.load",
        "yaml.unsafe_load",
        "torch.load",
        "dill.load",
        "dill.loads",
        "shelve.open",
        "joblib.load",
    }
)

SAFE_YAML_LOADERS: frozenset[str] = frozenset(
    {
        "SafeLoader",
        "CSafeLoader",
        "yaml.SafeLoader",
        "yaml.CSafeLoader",
    }
)

# ── MCP detection ────────────────────────────────────────────────────────────

MCP_IMPORTS: frozenset[str] = frozenset(
    {
        "mcp",
        "mcp.server",
        "mcp.client",
        "modelcontextprotocol",
    }
)

MCP_SHELL_CALLS: frozenset[str] = frozenset(
    {
        "subprocess.run",
        "subprocess.Popen",
        "subprocess.call",
        "subprocess.check_output",
        "os.system",
        "os.popen",
        "os.exec",
        "os.execvp",
    }
)

# ── Dynamic imports ──────────────────────────────────────────────────────────

DYNAMIC_IMPORT_CALLS: frozenset[str] = frozenset(
    {
        "importlib.import_module",
        "__import__",
    }
)

# ── Agent framework packages (for AW-SER-002) ───────────────────────────────

AGENT_FRAMEWORK_PACKAGES: frozenset[str] = frozenset(
    {
        "langchain",
        "langchain-core",
        "langchain-community",
        "crewai",
        "autogen",
        "pyautogen",
        "mcp",
        "llama-index",
        "llama-index-core",
        "openai-agents",
    }
)

# ── RAG delimiters ───────────────────────────────────────────────────────────

RAG_DELIMITER_PATTERNS: list[str] = [
    "<context>",
    "</context>",
    "<documents>",
    "</documents>",
    "<retrieved>",
    "</retrieved>",
    "[CONTEXT]",
    "[/CONTEXT]",
    "[DOCUMENTS]",
    "[/DOCUMENTS]",
    "```",
]

# ── Untrusted ingestion sources ──────────────────────────────────────────────

UNTRUSTED_SOURCE_CALLS: frozenset[str] = frozenset(
    {
        "requests.get",
        "requests.post",
        "httpx.get",
        "httpx.post",
        "urllib.request.urlopen",
        "BeautifulSoup",
        "WebBaseLoader",
        "UnstructuredFileLoader",
        "SeleniumURLLoader",
        "PlaywrightURLLoader",
    }
)

# ── Vector store network clients (for AW-RAG-004) ───────────────────────────

VECTOR_STORE_NETWORK_CLIENTS: frozenset[str] = frozenset(
    {
        "HttpClient",
        "QdrantClient",
        "WeaviateClient",
        "connect_to_custom",
        "connect_to_wcs",
    }
)

VECTOR_STORE_AUTH_KWARGS: frozenset[str] = frozenset(
    {
        "api_key",
        "auth_credentials",
        "token",
        "username",
        "password",
        "auth",
    }
)
