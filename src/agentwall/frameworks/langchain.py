"""Declarative framework model for LangChain.

Covers 12 vector store backends, LCEL pipe composition, factory methods,
the @tool decorator, and conversational memory classes.
"""

from __future__ import annotations

from agentwall.frameworks.base import (
    DecoratorPattern,
    FactoryPattern,
    FrameworkModel,
    PipePattern,
    StoreModel,
)

# ── Shared method maps ────────────────────────────────────────────────────────

# Standard read methods used by most LangChain vector stores.
_COMMON_READ: dict[str, str] = {
    "similarity_search": "filter",
    "similarity_search_with_score": "filter",
    "max_marginal_relevance_search": "filter",
}

# Standard write methods used by most LangChain vector stores.
_COMMON_WRITE: dict[str, str] = {
    "add_texts": "metadata",
    "add_documents": "metadatas",
}

# Retriever factory shared by all stores.
_RETRIEVER_FACTORY = "as_retriever"
_RETRIEVER_FILTER_PATH = "search_kwargs.filter"

# ── Store definitions ─────────────────────────────────────────────────────────

_STORES: dict[str, StoreModel] = {
    "Chroma": StoreModel(
        backend="chromadb",
        isolation_params=["collection_name"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "PGVector": StoreModel(
        backend="pgvector",
        isolation_params=["collection_name"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "Pinecone": StoreModel(
        backend="pinecone",
        isolation_params=["namespace"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "Qdrant": StoreModel(
        backend="qdrant",
        isolation_params=["collection_name"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "FAISS": StoreModel(
        backend="faiss",
        isolation_params=[],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
        has_builtin_acl=False,
    ),
    "Weaviate": StoreModel(
        backend="weaviate",
        isolation_params=["index_name"],
        write_methods=dict(_COMMON_WRITE),
        # Weaviate uses where_filter instead of filter for similarity_search.
        read_methods={
            "similarity_search": "where_filter",
            "similarity_search_with_score": "filter",
            "max_marginal_relevance_search": "filter",
        },
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "Neo4jVector": StoreModel(
        backend="neo4j",
        isolation_params=["index_name"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "Milvus": StoreModel(
        backend="milvus",
        isolation_params=["collection_name"],
        write_methods=dict(_COMMON_WRITE),
        # Milvus uses expr instead of filter for similarity_search.
        read_methods={
            "similarity_search": "expr",
            "similarity_search_with_score": "filter",
            "max_marginal_relevance_search": "filter",
        },
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "Redis": StoreModel(
        backend="redis",
        isolation_params=["index_name"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "ElasticsearchStore": StoreModel(
        backend="elasticsearch",
        isolation_params=["index_name"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "LanceDB": StoreModel(
        backend="lancedb",
        isolation_params=["table_name"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
    "MongoDBAtlasVectorSearch": StoreModel(
        backend="mongodb",
        isolation_params=["collection_name"],
        write_methods=dict(_COMMON_WRITE),
        read_methods=dict(_COMMON_READ),
        retriever_factory=_RETRIEVER_FACTORY,
        retriever_filter_path=_RETRIEVER_FILTER_PATH,
    ),
}

# ── Top-level model ───────────────────────────────────────────────────────────

LANGCHAIN_MODEL: FrameworkModel = FrameworkModel(
    name="langchain",
    stores=_STORES,
    pipe_patterns=[
        PipePattern(operator="|"),  # LCEL composition operator
    ],
    factory_patterns=[
        FactoryPattern(method="from_llm", kwarg="retriever", role="read_source"),
        FactoryPattern(method="from_chain_type", kwarg="retriever", role="read_source"),
    ],
    decorator_patterns=[
        DecoratorPattern(decorator="tool", registers_as="agent_tool"),
    ],
    memory_classes=[
        "ConversationBufferMemory",
        "ConversationBufferWindowMemory",
        "ConversationSummaryMemory",
        "ConversationSummaryBufferMemory",
        "VectorStoreRetrieverMemory",
        "ConversationEntityMemory",
        "ConversationKGMemory",
    ],
)
