"""Tests for ASM extractors."""

from __future__ import annotations

import ast
from pathlib import Path

from agentwall.extractors.context_sinks import _Counter as SinkCounter
from agentwall.extractors.context_sinks import extract_context_sinks
from agentwall.extractors.edge_linker import link_edges
from agentwall.extractors.entry_points import _Counter as EPCounter
from agentwall.extractors.entry_points import extract_entry_points
from agentwall.models import (
    ApplicationModel,
    ASMConfidence,
    ContextSink,
    Provenance,
    ReadOp,
    Store,
    WriteOp,
)


def _ep(tree: ast.Module, file: Path) -> list:
    return extract_entry_points(tree, file, counter=EPCounter("ep"))


def _sinks(tree: ast.Module, file: Path) -> list:
    return extract_context_sinks(tree, file, counter=SinkCounter("sink"))


def _prov(symbol: str = "f", line: int = 1) -> Provenance:
    return Provenance(file=Path("app.py"), line=line, col=0, symbol=symbol)


# ── extract_dict_keys + classify_collection_name ─────────────────────────


class TestDictKeyExtraction:
    def test_extracts_filter_keys(self) -> None:
        from agentwall.adapters.langchain import extract_dict_keys

        code = 'vs.similarity_search("q", filter={"user_id": uid, "tenant": t})'
        tree = ast.parse(code)
        call = tree.body[0].value  # type: ignore[attr-defined]
        keys = extract_dict_keys(call, "filter")
        assert keys == frozenset({"user_id", "tenant"})

    def test_extracts_metadata_keys(self) -> None:
        from agentwall.adapters.langchain import extract_dict_keys

        code = 'vs.add_documents(docs, metadata={"source": "web", "filename": f})'
        tree = ast.parse(code)
        call = tree.body[0].value  # type: ignore[attr-defined]
        keys = extract_dict_keys(call, "metadata")
        assert keys == frozenset({"source", "filename"})

    def test_returns_empty_when_no_kwarg(self) -> None:
        from agentwall.adapters.langchain import extract_dict_keys

        code = 'vs.similarity_search("q")'
        tree = ast.parse(code)
        call = tree.body[0].value  # type: ignore[attr-defined]
        keys = extract_dict_keys(call, "filter")
        assert keys == frozenset()

    def test_returns_empty_when_kwarg_is_variable(self) -> None:
        from agentwall.adapters.langchain import extract_dict_keys

        code = 'vs.similarity_search("q", filter=my_filter)'
        tree = ast.parse(code)
        call = tree.body[0].value  # type: ignore[attr-defined]
        keys = extract_dict_keys(call, "filter")
        assert keys == frozenset()


class TestCollectionNameClassification:
    def test_string_literal_is_static(self) -> None:
        from agentwall.adapters.langchain import classify_collection_name

        code = 'Chroma(collection_name="faq")'
        tree = ast.parse(code)
        call = tree.body[0].value  # type: ignore[attr-defined]
        name, is_static = classify_collection_name(call)
        assert name == "faq"
        assert is_static is True

    def test_fstring_is_dynamic(self) -> None:
        from agentwall.adapters.langchain import classify_collection_name

        code = 'Chroma(collection_name=f"user_{uid}")'
        tree = ast.parse(code)
        call = tree.body[0].value  # type: ignore[attr-defined]
        name, is_static = classify_collection_name(call)
        assert name is None
        assert is_static is False

    def test_variable_is_dynamic(self) -> None:
        from agentwall.adapters.langchain import classify_collection_name

        code = "Chroma(collection_name=coll_name)"
        tree = ast.parse(code)
        call = tree.body[0].value  # type: ignore[attr-defined]
        name, is_static = classify_collection_name(call)
        assert name is None
        assert is_static is False

    def test_missing_is_none(self) -> None:
        from agentwall.adapters.langchain import classify_collection_name

        code = "Chroma()"
        tree = ast.parse(code)
        call = tree.body[0].value  # type: ignore[attr-defined]
        name, is_static = classify_collection_name(call)
        assert name is None
        assert is_static is False


# ── Entry Point Extractor ────────────────────────────────────────────────


class TestFastAPIEntryPoints:
    def test_detects_post_route(self) -> None:
        code = """
@app.post("/upload")
async def upload(file):
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("api.py"))
        assert len(eps) == 1
        assert eps[0].kind == "http_route"
        assert eps[0].provenance.symbol == "upload"

    def test_detects_get_route(self) -> None:
        code = """
@app.get("/items")
def list_items():
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("api.py"))
        assert len(eps) == 1

    def test_detects_router_route(self) -> None:
        code = """
@router.post("/ingest")
async def ingest(data: dict):
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("routes.py"))
        assert len(eps) == 1

    def test_detects_auth_dependency(self) -> None:
        code = """
@app.post("/upload")
async def upload(file, user=Depends(get_current_user)):
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("api.py"))
        assert len(eps) == 1
        assert eps[0].auth == "authenticated"
        assert eps[0].confidence == ASMConfidence.CONFIRMED

    def test_no_auth_is_unknown(self) -> None:
        code = """
@app.post("/upload")
async def upload(file):
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("api.py"))
        assert eps[0].auth == "unknown"

    def test_celery_task(self) -> None:
        code = """
@celery.task
def nightly_reindex():
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("tasks.py"))
        assert len(eps) == 1
        assert eps[0].kind == "background_job"
        assert eps[0].auth == "unauthenticated"

    def test_flask_route(self) -> None:
        code = """
@app.route("/upload", methods=["POST"])
def upload():
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("views.py"))
        assert len(eps) == 1
        assert eps[0].kind == "http_route"

    def test_ignores_non_route_decorators(self) -> None:
        code = """
@tool
def search(query: str):
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("tools.py"))
        assert len(eps) == 0

    def test_ignores_plain_functions(self) -> None:
        code = """
def helper():
    pass
"""
        tree = ast.parse(code)
        eps = _ep(tree, Path("utils.py"))
        assert len(eps) == 0


# ── Context Sink Extractor ───────────────────────────────────────────────


class TestContextSinks:
    def test_detects_llm_invoke_with_retrieval_var(self) -> None:
        code = """
docs = vectorstore.similarity_search(query)
context = "\\n".join([d.page_content for d in docs])
response = llm.invoke(f"Context: {context}\\nQuestion: {query}")
"""
        tree = ast.parse(code)
        sinks = _sinks(tree, Path("app.py"))
        assert len(sinks) == 1
        assert sinks[0].kind == "llm_context"
        assert sinks[0].sanitized is False

    def test_no_sink_when_no_retrieval(self) -> None:
        code = """
response = llm.invoke("Hello world")
"""
        tree = ast.parse(code)
        sinks = _sinks(tree, Path("app.py"))
        assert len(sinks) == 0

    def test_sanitized_when_sanitize_called(self) -> None:
        code = """
docs = vectorstore.similarity_search(query)
clean = sanitize(docs)
response = llm.invoke(clean)
"""
        tree = ast.parse(code)
        sinks = _sinks(tree, Path("app.py"))
        assert len(sinks) == 1
        assert sinks[0].sanitized is True


# ── Edge Linker ──────────────────────────────────────────────────────────


class TestEdgeLinker:
    def test_links_write_to_store_by_store_id(self) -> None:
        store = Store(
            id="s-1",
            provenance=_prov("Chroma"),
            backend="chroma",
            collection_name="docs",
            collection_name_is_static=True,
            confidence=ASMConfidence.CONFIRMED,
        )
        write = WriteOp(
            id="w-1",
            provenance=_prov("add_docs"),
            store_id="s-1",
            method="add_documents",
            metadata_keys=frozenset({"source"}),
            confidence=ASMConfidence.CONFIRMED,
        )
        model = ApplicationModel(write_ops=[write], stores=[store])
        edges = link_edges(model)
        writes_to = [e for e in edges if e.kind == "writes_to"]
        assert len(writes_to) == 1
        assert writes_to[0].source_id == "w-1"
        assert writes_to[0].target_id == "s-1"

    def test_links_read_from_store(self) -> None:
        store = Store(
            id="s-1",
            provenance=_prov("Chroma"),
            backend="chroma",
            collection_name="docs",
            collection_name_is_static=True,
            confidence=ASMConfidence.CONFIRMED,
        )
        read = ReadOp(
            id="r-1",
            provenance=_prov("search"),
            store_id="s-1",
            method="similarity_search",
            filter_keys=frozenset(),
            has_filter=False,
            confidence=ASMConfidence.CONFIRMED,
        )
        model = ApplicationModel(stores=[store], read_ops=[read])
        edges = link_edges(model)
        reads_from = [e for e in edges if e.kind == "reads_from"]
        assert len(reads_from) == 1
        assert reads_from[0].source_id == "r-1"

    def test_links_read_to_sink(self) -> None:
        read = ReadOp(
            id="r-1",
            provenance=_prov("search", line=10),
            store_id="s-1",
            method="similarity_search",
            filter_keys=frozenset(),
            has_filter=False,
            confidence=ASMConfidence.CONFIRMED,
        )
        sink = ContextSink(
            id="sink-1",
            provenance=_prov("invoke", line=15),
            kind="llm_context",
            sanitized=False,
            confidence=ASMConfidence.INFERRED,
        )
        model = ApplicationModel(read_ops=[read], sinks=[sink])
        edges = link_edges(model)
        assembles = [e for e in edges if e.kind == "assembles_into"]
        assert len(assembles) == 1

    def test_no_spurious_edges(self) -> None:
        model = ApplicationModel()
        edges = link_edges(model)
        assert len(edges) == 0

    def test_trigger_scoped_by_line_range(self) -> None:
        """EntryPoint with end_line only triggers ops within its body."""
        from agentwall.models import EntryPoint

        # ep covers lines 1-5, write at line 3 (inside), write at line 10 (outside)
        ep = EntryPoint(
            id="ep-1",
            kind="http_route",
            provenance=Provenance(file=Path("app.py"), line=1, col=0, symbol="upload", end_line=5),
            auth="unknown",
            auth_mechanism=None,
            user_id_source=None,
            confidence=ASMConfidence.CONFIRMED,
        )
        write_in = WriteOp(
            id="w-1",
            provenance=_prov("add_docs", line=3),
            store_id="s-1",
            method="add_documents",
            metadata_keys=frozenset(),
            confidence=ASMConfidence.CONFIRMED,
        )
        write_out = WriteOp(
            id="w-2",
            provenance=_prov("add_docs", line=10),
            store_id="s-1",
            method="add_documents",
            metadata_keys=frozenset(),
            confidence=ASMConfidence.CONFIRMED,
        )
        model = ApplicationModel(entry_points=[ep], write_ops=[write_in, write_out])
        edges = link_edges(model)
        triggers = [e for e in edges if e.kind == "triggers"]
        assert len(triggers) == 1
        assert triggers[0].target_id == "w-1"

    def test_trigger_fallback_same_file_when_no_end_line(self) -> None:
        """Without end_line, falls back to same-file linking."""
        from agentwall.models import EntryPoint

        ep = EntryPoint(
            id="ep-1",
            kind="http_route",
            provenance=Provenance(file=Path("app.py"), line=1, col=0, symbol="upload"),
            auth="unknown",
            auth_mechanism=None,
            user_id_source=None,
            confidence=ASMConfidence.CONFIRMED,
        )
        write = WriteOp(
            id="w-1",
            provenance=_prov("add_docs", line=50),
            store_id="s-1",
            method="add_documents",
            metadata_keys=frozenset(),
            confidence=ASMConfidence.CONFIRMED,
        )
        model = ApplicationModel(entry_points=[ep], write_ops=[write])
        edges = link_edges(model)
        triggers = [e for e in edges if e.kind == "triggers"]
        assert len(triggers) == 1
