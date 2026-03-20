"""Tests for the L3 fixpoint property verifier.

TDD — tests written before implementation.
"""

from __future__ import annotations

from pathlib import Path

from agentwall.engine.extractor import extract_properties
from agentwall.engine.graph import ProjectGraph, build_project_graph
from agentwall.engine.models import (
    IsolationStrategy,
    StoreAccess,
    StoreProfile,
    ValueKind,
    Verdict,
)
from agentwall.engine.verifier import verify_tenant_isolation
from agentwall.frameworks.langchain import LANGCHAIN_MODEL

FIXTURES = Path(__file__).parent / "fixtures"


# ── Fixture helpers ────────────────────────────────────────────────────────────


def _files(name: str) -> list[Path]:
    return [FIXTURES / name / "agent.py"]


def _cross_files() -> list[Path]:
    return sorted((FIXTURES / "engine_cross_file").glob("*.py"))


# ── Core verdict tests ─────────────────────────────────────────────────────────


def test_basic_no_filter_violated() -> None:
    """No filter at all on similarity_search → VIOLATED."""
    files = _files("engine_basic")
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)

    assert any(r.verdict == Verdict.VIOLATED for r in results)


def test_tenant_collection_verified() -> None:
    """Per-tenant collection name → VERIFIED; no VIOLATED results."""
    files = _files("engine_tenant_collection")
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)

    violated = [r for r in results if r.verdict == Verdict.VIOLATED]
    assert len(violated) == 0


def test_static_filter_violated() -> None:
    """Static filter {"source": "web"} is not tenant-scoped → VIOLATED."""
    files = _files("engine_static_filter")
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)

    assert any(r.verdict == Verdict.VIOLATED for r in results)


def test_cross_file_tenant_flow() -> None:
    """user_id flows auth.py → api.py → retriever.py → filter → VERIFIED."""
    files = _cross_files()
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL, FIXTURES / "engine_cross_file")
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)

    verified = [r for r in results if r.verdict == Verdict.VERIFIED]
    assert len(verified) >= 1


def test_empty_profiles() -> None:
    """No profiles → no results."""
    graph = ProjectGraph(
        call_edges=[],
        composition_edges=[],
        identifiers={},
        extends={},
        unresolved=[],
        _class_methods={},
    )
    results = verify_tenant_isolation([], graph, LANGCHAIN_MODEL)
    assert results == []


# ── Result shape tests ─────────────────────────────────────────────────────────


def test_results_have_store_id() -> None:
    """Every PropertyVerification carries the store_id from its profile."""
    files = _files("engine_basic")
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)

    assert results
    for r in results:
        assert r.store_id
        assert "Chroma" in r.store_id


def test_results_carry_access_info() -> None:
    """Every PropertyVerification has a non-None StoreAccess."""
    files = _files("engine_basic")
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)

    for r in results:
        assert isinstance(r.access, StoreAccess)
        assert r.access.store_id == r.store_id


# ── Isolation-strategy shortcut ────────────────────────────────────────────────


def test_collection_per_tenant_all_verified() -> None:
    """COLLECTION_PER_TENANT isolation strategy → every result is VERIFIED."""
    files = _files("engine_tenant_collection")
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)

    # Confirm extractor sees COLLECTION_PER_TENANT
    assert any(p.isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT for p in profiles)

    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    # All read results (if any) should be VERIFIED; no VIOLATED
    assert all(r.verdict != Verdict.VIOLATED for r in results)


# ── Static-filter classification ───────────────────────────────────────────────


def test_compound_static_filter_is_violated() -> None:
    """A dict filter with only literal values must be VIOLATED."""
    files = _files("engine_static_filter")
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    results = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)

    # At least one VIOLATED where access has a COMPOUND_STATIC or LITERAL filter
    static_violated = [
        r
        for r in results
        if r.verdict == Verdict.VIOLATED
        and r.access.filter_kind
        in (ValueKind.COMPOUND_STATIC, ValueKind.LITERAL, ValueKind.DYNAMIC)
    ]
    assert static_violated


# ── Profile with no read extractions ──────────────────────────────────────────


def test_profile_with_no_reads_produces_no_results() -> None:
    """A StoreProfile with only write extractions yields no PropertyVerification."""
    from agentwall.engine.models import PropertyExtraction

    write_only = StoreProfile(
        store_id="Chroma:test.py:1",
        backend="chromadb",
        extractions=[
            PropertyExtraction(
                file=Path("test.py"),
                line=2,
                store_id="Chroma:test.py:1",
                operation="write",
                method="add_texts",
            )
        ],
    )
    graph = ProjectGraph(
        call_edges=[],
        composition_edges=[],
        identifiers={},
        extends={},
        unresolved=[],
        _class_methods={},
    )
    results = verify_tenant_isolation([write_only], graph, LANGCHAIN_MODEL)
    assert results == []


# ── Compound-tenant filter ─────────────────────────────────────────────────────


def test_compound_tenant_filter_is_verified() -> None:
    """A filter dict containing a tenant-scoped variable → VERIFIED."""
    from agentwall.engine.models import PropertyExtraction

    tenant_filtered = StoreProfile(
        store_id="Chroma:test.py:1",
        backend="chromadb",
        extractions=[
            PropertyExtraction(
                file=Path("test.py"),
                line=5,
                store_id="Chroma:test.py:1",
                operation="read",
                method="similarity_search",
                has_filter=True,
                filter_value_kind=ValueKind.COMPOUND_TENANT,
            )
        ],
    )
    graph = ProjectGraph(
        call_edges=[],
        composition_edges=[],
        identifiers={},
        extends={},
        unresolved=[],
        _class_methods={},
    )
    results = verify_tenant_isolation([tenant_filtered], graph, LANGCHAIN_MODEL)
    assert results
    assert all(r.verdict == Verdict.VERIFIED for r in results)


# ── Multiple profiles ──────────────────────────────────────────────────────────


def test_multiple_profiles_independently_assessed() -> None:
    """Two profiles with different isolation strategies yield independent verdicts."""
    from agentwall.engine.models import PropertyExtraction

    good_profile = StoreProfile(
        store_id="Chroma:good.py:1",
        backend="chromadb",
        extractions=[
            PropertyExtraction(
                file=Path("good.py"),
                line=5,
                store_id="Chroma:good.py:1",
                operation="read",
                method="similarity_search",
                has_filter=True,
                filter_value_kind=ValueKind.COMPOUND_TENANT,
            )
        ],
    )
    bad_profile = StoreProfile(
        store_id="Chroma:bad.py:1",
        backend="chromadb",
        extractions=[
            PropertyExtraction(
                file=Path("bad.py"),
                line=5,
                store_id="Chroma:bad.py:1",
                operation="read",
                method="similarity_search",
                has_filter=False,
                filter_value_kind=ValueKind.DYNAMIC,
            )
        ],
    )
    graph = ProjectGraph(
        call_edges=[],
        composition_edges=[],
        identifiers={},
        extends={},
        unresolved=[],
        _class_methods={},
    )
    results = verify_tenant_isolation([good_profile, bad_profile], graph, LANGCHAIN_MODEL)

    store_ids_by_verdict: dict[str, list[Verdict]] = {}
    for r in results:
        store_ids_by_verdict.setdefault(r.store_id, []).append(r.verdict)

    assert Verdict.VERIFIED in store_ids_by_verdict.get("Chroma:good.py:1", [])
    assert Verdict.VIOLATED in store_ids_by_verdict.get("Chroma:bad.py:1", [])
