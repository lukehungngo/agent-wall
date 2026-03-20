"""Tests for the L6 path coverage aggregator (pathcov.py)."""

from pathlib import Path

import pytest

from agentwall.engine.extractor import extract_properties
from agentwall.engine.graph import ProjectGraph, build_project_graph
from agentwall.engine.models import (
    IsolationStrategy,
    PropertyVerification,
    SecurityProperty,
    StoreAccess,
    StoreProfile,
    ValueKind,
    Verdict,
)
from agentwall.engine.pathcov import compute_path_coverage
from agentwall.engine.verifier import verify_tenant_isolation
from agentwall.frameworks.langchain import LANGCHAIN_MODEL

FIXTURES = Path(__file__).parent / "fixtures"


# ── Integration tests against real fixtures ───────────────────────────────────


def test_branching_partial_coverage():
    """Branching fixture has one filtered and one unfiltered path — expect violation."""
    files = [FIXTURES / "engine_branching" / "agent.py"]
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    verifications = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    coverages = compute_path_coverage(profiles, graph, verifications)

    assert len(coverages) >= 1
    cov = coverages[0]
    assert cov.coverage_ratio < 1.0
    assert len(cov.violated_paths) >= 1


def test_full_coverage_no_violations():
    """Tenant-collection fixture uses per-tenant collections — no violations expected."""
    files = [FIXTURES / "engine_tenant_collection" / "agent.py"]
    profiles = extract_properties(files, LANGCHAIN_MODEL)
    graph = build_project_graph(files, LANGCHAIN_MODEL)
    verifications = verify_tenant_isolation(profiles, graph, LANGCHAIN_MODEL)
    coverages = compute_path_coverage(profiles, graph, verifications)

    for cov in coverages:
        assert len(cov.violated_paths) == 0


def test_empty_verifications():
    """No profiles → empty list returned."""
    graph = build_project_graph([], LANGCHAIN_MODEL)
    coverages = compute_path_coverage([], graph, [])
    assert coverages == []


# ── Unit tests with synthetic data ────────────────────────────────────────────


def _make_empty_graph() -> ProjectGraph:
    return build_project_graph([], LANGCHAIN_MODEL)


def _make_profile(store_id: str, has_read: bool = True) -> StoreProfile:
    from agentwall.engine.models import PropertyExtraction

    extractions = []
    if has_read:
        extractions.append(
            PropertyExtraction(
                file=Path("agent.py"),
                line=10,
                store_id=store_id,
                operation="read",
                method="similarity_search",
                has_filter=False,
            )
        )
    return StoreProfile(
        store_id=store_id,
        backend="Chroma",
        extractions=extractions,
        file=Path("agent.py"),
        line=1,
    )


def _make_verification(store_id: str, verdict: Verdict, line: int = 10) -> PropertyVerification:
    access = StoreAccess(
        store_id=store_id,
        method="similarity_search",
        filter_kind=ValueKind.DYNAMIC,
    )
    return PropertyVerification(
        store_id=store_id,
        access=access,
        property=SecurityProperty.TENANT_ISOLATION,
        verdict=verdict,
        file=Path("agent.py"),
        line=line,
    )


def test_unit_verified_verdict_becomes_verified_path():
    graph = _make_empty_graph()
    profile = _make_profile("store1")
    v = _make_verification("store1", Verdict.VERIFIED)
    coverages = compute_path_coverage([profile], graph, [v])

    assert len(coverages) == 1
    cov = coverages[0]
    assert cov.store_id == "store1"
    assert len(cov.verified_paths) == 1
    assert len(cov.violated_paths) == 0
    assert len(cov.unknown_paths) == 0
    assert cov.total_paths == 1
    assert cov.coverage_ratio == 1.0


def test_unit_violated_verdict_becomes_violated_path():
    graph = _make_empty_graph()
    profile = _make_profile("store1")
    v = _make_verification("store1", Verdict.VIOLATED)
    coverages = compute_path_coverage([profile], graph, [v])

    cov = coverages[0]
    assert len(cov.violated_paths) == 1
    assert len(cov.verified_paths) == 0
    assert cov.coverage_ratio == 0.0


def test_unit_unknown_verdict_becomes_unknown_path():
    graph = _make_empty_graph()
    profile = _make_profile("store1")
    v = _make_verification("store1", Verdict.UNKNOWN)
    coverages = compute_path_coverage([profile], graph, [v])

    cov = coverages[0]
    assert len(cov.unknown_paths) == 1
    assert cov.unknown_paths[0].reason == "unresolved"
    assert cov.coverage_ratio == 0.0


def test_unit_partial_verdict_becomes_unknown_path():
    """PARTIAL verdict should be treated as UNKNOWN (not VERIFIED)."""
    graph = _make_empty_graph()
    profile = _make_profile("store1")
    v = _make_verification("store1", Verdict.PARTIAL)
    coverages = compute_path_coverage([profile], graph, [v])

    cov = coverages[0]
    assert len(cov.unknown_paths) == 1
    assert len(cov.verified_paths) == 0


def test_unit_mixed_verdicts_correct_counts():
    graph = _make_empty_graph()
    profile = _make_profile("store1")
    verifications = [
        _make_verification("store1", Verdict.VERIFIED, line=10),
        _make_verification("store1", Verdict.VIOLATED, line=11),
        _make_verification("store1", Verdict.UNKNOWN, line=12),
    ]
    coverages = compute_path_coverage([profile], graph, verifications)

    cov = coverages[0]
    assert cov.total_paths == 3
    assert len(cov.verified_paths) == 1
    assert len(cov.violated_paths) == 1
    assert len(cov.unknown_paths) == 1
    assert cov.coverage_ratio == pytest.approx(1 / 3)


def test_unit_profile_without_reads_omitted():
    """Profiles with no read extractions should not appear in the output."""
    graph = _make_empty_graph()
    profile = _make_profile("store1", has_read=False)
    coverages = compute_path_coverage([profile], graph, [])
    assert coverages == []


def test_unit_verifications_for_unknown_store_ignored():
    """Verifications referencing a store not in profiles are silently ignored."""
    graph = _make_empty_graph()
    profile = _make_profile("store1")
    v = _make_verification("store_other", Verdict.VIOLATED)
    coverages = compute_path_coverage([profile], graph, [v])

    assert len(coverages) == 1
    cov = coverages[0]
    assert cov.store_id == "store1"
    # No verifications matched store1 → all path lists empty, total_paths == 0
    assert cov.total_paths == 0
    assert cov.coverage_ratio == 0.0


@pytest.mark.parametrize(
    "verdicts,expected_ratio",
    [
        ([Verdict.VERIFIED, Verdict.VERIFIED], 1.0),
        ([Verdict.VIOLATED, Verdict.VIOLATED], 0.0),
        ([Verdict.VERIFIED, Verdict.VIOLATED], 0.5),
        ([], 0.0),
    ],
)
def test_unit_coverage_ratio_parametrized(verdicts: list[Verdict], expected_ratio: float) -> None:
    graph = _make_empty_graph()
    profile = _make_profile("store1")
    verifications = [_make_verification("store1", v, line=i) for i, v in enumerate(verdicts)]
    coverages = compute_path_coverage([profile], graph, verifications)

    assert len(coverages) == 1
    assert coverages[0].coverage_ratio == pytest.approx(expected_ratio)


def test_unit_collection_per_tenant_all_verified():
    """COLLECTION_PER_TENANT profile → all verifications become VerifiedPath."""
    from agentwall.engine.models import PropertyExtraction

    ext = PropertyExtraction(
        file=Path("agent.py"),
        line=5,
        store_id="store_col",
        operation="read",
        method="similarity_search",
        has_filter=False,
    )
    profile = StoreProfile(
        store_id="store_col",
        backend="Chroma",
        collection_name="tenant_{id}",
        collection_name_kind=ValueKind.TENANT_SCOPED,
        extractions=[ext],
        file=Path("agent.py"),
        line=1,
    )
    assert profile.isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT

    access = StoreAccess(
        store_id="store_col",
        method="similarity_search",
        filter_kind=ValueKind.DYNAMIC,
    )
    v = PropertyVerification(
        store_id="store_col",
        access=access,
        verdict=Verdict.VIOLATED,  # would normally be VIOLATED, but strategy overrides
        file=Path("agent.py"),
        line=5,
    )

    graph = _make_empty_graph()
    coverages = compute_path_coverage([profile], graph, [v])

    assert len(coverages) == 1
    cov = coverages[0]
    assert len(cov.verified_paths) == 1
    assert len(cov.violated_paths) == 0
    assert cov.coverage_ratio == 1.0


def test_unit_multiple_stores_independent():
    """Multiple profiles produce independent PathCoverage objects."""
    graph = _make_empty_graph()
    p1 = _make_profile("s1")
    p2 = _make_profile("s2")
    verifications = [
        _make_verification("s1", Verdict.VERIFIED),
        _make_verification("s2", Verdict.VIOLATED),
    ]
    coverages = compute_path_coverage([p1, p2], graph, verifications)

    assert len(coverages) == 2
    by_id = {c.store_id: c for c in coverages}
    assert by_id["s1"].coverage_ratio == 1.0
    assert by_id["s2"].coverage_ratio == 0.0
