"""Tests for ASM graph query analyzer."""

from __future__ import annotations

from pathlib import Path

from agentwall.analyzers.asm import ASMAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import (
    AgentSpec,
    ApplicationModel,
    ASMConfidence,
    ContextSink,
    Edge,
    EntryPoint,
    Provenance,
    ReadOp,
    ScanConfig,
    Severity,
    Store,
    WriteOp,
)


def _prov(symbol: str = "f", line: int = 1, file: str = "app.py") -> Provenance:
    return Provenance(file=Path(file), line=line, col=0, symbol=symbol)


def _store(id: str = "s-1", collection: str = "docs", static: bool = True) -> Store:
    return Store(
        id=id,
        provenance=_prov("Chroma"),
        backend="chroma",
        collection_name=collection,
        collection_name_is_static=static,
        confidence=ASMConfidence.CONFIRMED,
    )


def _write(id: str = "w-1", store_id: str = "s-1", keys: frozenset[str] = frozenset()) -> WriteOp:
    return WriteOp(
        id=id,
        provenance=_prov("add_docs"),
        store_id=store_id,
        method="add_documents",
        metadata_keys=keys,
        confidence=ASMConfidence.CONFIRMED,
    )


def _read(
    id: str = "r-1",
    store_id: str = "s-1",
    filter_keys: frozenset[str] = frozenset(),
    has_filter: bool = False,
) -> ReadOp:
    return ReadOp(
        id=id,
        provenance=_prov("search"),
        store_id=store_id,
        method="similarity_search",
        filter_keys=filter_keys,
        has_filter=has_filter,
        confidence=ASMConfidence.CONFIRMED,
    )


def _entry(id: str = "ep-1", auth: str = "unauthenticated") -> EntryPoint:
    return EntryPoint(
        id=id,
        kind="http_route",
        provenance=_prov("upload"),
        auth=auth,
        auth_mechanism=None,
        user_id_source=None,
        confidence=ASMConfidence.CONFIRMED,
    )


def _sink(id: str = "sink-1") -> ContextSink:
    return ContextSink(
        id=id,
        provenance=_prov("invoke", line=20),
        kind="llm_context",
        sanitized=False,
        confidence=ASMConfidence.INFERRED,
    )


def _edge(src: str, tgt: str, kind: str, conf: ASMConfidence = ASMConfidence.CONFIRMED) -> Edge:
    return Edge(source_id=src, target_id=tgt, kind=kind, confidence=conf, provenance=_prov())


def _ctx(model: ApplicationModel) -> AnalysisContext:
    ctx = AnalysisContext(target=Path("/tmp"), config=ScanConfig.default())
    ctx.spec = AgentSpec(framework="langchain", asm=model)
    return ctx


# ── Proof Strength ───────────────────────────────────────────────────────


class TestProofStrength:
    def test_all_confirmed(self) -> None:
        assert ASMAnalyzer()._proof_strength([_entry(), _write()]) == "confirmed"

    def test_inferred_downgrades(self) -> None:
        ep = EntryPoint(
            id="ep-1",
            kind="http_route",
            provenance=_prov(),
            auth="unauthenticated",
            auth_mechanism=None,
            user_id_source=None,
            confidence=ASMConfidence.INFERRED,
        )
        assert ASMAnalyzer()._proof_strength([ep, _write()]) == "possible"

    def test_unknown_downgrades_further(self) -> None:
        ep = EntryPoint(
            id="ep-1",
            kind="http_route",
            provenance=_prov(),
            auth="unauthenticated",
            auth_mechanism=None,
            user_id_source=None,
            confidence=ASMConfidence.UNKNOWN,
        )
        assert ASMAnalyzer()._proof_strength([ep, _write()]) == "uncertain"


# ── Q1: Unauthenticated Write ────────────────────────────────────────────


class TestQ1UnauthenticatedWrite:
    def test_fires_on_unauth_entry_to_write(self) -> None:
        model = ApplicationModel(
            entry_points=[_entry(auth="unauthenticated")],
            write_ops=[_write()],
            stores=[_store()],
            edges=[_edge("ep-1", "w-1", "triggers")],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q1 = [f for f in findings if f.rule_id == "AW-MEM-003" and f.layer == "ASM"]
        assert len(q1) >= 1
        assert q1[0].proof_strength is not None

    def test_does_not_fire_on_auth_entry(self) -> None:
        model = ApplicationModel(
            entry_points=[_entry(auth="authenticated")],
            write_ops=[_write()],
            stores=[_store()],
            edges=[_edge("ep-1", "w-1", "triggers")],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q1 = [f for f in findings if f.rule_id == "AW-MEM-003" and f.layer == "ASM"]
        assert len(q1) == 0


# ── Q2: Write-Read Key Mismatch ──────────────────────────────────────────


class TestQ2WriteReadKeyMismatch:
    def test_fires_when_filter_key_not_in_write_keys(self) -> None:
        model = ApplicationModel(
            write_ops=[_write(keys=frozenset({"source", "filename"}))],
            stores=[_store()],
            read_ops=[_read(filter_keys=frozenset({"user_id"}), has_filter=True)],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q2 = [f for f in findings if f.rule_id == "AW-MEM-002" and f.layer == "ASM"]
        assert len(q2) == 1
        assert "user_id" in q2[0].title

    def test_does_not_fire_when_keys_match(self) -> None:
        model = ApplicationModel(
            write_ops=[_write(keys=frozenset({"user_id", "source"}))],
            stores=[_store()],
            read_ops=[_read(filter_keys=frozenset({"user_id"}), has_filter=True)],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q2 = [f for f in findings if f.rule_id == "AW-MEM-002" and f.layer == "ASM"]
        assert len(q2) == 0

    def test_does_not_fire_when_no_filter(self) -> None:
        model = ApplicationModel(
            write_ops=[_write(keys=frozenset({"source"}))],
            stores=[_store()],
            read_ops=[_read(has_filter=False)],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q2 = [f for f in findings if f.rule_id == "AW-MEM-002" and f.layer == "ASM"]
        assert len(q2) == 0


# ── Q3: Static Shared Collection ─────────────────────────────────────────


class TestQ3StaticSharedCollection:
    def test_fires_on_static_collection_multi_writer_no_filter(self) -> None:
        model = ApplicationModel(
            entry_points=[_entry(id="ep-1"), _entry(id="ep-2")],
            write_ops=[_write(id="w-1"), _write(id="w-2")],
            stores=[_store(collection="faq", static=True)],
            read_ops=[_read(has_filter=False)],
            edges=[
                _edge("ep-1", "w-1", "triggers"),
                _edge("ep-2", "w-2", "triggers"),
            ],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q3 = [
            f
            for f in findings
            if f.rule_id == "AW-MEM-001" and f.layer == "ASM" and "shared" in f.title.lower()
        ]
        assert len(q3) >= 1

    def test_does_not_fire_on_dynamic_collection(self) -> None:
        model = ApplicationModel(
            entry_points=[_entry(id="ep-1"), _entry(id="ep-2")],
            write_ops=[_write(id="w-1"), _write(id="w-2")],
            stores=[_store(collection=None, static=False)],
            read_ops=[_read(has_filter=False)],
            edges=[
                _edge("ep-1", "w-1", "triggers"),
                _edge("ep-2", "w-2", "triggers"),
            ],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q3 = [
            f
            for f in findings
            if f.rule_id == "AW-MEM-001" and f.layer == "ASM" and "shared" in f.title.lower()
        ]
        assert len(q3) == 0

    def test_does_not_fire_with_single_writer(self) -> None:
        model = ApplicationModel(
            entry_points=[_entry(id="ep-1")],
            write_ops=[_write(id="w-1")],
            stores=[_store(collection="faq", static=True)],
            read_ops=[_read(has_filter=False)],
            edges=[_edge("ep-1", "w-1", "triggers")],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q3 = [
            f
            for f in findings
            if f.rule_id == "AW-MEM-001" and f.layer == "ASM" and "shared" in f.title.lower()
        ]
        assert len(q3) == 0


# ── Q4: Cross-Tenant Reachable ───────────────────────────────────────────


class TestQ4CrossTenantReachable:
    def test_fires_on_full_unscoped_path(self) -> None:
        model = ApplicationModel(
            write_ops=[_write(keys=frozenset({"source"}))],
            stores=[_store()],
            read_ops=[_read(has_filter=False)],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q4 = [f for f in findings if "Cross-tenant" in f.title and f.layer == "ASM"]
        assert len(q4) >= 1

    def test_does_not_fire_when_user_id_written(self) -> None:
        model = ApplicationModel(
            write_ops=[_write(keys=frozenset({"user_id", "source"}))],
            stores=[_store()],
            read_ops=[_read(has_filter=False)],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q4 = [f for f in findings if "Cross-tenant" in f.title and f.layer == "ASM"]
        assert len(q4) == 0

    def test_does_not_fire_when_read_has_filter(self) -> None:
        model = ApplicationModel(
            write_ops=[_write(keys=frozenset({"source"}))],
            stores=[_store()],
            read_ops=[_read(filter_keys=frozenset({"user_id"}), has_filter=True)],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q4 = [f for f in findings if "Cross-tenant" in f.title and f.layer == "ASM"]
        assert len(q4) == 0

    def test_evidence_path_includes_entry_points_and_sink(self) -> None:
        """Q4 should include full path: entry_w -> write -> store -> read -> entry_r -> sink."""
        ep_w = _entry(id="ep-1", auth="unknown")
        ep_r = _entry(id="ep-2", auth="unknown")
        write = _write(keys=frozenset({"source"}))
        read = _read(has_filter=False)
        store = _store()
        sink = _sink()
        model = ApplicationModel(
            entry_points=[ep_w, ep_r],
            write_ops=[write],
            stores=[store],
            read_ops=[read],
            sinks=[sink],
            edges=[
                _edge("ep-1", "w-1", "triggers"),
                _edge("ep-2", "r-1", "triggers"),
                _edge("r-1", "sink-1", "assembles_into"),
            ],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q4 = [f for f in findings if "Cross-tenant" in f.title and f.layer == "ASM"]
        assert len(q4) == 1
        path = q4[0].evidence_path
        assert path is not None
        types = [n["type"] for n in path]
        # Full chain: EntryPoint, WriteOp, Store, ReadOp, EntryPoint, ContextSink
        assert "EntryPoint" in types
        assert "WriteOp" in types
        assert "Store" in types
        assert "ReadOp" in types
        assert "ContextSink" in types
        assert types.count("EntryPoint") == 2


# ── Q5: Unsanitized Context ──────────────────────────────────────────────


class TestQ5UnsanitizedContext:
    def test_fires_on_unsanitized_sink(self) -> None:
        model = ApplicationModel(
            read_ops=[_read()],
            sinks=[_sink()],
            edges=[_edge("r-1", "sink-1", "assembles_into", ASMConfidence.INFERRED)],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q5 = [f for f in findings if f.rule_id == "AW-MEM-005" and f.layer == "ASM"]
        assert len(q5) == 1

    def test_does_not_fire_on_sanitized_sink(self) -> None:
        sink = ContextSink(
            id="sink-1",
            provenance=_prov("invoke", line=20),
            kind="llm_context",
            sanitized=True,
            confidence=ASMConfidence.CONFIRMED,
        )
        model = ApplicationModel(
            read_ops=[_read()],
            sinks=[sink],
            edges=[_edge("r-1", "sink-1", "assembles_into")],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q5 = [f for f in findings if f.rule_id == "AW-MEM-005" and f.layer == "ASM"]
        assert len(q5) == 0


# ── Safe model: no findings ──────────────────────────────────────────────


class TestQ3Q4Interaction:
    """Q3 (static shared collection) and Q4 (cross-tenant reachable) on same model."""

    def test_both_q3_and_q4_fire_on_shared_unscoped_store(self) -> None:
        store = _store(collection="shared", static=True)
        ep_a = _entry(id="ep-1", auth="authenticated")
        ep_b = _entry(id="ep-2", auth="authenticated")
        # Writes with no tenant keys
        w1 = _write(id="w-1", keys=frozenset({"source"}))
        w2 = _write(id="w-2", keys=frozenset({"source"}))
        read = _read(has_filter=False)
        model = ApplicationModel(
            entry_points=[ep_a, ep_b],
            write_ops=[w1, w2],
            stores=[store],
            read_ops=[read],
            edges=[
                _edge("ep-1", "w-1", "triggers"),
                _edge("ep-2", "w-2", "triggers"),
                _edge("ep-1", "r-1", "triggers"),
            ],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        rule_ids = {f.rule_id for f in findings}
        assert "AW-MEM-001" in rule_ids, "Q3 or Q4 should fire AW-MEM-001"
        # Both Q3 and Q4 emit AW-MEM-001 — expect at least 2
        mem001 = [f for f in findings if f.rule_id == "AW-MEM-001"]
        assert len(mem001) >= 2, f"Expected Q3+Q4 both firing, got {len(mem001)}"


# ── Severity Capping ────────────────────────────────────────────────────


class TestSeverityCapping:
    def test_critical_possible_caps_to_high(self) -> None:
        ana = ASMAnalyzer()
        assert ana._cap_severity(Severity.CRITICAL, "possible") == Severity.HIGH

    def test_critical_uncertain_caps_to_medium(self) -> None:
        ana = ASMAnalyzer()
        assert ana._cap_severity(Severity.CRITICAL, "uncertain") == Severity.MEDIUM

    def test_high_uncertain_caps_to_medium(self) -> None:
        ana = ASMAnalyzer()
        assert ana._cap_severity(Severity.HIGH, "uncertain") == Severity.MEDIUM

    def test_high_confirmed_stays_high(self) -> None:
        ana = ASMAnalyzer()
        assert ana._cap_severity(Severity.HIGH, "confirmed") == Severity.HIGH

    def test_medium_possible_stays_medium(self) -> None:
        ana = ASMAnalyzer()
        assert ana._cap_severity(Severity.MEDIUM, "possible") == Severity.MEDIUM


# ── Q4: Evidence includes all unscoped writes and unfiltered reads ──────


class TestQ4EvidenceAggregation:
    def test_evidence_includes_all_unscoped_writes_and_unfiltered_reads(self) -> None:
        ep_w = _entry(id="ep-1", auth="unknown")
        w1 = _write(id="w-1", keys=frozenset({"source"}))
        w2 = _write(id="w-2", keys=frozenset({"filename"}))
        w3 = _write(id="w-3", keys=frozenset({"tag"}))
        r1 = _read(id="r-1", has_filter=False)
        r2 = _read(id="r-2", has_filter=False)
        store = _store()
        model = ApplicationModel(
            entry_points=[ep_w],
            write_ops=[w1, w2, w3],
            stores=[store],
            read_ops=[r1, r2],
            edges=[_edge("ep-1", "w-1", "triggers")],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        q4 = [f for f in findings if "Cross-tenant" in f.title and f.layer == "ASM"]
        assert len(q4) == 1
        path = q4[0].evidence_path
        assert path is not None
        write_nodes = [n for n in path if n["type"] == "WriteOp"]
        read_nodes = [n for n in path if n["type"] == "ReadOp"]
        assert len(write_nodes) == 3, f"Expected 3 unscoped writes, got {len(write_nodes)}"
        assert len(read_nodes) == 2, f"Expected 2 unfiltered reads, got {len(read_nodes)}"


class TestASMSafe:
    def test_no_findings_on_properly_isolated_model(self) -> None:
        store = _store()
        write = _write(keys=frozenset({"user_id", "source"}))
        read = _read(filter_keys=frozenset({"user_id"}), has_filter=True)
        ep = _entry(auth="authenticated")
        sink = ContextSink(
            id="sink-1",
            provenance=_prov("invoke", line=20),
            kind="llm_context",
            sanitized=True,
            confidence=ASMConfidence.CONFIRMED,
        )
        model = ApplicationModel(
            entry_points=[ep],
            write_ops=[write],
            stores=[store],
            read_ops=[read],
            sinks=[sink],
            edges=[
                _edge("ep-1", "w-1", "triggers"),
                _edge("ep-1", "r-1", "triggers"),
                _edge("r-1", "sink-1", "assembles_into"),
            ],
        )
        findings = ASMAnalyzer().analyze(_ctx(model))
        assert len(findings) == 0
