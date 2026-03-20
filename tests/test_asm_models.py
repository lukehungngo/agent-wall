"""Tests for ASM data models."""

from __future__ import annotations

import dataclasses
from pathlib import Path

from agentwall.models import (
    ASM_CONFIDENCE_RANK,
    AgentSpec,
    ApplicationModel,
    ASMConfidence,
    Category,
    ContextSink,
    Edge,
    EntryPoint,
    Finding,
    Provenance,
    ReadOp,
    Severity,
    Store,
    WriteOp,
)


def _prov(symbol: str = "test_func") -> Provenance:
    return Provenance(file=Path("app.py"), line=1, col=0, symbol=symbol)


class TestASMConfidence:
    def test_values(self) -> None:
        assert ASMConfidence.CONFIRMED.value == "confirmed"
        assert ASMConfidence.INFERRED.value == "inferred"
        assert ASMConfidence.UNKNOWN.value == "unknown"

    def test_ordering(self) -> None:
        assert (
            ASM_CONFIDENCE_RANK[ASMConfidence.CONFIRMED]
            < ASM_CONFIDENCE_RANK[ASMConfidence.INFERRED]
        )
        assert (
            ASM_CONFIDENCE_RANK[ASMConfidence.INFERRED] < ASM_CONFIDENCE_RANK[ASMConfidence.UNKNOWN]
        )


class TestProvenance:
    def test_creation(self) -> None:
        p = Provenance(file=Path("src/app.py"), line=42, col=8, symbol="upload_doc")
        assert p.file == Path("src/app.py")
        assert p.line == 42
        assert p.col == 8
        assert p.symbol == "upload_doc"

    def test_frozen(self) -> None:
        p = Provenance(file=Path("x.py"), line=1, col=0, symbol="f")
        assert dataclasses.is_dataclass(p)


class TestEntryPoint:
    def test_http_route(self) -> None:
        ep = EntryPoint(
            id="ep-1",
            kind="http_route",
            provenance=_prov("upload"),
            auth="authenticated",
            auth_mechanism="Depends(get_current_user)",
            user_id_source="user",
            confidence=ASMConfidence.CONFIRMED,
        )
        assert ep.kind == "http_route"
        assert ep.auth == "authenticated"

    def test_background_job_defaults(self) -> None:
        ep = EntryPoint(
            id="ep-2",
            kind="background_job",
            provenance=_prov("reindex"),
            auth="unauthenticated",
            auth_mechanism=None,
            user_id_source=None,
            confidence=ASMConfidence.INFERRED,
        )
        assert ep.auth_mechanism is None


class TestWriteOp:
    def test_with_metadata_keys(self) -> None:
        w = WriteOp(
            id="w-1",
            provenance=_prov("ingest"),
            store_id="store-1",
            method="add_documents",
            metadata_keys=frozenset({"user_id", "source"}),
            confidence=ASMConfidence.CONFIRMED,
        )
        assert "user_id" in w.metadata_keys
        assert w.method == "add_documents"


class TestReadOp:
    def test_with_filter(self) -> None:
        r = ReadOp(
            id="r-1",
            provenance=_prov("search"),
            store_id="store-1",
            method="similarity_search",
            filter_keys=frozenset({"user_id"}),
            has_filter=True,
            confidence=ASMConfidence.CONFIRMED,
        )
        assert r.has_filter is True
        assert "user_id" in r.filter_keys

    def test_without_filter(self) -> None:
        r = ReadOp(
            id="r-2",
            provenance=_prov("search"),
            store_id="store-1",
            method="similarity_search",
            filter_keys=frozenset(),
            has_filter=False,
            confidence=ASMConfidence.CONFIRMED,
        )
        assert r.has_filter is False


class TestStore:
    def test_static_collection(self) -> None:
        s = Store(
            id="store-1",
            provenance=_prov("Chroma"),
            backend="chroma",
            collection_name="faq",
            collection_name_is_static=True,
            confidence=ASMConfidence.CONFIRMED,
        )
        assert s.collection_name_is_static is True

    def test_dynamic_collection(self) -> None:
        s = Store(
            id="store-2",
            provenance=_prov("Chroma"),
            backend="chroma",
            collection_name=None,
            collection_name_is_static=False,
            confidence=ASMConfidence.UNKNOWN,
        )
        assert s.collection_name_is_static is False


class TestContextSink:
    def test_unsanitized(self) -> None:
        cs = ContextSink(
            id="sink-1",
            provenance=_prov("build_prompt"),
            kind="llm_context",
            sanitized=False,
            confidence=ASMConfidence.INFERRED,
        )
        assert cs.sanitized is False
        assert cs.kind == "llm_context"


class TestEdge:
    def test_creation(self) -> None:
        e = Edge(
            source_id="ep-1",
            target_id="w-1",
            kind="triggers",
            confidence=ASMConfidence.CONFIRMED,
            provenance=_prov("upload"),
        )
        assert e.kind == "triggers"
        assert e.source_id == "ep-1"


class TestApplicationModel:
    def test_empty_model(self) -> None:
        model = ApplicationModel()
        assert len(model.stores) == 0

    def test_model_with_nodes(self) -> None:
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
        assert len(model.stores) == 1
        assert model.read_ops[0].store_id == "s-1"


class TestAgentSpecASM:
    def test_asm_defaults_to_none(self) -> None:
        spec = AgentSpec(framework="langchain")
        assert spec.asm is None

    def test_asm_can_be_set(self) -> None:
        model = ApplicationModel()
        spec = AgentSpec(framework="langchain", asm=model)
        assert spec.asm is not None


class TestFindingASMFields:
    def test_evidence_path_defaults_to_none(self) -> None:
        f = Finding(
            rule_id="AW-MEM-001",
            title="Test",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="Test",
        )
        assert f.evidence_path is None
        assert f.proof_strength is None

    def test_evidence_path_can_be_set(self) -> None:
        path = [
            {
                "type": "WriteOp",
                "file": "ingest.py",
                "line": 15,
                "detail": "metadata_keys: {source}",
            },
            {
                "type": "Store",
                "file": "config.py",
                "line": 8,
                "detail": "chroma, collection='docs'",
            },
        ]
        f = Finding(
            rule_id="AW-MEM-002",
            title="Test",
            severity=Severity.HIGH,
            category=Category.MEMORY,
            description="Test",
            evidence_path=path,
            proof_strength="confirmed",
        )
        assert len(f.evidence_path) == 2
        assert f.proof_strength == "confirmed"

    def test_evidence_path_serializes(self) -> None:
        f = Finding(
            rule_id="AW-MEM-001",
            title="Test",
            severity=Severity.CRITICAL,
            category=Category.MEMORY,
            description="Test",
            evidence_path=[{"type": "Store", "file": "x.py", "line": 1, "detail": "chroma"}],
            proof_strength="possible",
        )
        data = f.model_dump()
        assert data["evidence_path"] == [
            {"type": "Store", "file": "x.py", "line": 1, "detail": "chroma"}
        ]
        assert data["proof_strength"] == "possible"
