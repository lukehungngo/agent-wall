"""Tests for the L1 model-driven property extractor."""

from pathlib import Path

import pytest

from agentwall.engine.extractor import extract_properties
from agentwall.engine.models import IsolationStrategy, ValueKind
from agentwall.frameworks.langchain import LANGCHAIN_MODEL

FIXTURES = Path(__file__).parent / "fixtures"


def test_basic_no_filter() -> None:
    profiles = extract_properties([FIXTURES / "engine_basic" / "agent.py"], LANGCHAIN_MODEL)
    assert len(profiles) == 1
    p = profiles[0]
    assert p.backend == "chromadb"
    assert p.isolation_strategy == IsolationStrategy.NONE
    reads = [e for e in p.extractions if e.operation == "read"]
    assert len(reads) == 1
    assert reads[0].has_filter is False


def test_tenant_collection() -> None:
    profiles = extract_properties(
        [FIXTURES / "engine_tenant_collection" / "agent.py"], LANGCHAIN_MODEL
    )
    assert len(profiles) == 1
    assert profiles[0].isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT
    assert profiles[0].collection_name_kind == ValueKind.TENANT_SCOPED


def test_static_filter() -> None:
    profiles = extract_properties([FIXTURES / "engine_static_filter" / "agent.py"], LANGCHAIN_MODEL)
    assert len(profiles) == 1
    p = profiles[0]
    assert p.isolation_strategy == IsolationStrategy.NONE
    reads = [e for e in p.extractions if e.operation == "read"]
    assert reads[0].has_filter is True
    assert reads[0].filter_value_kind == ValueKind.COMPOUND_STATIC


def test_metadata_consistency_mismatch() -> None:
    profiles = extract_properties([FIXTURES / "engine_static_filter" / "agent.py"], LANGCHAIN_MODEL)
    mc = profiles[0].metadata_consistency
    assert "user_id" in mc.unfiltered_write_keys
    assert mc.has_tenant_key_on_both is False


def test_empty_file_list() -> None:
    profiles = extract_properties([], LANGCHAIN_MODEL)
    assert profiles == []


def test_parse_error_is_skipped(tmp_path: Path) -> None:
    bad = tmp_path / "bad.py"
    bad.write_text("def (broken syntax :")
    profiles = extract_properties([bad], LANGCHAIN_MODEL)
    assert profiles == []


def test_no_store_in_file(tmp_path: Path) -> None:
    clean = tmp_path / "clean.py"
    clean.write_text("x = 1 + 2\nprint(x)\n")
    profiles = extract_properties([clean], LANGCHAIN_MODEL)
    assert profiles == []


def test_missing_file_is_skipped(tmp_path: Path) -> None:
    missing = tmp_path / "nonexistent.py"
    profiles = extract_properties([missing], LANGCHAIN_MODEL)
    assert profiles == []


def test_write_extraction_keys() -> None:
    profiles = extract_properties([FIXTURES / "engine_static_filter" / "agent.py"], LANGCHAIN_MODEL)
    writes = [e for e in profiles[0].extractions if e.operation == "write"]
    assert len(writes) == 1
    assert "user_id" in writes[0].metadata_keys
    assert "source" in writes[0].metadata_keys


@pytest.mark.parametrize(
    "fixture,expected_backend",
    [
        ("engine_basic", "chromadb"),
        ("engine_tenant_collection", "chromadb"),
        ("engine_static_filter", "chromadb"),
    ],
)
def test_backend_detected(fixture: str, expected_backend: str) -> None:
    profiles = extract_properties([FIXTURES / fixture / "agent.py"], LANGCHAIN_MODEL)
    assert len(profiles) == 1
    assert profiles[0].backend == expected_backend


def test_read_no_filter_has_dynamic_filter_kind() -> None:
    profiles = extract_properties([FIXTURES / "engine_basic" / "agent.py"], LANGCHAIN_MODEL)
    reads = [e for e in profiles[0].extractions if e.operation == "read"]
    assert reads[0].filter_value_kind == ValueKind.DYNAMIC


def test_multiple_files_aggregate(tmp_path: Path) -> None:
    """Two files each instantiating a Chroma store → two profiles."""
    f1 = tmp_path / "a.py"
    f2 = tmp_path / "b.py"
    f1.write_text(
        "from langchain_community.vectorstores import Chroma\n"
        'db = Chroma(collection_name="col_a")\n'
        'results = db.similarity_search("q")\n'
    )
    f2.write_text(
        "from langchain_community.vectorstores import Chroma\n"
        'store = Chroma(collection_name="col_b")\n'
        'results = store.similarity_search("q")\n'
    )
    profiles = extract_properties([f1, f2], LANGCHAIN_MODEL)
    assert len(profiles) == 2
    backends = {p.backend for p in profiles}
    assert backends == {"chromadb"}
