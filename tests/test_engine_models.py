"""Tests for engine data models and ValueKind classifier."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from agentwall.engine.models import (
    IsolationStrategy,
    MetadataConsistency,
    PathCoverage,
    PropertyExtraction,
    SecurityProperty,
    StoreAccess,
    StoreProfile,
    ValueKind,
    Verdict,
    classify_value,
)

# ── classify_value ────────────────────────────────────────────────────────────


def test_literal_string() -> None:
    node = ast.Constant(value="global_docs")
    assert classify_value(node, set()) == ValueKind.LITERAL


def test_literal_int() -> None:
    node = ast.Constant(value=42)
    assert classify_value(node, set()) == ValueKind.LITERAL


def test_dynamic_variable() -> None:
    node = ast.Name(id="some_var", ctx=ast.Load())
    assert classify_value(node, set()) == ValueKind.DYNAMIC


def test_tenant_scoped_variable() -> None:
    node = ast.Name(id="user_id", ctx=ast.Load())
    assert classify_value(node, {"user_id"}) == ValueKind.TENANT_SCOPED


def test_compound_static_dict() -> None:
    """{"source": "web"} — all literal values."""
    node = ast.Dict(
        keys=[ast.Constant(value="source")],
        values=[ast.Constant(value="web")],
    )
    assert classify_value(node, set()) == ValueKind.COMPOUND_STATIC


def test_compound_tenant_dict() -> None:
    """{"user_id": uid} where uid is tenant-scoped."""
    node = ast.Dict(
        keys=[ast.Constant(value="user_id")],
        values=[ast.Name(id="uid", ctx=ast.Load())],
    )
    assert classify_value(node, {"uid"}) == ValueKind.COMPOUND_TENANT


def test_compound_dynamic_dict() -> None:
    """{"category": cat} where cat is dynamic but not tenant."""
    node = ast.Dict(
        keys=[ast.Constant(value="category")],
        values=[ast.Name(id="cat", ctx=ast.Load())],
    )
    assert classify_value(node, set()) == ValueKind.COMPOUND_DYNAMIC


def test_fstring_with_tenant() -> None:
    """f"docs_{tenant_id}" -> TENANT_SCOPED."""
    node = ast.JoinedStr(
        values=[
            ast.Constant(value="docs_"),
            ast.FormattedValue(
                value=ast.Name(id="tenant_id", ctx=ast.Load()),
                conversion=-1,
            ),
        ]
    )
    assert classify_value(node, {"tenant_id"}) == ValueKind.TENANT_SCOPED


def test_fstring_without_tenant() -> None:
    """f"docs_{version}" -> DYNAMIC."""
    node = ast.JoinedStr(
        values=[
            ast.Constant(value="docs_"),
            ast.FormattedValue(
                value=ast.Name(id="version", ctx=ast.Load()),
                conversion=-1,
            ),
        ]
    )
    assert classify_value(node, set()) == ValueKind.DYNAMIC


def test_dict_with_double_star_unpacking() -> None:
    """Dict with None value (** unpacking) is handled without error."""
    node = ast.Dict(
        keys=[None],
        values=[ast.Name(id="extra", ctx=ast.Load())],
    )
    # Should not raise; None keys with dynamic value -> COMPOUND_DYNAMIC
    result = classify_value(node, set())
    assert result == ValueKind.COMPOUND_DYNAMIC


def test_unknown_node_type_is_dynamic() -> None:
    """Unrecognised AST nodes default to DYNAMIC."""
    node = ast.Call(
        func=ast.Name(id="some_func", ctx=ast.Load()),
        args=[],
        keywords=[],
    )
    assert classify_value(node, set()) == ValueKind.DYNAMIC


# ── StoreProfile.isolation_strategy ──────────────────────────────────────────


def _make_profile(
    collection_name_kind: ValueKind = ValueKind.DYNAMIC,
    read_filter_kinds: list[ValueKind] | None = None,
) -> StoreProfile:
    extractions: list[PropertyExtraction] = []
    for kind in read_filter_kinds or []:
        extractions.append(
            PropertyExtraction(
                file=Path("dummy.py"),
                line=1,
                store_id="s1",
                operation="read",
                method="similarity_search",
                has_filter=True,
                filter_value_kind=kind,
            )
        )
    return StoreProfile(
        store_id="s1",
        backend="chroma",
        collection_name_kind=collection_name_kind,
        extractions=extractions,
    )


def test_isolation_collection_per_tenant() -> None:
    profile = _make_profile(collection_name_kind=ValueKind.TENANT_SCOPED)
    assert profile.isolation_strategy == IsolationStrategy.COLLECTION_PER_TENANT


def test_isolation_filter_on_read() -> None:
    profile = _make_profile(
        read_filter_kinds=[ValueKind.COMPOUND_TENANT, ValueKind.COMPOUND_TENANT]
    )
    assert profile.isolation_strategy == IsolationStrategy.FILTER_ON_READ


def test_isolation_partial_filter() -> None:
    profile = _make_profile(
        read_filter_kinds=[ValueKind.COMPOUND_TENANT, ValueKind.COMPOUND_STATIC]
    )
    assert profile.isolation_strategy == IsolationStrategy.PARTIAL_FILTER


def test_isolation_none_no_reads() -> None:
    profile = _make_profile()
    assert profile.isolation_strategy == IsolationStrategy.NONE


def test_isolation_none_untenanted_reads() -> None:
    profile = _make_profile(read_filter_kinds=[ValueKind.COMPOUND_STATIC])
    assert profile.isolation_strategy == IsolationStrategy.NONE


# ── MetadataConsistency ───────────────────────────────────────────────────────


def test_unfiltered_write_keys() -> None:
    mc = MetadataConsistency(
        write_keys=frozenset({"user_id", "source", "timestamp"}),
        read_filter_keys=frozenset({"user_id"}),
    )
    assert mc.unfiltered_write_keys == frozenset({"source", "timestamp"})


def test_has_tenant_key_on_both_true() -> None:
    mc = MetadataConsistency(
        write_keys=frozenset({"user_id", "source"}),
        read_filter_keys=frozenset({"user_id"}),
    )
    assert mc.has_tenant_key_on_both is True


def test_has_tenant_key_on_both_false_missing_from_read() -> None:
    mc = MetadataConsistency(
        write_keys=frozenset({"user_id"}),
        read_filter_keys=frozenset({"source"}),
    )
    assert mc.has_tenant_key_on_both is False


def test_has_tenant_key_on_both_false_no_tenant_key() -> None:
    mc = MetadataConsistency(
        write_keys=frozenset({"source", "category"}),
        read_filter_keys=frozenset({"source"}),
    )
    assert mc.has_tenant_key_on_both is False


# ── PathCoverage.coverage_ratio ───────────────────────────────────────────────


def test_coverage_ratio_zero_when_no_paths() -> None:
    pc = PathCoverage(store_id="s1")
    assert pc.coverage_ratio == 0.0


def test_coverage_ratio_full() -> None:
    from agentwall.engine.models import VerifiedPath

    vp = VerifiedPath(entry_file=Path("api.py"), entry_line=10)
    pc = PathCoverage(store_id="s1", total_paths=1, verified_paths=[vp])
    assert pc.coverage_ratio == pytest.approx(1.0)


def test_coverage_ratio_partial() -> None:
    from agentwall.engine.models import VerifiedPath

    vp = VerifiedPath(entry_file=Path("api.py"), entry_line=10)
    pc = PathCoverage(store_id="s1", total_paths=4, verified_paths=[vp])
    assert pc.coverage_ratio == pytest.approx(0.25)


# ── ValueKind enum values ─────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "member, expected_value",
    [
        (ValueKind.LITERAL, "literal"),
        (ValueKind.DYNAMIC, "dynamic"),
        (ValueKind.TENANT_SCOPED, "tenant"),
        (ValueKind.COMPOUND_STATIC, "cstatic"),
        (ValueKind.COMPOUND_DYNAMIC, "cdynamic"),
        (ValueKind.COMPOUND_TENANT, "ctenant"),
    ],
)
def test_value_kind_string_values(member: ValueKind, expected_value: str) -> None:
    assert member.value == expected_value


# ── Verdict and SecurityProperty enum values ──────────────────────────────────


def test_verdict_values() -> None:
    assert Verdict.VERIFIED.value == "verified"
    assert Verdict.VIOLATED.value == "violated"
    assert Verdict.PARTIAL.value == "partial"
    assert Verdict.UNKNOWN.value == "unknown"


def test_security_property_values() -> None:
    assert SecurityProperty.TENANT_ISOLATION.value == "tenant_isolation"


# ── StoreAccess frozen dataclass ──────────────────────────────────────────────


def test_store_access_immutable() -> None:
    sa = StoreAccess(
        store_id="s1", method="similarity_search", filter_kind=ValueKind.COMPOUND_TENANT
    )
    with pytest.raises(AttributeError):
        sa.store_id = "other"  # type: ignore[misc]
