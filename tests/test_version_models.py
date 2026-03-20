"""Tests for Category enum expansion, VersionModifier, and CVEMatch models."""

from agentwall.models import Category, CVEMatch, Severity, VersionModifier


class TestCategoryEnum:
    def test_new_categories_exist(self) -> None:
        assert Category.SECRETS == "secrets"
        assert Category.RAG == "rag"
        assert Category.MCP == "mcp"
        assert Category.SERIALIZATION == "serialization"
        assert Category.AGENT == "agent"

    def test_existing_categories_unchanged(self) -> None:
        assert Category.MEMORY == "memory"
        assert Category.TOOL == "tool"


class TestVersionModifier:
    def test_defaults(self) -> None:
        m = VersionModifier(library="chromadb")
        assert m.resolved_version is None
        assert m.suppress == []
        assert m.downgrade == {}
        assert m.upgrade == {}
        assert m.facts == {}
        assert m.cves == []

    def test_with_values(self) -> None:
        m = VersionModifier(
            library="chromadb",
            resolved_version="0.4.1",
            upgrade={"AW-MEM-003": Severity.HIGH},
            facts={"has_auth_support": True},
        )
        assert m.resolved_version == "0.4.1"
        assert m.upgrade["AW-MEM-003"] == Severity.HIGH
        assert m.facts["has_auth_support"] is True


class TestCVEMatch:
    def test_creation(self) -> None:
        cve = CVEMatch(
            id="CVE-2024-12345",
            severity=Severity.HIGH,
            description="Auth bypass",
            library="chromadb",
            version="0.4.1",
        )
        assert cve.id == "CVE-2024-12345"
        assert cve.library == "chromadb"
