from pathlib import Path

from agentwall.version_resolver import (
    load_version_data,
    resolve_modifiers,
    resolve_version_from_pyproject,
    resolve_version_from_requirements,
)


class TestLoadVersionData:
    def test_loads_chromadb_yaml(self) -> None:
        data = load_version_data()
        assert "chromadb" in data
        assert data["chromadb"]["pypi_name"] == "chromadb"
        assert len(data["chromadb"]["versions"]) > 0

    def test_loads_all_yaml_files(self) -> None:
        data = load_version_data()
        assert len(data) >= 9


class TestResolveFromRequirements:
    def test_pinned_version(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("chromadb==0.4.1\n")
        versions = resolve_version_from_requirements(tmp_path / "requirements.txt")
        assert versions["chromadb"] == "0.4.1"

    def test_range_uses_lower_bound(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("chromadb>=0.4.0,<0.5.0\n")
        versions = resolve_version_from_requirements(tmp_path / "requirements.txt")
        assert versions["chromadb"] == "0.4.0"

    def test_unpinned_returns_none(self, tmp_path: Path) -> None:
        (tmp_path / "requirements.txt").write_text("chromadb\n")
        versions = resolve_version_from_requirements(tmp_path / "requirements.txt")
        assert versions["chromadb"] is None

    def test_missing_file(self, tmp_path: Path) -> None:
        versions = resolve_version_from_requirements(tmp_path / "requirements.txt")
        assert versions == {}


class TestResolveFromPyproject:
    def test_pinned_version(self, tmp_path: Path) -> None:
        (tmp_path / "pyproject.toml").write_text('[project]\ndependencies = ["chromadb==0.4.1"]\n')
        versions = resolve_version_from_pyproject(tmp_path / "pyproject.toml")
        assert versions["chromadb"] == "0.4.1"


class TestResolveModifiers:
    def test_matching_version_returns_modifier(self) -> None:
        data = load_version_data()
        modifiers = resolve_modifiers({"chromadb": "0.3.0"}, data)
        assert "chromadb" in modifiers
        m = modifiers["chromadb"]
        assert "AW-MEM-003" in m.upgrade

    def test_no_match_returns_empty(self) -> None:
        data = load_version_data()
        modifiers = resolve_modifiers({"unknown-lib": "1.0.0"}, data)
        assert "unknown-lib" not in modifiers

    def test_unresolved_version_returns_no_modifiers(self) -> None:
        data = load_version_data()
        modifiers = resolve_modifiers({"chromadb": None}, data)
        m = modifiers.get("chromadb")
        assert m is None or (m.suppress == [] and m.upgrade == {} and m.downgrade == {})
