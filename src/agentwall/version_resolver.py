"""Resolve library versions from dependency files and match against YAML version data."""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib  # type: ignore[import-not-found]

import yaml
from packaging.specifiers import SpecifierSet
from packaging.version import Version

from agentwall.models import CVEMatch, Severity, VersionModifier

_SEVERITY_MAP: dict[str, Severity] = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "info": Severity.INFO,
}


def load_version_data() -> dict[str, dict[str, Any]]:
    """Load all YAML version data files from package data directory."""
    data_dir = Path(__file__).parent / "data" / "versions"
    result: dict[str, dict[str, Any]] = {}
    if not data_dir.exists():
        return result
    for yaml_file in sorted(data_dir.glob("*.yaml")):
        with open(yaml_file) as f:
            doc = yaml.safe_load(f)
        if doc and "pypi_name" in doc:
            result[doc["pypi_name"]] = doc
    return result


def _normalize_name(name: str) -> str:
    """Normalize PyPI package name: lowercase, hyphens/underscores/dots to hyphens."""
    return re.sub(r"[-_.]+", "-", name).lower()


def _extract_lower_bound(spec_str: str) -> str | None:
    """Extract lower bound version from a PEP 440 specifier string."""
    for part in spec_str.split(","):
        part = part.strip()
        if part.startswith(">="):
            return part[2:].strip()
        if part.startswith("=="):
            return part[2:].strip()
    return None


def resolve_version_from_requirements(path: Path) -> dict[str, str | None]:
    """Parse requirements.txt and extract package versions."""
    if not path.exists():
        return {}
    result: dict[str, str | None] = {}
    for line in path.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#") or line.startswith("-"):
            continue
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)", line)
        if not match:
            continue
        name = _normalize_name(match.group(1))
        spec = match.group(2).strip()
        if not spec:
            result[name] = None
        elif spec.startswith("=="):
            result[name] = spec[2:].strip()
        else:
            result[name] = _extract_lower_bound(spec)
    return result


def resolve_version_from_pyproject(path: Path) -> dict[str, str | None]:
    """Parse pyproject.toml [project].dependencies for versions."""
    if not path.exists():
        return {}

    with open(path, "rb") as f:
        data = tomllib.load(f)
    deps: list[str] = data.get("project", {}).get("dependencies", [])
    result: dict[str, str | None] = {}
    for dep in deps:
        match = re.match(r"^([a-zA-Z0-9_.-]+)\s*(.*)", dep)
        if not match:
            continue
        name = _normalize_name(match.group(1))
        spec = match.group(2).strip()
        if not spec:
            result[name] = None
        elif spec.startswith("=="):
            result[name] = spec[2:].strip()
        else:
            result[name] = _extract_lower_bound(spec)
    return result


def resolve_versions(target: Path) -> dict[str, str | None]:
    """Resolve library versions from a project directory. Best-effort, pessimistic."""
    versions: dict[str, str | None] = {}
    for req_file in ["requirements.txt", "requirements-dev.txt"]:
        versions.update(resolve_version_from_requirements(target / req_file))
    pyproject = target / "pyproject.toml"
    if pyproject.exists():
        versions.update(resolve_version_from_pyproject(pyproject))
    return versions


def resolve_modifiers(
    versions: dict[str, str | None],
    version_data: dict[str, dict[str, Any]],
) -> dict[str, VersionModifier]:
    """Match resolved versions against YAML data and produce VersionModifiers."""
    result: dict[str, VersionModifier] = {}
    for pypi_name, data in version_data.items():
        normalized = _normalize_name(pypi_name)
        version_str = versions.get(normalized)
        if version_str is None:
            continue
        try:
            ver = Version(version_str)
        except Exception:
            continue

        # Collect facts from matching version ranges
        facts: dict[str, bool | str] = {}
        for v_entry in data.get("versions", []):
            spec = SpecifierSet(v_entry["range"])
            if ver in spec:
                facts.update(v_entry.get("facts", {}))

        # Collect modifiers from matching ranges
        suppress: list[str] = []
        downgrade: dict[str, Severity] = {}
        upgrade: dict[str, Severity] = {}
        for mod in data.get("modifiers", []):
            spec = SpecifierSet(mod["range"])
            if ver in spec:
                suppress.extend(mod.get("suppress", []))
                for rule_id, sev_str in mod.get("downgrade", {}).items():
                    downgrade[rule_id] = _SEVERITY_MAP[sev_str.lower()]
                for rule_id, sev_str in mod.get("upgrade", {}).items():
                    upgrade[rule_id] = _SEVERITY_MAP[sev_str.lower()]

        # Collect CVE matches
        cves: list[CVEMatch] = []
        for cve in data.get("cves", []):
            spec = SpecifierSet(cve["range"])
            if ver in spec:
                cves.append(
                    CVEMatch(
                        id=cve["id"],
                        severity=_SEVERITY_MAP[cve["severity"].lower()],
                        description=cve["description"],
                        library=pypi_name,
                        version=version_str,
                    )
                )

        result[normalized] = VersionModifier(
            library=pypi_name,
            resolved_version=version_str,
            suppress=suppress,
            downgrade=downgrade,
            upgrade=upgrade,
            facts=facts,
            cves=cves,
        )
    return result
