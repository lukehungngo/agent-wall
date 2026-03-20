"""L0-versions analyzer -- resolve library versions and inject modifiers into context."""

from __future__ import annotations

from collections.abc import Sequence

from agentwall.context import AnalysisContext
from agentwall.models import Category, Finding
from agentwall.patterns import AGENT_FRAMEWORK_PACKAGES
from agentwall.rules import AW_SER_002
from agentwall.version_resolver import load_version_data, resolve_modifiers, resolve_versions


class VersionsAnalyzer:
    """Resolve library versions from deps files, inject modifiers, flag unpinned deps."""

    name: str = "L0-versions"
    depends_on: Sequence[str] = ()
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = True

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []

        # Resolve versions from deps files
        versions = resolve_versions(ctx.target)

        # Load YAML data and produce modifiers
        version_data = load_version_data()
        ctx.version_modifiers = resolve_modifiers(versions, version_data)

        # Flag unpinned agent framework dependencies (AW-SER-002)
        normalized_agent_pkgs = {
            name.lower().replace("_", "-") for name in AGENT_FRAMEWORK_PACKAGES
        }
        for pkg_name, ver in versions.items():
            if pkg_name in normalized_agent_pkgs and ver is None:
                findings.append(
                    Finding(
                        rule_id=AW_SER_002.rule_id,
                        title=AW_SER_002.title,
                        severity=AW_SER_002.severity,
                        category=AW_SER_002.category,
                        description=f"{pkg_name} has no version pin. {AW_SER_002.description}",
                        layer="L0",
                    )
                )

        # Emit CVE findings
        for modifier in ctx.version_modifiers.values():
            for cve in modifier.cves:
                findings.append(
                    Finding(
                        rule_id=cve.id,
                        title=f"Known CVE in {cve.library} {cve.version}",
                        severity=cve.severity,
                        category=Category.SERIALIZATION,
                        description=cve.description,
                        layer="L0",
                    )
                )

        return findings
