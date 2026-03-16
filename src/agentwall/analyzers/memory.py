"""Memory security analyzer — AW-MEM-001/002/003."""

from __future__ import annotations

from agentwall.models import AgentSpec, Finding, MemoryConfig
from agentwall.rules import AW_MEM_001, AW_MEM_002, AW_MEM_003, RuleDef


def _finding_from_rule(rule: RuleDef, mc: MemoryConfig) -> Finding:
    return Finding(
        rule_id=rule.rule_id,
        title=rule.title,
        severity=rule.severity,
        category=rule.category,
        description=rule.description,
        fix=rule.fix,
        file=mc.source_file,
        line=mc.source_line,
    )


class MemoryAnalyzer:
    """Fire memory-related rules against an AgentSpec."""

    def analyze(self, spec: AgentSpec) -> list[Finding]:
        findings: list[Finding] = []
        for mc in spec.memory_configs:
            findings.extend(self._check(mc))
        return findings

    def _check(self, mc: MemoryConfig) -> list[Finding]:
        findings: list[Finding] = []

        no_isolation = not mc.has_tenant_isolation
        no_filter = not mc.has_metadata_filter_on_retrieval
        no_write_meta = not mc.has_metadata_on_write

        # AW-MEM-001: no isolation AND no retrieval filter
        if no_isolation and no_filter:
            findings.append(_finding_from_rule(AW_MEM_001, mc))

        # AW-MEM-002: has write metadata BUT no retrieval filter (false sense of security)
        if mc.has_metadata_on_write and no_filter:
            findings.append(_finding_from_rule(AW_MEM_002, mc))

        # AW-MEM-003: no access control at all
        if no_isolation and no_write_meta and no_filter:
            findings.append(_finding_from_rule(AW_MEM_003, mc))

        return findings
