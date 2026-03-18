"""Agent-optimized JSON reporter (FR-501)."""

from __future__ import annotations

import json
from collections import Counter, defaultdict
from pathlib import Path

from agentwall import __version__
from agentwall.models import Finding, ScanResult


def _false_positive_hint(finding: Finding) -> str:
    """Generate guidance on when this finding might be a false positive."""
    hints: dict[str, str] = {
        "AW-MEM-001": "If isolation is handled by a middleware layer not visible in this file, this may be a false positive.",
        "AW-MEM-002": "If the write and read paths use separate collections scoped per-tenant, this may be a false positive.",
        "AW-MEM-003": "If access control is enforced at the infrastructure level (e.g. separate database per tenant), this may be a false positive.",
        "AW-MEM-004": "If input sanitization happens in a shared utility or middleware before reaching this code, this may be a false positive.",
        "AW-MEM-005": "If retrieved content is sanitized before injection into the prompt by an upstream layer, this may be a false positive.",
        "AW-TOOL-001": "If approval is handled by an orchestration layer wrapping this agent, this may be a false positive.",
        "AW-TOOL-002": "If the execution environment is sandboxed (e.g. container, restricted subprocess), this may be a false positive.",
        "AW-TOOL-003": "If user-scope checks are enforced by a decorator or middleware not visible in this file, this may be a false positive.",
        "AW-TOOL-004": "If the tool description is set dynamically at runtime, this may be a false positive.",
        "AW-TOOL-005": "If the high tool count is intentional for a multi-purpose agent with proper guardrails, this may be a false positive.",
    }
    return hints.get(
        finding.rule_id,
        "Review the surrounding code and infrastructure to determine if this finding applies.",
    )


def _flatten_finding(
    finding: Finding,
    framework: str | None,
    related: list[dict[str, object]],
) -> dict[str, object]:
    """Flatten a Finding into an agent-consumable structure."""
    file_str = str(finding.file) if finding.file else None
    flat: dict[str, object] = {
        "rule_id": finding.rule_id,
        "severity": finding.severity.value,
        "confidence": finding.confidence.value,
        "category": finding.category.value,
        "title": finding.title,
        "description": finding.description,
        "file": file_str,
        "line": finding.line,
        "fix_suggestion": finding.fix,
        "remediation_hint": _remediation_hint(finding),
        "framework_detected": framework,
        "affected_component": _affected_component(finding),
        "attack_vector_id": _attack_vector_id(finding),
        "verification": f"agentwall verify --finding {finding.rule_id} {file_str or '.'}",
        "related_findings": related,
        "false_positive_hint": _false_positive_hint(finding),
    }
    if finding.layer:
        flat["detection_layer"] = finding.layer
    if finding.file_context:
        flat["file_context"] = finding.file_context
    return flat


def _remediation_hint(finding: Finding) -> str:
    """Generate a contextual remediation hint for agents."""
    hints: dict[str, str] = {
        "AW-MEM-001": "Add a metadata filter parameter (e.g. filter={'user_id': user_id}) to every similarity_search() and as_retriever() call.",
        "AW-MEM-002": "The write path has user metadata, but the read path does not filter by it. Add the same metadata key as a filter on retrieval.",
        "AW-MEM-003": "No access control detected. Consider per-user collections, namespace isolation, or metadata-based filtering.",
        "AW-MEM-004": "Validate and sanitize all content before storing to memory. Use allowlists for expected input formats.",
        "AW-MEM-005": "Add a sanitization step between memory retrieval and context injection. Strip or escape control characters.",
        "AW-TOOL-001": "Wrap this tool with HumanApprovalCallbackHandler or an equivalent approval gate.",
        "AW-TOOL-002": "Replace dynamic code execution with a restricted allowlist of operations.",
        "AW-TOOL-003": "Add a user-scope permission check at the start of the tool function.",
        "AW-TOOL-004": "Add a descriptive docstring or description= parameter to the tool definition.",
        "AW-TOOL-005": "Split tools across specialized sub-agents to reduce per-agent tool count.",
    }
    return hints.get(finding.rule_id, finding.fix or "Review and fix manually.")


def _affected_component(finding: Finding) -> str:
    """Determine the affected component type."""
    if finding.rule_id.startswith("AW-MEM"):
        return "memory_store"
    if finding.rule_id.startswith("AW-TOOL"):
        return "tool_registration"
    return "unknown"


def _attack_vector_id(finding: Finding) -> str | None:
    """Map rule IDs to attack vector catalog entries."""
    mapping: dict[str, str] = {
        "AW-MEM-001": "AW-ATK-MEM-001",
        "AW-MEM-002": "AW-ATK-MEM-002",
        "AW-MEM-003": "AW-ATK-MEM-003",
        "AW-MEM-004": "AW-ATK-MEM-004",
        "AW-MEM-005": "AW-ATK-INJ-001",
        "AW-TOOL-001": "AW-ATK-AGT-001",
        "AW-TOOL-002": "AW-ATK-AGT-001",
        "AW-TOOL-003": "AW-ATK-AGT-001",
    }
    return mapping.get(finding.rule_id)


def _build_related_map(findings: list[Finding]) -> dict[str, list[dict[str, object]]]:
    """Group findings by rule_id for related_findings references."""
    by_rule: dict[str, list[dict[str, object]]] = defaultdict(list)
    for f in findings:
        by_rule[f.rule_id].append(
            {
                "file": str(f.file) if f.file else None,
                "line": f.line,
            }
        )
    return dict(by_rule)


def build_agent_json(result: ScanResult) -> dict[str, object]:
    """Build the agent-optimized JSON structure."""
    related_map = _build_related_map(result.findings)

    flat_findings: list[dict[str, object]] = []
    for f in result.findings:
        # Related findings are the other findings with the same rule_id
        related = [
            r
            for r in related_map.get(f.rule_id, [])
            if r["file"] != (str(f.file) if f.file else None) or r["line"] != f.line
        ]
        flat_findings.append(_flatten_finding(f, result.framework, related))

    return {
        "schema_version": "1.0",
        "scanner": "agentwall",
        "scanner_version": __version__,
        "target": str(result.target),
        "framework": result.framework,
        "scanned_files": result.scanned_files,
        "total_findings": len(result.findings),
        "severity_counts": {
            sev.value: len(findings) for sev, findings in result.by_severity.items() if findings
        },
        "confidence_counts": {
            cl.value: count
            for cl, count in Counter(f.confidence for f in result.findings).items()
        },
        "findings": flat_findings,
        "errors": result.errors,
    }


class AgentJsonReporter:
    """AI agent-optimized JSON output (FR-501)."""

    def render(self, result: ScanResult, output: Path) -> None:
        data = build_agent_json(result)
        output.write_text(json.dumps(data, indent=2), encoding="utf-8")
