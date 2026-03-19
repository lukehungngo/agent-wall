"""SARIF v2.1.0 reporter."""

from __future__ import annotations

import json
from pathlib import Path

from agentwall import __version__
from agentwall.models import Finding, ScanResult, Severity
from agentwall.reporters.agent_json import _attack_vector_id
from agentwall.rules import ALL_RULES

_SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json"
_SARIF_VERSION = "2.1.0"
_TOOL_NAME = "AgentWall"
_TOOL_VERSION = __version__
_TOOL_URI = "https://github.com/lukehungngo/agentwall"

_SEVERITY_TO_LEVEL: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def _build_reporting_descriptors() -> list[dict[str, object]]:
    """Build SARIF reportingDescriptor objects from the rule registry."""
    descriptors: list[dict[str, object]] = []
    for _rule_id, rule in sorted(ALL_RULES.items()):
        descriptor: dict[str, object] = {
            "id": rule.rule_id,
            "name": rule.title.replace(" ", ""),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.description},
            "helpUri": f"{_TOOL_URI}#rules",
            "defaultConfiguration": {
                "level": _SEVERITY_TO_LEVEL[rule.severity],
            },
            "properties": {
                "agentwall:category": rule.category.value,
                "agentwall:severity": rule.severity.value,
            },
        }
        descriptors.append(descriptor)
    return descriptors


def _build_result(finding: Finding) -> dict[str, object]:
    """Build a SARIF result object from a Finding."""
    result: dict[str, object] = {
        "ruleId": finding.rule_id,
        "level": _SEVERITY_TO_LEVEL[finding.severity],
        "message": {"text": finding.description},
    }

    if finding.file is not None:
        location: dict[str, object] = {
            "physicalLocation": {
                "artifactLocation": {
                    "uri": str(finding.file),
                    "uriBaseId": "%SRCROOT%",
                },
            },
        }
        if finding.line is not None:
            location["physicalLocation"]["region"] = {  # type: ignore[index]
                "startLine": finding.line,
            }
        result["locations"] = [location]

    file_str = str(finding.file) if finding.file else "."
    properties: dict[str, object] = {
        "agentwall:confidence": finding.confidence.value,
        "agentwall:category": finding.category.value,
        "agentwall:verification_command": f"agentwall verify --finding {finding.rule_id} {file_str}",
    }
    attack_vector = _attack_vector_id(finding)
    if attack_vector is not None:
        properties["agentwall:attack_vector"] = attack_vector
    if finding.fix:
        properties["agentwall:fix"] = finding.fix
    if finding.layer:
        properties["agentwall:layer"] = finding.layer
    if finding.file_context:
        properties["agentwall:file_context"] = finding.file_context
    if finding.evidence_path:
        properties["agentwall:evidence_path"] = finding.evidence_path
    if finding.proof_strength:
        properties["agentwall:proof_strength"] = finding.proof_strength

    result["properties"] = properties
    return result


def build_sarif(result: ScanResult) -> dict[str, object]:
    """Build the full SARIF v2.1.0 document from a ScanResult."""
    invocation: dict[str, object] = {
        "executionSuccessful": True,
        "commandLine": f"agentwall scan {result.target}",
    }
    if result.warnings:
        invocation["toolConfigurationNotifications"] = [
            {
                "message": {"text": w},
                "level": "note",
                "descriptor": {"id": "agentwall-warning"},
            }
            for w in result.warnings
        ]

    sarif: dict[str, object] = {
        "$schema": _SARIF_SCHEMA,
        "version": _SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": _TOOL_NAME,
                        "version": _TOOL_VERSION,
                        "informationUri": _TOOL_URI,
                        "rules": _build_reporting_descriptors(),
                    },
                },
                "results": [_build_result(f) for f in result.findings],
                "invocations": [invocation],
            },
        ],
    }
    return sarif


class SarifReporter:
    """SARIF v2.1.0 output for GitHub Security tab integration."""

    def render(self, result: ScanResult, output: Path) -> None:
        sarif = build_sarif(result)
        output.write_text(json.dumps(sarif, indent=2), encoding="utf-8")
