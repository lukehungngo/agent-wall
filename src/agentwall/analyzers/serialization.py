"""L1-serialization analyzer — detect unsafe deserialization and dynamic imports."""

from __future__ import annotations

import ast
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import Finding
from agentwall.patterns import DYNAMIC_IMPORT_CALLS, SAFE_YAML_LOADERS, UNSAFE_DESER_CALLS
from agentwall.rules import AW_SER_001, AW_SER_003


class SerializationAnalyzer:
    """Detect unsafe deserialization and dynamic plugin loading."""

    name: str = "L1-serialization"
    depends_on: Sequence[str] = ("L0-versions",)
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = True

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        findings: list[Finding] = []
        for source_file in ctx.source_files:
            try:
                tree = ast.parse(source_file.read_text())
            except (SyntaxError, UnicodeDecodeError):
                continue
            findings.extend(self._check_file(ctx, tree, source_file))
        return findings

    def _check_file(self, ctx: AnalysisContext, tree: ast.Module, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue

            call_name = self._get_qualified_name(node)
            if not call_name:
                continue

            # Check unsafe deserialization
            if call_name in UNSAFE_DESER_CALLS:
                # Special case: yaml.load with safe Loader is OK
                if call_name == "yaml.load" and self._has_safe_yaml_loader(node):
                    continue
                if not ctx.should_suppress(AW_SER_001.rule_id):
                    sev = ctx.severity_override(AW_SER_001.rule_id) or AW_SER_001.severity
                    findings.append(
                        Finding(
                            rule_id=AW_SER_001.rule_id,
                            title=AW_SER_001.title,
                            severity=sev,
                            category=AW_SER_001.category,
                            description=f"Call to {call_name}() detected. {AW_SER_001.description}",
                            file=path,
                            line=getattr(node, "lineno", None),
                            fix=AW_SER_001.fix,
                            layer="L1",
                        )
                    )

            # Check dynamic imports with variable argument
            if (
                call_name in DYNAMIC_IMPORT_CALLS
                and node.args
                and not isinstance(node.args[0], ast.Constant)
                and not ctx.should_suppress(AW_SER_003.rule_id)
            ):
                sev = ctx.severity_override(AW_SER_003.rule_id) or AW_SER_003.severity
                findings.append(
                    Finding(
                        rule_id=AW_SER_003.rule_id,
                        title=AW_SER_003.title,
                        severity=sev,
                        category=AW_SER_003.category,
                        description=(
                            f"Dynamic {call_name}() with variable argument. "
                            f"{AW_SER_003.description}"
                        ),
                        file=path,
                        line=getattr(node, "lineno", None),
                        fix=AW_SER_003.fix,
                        layer="L1",
                    )
                )
        return findings

    @staticmethod
    def _get_qualified_name(node: ast.Call) -> str | None:
        """Get 'module.func' name from a Call node."""
        if isinstance(node.func, ast.Attribute) and isinstance(node.func.value, ast.Name):
            return f"{node.func.value.id}.{node.func.attr}"
        if isinstance(node.func, ast.Name):
            return node.func.id
        return None

    @staticmethod
    def _has_safe_yaml_loader(node: ast.Call) -> bool:
        """Check if a yaml.load() call uses a safe Loader kwarg."""
        for kw in node.keywords:
            if kw.arg == "Loader":
                if isinstance(kw.value, ast.Attribute) and isinstance(kw.value.value, ast.Name):
                    loader_name = f"{kw.value.value.id}.{kw.value.attr}"
                    return loader_name in SAFE_YAML_LOADERS
                if isinstance(kw.value, ast.Name):
                    return kw.value.id in SAFE_YAML_LOADERS
        return False
