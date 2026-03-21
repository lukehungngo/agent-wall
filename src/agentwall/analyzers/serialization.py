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
        safe_vars = self._collect_safe_import_vars(tree)
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
                and not self._is_dict_lookup_import(node)
                and not self._is_safe_var_import(node, safe_vars)
                and not self._is_fstring_with_constant_prefix(node)
                and not self._is_config_attribute_import(node)
                and not self._is_try_except_guarded(node, tree)
                and not self._is_constant_format_call(node)
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

    @staticmethod
    def _is_constant_dict_name(name: str) -> bool:
        """Return True when the name looks like a module-level constant dict.

        Conventions: leading underscore (_IMPORTS, _LIBS) or ALL_CAPS (BACKEND_MAP).
        Plain lowercase names (plugins, registry) could be local dicts populated
        from user input, so they are NOT considered safe.
        """
        return name.startswith("_") or name == name.upper()

    @staticmethod
    def _is_constant_dict_subscript(node: ast.expr) -> bool:
        """Return True when node is a subscript on a module-level constant dict name."""
        return (
            isinstance(node, ast.Subscript)
            and isinstance(node.value, ast.Name)
            and SerializationAnalyzer._is_constant_dict_name(node.value.id)
        )

    @staticmethod
    def _collect_safe_import_vars(tree: ast.Module) -> set[str]:
        """Collect variable names assigned from dict-lookup on module-level constants.

        Tracks: ``x = _DICT[name]`` and ``x = "." + _DICT[name]``.
        These are safe for use in ``importlib.import_module(x)``.
        """
        safe: set[str] = set()
        for node in ast.walk(tree):
            if not isinstance(node, ast.Assign):
                continue
            if SerializationAnalyzer._is_safe_import_source(node.value):
                for target in node.targets:
                    if isinstance(target, ast.Name):
                        safe.add(target.id)
        return safe

    @staticmethod
    def _is_safe_import_source(node: ast.expr) -> bool:
        """Check if an expression is a known-safe import source.

        Safe patterns:
        - ``_DICT[name]`` (subscript on constant dict)
        - ``"." + _DICT[name]`` (BinOp with constant dict subscript)
        """
        if SerializationAnalyzer._is_constant_dict_subscript(node):
            return True
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return SerializationAnalyzer._is_safe_import_source(
                node.left
            ) or SerializationAnalyzer._is_safe_import_source(node.right)
        return False

    @staticmethod
    def _is_safe_var_import(node: ast.Call, safe_vars: set[str]) -> bool:
        """Return True when the first arg is a Name that was assigned from a safe source."""
        if not node.args:
            return False
        arg = node.args[0]
        return isinstance(arg, ast.Name) and arg.id in safe_vars

    @staticmethod
    def _is_fstring_with_constant_prefix(node: ast.Call) -> bool:
        """Suppress when import arg is f"myapp.backends.{name}" with multi-segment dotted prefix.

        Requires at least 2 dots in the prefix (e.g. ``myapp.backends.``) to ensure
        the constant portion constrains to a real package hierarchy.  A single-segment
        prefix like ``plugins.`` is too broad to be considered safe.
        """
        if not node.args:
            return False
        arg = node.args[0]
        if not isinstance(arg, ast.JoinedStr) or not arg.values:
            return False
        first = arg.values[0]
        return (
            isinstance(first, ast.Constant)
            and isinstance(first.value, str)
            and first.value.count(".") >= 2
        )

    @staticmethod
    def _is_config_attribute_import(node: ast.Call) -> bool:
        """Suppress when arg is a config-style attribute like settings.BACKEND_CLASS.

        Only suppresses when the attribute name is ALL_CAPS (constant convention).
        Attributes like ``request.module_name`` are NOT considered safe.
        """
        if not node.args:
            return False
        arg = node.args[0]
        return (
            isinstance(arg, ast.Attribute)
            and isinstance(arg.attr, str)
            and arg.attr == arg.attr.upper()
            and arg.attr.replace("_", "").isalpha()
        )

    @staticmethod
    def _is_try_except_guarded(node: ast.Call, tree: ast.Module) -> bool:
        """Suppress when the import call is inside a try/except ImportError block."""
        for parent in ast.walk(tree):
            if not isinstance(parent, ast.Try):
                continue
            for handler in parent.handlers:
                if handler.type is None:
                    continue
                handler_name: str | None = None
                if isinstance(handler.type, ast.Name):
                    handler_name = handler.type.id
                elif isinstance(handler.type, ast.Tuple):
                    handler_name = ",".join(
                        getattr(e, "id", "") for e in handler.type.elts
                    )
                if handler_name and "ImportError" in handler_name:
                    for child in ast.walk(parent):
                        if child is node:
                            return True
        return False

    @staticmethod
    def _is_constant_format_call(node: ast.Call) -> bool:
        """Suppress when arg is "module.{}".format(name) — constant constrains namespace."""
        if not node.args:
            return False
        arg = node.args[0]
        return (
            isinstance(arg, ast.Call)
            and isinstance(arg.func, ast.Attribute)
            and arg.func.attr == "format"
            and isinstance(arg.func.value, ast.Constant)
            and isinstance(arg.func.value.value, str)
            and "." in arg.func.value.value
        )

    @staticmethod
    def _is_dict_lookup_import(node: ast.Call) -> bool:
        """Return True when the first arg to import_module is a safe dict-lookup pattern.

        Suppressed patterns:
        - ``importlib.import_module(_IMPORTS[name])``  — direct subscript
        - ``importlib.import_module("." + _LIBS[name])``  — BinOp with one constant-dict side
        """
        if not node.args:
            return False

        arg = node.args[0]

        if SerializationAnalyzer._is_constant_dict_subscript(arg):
            return True

        if isinstance(arg, ast.BinOp) and isinstance(arg.op, ast.Add):
            return SerializationAnalyzer._is_constant_dict_subscript(
                arg.left
            ) or SerializationAnalyzer._is_constant_dict_subscript(arg.right)

        return False
