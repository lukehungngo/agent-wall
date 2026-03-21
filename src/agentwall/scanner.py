"""Scanner orchestrator — registry-driven analysis pipeline."""

from __future__ import annotations

import logging
import warnings
from collections import deque
from pathlib import Path
from typing import TYPE_CHECKING

from agentwall.adapters.langchain import LangChainAdapter
from agentwall.analyzers import ANALYZERS
from agentwall.context import AnalysisContext
from agentwall.detector import _source_files, auto_detect_framework
from agentwall.models import Finding, ScanConfig, ScanResult
from agentwall.postprocess import apply_file_context, dedup, sort

if TYPE_CHECKING:
    from agentwall.context import Analyzer

logger = logging.getLogger(__name__)


def _layer_group(name: str) -> str:
    """Map analyzer name to its layer group: 'L1-memory' → 'L1', 'ASM' → 'ASM'."""
    return name.split("-")[0]


def _resolve_order(
    analyzers: list[type[Analyzer]],
    enabled: set[str],
) -> list[type[Analyzer]]:
    """Topologically sort analyzers by depends_on, filtering by enabled layers.

    Auto-includes transitive dependencies: if L3 is enabled and depends on L2,
    L2 is included even if not explicitly in ``enabled``.
    """
    by_name: dict[str, type[Analyzer]] = {a.name: a for a in analyzers}

    # Expand enabled set to include transitive dependencies
    expanded: set[str] = set()

    def _expand(name: str) -> None:
        if name in expanded:
            return
        expanded.add(name)
        if name in by_name:
            for dep in by_name[name].depends_on:
                _expand(dep)

    for name, cls in by_name.items():
        group = _layer_group(name)
        if getattr(cls, "opt_in", False):
            # opt-in analyzers only run when explicitly enabled
            if name in enabled or group in enabled:
                _expand(name)
        elif group in enabled or name in enabled:
            _expand(name)

    # ASM runs whenever layers go beyond L0-L2 (matches pre-refactor behavior)
    if "ASM" in by_name and not enabled.issubset({"L0", "L1", "L2"}):
        _expand("ASM")

    # Filter to expanded set
    filtered = [a for a in analyzers if a.name in expanded]

    # Topological sort (Kahn's algorithm)
    in_degree: dict[str, int] = {a.name: 0 for a in filtered}
    for a in filtered:
        for dep in a.depends_on:
            if dep in in_degree:
                in_degree[a.name] += 1

    queue = deque(a for a in filtered if in_degree[a.name] == 0)
    result: list[type[Analyzer]] = []
    while queue:
        node = queue.popleft()
        result.append(node)
        for a in filtered:
            if node.name in a.depends_on and a.name in in_degree:
                in_degree[a.name] -= 1
                if in_degree[a.name] == 0:
                    queue.append(a)

    if len(result) != len(filtered):
        missing = {a.name for a in filtered} - {a.name for a in result}
        msg = f"Dependency cycle detected among analyzers: {sorted(missing)}"
        raise ValueError(msg)

    return result


def scan(
    target: Path,
    framework: str | None = None,
    config: ScanConfig | None = None,
) -> ScanResult:
    """Run a full scan on *target* and return a ScanResult.

    Analysis layers (all additive — higher layers refine, not replace):
        L0  Regex / Import Matching         (framework detection)
        L1  Single-File AST Visitor         (kwarg inspection)
        L2  Inter-Procedural Call Graph     (cross-file resolution)
        L3  Taint Analysis                  (source → sink flow)
        L4  Config Auditing                 (infra misconfiguration)
        L5  Semgrep Rules                   (declarative patterns)
        L6  Symbolic / Abstract Interp.     (path-sensitive)
        L7  Runtime Instrumentation         (dynamic, opt-in)
        L8  LLM-Assisted Confidence         (ambiguity resolver)
    """
    if config is None:
        config = ScanConfig.default()

    layers = set(config.layers)
    if config.dynamic:
        layers.add("L7")
    if config.llm_assist:
        layers.add("L8")

    # ── L0: Framework detection ──────────────────────────────────────────
    detected = framework or auto_detect_framework(target)
    scan_warnings: list[str] = []

    # ── Collect source files (always, regardless of framework) ───────────
    source_files = _source_files(target)

    # ── Parse adapter ────────────────────────────────────────────────────
    spec = None
    if detected == "langchain":
        lc_adapter = LangChainAdapter()
        spec = lc_adapter.parse(target)
    elif detected == "llamaindex":
        from agentwall.adapters.llamaindex import LlamaIndexAdapter

        li_adapter = LlamaIndexAdapter()
        spec = li_adapter.parse(target)
    elif detected == "crewai":
        from agentwall.adapters.crewai import CrewAIAdapter

        cr_adapter = CrewAIAdapter()
        spec = cr_adapter.parse(target)
    elif detected == "openai_agents":
        from agentwall.adapters.openai_agents import OpenAIAgentsAdapter

        oa_adapter = OpenAIAgentsAdapter()
        spec = oa_adapter.parse(target)
    elif detected == "autogen":
        from agentwall.adapters.autogen import AutoGenAdapter

        ag_adapter = AutoGenAdapter()
        spec = ag_adapter.parse(target)
    elif detected == "vectorstore_direct":
        from agentwall.adapters.vectorstore_direct import VectorStoreDirectAdapter

        vs_adapter = VectorStoreDirectAdapter()
        spec = vs_adapter.parse(target)
    else:
        scan_warnings.append(
            f"Unsupported or undetected framework: {detected!r}. "
            "Only framework-agnostic analyzers will run."
        )

    ctx = AnalysisContext(target=target, config=config, spec=spec, source_files=source_files)

    # ── Run analyzers in dependency order ─────────────────────────────────
    ordered = _resolve_order(ANALYZERS, layers)
    shadow = config.shadow_layers | ({"ASM"} if config.asm_shadow else set())

    for analyzer_cls in ordered:
        # Skip non-framework-agnostic analyzers when no adapter was run
        if ctx.spec is None and not getattr(analyzer_cls, "framework_agnostic", False):
            continue

        group = _layer_group(analyzer_cls.name)

        # Shadow mode: run but suppress output
        if analyzer_cls.name in shadow:
            try:
                shadow_findings = analyzer_cls().analyze(ctx)
                shadow_logger = logging.getLogger(f"agentwall.{analyzer_cls.name.lower()}")
                for f in shadow_findings:
                    shadow_logger.debug(
                        "%s shadow: %s %s at %s:%s",
                        analyzer_cls.name,
                        f.rule_id,
                        f.title,
                        f.file,
                        f.line,
                    )
            except Exception as exc:
                msg = f"{analyzer_cls.name} analysis failed: {exc}"
                warnings.warn(msg, stacklevel=2)
                ctx.errors.append(msg)
            continue

        try:
            findings = analyzer_cls().analyze(ctx)
            if analyzer_cls.replace:
                # Refinement layer — replaces rather than extends
                ctx.findings = findings
            else:
                _collect_findings(ctx, findings, group)
        except Exception as exc:
            msg = f"{analyzer_cls.name} analysis failed: {exc}"
            warnings.warn(msg, stacklevel=2)
            ctx.errors.append(msg)
            logger.warning(msg)

    # ── Finalize ─────────────────────────────────────────────────────────
    all_findings = dedup(ctx.findings)
    all_findings = apply_file_context(all_findings)
    all_findings = sort(all_findings)

    scanned = len(spec.source_files) if spec else len(source_files)

    return ScanResult(
        target=target,
        framework=detected,
        findings=all_findings,
        scanned_files=scanned,
        errors=ctx.errors,
        warnings=scan_warnings,
    )


def _collect_findings(
    ctx: AnalysisContext,
    findings: list[Finding],
    layer_group: str,
) -> None:
    """Add findings to context, tagging with layer if not already tagged."""
    for f in findings:
        if f.layer is None:
            ctx.findings.append(f.model_copy(update={"layer": layer_group}))
        else:
            ctx.findings.append(f)
