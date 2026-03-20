"""Verify that L2→L3→L6 share data through AnalysisContext."""

from pathlib import Path

from agentwall.analyzers.callgraph import CallGraphAnalyzer
from agentwall.analyzers.symbolic import SymbolicAnalyzer
from agentwall.analyzers.taint import TaintAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig


def _make_ctx(tmp_path: Path) -> AnalysisContext:
    py_file = tmp_path / "app.py"
    py_file.write_text("def foo(): pass\n")
    from agentwall.adapters.langchain import LangChainAdapter

    spec = LangChainAdapter().parse(tmp_path)
    return AnalysisContext(target=tmp_path, config=ScanConfig.default(), spec=spec)


class TestL2WritesCallGraph:
    def test_call_graph_populated_after_l2(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        CallGraphAnalyzer().analyze(ctx)
        assert ctx.call_graph is not None


class TestL3FallbackWithoutCallGraph:
    def test_l3_works_without_call_graph(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        assert ctx.call_graph is None
        findings = TaintAnalyzer().analyze(ctx)
        assert isinstance(findings, list)

    def test_l3_writes_taint_results(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        TaintAnalyzer().analyze(ctx)
        assert ctx.taint_results is not None


class TestL6FallbackWithoutTaint:
    def test_l6_works_without_taint_results(self, tmp_path: Path) -> None:
        ctx = _make_ctx(tmp_path)
        assert ctx.taint_results is None
        findings = SymbolicAnalyzer().analyze(ctx)
        assert isinstance(findings, list)
