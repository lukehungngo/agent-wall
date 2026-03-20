"""Tests for L1-rag analyzer."""

from pathlib import Path

from agentwall.adapters.langchain import LangChainAdapter
from agentwall.analyzers.rag import RAGAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"


def _make_ctx(fixture: Path) -> AnalysisContext:
    spec = LangChainAdapter().parse(fixture)
    return AnalysisContext(
        target=fixture,
        config=ScanConfig(),
        spec=spec,
        source_files=list(fixture.glob("*.py")),
    )


class TestRAGAnalyzerMeta:
    def test_name_and_flags(self) -> None:
        assert RAGAnalyzer.name == "L1-rag"
        assert RAGAnalyzer.framework_agnostic is False


class TestRAGAnalyzerUnsafe:
    def test_detects_unencrypted_persistence(self) -> None:
        ctx = _make_ctx(FIXTURES / "rag_unsafe")
        findings = RAGAnalyzer().analyze(ctx)
        rag_003 = [f for f in findings if f.rule_id == "AW-RAG-003"]
        assert len(rag_003) >= 1

    def test_detects_network_store_without_auth(self) -> None:
        ctx = _make_ctx(FIXTURES / "rag_unsafe")
        findings = RAGAnalyzer().analyze(ctx)
        rag_004 = [f for f in findings if f.rule_id == "AW-RAG-004"]
        assert len(rag_004) >= 1

    def test_detects_missing_delimiters(self) -> None:
        ctx = _make_ctx(FIXTURES / "rag_unsafe")
        findings = RAGAnalyzer().analyze(ctx)
        rag_001 = [f for f in findings if f.rule_id == "AW-RAG-001"]
        assert len(rag_001) >= 1

    def test_detects_untrusted_ingestion(self) -> None:
        ctx = _make_ctx(FIXTURES / "rag_unsafe")
        findings = RAGAnalyzer().analyze(ctx)
        rag_002 = [f for f in findings if f.rule_id == "AW-RAG-002"]
        assert len(rag_002) >= 1

    def test_findings_have_file_and_line(self) -> None:
        ctx = _make_ctx(FIXTURES / "rag_unsafe")
        findings = RAGAnalyzer().analyze(ctx)
        for f in findings:
            assert f.file is not None
            assert f.line is not None
            assert f.layer == "L1"


class TestRAGAnalyzerClean:
    def test_no_findings_in_clean_file(self, tmp_path: Path) -> None:
        (tmp_path / "app.py").write_text("x = 42\n")
        spec = LangChainAdapter().parse(tmp_path)
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            spec=spec,
            source_files=[tmp_path / "app.py"],
        )
        findings = RAGAnalyzer().analyze(ctx)
        assert findings == []

    def test_no_findings_on_empty_source_files(self, tmp_path: Path) -> None:
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            spec=None,
            source_files=[],
        )
        findings = RAGAnalyzer().analyze(ctx)
        assert findings == []

    def test_syntax_error_file_skipped(self, tmp_path: Path) -> None:
        bad = tmp_path / "bad.py"
        bad.write_text("def foo(:\n")
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            spec=None,
            source_files=[bad],
        )
        findings = RAGAnalyzer().analyze(ctx)
        assert findings == []
