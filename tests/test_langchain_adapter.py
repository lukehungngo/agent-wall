"""Tests for LangChainAdapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentwall.adapters.langchain import LangChainAdapter

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def adapter() -> LangChainAdapter:
    return LangChainAdapter()


class TestLangChainAdapterBasic:
    def test_returns_agent_spec(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_basic")
        assert spec.framework == "langchain"

    def test_detects_tool_decorator(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_basic")
        tool_names = [t.name for t in spec.tools]
        assert "search_web" in tool_names

    def test_detects_chroma_backend(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_basic")
        backends = [m.backend for m in spec.memory_configs]
        assert "chroma" in backends

    def test_basic_no_retrieval_filter(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_basic")
        chroma = next(m for m in spec.memory_configs if m.backend == "chroma")
        # as_retriever() with no filter
        assert not chroma.has_metadata_filter_on_retrieval

    def test_source_files_populated(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_basic")
        assert len(spec.source_files) >= 1


class TestLangChainAdapterUnsafe:
    def test_detects_tool_class(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_unsafe")
        tool_names = [t.name for t in spec.tools]
        assert "RunShell" in tool_names
        assert "DeleteFile" in tool_names

    def test_shell_tool_flagged_exec(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_unsafe")
        shell = next(t for t in spec.tools if t.name == "RunShell")
        assert shell.accepts_code_execution is True

    def test_delete_tool_flagged_destructive(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_unsafe")
        delete = next(t for t in spec.tools if t.name == "DeleteFile")
        assert delete.is_destructive is True

    def test_no_retrieval_filter(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_unsafe")
        chroma = next(m for m in spec.memory_configs if m.backend == "chroma")
        assert not chroma.has_metadata_filter_on_retrieval

    def test_no_write_metadata(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_unsafe")
        chroma = next(m for m in spec.memory_configs if m.backend == "chroma")
        assert not chroma.has_metadata_on_write


class TestLangChainAdapterSafe:
    def test_tool_has_user_scope_check(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_safe")
        tool = next(t for t in spec.tools if t.name == "get_user_data")
        assert tool.has_user_scope_check is True

    def test_has_retrieval_filter(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_safe")
        chroma = next(m for m in spec.memory_configs if m.backend == "chroma")
        assert chroma.has_metadata_filter_on_retrieval is True

    def test_tool_has_description(self, adapter: LangChainAdapter) -> None:
        spec = adapter.parse(FIXTURES / "langchain_safe")
        tool = next(t for t in spec.tools if t.name == "get_user_data")
        assert tool.description is not None


class TestLangChainAdapterEdgeCases:
    def test_parse_error_skips_file(self, adapter: LangChainAdapter, tmp_path: Path) -> None:
        bad = tmp_path / "bad.py"
        bad.write_text("def (\n", encoding="utf-8")
        spec = adapter.parse(tmp_path)
        assert spec.framework == "langchain"
        assert len(spec.source_files) == 0

    def test_empty_directory(self, adapter: LangChainAdapter, tmp_path: Path) -> None:
        spec = adapter.parse(tmp_path)
        assert spec.tools == []
        assert spec.memory_configs == []
