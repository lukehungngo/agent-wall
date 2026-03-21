"""Tests for AutoGenAdapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentwall.adapters.autogen import AutoGenAdapter

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def adapter() -> AutoGenAdapter:
    return AutoGenAdapter()


class TestAutoGenAdapterBasic:
    def test_returns_agent_spec(self, adapter: AutoGenAdapter) -> None:
        spec = adapter.parse(FIXTURES / "autogen_basic")
        assert spec.framework == "autogen"

    def test_source_files_populated(self, adapter: AutoGenAdapter) -> None:
        spec = adapter.parse(FIXTURES / "autogen_basic")
        assert len(spec.source_files) >= 1

    def test_detects_registered_tools(self, adapter: AutoGenAdapter) -> None:
        """register_for_execution/llm decorated functions create ToolSpecs."""
        spec = adapter.parse(FIXTURES / "autogen_basic")
        tool_names = [t.name for t in spec.tools]
        assert "run_shell" in tool_names
        assert "delete_file" in tool_names

    def test_destructive_tool_flagged(self, adapter: AutoGenAdapter) -> None:
        spec = adapter.parse(FIXTURES / "autogen_basic")
        tool = next(t for t in spec.tools if t.name == "delete_file")
        assert tool.is_destructive is True

    def test_code_exec_detected(self, adapter: AutoGenAdapter) -> None:
        """subprocess in run_shell is detected as code execution."""
        spec = adapter.parse(FIXTURES / "autogen_basic")
        tool = next(t for t in spec.tools if t.name == "run_shell")
        assert tool.accepts_code_execution is True

    def test_tool_descriptions(self, adapter: AutoGenAdapter) -> None:
        """Decorator description is preferred over docstring."""
        spec = adapter.parse(FIXTURES / "autogen_basic")
        tool = next(t for t in spec.tools if t.name == "run_shell")
        assert tool.description == "Run shell commands"

    def test_detects_agents(self, adapter: AutoGenAdapter) -> None:
        spec = adapter.parse(FIXTURES / "autogen_basic")
        assert spec.metadata.get("agent_count") == 2

    def test_detects_chats(self, adapter: AutoGenAdapter) -> None:
        spec = adapter.parse(FIXTURES / "autogen_basic")
        assert spec.metadata.get("chat_count") == 1


class TestAutoGenAdapterEdgeCases:
    def test_empty_directory(self, adapter: AutoGenAdapter, tmp_path: Path) -> None:
        spec = adapter.parse(tmp_path)
        assert spec.tools == []
        assert spec.memory_configs == []
        assert spec.framework == "autogen"

    def test_parse_error_skips_file(self, adapter: AutoGenAdapter, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text("def (\n", encoding="utf-8")
        spec = adapter.parse(tmp_path)
        assert len(spec.source_files) == 0

    def test_no_autogen_patterns(self, adapter: AutoGenAdapter, tmp_path: Path) -> None:
        (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
        spec = adapter.parse(tmp_path)
        assert spec.tools == []
        assert spec.memory_configs == []

    def test_register_function_call(self, adapter: AutoGenAdapter, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text(
            "from autogen import register_function\n"
            "register_function(name='calc', description='Calculator')\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert len(spec.tools) == 1
        assert spec.tools[0].name == "calc"
        assert spec.tools[0].description == "Calculator"

    def test_llm_config_functions(self, adapter: AutoGenAdapter, tmp_path: Path) -> None:
        (tmp_path / "agent.py").write_text(
            "from autogen import AssistantAgent\n"
            "a = AssistantAgent(\n"
            "    name='bot',\n"
            "    llm_config={'functions': [{'name': 'search', 'description': 'Search'}]},\n"
            ")\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        tool_names = [t.name for t in spec.tools]
        assert "search" in tool_names

    def test_tool_docstring_fallback(self, adapter: AutoGenAdapter, tmp_path: Path) -> None:
        """When no decorator description, docstring is used."""
        (tmp_path / "agent.py").write_text(
            "import autogen\n"
            "a = autogen.AssistantAgent(name='bot')\n"
            "@a.register_for_llm()\n"
            "def my_tool(x: str) -> str:\n"
            "    '''My docstring.'''\n"
            "    return x\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert spec.tools[0].description == "My docstring."
