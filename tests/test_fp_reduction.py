"""Tests for AW-SER-003 false positive reduction — dict-lookup dynamic imports."""

from __future__ import annotations

from pathlib import Path

from agentwall.analyzers.serialization import SerializationAnalyzer


def _make_ctx(tmp_path: Path, code: str, filename: str = "module.py"):
    from agentwall.context import AnalysisContext
    from agentwall.models import ScanConfig

    p = tmp_path / filename
    p.write_text(code)
    return AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[p])


def _ser003_findings(tmp_path: Path, code: str) -> list[str]:
    ctx = _make_ctx(tmp_path, code)
    analyzer = SerializationAnalyzer()
    findings = analyzer.analyze(ctx)
    return [f.rule_id for f in findings if f.rule_id == "AW-SER-003"]


# ---------------------------------------------------------------------------
# Suppression tests — these patterns are safe lazy-loading idioms
# ---------------------------------------------------------------------------


def test_dict_lookup_import_is_suppressed(tmp_path: Path) -> None:
    """importlib.import_module(_IMPORTS[name]) must NOT fire AW-SER-003."""
    code = """\
import importlib

_IMPORTS = {"foo": ".bar", "baz": ".qux"}

def __getattr__(name):
    if name in _IMPORTS:
        return importlib.import_module(_IMPORTS[name], __name__)
    raise AttributeError(name)
"""
    assert _ser003_findings(tmp_path, code) == []


def test_fstring_with_literal_prefix_is_suppressed(tmp_path: Path) -> None:
    """importlib.import_module("." + _LIBS[name]) must NOT fire AW-SER-003."""
    # The suppression operates on direct call args only. The BinOp "." + _LIBS[name]
    # as the first argument is a constant-dict subscript on one side — safe to suppress.
    code = """\
import importlib

_LIBS = {"numpy": "np", "pandas": "pd"}

def __getattr__(name):
    return importlib.import_module("." + _LIBS[name], __name__)
"""
    assert _ser003_findings(tmp_path, code) == []


def test_all_caps_dict_lookup_is_suppressed(tmp_path: Path) -> None:
    """importlib.import_module(BACKEND_MAP[key]) must NOT fire AW-SER-003."""
    code = """\
import importlib

BACKEND_MAP = {"chroma": ".backends.chroma", "pgvector": ".backends.pgvector"}

def load_backend(key):
    return importlib.import_module(BACKEND_MAP[key], __name__)
"""
    assert _ser003_findings(tmp_path, code) == []


# ---------------------------------------------------------------------------
# Positive tests — these patterns MUST still fire
# ---------------------------------------------------------------------------


def test_bare_variable_import_still_fires(tmp_path: Path) -> None:
    """importlib.import_module(plugin_name) with no dict lookup → AW-SER-003."""
    code = """\
import importlib

def load_plugin(plugin_name):
    return importlib.import_module(plugin_name)
"""
    assert _ser003_findings(tmp_path, code) == ["AW-SER-003"]


def test_user_controlled_import_still_fires(tmp_path: Path) -> None:
    """importlib.import_module(request.module_name) → AW-SER-003."""
    code = """\
import importlib

def handle(request):
    return importlib.import_module(request.module_name)
"""
    assert _ser003_findings(tmp_path, code) == ["AW-SER-003"]


def test_fstring_import_still_fires(tmp_path: Path) -> None:
    """importlib.import_module(f"plugins.{name}") is a JoinedStr, not a dict subscript → fires."""
    code = """\
import importlib

def load(name):
    return importlib.import_module(f"plugins.{name}")
"""
    assert _ser003_findings(tmp_path, code) == ["AW-SER-003"]


def test_lowercase_dict_name_still_fires(tmp_path: Path) -> None:
    """importlib.import_module(plugins[name]) where 'plugins' is a plain lowercase name fires.

    We only suppress when the dict name starts with _ or is ALL_CAPS, because those
    naming conventions signal module-level constants. A generic lowercase name like
    'plugins' could be any local dict — including one populated from user input.
    """
    code = """\
import importlib

def load(plugins, name):
    return importlib.import_module(plugins[name])
"""
    assert _ser003_findings(tmp_path, code) == ["AW-SER-003"]


# ---------------------------------------------------------------------------
# AW-CFG-hardcoded-secret false positive reduction
# ---------------------------------------------------------------------------


def _make_env_file(tmp_path: Path, filename: str, content: str) -> Path:
    p = tmp_path / filename
    p.write_text(content)
    return p


def _cfg_secret_findings(tmp_path: Path, filename: str, content: str) -> list[str]:
    from agentwall.analyzers.config import ConfigAuditor
    from agentwall.context import AnalysisContext
    from agentwall.models import ScanConfig

    env_file = _make_env_file(tmp_path, filename, content)
    ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[env_file])
    auditor = ConfigAuditor()
    findings = auditor.analyze(ctx)
    return [f.rule_id for f in findings if f.rule_id == "AW-CFG-hardcoded-secret"]


class TestCFGHardcodedSecretFalsePositives:
    def test_env_test_file_suppressed(self, tmp_path: Path) -> None:
        """.env.test with fake-api-key value must NOT fire."""
        result = _cfg_secret_findings(tmp_path, ".env.test", "OPENAI_API_KEY=fake-api-key\n")
        assert result == []

    def test_env_template_file_suppressed(self, tmp_path: Path) -> None:
        """.env.template with your-key-here placeholder must NOT fire."""
        result = _cfg_secret_findings(tmp_path, ".env.template", "API_KEY=your-key-here\n")
        assert result == []

    def test_empty_value_suppressed(self, tmp_path: Path) -> None:
        """.env with empty value must NOT fire."""
        result = _cfg_secret_findings(tmp_path, ".env", "OPENAI_API_KEY=\n")
        assert result == []

    def test_fake_prefix_suppressed(self, tmp_path: Path) -> None:
        """.env with fake- prefix value must NOT fire."""
        result = _cfg_secret_findings(tmp_path, ".env", "API_KEY=fake-anthropic-key\n")
        assert result == []

    def test_non_secret_key_suppressed(self, tmp_path: Path) -> None:
        """.env with non-secret key suffix must NOT fire."""
        result = _cfg_secret_findings(tmp_path, ".env", "PASSWORD_LOGIN_LOCK_SECONDS=300\n")
        assert result == []

    def test_real_default_password_still_fires(self, tmp_path: Path) -> None:
        """.env with real-looking default password MUST fire."""
        result = _cfg_secret_findings(tmp_path, ".env", "ELASTIC_PASSWORD=infini_rag_flow\n")
        assert result == ["AW-CFG-hardcoded-secret"]


# ---------------------------------------------------------------------------
# AW-SEC-003 false positive reduction — content reference required
# ---------------------------------------------------------------------------


class TestSEC003FalsePositives:
    """Verify that metadata-only references to context vars do not fire AW-SEC-003."""

    def _sec003_count(self, tmp_path: Path, code: str) -> int:
        from agentwall.analyzers.secrets import SecretsAnalyzer
        from agentwall.context import AnalysisContext
        from agentwall.models import ScanConfig

        p = tmp_path / "module.py"
        p.write_text(code)
        ctx = AnalysisContext(target=tmp_path, config=ScanConfig.default(), source_files=[p])
        findings = SecretsAnalyzer().analyze(ctx)
        return sum(1 for f in findings if f.rule_id == "AW-SEC-003")

    def test_len_of_context_var_is_suppressed(self, tmp_path: Path) -> None:
        """len(messages) logs a count — not content. Must NOT fire."""
        code = "import logging\nlogger = logging.getLogger(__name__)\nlogger.debug(len(messages))\n"
        assert self._sec003_count(tmp_path, code) == 0

    def test_attribute_of_context_var_is_suppressed(self, tmp_path: Path) -> None:
        """context.function.name logs a metadata attribute — not content. Must NOT fire."""
        code = "import logging\nlogger = logging.getLogger(__name__)\nlogger.info(context.function.name)\n"
        assert self._sec003_count(tmp_path, code) == 0

    def test_token_count_is_suppressed(self, tmp_path: Path) -> None:
        """llm.get_token_count(messages) extracts metadata — must NOT fire."""
        code = "import logging\nlogger = logging.getLogger(__name__)\nlogger.info(llm.get_token_count(messages))\n"
        assert self._sec003_count(tmp_path, code) == 0

    def test_direct_context_var_still_fires(self, tmp_path: Path) -> None:
        """logger.debug(messages) logs content directly — must fire."""
        code = "import logging\nlogger = logging.getLogger(__name__)\nlogger.debug(messages)\n"
        assert self._sec003_count(tmp_path, code) == 1

    def test_fstring_with_context_var_still_fires(self, tmp_path: Path) -> None:
        """f-string interpolating the var directly logs content — must fire."""
        code = 'import logging\nlogger = logging.getLogger(__name__)\nlogger.debug(f"payload: {messages}")\n'
        assert self._sec003_count(tmp_path, code) == 1


# ---------------------------------------------------------------------------
# AW-MEM-001 false positive reduction — engine StoreProfile isolation
# ---------------------------------------------------------------------------


class TestMEM001FalsePositives:
    def test_no_engine_profiles_fires_normally(self, tmp_path: Path) -> None:
        """Without engine profiles, MEM-001 fires as CRITICAL."""
        from agentwall.analyzers.memory import MemoryAnalyzer
        from agentwall.models import MemoryConfig

        ctx = _make_ctx(tmp_path, "# empty", "agent.py")
        ctx.spec = type(
            "Spec",
            (),
            {
                "framework": "langchain",
                "memory_configs": [MemoryConfig(backend="chromadb")],
                "tools": [],
                "source_files": [],
                "metadata": {},
                "asm": None,
            },
        )()
        findings = MemoryAnalyzer().analyze(ctx)
        mem001 = [f for f in findings if f.rule_id == "AW-MEM-001"]
        assert any(f.severity.value == "critical" for f in mem001)

    def test_collection_per_tenant_downgrades(self, tmp_path: Path) -> None:
        """Engine says COLLECTION_PER_TENANT -> downgrade to MEDIUM."""
        from agentwall.analyzers.memory import MemoryAnalyzer
        from agentwall.engine.models import StoreProfile, ValueKind
        from agentwall.models import MemoryConfig

        ctx = _make_ctx(tmp_path, "# empty", "agent.py")
        ctx.spec = type(
            "Spec",
            (),
            {
                "framework": "langchain",
                "memory_configs": [MemoryConfig(backend="chromadb")],
                "tools": [],
                "source_files": [],
                "metadata": {},
                "asm": None,
            },
        )()
        ctx.store_profiles = [
            StoreProfile(
                store_id="t",
                backend="chromadb",
                collection_name_kind=ValueKind.TENANT_SCOPED,
            )
        ]
        findings = MemoryAnalyzer().analyze(ctx)
        mem001 = [f for f in findings if f.rule_id == "AW-MEM-001"]
        for f in mem001:
            assert f.severity.value != "critical", "Per-tenant should not be CRITICAL"

    def test_filter_on_read_suppresses(self, tmp_path: Path) -> None:
        """Engine says FILTER_ON_READ -> suppress MEM-001."""
        from agentwall.analyzers.memory import MemoryAnalyzer
        from agentwall.engine.models import PropertyExtraction, StoreProfile, ValueKind
        from agentwall.models import MemoryConfig

        ctx = _make_ctx(tmp_path, "# empty", "agent.py")
        ctx.spec = type(
            "Spec",
            (),
            {
                "framework": "langchain",
                "memory_configs": [MemoryConfig(backend="chromadb")],
                "tools": [],
                "source_files": [],
                "metadata": {},
                "asm": None,
            },
        )()
        profile = StoreProfile(store_id="t", backend="chromadb")
        profile.extractions.append(
            PropertyExtraction(
                file=tmp_path / "agent.py",
                line=1,
                store_id="t",
                operation="read",
                method="similarity_search",
                has_filter=True,
                filter_value_kind=ValueKind.COMPOUND_TENANT,
            )
        )
        ctx.store_profiles = [profile]
        findings = MemoryAnalyzer().analyze(ctx)
        mem001 = [f for f in findings if f.rule_id == "AW-MEM-001"]
        assert len(mem001) == 0, "FILTER_ON_READ should suppress MEM-001"


# ---------------------------------------------------------------------------
# AW-MEM-005 false positive reduction — retrieval path required
# ---------------------------------------------------------------------------


class TestMEM005FalsePositives:
    """AW-MEM-005: no sanitization on retrieved memory.

    FP: fires on store constructor/init lines without retrieval.
    """

    def test_store_with_retrieval_fires(self, tmp_path: Path):
        """Store with similarity_search should fire MEM-005."""
        code = '''
from langchain_community.vectorstores import Chroma
db = Chroma(collection_name="docs")
results = db.similarity_search("query")
'''
        p = tmp_path / "agent.py"
        p.write_text(code)
        from agentwall.adapters.langchain import LangChainAdapter
        spec = LangChainAdapter().parse(tmp_path)
        ctx = _make_ctx(tmp_path, code)
        ctx.spec = spec
        from agentwall.analyzers.memory import MemoryAnalyzer
        findings = MemoryAnalyzer().analyze(ctx)
        mem005 = [f for f in findings if f.rule_id == "AW-MEM-005"]
        assert len(mem005) >= 1, "Store WITH retrieval should fire MEM-005"

    def test_store_without_retrieval_suppressed(self, tmp_path: Path):
        """Store that only does add_texts (no read) should NOT fire MEM-005."""
        code = '''
from langchain_community.vectorstores import Chroma
db = Chroma(collection_name="docs")
db.add_texts(["hello world"])
'''
        p = tmp_path / "agent.py"
        p.write_text(code)
        from agentwall.adapters.langchain import LangChainAdapter
        spec = LangChainAdapter().parse(tmp_path)
        ctx = _make_ctx(tmp_path, code)
        ctx.spec = spec
        from agentwall.analyzers.memory import MemoryAnalyzer
        findings = MemoryAnalyzer().analyze(ctx)
        mem005 = [f for f in findings if f.rule_id == "AW-MEM-005"]
        assert len(mem005) == 0, "Write-only store should NOT fire MEM-005"
