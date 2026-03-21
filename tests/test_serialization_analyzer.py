from pathlib import Path

from agentwall.analyzers.serialization import SerializationAnalyzer
from agentwall.context import AnalysisContext
from agentwall.models import ScanConfig

FIXTURES = Path(__file__).parent / "fixtures"


class TestSerializationAnalyzer:
    def test_name_and_flags(self) -> None:
        assert SerializationAnalyzer.name == "L1-serialization"
        assert SerializationAnalyzer.framework_agnostic is True

    def test_detects_pickle_load(self) -> None:
        fixture = FIXTURES / "serialization_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_001 = [f for f in findings if f.rule_id == "AW-SER-001"]
        assert len(ser_001) >= 1

    def test_detects_yaml_load_without_safe_loader(self) -> None:
        fixture = FIXTURES / "serialization_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_001 = [f for f in findings if f.rule_id == "AW-SER-001"]
        descs = [f.description for f in ser_001]
        assert any("yaml" in d.lower() for d in descs)

    def test_detects_dynamic_import(self) -> None:
        fixture = FIXTURES / "serialization_unsafe"
        ctx = AnalysisContext(
            target=fixture,
            config=ScanConfig(),
            source_files=list(fixture.glob("*.py")),
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser_003) >= 1

    def test_safe_yaml_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "safe.py").write_text(
            "import yaml\ndata = yaml.load(f, Loader=yaml.SafeLoader)\n"
        )
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "safe.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        assert all(f.rule_id != "AW-SER-001" for f in findings)

    def test_empty_file(self, tmp_path: Path) -> None:
        (tmp_path / "empty.py").write_text("")
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "empty.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        assert findings == []

    def test_syntax_error_skipped(self, tmp_path: Path) -> None:
        (tmp_path / "bad.py").write_text("def broken(:\n")
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "bad.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        assert findings == []

    def test_static_import_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "static.py").write_text(
            'import importlib\nmod = importlib.import_module("fixed_module")\n'
        )
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "static.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser_003) == 0


class TestSER003FPSuppressions:
    """Tests for SER-003 false-positive suppression heuristics (KR1.4)."""

    def test_fstring_with_constant_prefix_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "fstr.py").write_text(
            'import importlib\n'
            'name = "redis"\n'
            'mod = importlib.import_module(f"myapp.backends.{name}")\n'
        )
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "fstr.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser_003) == 0

    def test_config_attribute_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "cfg.py").write_text(
            'import importlib\n'
            'mod = importlib.import_module(settings.BACKEND_CLASS)\n'
        )
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "cfg.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser_003) == 0

    def test_try_except_guarded_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "guarded.py").write_text(
            'import importlib\n'
            'try:\n'
            '    mod = importlib.import_module(name)\n'
            'except ImportError:\n'
            '    pass\n'
        )
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "guarded.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser_003) == 0

    def test_constant_format_not_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "fmt.py").write_text(
            'import importlib\n'
            'mod = importlib.import_module("myapp.{}".format(name))\n'
        )
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "fmt.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser_003) == 0

    def test_unsafe_dynamic_import_still_flagged(self, tmp_path: Path) -> None:
        (tmp_path / "unsafe.py").write_text(
            'import importlib\n'
            'mod = importlib.import_module(user_input)\n'
        )
        ctx = AnalysisContext(
            target=tmp_path,
            config=ScanConfig(),
            source_files=[tmp_path / "unsafe.py"],
        )
        findings = SerializationAnalyzer().analyze(ctx)
        ser_003 = [f for f in findings if f.rule_id == "AW-SER-003"]
        assert len(ser_003) >= 1
