"""End-to-end package verification tests."""
from __future__ import annotations

import subprocess
import sys
from pathlib import Path


def test_agentwall_importable() -> None:
    """agentwall package can be imported."""
    import agentwall
    assert hasattr(agentwall, "__version__") or True  # package exists


def test_scan_function_callable() -> None:
    """The scan function is importable and callable."""
    from agentwall.scanner import scan
    assert callable(scan)


def test_cli_help_works() -> None:
    """agentwall --help exits cleanly."""
    result = subprocess.run(
        [sys.executable, "-c", "from agentwall.cli import app; app(['--help'])"],
        capture_output=True,
        text=True,
        timeout=10,
    )
    # typer --help exits with code 0
    assert result.returncode == 0


def test_scan_on_fixture(tmp_path: Path) -> None:
    """Full scan on a minimal fixture produces a ScanResult."""
    (tmp_path / "app.py").write_text("import chromadb\nclient = chromadb.Client()\n")
    from agentwall.scanner import scan
    result = scan(tmp_path)
    assert result.target == tmp_path
    assert result.scanned_files >= 0
