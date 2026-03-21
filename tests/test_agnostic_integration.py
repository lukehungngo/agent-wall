"""Integration test: scanner runs RAG+AGT+MEM+TOOL on projects without framework adapter."""

from __future__ import annotations

from pathlib import Path

from agentwall.scanner import scan


def test_agnostic_scan_produces_mem_findings(tmp_path: Path) -> None:
    """Full scan on a project with vectorstore patterns but no framework."""
    (tmp_path / "app.py").write_text(
        'import chromadb\n'
        'client = chromadb.Client()\n'
        'col = client.create_collection("docs")\n'
        'results = col.query(query_texts=["test"])\n'
    )
    result = scan(tmp_path)
    assert len(result.findings) > 0, "Agnostic scan should produce findings"
    rule_ids = {f.rule_id for f in result.findings}
    has_mem = any(r.startswith("AW-MEM") for r in rule_ids)
    assert has_mem, f"Expected MEM findings, got: {rule_ids}"


def test_agnostic_scan_produces_tool_findings(tmp_path: Path) -> None:
    """Full scan on a project with tool patterns but no framework."""
    (tmp_path / "app.py").write_text(
        'def run_code(code):\n'
        '    """Execute arbitrary code."""\n'
        '    return eval(code)\n'
    )
    result = scan(tmp_path)
    assert len(result.findings) > 0, "Agnostic scan should produce TOOL findings"
    rule_ids = {f.rule_id for f in result.findings}
    has_tool = any(r.startswith("AW-TOOL") for r in rule_ids)
    assert has_tool, f"Expected TOOL findings, got: {rule_ids}"


def test_agnostic_scan_no_false_positives_on_clean(tmp_path: Path) -> None:
    """Clean project with no vectorstore/tool patterns gets no MEM/TOOL findings."""
    (tmp_path / "app.py").write_text(
        'def hello():\n'
        '    return "world"\n'
    )
    result = scan(tmp_path)
    rule_ids = {f.rule_id for f in result.findings}
    mem_tool = {r for r in rule_ids if r.startswith("AW-MEM") or r.startswith("AW-TOOL")}
    assert len(mem_tool) == 0, f"Clean project should not get MEM/TOOL findings, got: {mem_tool}"
