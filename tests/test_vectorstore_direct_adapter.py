"""Tests for VectorStoreDirectAdapter."""

from __future__ import annotations

from pathlib import Path

import pytest

from agentwall.adapters.vectorstore_direct import VectorStoreDirectAdapter

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture()
def adapter() -> VectorStoreDirectAdapter:
    return VectorStoreDirectAdapter()


class TestVectorStoreDirectBasic:
    def test_returns_agent_spec(self, adapter: VectorStoreDirectAdapter) -> None:
        spec = adapter.parse(FIXTURES / "vectorstore_direct_basic")
        assert spec.framework == "vectorstore_direct"

    def test_source_files_populated(self, adapter: VectorStoreDirectAdapter) -> None:
        spec = adapter.parse(FIXTURES / "vectorstore_direct_basic")
        assert len(spec.source_files) >= 1

    def test_detects_chromadb_persistent_client(
        self, adapter: VectorStoreDirectAdapter
    ) -> None:
        spec = adapter.parse(FIXTURES / "vectorstore_direct_basic")
        backends = [m.backend for m in spec.memory_configs]
        assert "chromadb" in backends

    def test_no_tools_in_basic_fixture(
        self, adapter: VectorStoreDirectAdapter
    ) -> None:
        """No eval/exec/subprocess in fixture -> no ToolSpecs."""
        spec = adapter.parse(FIXTURES / "vectorstore_direct_basic")
        assert spec.tools == []


class TestVectorStoreDirectConstructors:
    def test_faiss_index(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            "import faiss\n" "index = faiss.IndexFlatL2(128)\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert len(spec.memory_configs) == 1
        assert spec.memory_configs[0].backend == "faiss"

    def test_qdrant_client(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            "from qdrant_client import QdrantClient\n"
            "client = QdrantClient(url='http://localhost:6333')\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert len(spec.memory_configs) == 1
        assert spec.memory_configs[0].backend == "qdrant"

    def test_milvus_client(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            "from pymilvus import MilvusClient\n"
            "client = MilvusClient(uri='http://localhost:19530')\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert len(spec.memory_configs) == 1
        assert spec.memory_configs[0].backend == "milvus"

    def test_weaviate_connect_to_local(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            "import weaviate\n" "client = weaviate.connect_to_local()\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert len(spec.memory_configs) == 1
        assert spec.memory_configs[0].backend == "weaviate"

    def test_pinecone_constructor(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            "from pinecone import Pinecone\n"
            "pc = Pinecone(api_key='xxx')\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert len(spec.memory_configs) == 1
        assert spec.memory_configs[0].backend == "pinecone"


class TestVectorStoreDirectEdgeCases:
    def test_empty_directory(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        spec = adapter.parse(tmp_path)
        assert spec.tools == []
        assert spec.memory_configs == []
        assert spec.framework == "vectorstore_direct"

    def test_parse_error_skips_file(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        (tmp_path / "bad.py").write_text("def (\n", encoding="utf-8")
        spec = adapter.parse(tmp_path)
        assert len(spec.source_files) == 0

    def test_code_exec_function_detected(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            "def run_code(code: str) -> str:\n"
            "    return eval(code)\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert len(spec.tools) == 1
        assert spec.tools[0].name == "run_code"
        assert spec.tools[0].accepts_code_execution is True

    def test_destructive_exec_function(
        self, adapter: VectorStoreDirectAdapter, tmp_path: Path
    ) -> None:
        (tmp_path / "app.py").write_text(
            "import subprocess\n"
            "def delete_all(path: str) -> None:\n"
            "    subprocess.run(['rm', '-rf', path])\n",
            encoding="utf-8",
        )
        spec = adapter.parse(tmp_path)
        assert len(spec.tools) == 1
        assert spec.tools[0].is_destructive is True
        assert spec.tools[0].accepts_code_execution is True
