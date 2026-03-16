"""Core data models."""

from __future__ import annotations

from enum import Enum
from pathlib import Path

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class Category(str, Enum):
    MEMORY = "memory"
    TOOL = "tool"


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: Severity
    category: Category
    description: str
    file: Path | None = None
    line: int | None = None
    fix: str | None = None


class ToolSpec(BaseModel):
    name: str
    description: str | None = None
    is_destructive: bool = False
    accepts_code_execution: bool = False
    has_approval_gate: bool = False
    has_user_scope_check: bool = False
    source_file: Path | None = None
    source_line: int | None = None


class MemoryConfig(BaseModel):
    backend: str  # "chroma", "pgvector", "pinecone", etc.
    has_tenant_isolation: bool = False
    has_metadata_filter_on_retrieval: bool = False
    has_metadata_on_write: bool = False
    sanitizes_retrieved_content: bool = False
    collection_name: str | None = None
    source_file: Path | None = None
    source_line: int | None = None


class AgentSpec(BaseModel):
    framework: str
    source_files: list[Path] = Field(default_factory=list)
    tools: list[ToolSpec] = Field(default_factory=list)
    memory_configs: list[MemoryConfig] = Field(default_factory=list)
    metadata: dict[str, object] = Field(default_factory=dict)


class ScanResult(BaseModel):
    target: Path
    framework: str | None
    findings: list[Finding] = Field(default_factory=list)
    scanned_files: int = 0
    errors: list[str] = Field(default_factory=list)

    @property
    def critical(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.CRITICAL]

    @property
    def high(self) -> list[Finding]:
        return [f for f in self.findings if f.severity == Severity.HIGH]

    @property
    def by_severity(self) -> dict[Severity, list[Finding]]:
        result: dict[Severity, list[Finding]] = {s: [] for s in Severity}
        for f in self.findings:
            result[f.severity].append(f)
        return result
