"""Analyzer registry — single source of truth for all analysis layers."""

from __future__ import annotations

from typing import TYPE_CHECKING

from agentwall.analyzers.agent_arch import AgentArchAnalyzer
from agentwall.analyzers.asm import ASMAnalyzer
from agentwall.analyzers.callgraph import CallGraphAnalyzer
from agentwall.analyzers.confidence import ConfidenceScorerAnalyzer
from agentwall.analyzers.config import ConfigAuditor
from agentwall.analyzers.mcp_security import MCPSecurityAnalyzer
from agentwall.analyzers.memory import MemoryAnalyzer
from agentwall.analyzers.rag import RAGAnalyzer
from agentwall.analyzers.runtime import RuntimeAnalyzer
from agentwall.analyzers.secrets import SecretsAnalyzer
from agentwall.analyzers.semgrep import SemgrepAnalyzer
from agentwall.analyzers.serialization import SerializationAnalyzer
from agentwall.analyzers.symbolic import SymbolicAnalyzer
from agentwall.analyzers.taint import TaintAnalyzer
from agentwall.analyzers.tools import ToolAnalyzer
from agentwall.analyzers.versions import VersionsAnalyzer

if TYPE_CHECKING:
    from agentwall.context import Analyzer

# Order doesn't matter — _resolve_order topologically sorts by depends_on.
# To add a new analyzer: create the class, add one entry here.
ANALYZERS: list[type[Analyzer]] = [
    VersionsAnalyzer,            # L0-versions, depends_on=(), framework_agnostic
    SecretsAnalyzer,             # L1-secrets, depends_on=("L0-versions",), framework_agnostic
    SerializationAnalyzer,       # L1-serialization, depends_on=("L0-versions",), framework_agnostic
    MCPSecurityAnalyzer,         # L1-mcp, depends_on=("L0-versions",), framework_agnostic
    RAGAnalyzer,                 # L1-rag, depends_on=("L0-versions",)
    MemoryAnalyzer,              # L1-memory, depends_on=()
    ToolAnalyzer,                # L1-tools,  depends_on=()
    AgentArchAnalyzer,           # L2-agent,  depends_on=("L0-versions",)
    CallGraphAnalyzer,           # L2,        depends_on=("L1-memory", "L1-tools")
    TaintAnalyzer,               # L3,        depends_on=("L2",)
    ConfigAuditor,               # L4,        depends_on=()
    SemgrepAnalyzer,             # L5,        depends_on=()
    SymbolicAnalyzer,            # L6,        depends_on=("L3",)
    ASMAnalyzer,                 # ASM,       depends_on=("L2",)
    RuntimeAnalyzer,             # L7,        depends_on=("L1-memory", "L1-tools"), opt_in
    ConfidenceScorerAnalyzer,    # L8,        depends_on=(), opt_in
]
