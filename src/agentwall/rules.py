"""All AW-MEM-* and AW-TOOL-* rule definitions."""

from dataclasses import dataclass

from agentwall.models import Category, Severity


@dataclass(frozen=True)
class RuleDef:
    rule_id: str
    title: str
    severity: Severity
    category: Category
    description: str
    fix: str


# ── Memory rules ─────────────────────────────────────────────────────────────

AW_MEM_001 = RuleDef(
    rule_id="AW-MEM-001",
    title="No tenant isolation in vector store",
    severity=Severity.CRITICAL,
    category=Category.MEMORY,
    description=(
        "Vector store queries are executed without any user/tenant filter. "
        "A similarity search returns the globally closest vectors — including other users' data."
    ),
    fix="Add a metadata filter on every retrieval call: similarity_search(query, filter={'user_id': user_id})",
)

AW_MEM_002 = RuleDef(
    rule_id="AW-MEM-002",
    title="Shared collection without metadata filter on retrieval",
    severity=Severity.HIGH,
    category=Category.MEMORY,
    description=(
        "Documents are written with user-scoped metadata (e.g. user_id) but retrieved "
        "without a matching filter. The write-time metadata provides false security."
    ),
    fix="Ensure every retrieval call includes the same metadata filter used at write time.",
)

AW_MEM_003 = RuleDef(
    rule_id="AW-MEM-003",
    title="Memory backend has no access control configuration",
    severity=Severity.HIGH,
    category=Category.MEMORY,
    description=(
        "The configured memory backend has no observable access control setup. "
        "Without explicit isolation, all agents share the same memory namespace."
    ),
    fix="Configure per-user collections or namespaces, or add metadata-based filtering.",
)

AW_MEM_004 = RuleDef(
    rule_id="AW-MEM-004",
    title="Known injection patterns in memory retrieval path",
    severity=Severity.HIGH,
    category=Category.MEMORY,
    description=(
        "The memory retrieval path uses unsanitized external input. "
        "This is a vector for memory poisoning attacks (MINJA, MemoryGraft patterns)."
    ),
    fix="Sanitize all content before storing it to memory. Validate retrieved content before injecting into context.",
)

AW_MEM_005 = RuleDef(
    rule_id="AW-MEM-005",
    title="No sanitization on retrieved memory before context injection",
    severity=Severity.MEDIUM,
    category=Category.MEMORY,
    description=(
        "Retrieved memory content is injected directly into the agent context without sanitization. "
        "Poisoned memories can influence agent behavior across sessions."
    ),
    fix="Pass retrieved memories through a sanitization step before adding to context.",
)

# ── Tool rules ────────────────────────────────────────────────────────────────

AW_TOOL_001 = RuleDef(
    rule_id="AW-TOOL-001",
    title="Destructive tool accessible without approval gate",
    severity=Severity.HIGH,
    category=Category.TOOL,
    description=(
        "A tool classified as destructive (deletes data, modifies files, sends messages) "
        "is registered without a human-in-the-loop approval gate."
    ),
    fix="Wrap destructive tools with an approval gate (e.g. HumanApprovalCallbackHandler).",
)

AW_TOOL_002 = RuleDef(
    rule_id="AW-TOOL-002",
    title="Tool accepts arbitrary code/SQL/shell execution",
    severity=Severity.MEDIUM,
    category=Category.TOOL,
    description=(
        "A tool can execute arbitrary code, SQL queries, or shell commands. "
        "Without input validation this enables prompt-injection-to-RCE escalation."
    ),
    fix="Restrict tool inputs with an allowlist schema. Avoid eval/exec patterns.",
)

AW_TOOL_003 = RuleDef(
    rule_id="AW-TOOL-003",
    title="High-risk tool lacks user-scope access check",
    severity=Severity.MEDIUM,
    category=Category.TOOL,
    description=(
        "A high-risk tool (file access, database query, API call) does not verify "
        "that the requesting user has permission to perform the requested action."
    ),
    fix="Add a user-scope check at the start of the tool function.",
)

AW_TOOL_004 = RuleDef(
    rule_id="AW-TOOL-004",
    title="Tool has no description",
    severity=Severity.LOW,
    category=Category.TOOL,
    description=(
        "A registered tool has no description. This blocks risk classification and "
        "degrades the LLM's ability to select tools correctly."
    ),
    fix="Add a docstring or description= argument to every tool.",
)

AW_TOOL_005 = RuleDef(
    rule_id="AW-TOOL-005",
    title="Agent has >15 tools (exceeds recommended limit)",
    severity=Severity.INFO,
    category=Category.TOOL,
    description=(
        "The agent has more than 15 registered tools. Large tool sets increase "
        "token usage and reduce tool-selection accuracy."
    ),
    fix="Split the agent into specialized sub-agents with focused tool sets.",
)

# ── Registry ──────────────────────────────────────────────────────────────────

ALL_RULES: dict[str, RuleDef] = {
    r.rule_id: r
    for r in [
        AW_MEM_001, AW_MEM_002, AW_MEM_003, AW_MEM_004, AW_MEM_005,
        AW_TOOL_001, AW_TOOL_002, AW_TOOL_003, AW_TOOL_004, AW_TOOL_005,
    ]
}
