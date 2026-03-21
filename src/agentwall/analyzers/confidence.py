"""L8 — LLM-Assisted Confidence Scoring.

Reduces false positives by using a tiered approach:
1. Regex heuristic — resolves most cases (no LLM needed)
2. Local model (Ollama) — for ambiguous cases
3. API (Claude Haiku) — last resort, opt-in only

Capital-aware: regex first, local model second, API last.
"""

from __future__ import annotations

import re
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING

from agentwall.models import ConfidenceLevel, Finding

if TYPE_CHECKING:
    from agentwall.context import AnalysisContext

# ── L8a: Regex heuristic ────────────────────────────────────────────────────

# Variable names that strongly suggest per-user scoping
_PER_USER_PATTERNS = re.compile(
    r"""(?x)
    (?:^|_)(?:
        user_?id | tenant_?id | org_?id | owner_?id |
        account_?id | customer_?id | team_?id |
        user_?name | user_?email | session_?id |
        auth_?user | current_?user | request_?user
    )(?:$|_)
    """,
    re.IGNORECASE,
)

# Variable names that strongly suggest shared/global scope
_SHARED_PATTERNS = re.compile(
    r"""(?x)
    (?:^|_)(?:
        global | shared | public | common | default |
        system | admin | all_?users | everyone |
        kb_?name | knowledge_?base | corpus |
        collection_?name | index_?name | namespace
    )(?:$|_)
    """,
    re.IGNORECASE,
)

# Collection name patterns that suggest per-user
_PER_USER_COLLECTION = re.compile(
    r"""(?x)
    (?:user | tenant | org | account | customer)
    [_-]?\d* | {.*?user.*?} | f["'].*?user.*?["']
    """,
    re.IGNORECASE,
)


@dataclass
class ConfidenceVerdict:
    """Result of confidence scoring for a single finding."""

    finding: Finding
    original_confidence: ConfidenceLevel
    scored_confidence: ConfidenceLevel
    reason: str
    method: str  # "regex", "local_llm", "api_llm"


def _regex_score_variable(name: str) -> tuple[ConfidenceLevel, str] | None:
    """Score a variable name using regex heuristics.

    Returns (confidence, reason) or None if ambiguous.
    """
    if _PER_USER_PATTERNS.search(name):
        return ConfidenceLevel.LOW, f"'{name}' appears to be a per-user identifier"
    if _SHARED_PATTERNS.search(name):
        return ConfidenceLevel.HIGH, f"'{name}' appears to be a shared/global identifier"
    return None


def _regex_score_collection(name: str | None) -> tuple[ConfidenceLevel, str] | None:
    """Score a collection name using regex heuristics."""
    if not name:
        return None
    if _PER_USER_COLLECTION.search(name):
        return ConfidenceLevel.LOW, f"Collection '{name}' appears to be per-user scoped"
    return None


def _extract_code_context(file_path: Path, line: int, window: int = 25) -> str:
    """Extract code context around a finding for LLM analysis."""
    try:
        lines = file_path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError):
        return ""

    start = max(0, line - window)
    end = min(len(lines), line + window)
    return "\n".join(lines[start:end])


# ── L8b: Local model (Ollama) ──────────────────────────────────────────────

_OLLAMA_PROMPT = """Given this Python code, determine if the variable or pattern is:
- PER_USER: scoped to a specific user/tenant (reduces finding severity)
- SHARED: accessible to all users (confirms finding severity)
- AMBIGUOUS: cannot determine from context

Code context:
```python
{code}
```

Variable/pattern in question: {variable}
Finding: {finding_description}

Answer exactly one of: PER_USER, SHARED, AMBIGUOUS
"""


_VALID_MODEL_RE = re.compile(r"^[a-zA-Z0-9._:/-]+$")


def _query_ollama(prompt: str, model: str = "codellama:7b") -> str | None:
    """Query local Ollama instance. Returns None if unavailable."""
    if not _VALID_MODEL_RE.match(model):
        return None
    try:
        import subprocess

        result = subprocess.run(
            ["ollama", "run", model, prompt],
            capture_output=True,
            text=True,
            timeout=30,
        )
        if result.returncode == 0:
            return result.stdout.strip()
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    return None


def _ollama_available() -> bool:
    """Check if Ollama is running."""
    try:
        import subprocess

        result = subprocess.run(
            ["ollama", "list"],
            capture_output=True,
            text=True,
            timeout=5,
        )
        return result.returncode == 0
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return False


# ── L8c: API (Claude Haiku) ────────────────────────────────────────────────

_API_PROMPT = """You are a security analyst reviewing a Python codebase for memory isolation issues.

Given this code context, determine if `{variable}` is a per-user identifier or a shared/global identifier.

Code:
```python
{code}
```

Consider: variable name, how it's set, class context, and comments.

Answer exactly one of:
- PER_USER: This variable scopes data to a specific user or tenant
- SHARED: This variable is used for shared/global data access
- AMBIGUOUS: Cannot determine from context alone

Answer:"""


def _query_api(prompt: str) -> str | None:
    """Query Claude API. Returns None if unavailable or not configured."""
    try:
        import anthropic  # type: ignore[import-not-found,import-untyped,unused-ignore]

        client = anthropic.Anthropic()
        message = client.messages.create(
            model="claude-haiku-4-5-20251001",
            max_tokens=50,
            messages=[{"role": "user", "content": prompt}],
        )
        text: str = message.content[0].text  # type: ignore[union-attr,unused-ignore]
        return text.strip()
    except Exception:
        return None


# ── Scorer ──────────────────────────────────────────────────────────────────


class ConfidenceScorer:
    """L8: Multi-tiered confidence scoring for findings."""

    def __init__(
        self,
        allow_local_llm: bool = True,
        allow_api: bool = False,
        ollama_model: str = "codellama:7b",
    ) -> None:
        self.allow_local_llm = allow_local_llm
        self.allow_api = allow_api
        self.ollama_model = ollama_model

    def score(
        self, findings: list[Finding], spec_metadata: dict[str, object] | None = None
    ) -> list[ConfidenceVerdict]:
        """Score confidence for a list of findings."""
        verdicts: list[ConfidenceVerdict] = []
        for finding in findings:
            verdict = self._score_single(finding)
            verdicts.append(verdict)
        return verdicts

    def _score_single(self, finding: Finding) -> ConfidenceVerdict:
        """Score a single finding using tiered approach."""
        # L8a: Regex heuristic
        regex_result = self._regex_resolve(finding)
        if regex_result:
            return regex_result

        # L8b: Local model
        if self.allow_local_llm:
            llm_result = self._local_resolve(finding)
            if llm_result:
                return llm_result

        # L8c: API (last resort)
        if self.allow_api:
            api_result = self._api_resolve(finding)
            if api_result:
                return api_result

        # Default: keep original confidence
        return ConfidenceVerdict(
            finding=finding,
            original_confidence=finding.confidence,
            scored_confidence=finding.confidence,
            reason="No additional confidence signal available",
            method="none",
        )

    def _regex_resolve(self, finding: Finding) -> ConfidenceVerdict | None:
        """L8a: Try to resolve confidence via regex heuristics."""
        # Check description for variable names
        desc = finding.description.lower()
        for word in desc.split():
            word = word.strip("'\"().,;:")
            result = _regex_score_variable(word)
            if result:
                confidence, reason = result
                return ConfidenceVerdict(
                    finding=finding,
                    original_confidence=finding.confidence,
                    scored_confidence=confidence,
                    reason=reason,
                    method="regex",
                )

        # Check if finding has a file/line — look at the code
        if finding.file and finding.line:
            context = _extract_code_context(finding.file, finding.line, window=5)
            per_user_signals: list[str] = []
            shared_signals: list[str] = []
            for line in context.splitlines():
                # Strip comments and string literals to avoid false matches
                code_line = re.sub(r"#.*$", "", line)
                code_line = re.sub(r"([\"'])(?:(?!\1).)*\1", "", code_line)
                for word in re.findall(r"\b\w+\b", code_line):
                    result = _regex_score_variable(word)
                    if result:
                        if result[0] == ConfidenceLevel.LOW:
                            per_user_signals.append(result[1])
                        else:
                            shared_signals.append(result[1])

            # Use majority signal — shared wins ties (conservative)
            if shared_signals and len(shared_signals) >= len(per_user_signals):
                return ConfidenceVerdict(
                    finding=finding,
                    original_confidence=finding.confidence,
                    scored_confidence=ConfidenceLevel.HIGH,
                    reason=shared_signals[0],
                    method="regex",
                )
            if per_user_signals and not shared_signals:
                return ConfidenceVerdict(
                    finding=finding,
                    original_confidence=finding.confidence,
                    scored_confidence=ConfidenceLevel.LOW,
                    reason=per_user_signals[0],
                    method="regex",
                )

        return None

    def _local_resolve(self, finding: Finding) -> ConfidenceVerdict | None:
        """L8b: Try to resolve via local LLM (Ollama)."""
        if not _ollama_available():
            return None

        if not finding.file or not finding.line:
            return None

        context = _extract_code_context(finding.file, finding.line)
        prompt = _OLLAMA_PROMPT.format(
            code=context,
            variable=finding.description,
            finding_description=finding.title,
        )

        response = _query_ollama(prompt, self.ollama_model)
        if not response:
            return None

        return self._parse_llm_response(finding, response, "local_llm")

    def _api_resolve(self, finding: Finding) -> ConfidenceVerdict | None:
        """L8c: Try to resolve via Claude API."""
        if not finding.file or not finding.line:
            return None

        context = _extract_code_context(finding.file, finding.line)
        prompt = _API_PROMPT.format(
            code=context,
            variable=finding.description,
        )

        response = _query_api(prompt)
        if not response:
            return None

        return self._parse_llm_response(finding, response, "api_llm")

    def _parse_llm_response(
        self, finding: Finding, response: str, method: str
    ) -> ConfidenceVerdict | None:
        """Parse LLM response and map to confidence level."""
        response_upper = response.upper().strip()

        if "PER_USER" in response_upper:
            return ConfidenceVerdict(
                finding=finding,
                original_confidence=finding.confidence,
                scored_confidence=ConfidenceLevel.LOW,
                reason=f"LLM ({method}): determined variable is per-user scoped",
                method=method,
            )
        elif "SHARED" in response_upper:
            return ConfidenceVerdict(
                finding=finding,
                original_confidence=finding.confidence,
                scored_confidence=ConfidenceLevel.HIGH,
                reason=f"LLM ({method}): confirmed variable is shared/global",
                method=method,
            )
        elif "AMBIGUOUS" in response_upper:
            return ConfidenceVerdict(
                finding=finding,
                original_confidence=finding.confidence,
                scored_confidence=ConfidenceLevel.MEDIUM,
                reason=f"LLM ({method}): unable to determine scope",
                method=method,
            )

        return None

    def apply_scores(self, findings: list[Finding]) -> list[Finding]:
        """Score findings and return updated list with adjusted confidence."""
        verdicts = self.score(findings)
        updated: list[Finding] = []
        for verdict in verdicts:
            if verdict.scored_confidence != verdict.original_confidence:
                updated.append(
                    verdict.finding.model_copy(update={"confidence": verdict.scored_confidence})
                )
            else:
                updated.append(verdict.finding)
        return updated


class ConfidenceScorerAnalyzer:
    """Thin registry wrapper around LLM-assisted confidence scoring (L8)."""

    name: str = "L8"
    depends_on: Sequence[str] = ()
    replace: bool = True  # transforms all existing findings
    opt_in: bool = True
    framework_agnostic: bool = True  # only reads ctx.findings, no ctx.spec needed

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        scorer = ConfidenceScorer(allow_local_llm=True, allow_api=False)
        return scorer.apply_scores(ctx.findings)
