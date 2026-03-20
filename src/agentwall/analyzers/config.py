"""L4 Configuration Auditor — scans config files for insecure vector store settings."""

from __future__ import annotations

import json
import re
from collections.abc import Sequence
from pathlib import Path

from agentwall.context import AnalysisContext
from agentwall.models import Category, Finding, Severity

# Directories to skip during config file search
_SKIP_DIRS = frozenset(
    [
        ".git",
        ".venv",
        "venv",
        ".tox",
        "__pycache__",
        "node_modules",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        "dist",
        "build",
        ".eggs",
        "site-packages",
        "semgrep_rules",
    ]
)

# Config file patterns to scan
_CONFIG_GLOBS = [
    "docker-compose.yml",
    "docker-compose.yaml",
    ".env",
    ".env.*",
]

# Patterns that indicate insecure configuration
_UNSAFE_PATTERNS: list[tuple[str, re.Pattern[str], str, str, Severity]] = [
    (
        "allow-reset",
        re.compile(r"""allow_reset\s*[=:]\s*(?:True|true|1|"true"|'true')"""),
        "allow_reset=True permits full collection deletion",
        "Set allow_reset=False in production. Use explicit migration scripts for collection management.",
        Severity.HIGH,
    ),
    (
        "no-auth",
        re.compile(
            r'(?:CHROMA_SERVER_AUTH|chroma_client_auth_provider)\s*[=:]\s*(?:None|null|""|'
            + r"''|\s*$)",
            re.MULTILINE,
        ),
        "Vector store authentication explicitly disabled",
        "Configure authentication for your vector store. Use API keys or OAuth tokens.",
        Severity.HIGH,
    ),
    (
        "debug-mode",
        re.compile(r"""DEBUG\s*[=:]\s*(?:True|true|1|"true"|'true')"""),
        "DEBUG=True in production configuration",
        "Set DEBUG=False in production. Debug mode may expose internal state and stack traces.",
        Severity.MEDIUM,
    ),
    (
        "no-tls",
        re.compile(r"""sslmode\s*[=:]\s*(?:disable|"disable"|'disable')"""),
        "Database connection without TLS (sslmode=disable)",
        "Set sslmode=require or sslmode=verify-full for production database connections.",
        Severity.HIGH,
    ),
    (
        "exposed-port",
        re.compile(r"""["']0\.0\.0\.0:\d+:\d+["']"""),
        "Service port exposed on all interfaces (0.0.0.0)",
        "Bind to 127.0.0.1 or a specific internal IP instead of 0.0.0.0.",
        Severity.MEDIUM,
    ),
    (
        "no-password",
        re.compile(
            r'(?:PASSWORD|REDIS_PASSWORD|NEO4J_PASSWORD|MONGO_PASSWORD)\s*[=:]\s*(?:""|'
            + r"''|None|null|\s*$)",
            re.MULTILINE,
        ),
        "Service password is empty or unset",
        "Set a strong password for all database and vector store services.",
        Severity.HIGH,
    ),
    (
        "anonymous-access",
        re.compile(r"""anonymous_access\s*[=:]\s*(?:True|true|1|enabled)"""),
        "Anonymous access enabled on vector store",
        "Disable anonymous access and require authentication for all connections.",
        Severity.HIGH,
    ),
]

# Python config patterns (AST-free, regex on source)
_PYTHON_UNSAFE_PATTERNS: list[tuple[str, re.Pattern[str], str, str, Severity]] = [
    (
        "chroma-ephemeral",
        re.compile(r"""chromadb\.(?:Client|EphemeralClient)\s*\(\s*\)"""),
        "ChromaDB ephemeral client used — data lost on restart, no auth",
        "Use chromadb.HttpClient() or PersistentClient() with authentication settings.",
        Severity.MEDIUM,
    ),
    (
        "faiss-no-wrapper",
        re.compile(r"""FAISS\.(?:from_texts|from_documents|from_embeddings)\s*\("""),
        "FAISS vector store has no native access control",
        "FAISS has no built-in access control. Wrap with application-level tenant filtering.",
        Severity.HIGH,
    ),
]


def _should_skip(path: Path, target: Path) -> bool:
    """Return True if path is inside a directory we should skip."""
    try:
        rel = path.relative_to(target)
    except ValueError:
        return False
    return any(part in _SKIP_DIRS or part.endswith(".egg-info") for part in rel.parts)


class ConfigAuditor:
    """Scans configuration files for insecure vector store and infrastructure settings."""

    name: str = "L4"
    depends_on: Sequence[str] = ()
    replace: bool = False
    opt_in: bool = False
    framework_agnostic: bool = True

    def analyze(self, ctx: AnalysisContext) -> list[Finding]:
        target = ctx.target
        findings: list[Finding] = []
        for config_file in self._find_config_files(target):
            findings.extend(self._audit_file(config_file))
        for py_file in self._find_python_configs(target):
            findings.extend(self._audit_python_file(py_file))
        for json_file in self._find_json_configs(target):
            findings.extend(self._audit_json_file(json_file))
        return findings

    def _find_config_files(self, target: Path) -> list[Path]:
        files: list[Path] = []
        for glob in _CONFIG_GLOBS:
            files.extend(f for f in target.rglob(glob) if not _should_skip(f, target))
        return sorted(set(files))

    def _find_python_configs(self, target: Path) -> list[Path]:
        """Find Python files that look like config (settings.py, config.py, etc.)."""
        patterns = ["**/settings.py", "**/config.py", "**/conf.py"]
        files: list[Path] = []
        for pattern in patterns:
            files.extend(f for f in target.rglob(pattern) if not _should_skip(f, target))
        return sorted(set(files))

    def _find_json_configs(self, target: Path) -> list[Path]:
        """Find JSON config files (e.g. Milvus config)."""
        return sorted(
            f
            for f in target.rglob("*.json")
            if not _should_skip(f, target) and "config" in f.stem.lower()
        )

    def _audit_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return findings

        for rule_suffix, pattern, title, fix, severity in _UNSAFE_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id=f"AW-CFG-{rule_suffix}",
                        title=title,
                        severity=severity,
                        category=Category.MEMORY,
                        description=f"Found in {path.name}: {match.group().strip()}",
                        file=path,
                        line=line_num,
                        fix=fix,
                    )
                )
        # Check for sensitive data in .env files
        if path.name.startswith(".env"):
            findings.extend(self._check_env_secrets(path, content))

        # Check docker-compose for exposed vector DB ports
        if "docker-compose" in path.name:
            findings.extend(self._check_docker_compose(path, content))

        return findings

    def _audit_python_file(self, path: Path) -> list[Finding]:
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8")
        except (OSError, UnicodeDecodeError):
            return findings

        for rule_suffix, pattern, title, fix, severity in _PYTHON_UNSAFE_PATTERNS:
            for match in pattern.finditer(content):
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id=f"AW-CFG-{rule_suffix}",
                        title=title,
                        severity=severity,
                        category=Category.MEMORY,
                        description=f"Found in {path.name}: {match.group().strip()}",
                        file=path,
                        line=line_num,
                        fix=fix,
                    )
                )
        return findings

    def _audit_json_file(self, path: Path) -> list[Finding]:
        """Check JSON config files for insecure settings."""
        findings: list[Finding] = []
        try:
            content = path.read_text(encoding="utf-8")
            data = json.loads(content)
        except (OSError, UnicodeDecodeError, json.JSONDecodeError):
            return findings

        if not isinstance(data, dict):
            return findings

        # Check for authorization disabled
        auth_val = data.get("authorization", {})
        if isinstance(auth_val, dict) and not auth_val.get("enabled", True):
            findings.append(
                Finding(
                    rule_id="AW-CFG-auth-disabled",
                    title="Authorization explicitly disabled in config",
                    severity=Severity.HIGH,
                    category=Category.MEMORY,
                    description="authorization.enabled=false in configuration file.",
                    file=path,
                    line=1,
                    fix="Set authorization.enabled=true in production.",
                )
            )

        return findings

    def _check_env_secrets(self, path: Path, content: str) -> list[Finding]:
        """Check for hardcoded API keys or tokens in .env files."""
        findings: list[Finding] = []
        secret_pattern = re.compile(
            r"^((?:\w*(?:API_KEY|SECRET|TOKEN|PASSWORD))\w*)\s*=\s*(.+)$",
            re.MULTILINE,
        )
        placeholders = {
            "",
            "changeme",
            "your-key-here",
            "xxx",
            "CHANGE_ME",
            "placeholder",
            "YOUR_API_KEY",
            "TODO",
            "dummy",
            "test",
            "example",
        }
        for match in secret_pattern.finditer(content):
            value = match.group(2).strip().strip("\"'")
            if value and value not in placeholders:
                line_num = content[: match.start()].count("\n") + 1
                findings.append(
                    Finding(
                        rule_id="AW-CFG-hardcoded-secret",
                        title=f"Hardcoded secret in {path.name}: {match.group(1)}",
                        severity=Severity.HIGH,
                        category=Category.MEMORY,
                        description=(
                            f"Secret '{match.group(1)}' has a hardcoded value. "
                            "This may be committed to version control."
                        ),
                        file=path,
                        line=line_num,
                        fix="Use environment variables or a secret manager. Never commit secrets.",
                    )
                )
        return findings

    def _check_docker_compose(self, path: Path, content: str) -> list[Finding]:
        """Check docker-compose for vector DB services with insecure config."""
        findings: list[Finding] = []
        _db_images = re.compile(
            r"""image:\s*["']?(chromadb|qdrant|weaviate|milvus|redis|neo4j|elasticsearch)""",
        )
        for match in _db_images.finditer(content):
            db_name = match.group(1)
            line_num = content[: match.start()].count("\n") + 1
            # Look forward ~1000 chars for auth env vars in this service block
            region_end = min(len(content), match.end() + 1000)
            region = content[match.start() : region_end]
            auth_keywords = ["AUTH", "PASSWORD", "TOKEN", "API_KEY", "SECRET"]
            if not any(kw in region.upper() for kw in auth_keywords):
                findings.append(
                    Finding(
                        rule_id="AW-CFG-docker-no-auth",
                        title=f"{db_name} container has no visible authentication config",
                        severity=Severity.MEDIUM,
                        category=Category.MEMORY,
                        description=(
                            f"Docker service using {db_name} image has no authentication "
                            "environment variables. The service may be accessible without credentials."
                        ),
                        file=path,
                        line=line_num,
                        fix=f"Add authentication environment variables for {db_name}.",
                    )
                )

        return findings
