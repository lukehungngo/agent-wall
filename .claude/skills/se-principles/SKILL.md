# Skill: Software Engineering Principles

Reference this skill before finalizing any design or reviewing any non-trivial change.
These are not guidelines — they are constraints. Violations require explicit justification.

---

## SOLID

### S — Single Responsibility
One reason to change. One job per class, one job per function.

**In AgentWall:**
- `ChromaProbe` detects leakage in Chroma. It does not parse LangChain agents.
- `MemoryAnalyzer` runs memory rules. It does not render output.
- `JsonReporter` formats JSON. It does not compute severities.

**Red flags:** function name contains "and", class has >2 dependencies injected,
test requires >3 mocks to isolate.

---

### O — Open/Closed
Open for extension, closed for modification. Add new behavior without editing existing code.

**In AgentWall:**
- New rule → add to `rules.py` + new `_check_*` function in the analyzer. Never edit existing checks.
- New probe → add to `PROBE_REGISTRY` + new file in `probes/`. Never edit `MemoryAnalyzer`.
- New reporter → implement `Reporter` protocol + register. Never edit `scan.py`.

**Red flags:** adding a feature requires editing a `if/elif` chain in core logic,
or adding an argument to a function used in 5+ places.

---

### L — Liskov Substitution
Subtypes must be substitutable for their base types without breaking callers.

**In AgentWall:**
- All probes implement `MemoryProbe` Protocol. Any probe must be safely passed anywhere a
  `MemoryProbe` is expected. A probe that throws on `detect_static()` breaks LSP.
- All reporters implement `Reporter` Protocol. A reporter that only works with `ScanResult`
  containing findings but crashes on empty results breaks LSP.

**Red flags:** `isinstance` checks to dispatch behavior, `# type: ignore` on a Protocol impl,
subclass that narrows input types or widens output types.

---

### I — Interface Segregation
Don't force implementations to depend on methods they don't use.

**In AgentWall:**
- `MemoryProbe` has two methods: `detect_static` and `probe_live`. A probe that only supports
  static analysis should still implement `probe_live` — returning a `ProbeResult` with
  `supported=False`. Never add a third method to the Protocol without consensus.
- Keep `Reporter` minimal. If you need a method only for one reporter type, it doesn't belong
  in the shared Protocol.

**Red flags:** Protocol with 5+ methods where most implementations raise `NotImplementedError`.

---

### D — Dependency Inversion
High-level modules must not depend on low-level modules. Both depend on abstractions.

**In AgentWall:**
- `MemoryAnalyzer` depends on `MemoryProbe` (Protocol), not on `ChromaProbe` (concrete).
- `scan.py` (orchestrator) depends on `Analyzer` Protocol, not on `MemoryAnalyzer` directly.
- `cli.py` depends on `scan()` function signature, not on internal scanner state.

**Red flags:** `from agentwall.probes.chroma import ChromaProbe` in `analyzer.py`,
`from agentwall.cli import app` in `scanner.py`.

---

## Managing Complexity

### The complexity budget
Every abstraction you add costs future readers. You must pay for it with a concrete benefit:
eliminated duplication, enforced invariant, or hidden volatile detail. If you can't name the
benefit, the abstraction is premature.

**Rules:**
1. Flat is better than nested. Restructure to reduce nesting depth before adding a class.
2. Prefer pure functions. Side effects are complexity. Isolate them at the boundary (CLI, reporters).
3. Make illegal states unrepresentable. Use `Literal`, `Enum`, `NewType`, and Pydantic
   validators to make invalid data impossible to construct — not to detect at runtime.
4. Complexity must be justified locally. If a function is hard to read, simplify it.
   Don't add a comment explaining a bad name — fix the name.

### Cyclomatic complexity ceiling
- Functions: max complexity 10. If higher, decompose.
- Run `ruff check --select C90` to measure. Fix before merging.

---

## Duplication — Two Dimensions

### 1. Code duplication (DRY)
The same logic expressed in two places will diverge. Extract when the same logic appears
in **2+ places AND serves the same conceptual purpose**.

Do not extract just because the code looks similar. Ask: "If the rule changes, must I change
both copies?" If yes → extract. If the two copies serve different purposes that happen to
look similar today → leave them separate.

**In AgentWall:**
```python
# BAD: same filter-check logic copied into ChromaProbe and PineconeProbe
# GOOD: extract _has_user_filter(call_node: ast.Call) -> bool into probes/ast_helpers.py
```

### 2. Intention / conceptual duplication
Two different implementations of the same concept. More dangerous than code duplication
because it's invisible to grep.

**In AgentWall — known risks:**
- Don't express "this finding is high severity" in both the rule definition AND the analyzer
  conditional. Severity lives in the rule definition only (`rules.py`).
- Don't express "this is a LangChain agent" in both the parser AND the probe. Parser owns
  framework detection. Probe trusts `AgentSpec.framework`.
- Don't express "user_id is the isolation key" in both the memory config model AND the probe
  check. The model owns the canonical field name.

**Rule:** Each concept has exactly one home. Everything else references that home.

---

## Clean Architecture

### Layer order (strict — no exceptions)

```
cli.py                  ← entry point, I/O, user interaction
  └── scanner.py        ← orchestration, coordinates analyzers + reporters
        ├── parsers/    ← framework adapters, produce AgentSpec (pure)
        ├── analyzers/  ← stateless rules engine, consumes AgentSpec, produces Finding[]
        │     └── probes/ ← backend-specific detection, called by MemoryAnalyzer
        ├── models.py   ← shared data types, no business logic
        ├── rules.py    ← rule registry, severity/category definitions
        └── reporters/  ← output formatting, consumes ScanResult (pure)
```

**Dependency rule:** dependencies point inward only.
- `cli` may import `scanner`, `models`
- `scanner` may import `parsers`, `analyzers`, `reporters`, `models`
- `analyzers` may import `probes`, `models`, `rules`
- `probes` may import `models` only
- `models` imports nothing from agentwall
- `rules` imports nothing from agentwall

**Violations:**
- `models.py` importing from `analyzers/` → **P0**
- `probes/chroma.py` importing from `parsers/` → **P0**
- `reporters/` importing from `analyzers/` → **P0**

### No circular imports
Run `python -c "import agentwall"` — if it raises `ImportError` due to circular deps, fix it.
Circular imports always indicate a layer violation or misplaced concept.

### Keep the boundary explicit
`cli.py` is the only place that:
- Reads from stdin / argv
- Writes to stdout / stderr
- Calls `sys.exit()`
- Handles keyboard interrupts

Everything else is pure logic. This makes the entire scanner testable without a CLI harness.

---

## Package Dependency Flow

### Allowed imports by layer

| Module | May import from |
|---|---|
| `cli.py` | `scanner`, `models`, stdlib, typer, rich |
| `scanner.py` | `parsers`, `analyzers`, `reporters`, `models`, `rules`, stdlib |
| `parsers/*` | `models`, stdlib, `ast` |
| `analyzers/*` | `probes`, `models`, `rules`, stdlib |
| `probes/*` | `models`, stdlib — **backend SDK only inside `probe_live()`** |
| `reporters/*` | `models`, stdlib, rich |
| `models.py` | stdlib, pydantic |
| `rules.py` | `models`, stdlib |

### Third-party dependency rules
1. **Core install** (`pip install agentwall`) must have zero vector DB dependencies.
   All backend SDKs are optional extras: `agentwall[chroma]`, `agentwall[neo4j]`, `agentwall[all]`.
2. New dependency requires justification: what problem, why this library, what's the
   maintenance status, any known CVEs?
3. Pin direct dependencies in `pyproject.toml`. Never pin transitive deps manually.
4. Check with `supply-chain-risk-auditor` skill before adding any new package.

### Import linting
`ruff check --select I` enforces import ordering.
Consider adding `flake8-tidy-imports` or equivalent to ban upward-layer imports in CI.
