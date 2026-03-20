# AgentWall v1.0 Release OKRs

**Date:** 2026-03-21
**Status:** Planning
**Gate:** Do not release until all KRs marked REQUIRED are met

---

## Current State Assessment

| Dimension | Reality | Production Standard | Gap |
|---|---|---|---|
| Framework adapters | 1 (LangChain). LlamaIndex/CrewAI have models but zero adapters | 3+ with deep analysis | Critical |
| FP rate | ~35% measured (MEM-001: 100%, SEC-003: 53%, CFG: 75%) | <15% | Critical |
| Engine integration | Runs in try/except, produces zero finding changes on real projects | Engine drives all findings | High |
| Non-LangChain detection | 32 projects undetected (Dify 129k, RAGFlow 70k, MetaGPT 58k, OpenHands 65k) | Auto-detect all major frameworks | High |
| CI/CD | CLI only | GitHub Action + SARIF upload | High |
| Documentation | README only, no rule reference | Full docs | Medium |
| Test coverage | 72% (623 tests) | >85% | Medium |
| Zero-finding rate | 21% of projects get zero findings | <10% for vector-store projects | Medium |

### Key Findings from Benchmark Triage (98 findings manually verified)

- **MEM-001 (100% FP):** Fires on library code, single-user tools, per-collection isolation. The flagship rule is broken.
- **SEC-003 (53% FP → ~25% after Phase 1):** `len(messages)`, `context.function.name` — metadata, not content.
- **CFG-hardcoded-secret (75% FP → ~15% after Phase 1):** Templates, placeholders, non-secret key names.
- **SER-003 (47% FP → ~40% after indirection fix):** Lazy `__getattr__` dict-lookup pattern.
- **Engine isolation:** store_profiles populated but MEM-001 downgrade never triggers because adapter and engine classify stores differently.

### Framework Detection Breakdown (106 projects)

| Framework | Detected | Has Adapter | Gets Deep Analysis |
|---|---|---|---|
| LangChain | 58 | Yes | Yes |
| OpenAI Agents | 11 | No | No (generic rules only) |
| AutoGen | 3 | No | No |
| LlamaIndex | 1 | No | No |
| CrewAI | 1 | No | No |
| Undetected | 32 | No | No |

---

## Objective 1: Make Findings Trustworthy (FP < 15%) — STEP 1

**Why first:** Nobody adopts a scanner that cries wolf. Every other objective is meaningless if users suppress all findings.

| KR | Metric | Current | Target | How | Required |
|---|---|---|---|---|---|
| KR1.1 | MEM-001 FP rate | 100% | <20% | Skip library/site-packages code. Require HTTP entry point (from ASM) to confirm multi-tenant context. Downgrade single-file projects to INFO. | Yes |
| KR1.2 | SEC-003 FP rate | ~25% | <20% | Done (Phase 1). Verify on re-triage. | Yes |
| KR1.3 | CFG-hardcoded-secret FP rate | ~15% | <15% | Done (Phase 1). Verify on re-triage. | Yes |
| KR1.4 | SER-003 FP rate | ~40% | <25% | Variable indirection done. Add f-string with hardcoded-only prefix suppression. | Yes |
| KR1.5 | Overall FP rate | ~35% | <15% | Re-triage 100 findings after all fixes. Publish rate in README. | Yes |
| KR1.6 | Engine drives findings | 0% | 100% of MEM findings | Replace MemoryConfig boolean flags with StoreProfile.isolation_strategy as primary decision source in MemoryAnalyzer. | Yes |

### KR1.1 Detail: Fixing MEM-001

The rule's assumption — "every `similarity_search()` without `filter=` is a vulnerability" — is wrong for:

1. **Library/framework code** (LlamaIndex base classes, Pinecone integration): Intentionally generic. The caller provides filters.
2. **Per-collection isolation** (LangChain-Chatchat: each KB = own collection): No filter needed.
3. **Single-user tools** (Vanna, local CLI apps): No multi-tenancy exists.
4. **Non-query operations** (collection teardown, metrics counting): Not retrieval.

Fix approach:
- Check if file is inside `site-packages/` or a known framework package → suppress
- Use engine `StoreProfile.isolation_strategy == COLLECTION_PER_TENANT` → downgrade to MEDIUM
- Check ASM entry_points for HTTP routes → if none, likely single-user tool → downgrade to INFO
- Only fire CRITICAL when: shared collection + no filter + HTTP entry point exists

### KR1.6 Detail: Engine Wiring

Current state: Engine runs, populates `ctx.store_profiles`, but MemoryAnalyzer still uses `MemoryConfig` boolean flags. The engine's `ValueKind.COMPOUND_TENANT` vs `COMPOUND_STATIC` classification never reaches the finding decision.

Fix: In `MemoryAnalyzer._check()`, when `ctx.store_profiles` is available, use `StoreProfile.isolation_strategy` as the primary decision instead of `mc.has_tenant_isolation` / `mc.has_metadata_filter_on_retrieval`.

---

## Objective 2: Cover the Market (3+ Frameworks) — STEP 2

**Why second:** LangChain-only = ~35% market coverage. LangChain + LlamaIndex + CrewAI = ~75%.

| KR | Metric | Current | Target | How | Required |
|---|---|---|---|---|---|
| KR2.1 | LlamaIndex adapter | Model only (no adapter) | Full analysis (MEM/TOOL/RAG rules fire) | Write `adapters/llamaindex.py` using existing framework model. ~300 LOC. | Yes |
| KR2.2 | CrewAI adapter | Model only | Full analysis (MEM/TOOL/AGT rules fire) | Write `adapters/crewai.py`. CrewAI uses `@agent`, `@task`, `@crew` decorators. | Yes |
| KR2.3 | Framework detection | 32 projects undetected | Dify, RAGFlow, MetaGPT, OpenHands detected | Expand `detector.py` import patterns. These use LangChain/LlamaIndex internally — detect transitive deps. | Yes |
| KR2.4 | Zero-finding rate | 21% | <10% for vector-store projects | If project imports chromadb/pinecone/qdrant but framework=none, run framework-agnostic vector store analysis. | No |
| KR2.5 | Benchmark coverage | 84/106 with findings | 90+ of 106 | Re-run BENCHMARK3000 after framework expansion. | No |

### Adapter Scope

Each adapter implements `AbstractAdapter.parse(target) -> AgentSpec`:
- Walk AST of all Python files
- Extract `ToolSpec[]` (tools with names, descriptions, destructive/exec flags)
- Extract `MemoryConfig[]` (vector store instances with isolation/filter/metadata flags)
- Extract `ApplicationModel` (ASM graph: entry points, stores, reads, writes, sinks, edges)

The engine then runs against the AgentSpec — identical analysis regardless of framework.

### Detection Expansion

Projects like Dify (129k stars) and RAGFlow (70k) are undetected because they don't directly import `langchain`. They use:
- Internal vector store wrappers
- Direct chromadb/pinecone/qdrant SDK calls
- Custom RAG pipelines

Fix: Add detection for direct vector store SDK imports:
```python
if any import matches chromadb|pinecone|qdrant_client|pymilvus|weaviate → "vectorstore_direct"
```
Then run a lightweight adapter that extracts store instances without framework-specific patterns.

---

## Objective 3: Ship CI/CD Integration — STEP 3

**Why third:** "Run in CI or it doesn't exist" for production teams.

| KR | Metric | Current | Target | How | Required |
|---|---|---|---|---|---|
| KR3.1 | GitHub Action | None | Published to marketplace | `action.yml`: install agentwall, run scan, upload SARIF | Yes |
| KR3.2 | PR comment | None | Findings diff in PR | Action posts comment with new/resolved findings vs base branch | No |
| KR3.3 | Quality gate | `--fail-on` exists | Documented in Action README | Already implemented. Document. | Yes |
| KR3.4 | Incremental scan | None | <30s on PR diff | `--changed-files` flag — only scan files in git diff | No |

### GitHub Action Design

```yaml
# .github/workflows/agentwall.yml
name: AgentWall Security Scan
on: [push, pull_request]
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: agentwall/scan-action@v1
        with:
          format: sarif
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v3
        with:
          sarif_file: agentwall.sarif
```

---

## Objective 4: Documentation for Adoption — STEP 3

| KR | Metric | Current | Target | How | Required |
|---|---|---|---|---|---|
| KR4.1 | README | Basic | Install → scan → fix in <2 minutes | Rewrite with quickstart, output example, rule table, badges | Yes |
| KR4.2 | Rule reference | None | Every rule documented | Generate from `rules.py`: description, severity, example, fix, FP guidance | Yes |
| KR4.3 | Getting started | None | 3 workflows | Local dev, CI pipeline, AI agent integration | No |
| KR4.4 | `agentwall explain` | None | CLI command | Print rule description, example, fix, OWASP mapping | No |

---

## Objective 5: Quality Bar — STEP 4

| KR | Metric | Current | Target | How | Required |
|---|---|---|---|---|---|
| KR5.1 | Test coverage | 72% | >85% | Focus on engine integration, L2 edge cases, adapter tests | Yes |
| KR5.2 | Benchmark regression | No labeled set | Zero TP lost between versions | 100-finding labeled test set checked on every release | Yes |
| KR5.3 | Performance | ~10s | <30s on any project <100k LOC | Profile Langflow scan (1274 files) | Yes |
| KR5.4 | Package | Untested recently | `pip install agentwall && agentwall scan . --format sarif` works first try | End-to-end test in CI | Yes |

---

## Execution Timeline

```
STEP 1: O1 — FP < 15%
  ├── KR1.1: Fix MEM-001 (skip library, require multi-tenant evidence)
  ├── KR1.6: Wire engine StoreProfile into MemoryAnalyzer
  ├── KR1.4: SER-003 f-string prefix suppression
  └── Re-triage 100 findings → measure FP rate

STEP 2: O2 — Multi-framework
  ├── KR2.1: LlamaIndex adapter (~300 LOC)
  ├── KR2.2: CrewAI adapter (~300 LOC)
  ├── KR2.3: Expand detector (Dify, RAGFlow, MetaGPT, OpenHands)
  └── KR2.5: Re-run BENCHMARK3000

STEP 3: O3 + O4 — CI/CD + Docs
  ├── KR3.1: GitHub Action
  ├── KR3.3: Quality gate documentation
  ├── KR4.1: README rewrite
  └── KR4.2: Rule reference

STEP 4: O5 — Quality + Launch
  ├── KR5.1: Test coverage >85%
  ├── KR5.2: Labeled test set
  ├── KR5.4: Package verification
  └── Launch: PyPI + GitHub + blog + HN
```

---

## v1.0 Release Gate

**Do NOT release until ALL of these are true:**

- [ ] FP rate <15% on 100-finding labeled test set
- [ ] 3+ frameworks with full analysis (LangChain + LlamaIndex + CrewAI)
- [ ] 80+ of 106 benchmark projects get findings
- [ ] GitHub Action published and tested on 3 real repos
- [ ] README quickstart works in <2 minutes on a clean machine
- [ ] Every rule has description, severity, fix guidance
- [ ] `pip install agentwall && agentwall scan . --format sarif` works on clean machine
- [ ] 623+ tests passing, >85% coverage, ruff clean, mypy strict
- [ ] Engine StoreProfile is the primary decision source for MEM rules
- [ ] No known P0 issues in the issue tracker

---

## What Success Looks Like

**STEP 1 complete:** A developer scans Langflow and gets 40 findings instead of 117. Every finding is actionable. Zero "why did it flag this library code?" moments.

**STEP 2 complete:** Same developer scans a CrewAI project and gets memory isolation findings. Scans a LlamaIndex project and gets RAG injection findings. One tool, three frameworks.

**STEP 3 complete:** Developer adds AgentWall to their GitHub Actions. Every PR shows a security diff. SARIF findings appear in the Security tab. Blocking on CRITICAL.

**STEP 4 complete:** `pip install agentwall` on a fresh machine. README gets them scanning in 90 seconds. Blog post on Hacker News. First external issue filed.
