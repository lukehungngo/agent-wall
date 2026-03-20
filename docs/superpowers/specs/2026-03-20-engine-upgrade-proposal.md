# AgentWall Engine Upgrade Proposal: L1–L3, L6

**Date:** 2026-03-20
**Author:** SoH Engineering
**Status:** Draft
**Scope:** Make each analysis layer 10x stronger using proven SAST algorithms, adapted for AI security property verification

---

## 1. Thesis

AgentWall's moat is not rule count — it's analysis depth. Traditional SAST tools (Semgrep, CodeQL, Pysa) have best-in-class engines for generic vulnerability detection. AgentWall should steal their algorithms but scope them to AI security property verification — a narrower problem that allows deeper, more precise analysis with less engineering effort.

**The split:** Engine (general, reusable) + Framework Model (declarative, per-framework).

Adding a new framework = writing a model file. The engine stays untouched.

---

## 2. Current State vs. Target

| Layer | SAST Step | Current | Target | Algorithm Source |
|-------|-----------|---------|--------|-----------------|
| **L1** | Parse → Extract | Hardcoded `_FileVisitor` with `_VECTOR_STORES` dict, kwarg presence checks | Model-driven property extractor that classifies values (static/dynamic/tenant-scoped) | Semgrep pattern catalog concept |
| **L2** | Connect → Graph | Single-file call graph, imports unresolved, breaks on class dispatch | Assignment-based interprocedural call graph + model-driven composition graph. Single-level inheritance. No type inference, no dynamic dispatch (marked UNKNOWN) | PyCG (ICSE '21) |
| **L3** | Track → Verify | Single-function `_TaintVisitor`, resets at function boundary | Per-function summaries + fixpoint iteration for tenant isolation verification | Pysa fixpointAnalysis |
| **L6** | Reason → Paths | Single-function lattice, no condition narrowing | Interprocedural path coverage — verify property across ALL callers | CodeQL GlobalWithState |

---

## 3. L1 Upgrade: Model-Driven Property Extractor

### 3.1 Problem

Current L1 answers: "Is `filter=` present on this call?" (binary yes/no).

It cannot distinguish:

```python
# Case A: Static filter — INSECURE (no tenant scoping)
db.similarity_search(query, filter={"source": "web"})

# Case B: Dynamic filter with tenant ID — SECURE
db.similarity_search(query, filter={"user_id": uid})

# Case C: Per-tenant collection — SECURE (no filter needed)
db = Chroma(collection_name=f"docs_{tenant_id}")
db.similarity_search(query)

# Case D: Filter present but wrong key — INSECURE
# Write: add_documents(metadata={"user_id": uid, "org_id": org})
# Read:  similarity_search(filter={"category": cat})  ← doesn't filter on user_id!
```

### 3.2 Algorithm: Value Classification

Introduce a value classifier that categorizes every extracted property:

```python
class ValueKind(Enum):
    LITERAL = "literal"           # "global_docs", 42
    DYNAMIC = "dynamic"           # variable reference, can't determine
    TENANT_SCOPED = "tenant"      # contains tenant identifier (user_id, org_id, etc.)
    COMPOUND_STATIC = "cstatic"   # dict with all literal values: {"source": "web"}
    COMPOUND_DYNAMIC = "cdynamic" # dict with at least one dynamic value
    COMPOUND_TENANT = "ctenant"   # dict with at least one tenant-scoped value
```

The AST visitor classifies every kwarg value by walking the expression:

```python
def classify_value(node: ast.expr, tainted_names: set[str]) -> ValueKind:
    """Classify an AST expression by its security-relevant kind."""
    if isinstance(node, ast.Constant):
        return ValueKind.LITERAL
    if isinstance(node, ast.Name):
        if node.id in tainted_names:
            return ValueKind.TENANT_SCOPED
        return ValueKind.DYNAMIC
    if isinstance(node, ast.JoinedStr):  # f-string
        for val in node.values:
            if classify_value(val, tainted_names) == ValueKind.TENANT_SCOPED:
                return ValueKind.TENANT_SCOPED
        return ValueKind.DYNAMIC
    if isinstance(node, ast.Dict):
        kinds = [classify_value(v, tainted_names) for v in node.values]
        if any(k == ValueKind.TENANT_SCOPED for k in kinds):
            return ValueKind.COMPOUND_TENANT
        if all(k == ValueKind.LITERAL for k in kinds):
            return ValueKind.COMPOUND_STATIC
        return ValueKind.COMPOUND_DYNAMIC
    return ValueKind.DYNAMIC
```

### 3.3 Algorithm: Write-Read Metadata Consistency

Cross-reference metadata keys set on write with filter keys used on read:

```python
@dataclass
class MetadataConsistency:
    write_keys: frozenset[str]    # keys set via add_documents(metadata={...})
    read_filter_keys: frozenset[str]  # keys used in similarity_search(filter={...})

    @property
    def unfiltered_write_keys(self) -> frozenset[str]:
        """Keys written but never filtered on — potential isolation gap."""
        return self.write_keys - self.read_filter_keys

    @property
    def has_tenant_key_on_both(self) -> bool:
        """At least one tenant-scoped key appears in both write and read."""
        tenant_keys = {"user_id", "tenant_id", "org_id", "owner_id"}
        return bool(self.write_keys & self.read_filter_keys & tenant_keys)
```

This enables a new finding: **"metadata key `user_id` is set on write but not filtered on read"** — currently impossible to detect.

### 3.4 Framework Model (Declarative)

Replace hardcoded `_VECTOR_STORES` dict with a declarative model:

```python
# src/agentwall/models/langchain.py
LANGCHAIN_MODEL = FrameworkModel(
    name="langchain",
    stores={
        "Chroma": StoreModel(
            backend="chromadb",
            isolation_params=["collection_name"],
            write_methods={"add_texts": "metadata", "add_documents": "metadata"},
            read_methods={
                "similarity_search": "filter",
                "similarity_search_with_score": "filter",
                "max_marginal_relevance_search": "filter",
            },
            retriever_factory="as_retriever",
            retriever_filter_path="search_kwargs.filter",
            auth_params=["client_settings", "http_client"],
            persistence_params=["persist_directory"],
        ),
        "PGVector": StoreModel(
            backend="pgvector",
            isolation_params=["collection_name"],
            write_methods={"add_texts": "metadatas", "add_documents": "metadatas"},
            read_methods={"similarity_search": "filter"},
            retriever_factory="as_retriever",
            retriever_filter_path="search_kwargs.filter",
            auth_params=["connection_string"],
        ),
        # ... one entry per vector store
    },
    composition_patterns=[
        PipePattern(operator="|", connects="output_to_input"),
        FactoryPattern(method="from_llm", kwarg="retriever", role="read_source"),
        FactoryPattern(method="from_chain_type", kwarg="retriever", role="read_source"),
    ],
    auth_sources=[
        "request.user", "request.user_id", "session.user_id",
        "g.user", "current_user", "jwt.sub",
    ],
    tenant_param_names=["user_id", "tenant_id", "org_id", "owner_id"],
    memory_classes=["ConversationBufferMemory", "ConversationSummaryMemory", ...],
)
```

**Adding Pinecone + LlamaIndex:**

```python
LLAMAINDEX_MODEL = FrameworkModel(
    name="llamaindex",
    stores={
        "PineconeVectorStore": StoreModel(
            backend="pinecone",
            isolation_params=["namespace"],  # Pinecone uses namespace, not collection
            write_methods={"add": "metadata"},
            read_methods={"query": "filters"},  # different kwarg name!
            auth_params=["api_key", "environment"],
        ),
    },
    # ...
)
```

Zero engine changes. The L1 engine reads the model and knows what to extract.

### 3.5 Impact on Current Rules

| Rule | Current Detection | After L1 Upgrade |
|------|-------------------|------------------|
| AW-MEM-001 | `filter=` kwarg absent | Filter absent OR filter present but `COMPOUND_STATIC` (no tenant scoping) OR per-tenant collection detected → suppress |
| AW-MEM-002 | Heuristic from L3 | Write metadata keys ∩ read filter keys = ∅ for tenant keys |
| AW-MEM-003 | Backend name check | Backend capabilities from model (e.g., FAISS → no ACL by definition) |
| AW-MEM-005 | `SANITIZE_NAMES` string search | Sanitization function in model, verified by L2 call graph |

### 3.6 Data Model Changes

```python
# New: replaces boolean flags with structured evidence
@dataclass(frozen=True)
class PropertyExtraction:
    """A single extracted property from a framework call."""
    call_site: Provenance                 # where in code
    store_id: str                         # which store instance
    operation: Literal["read", "write", "init"]
    method: str                           # "similarity_search", "add_documents", etc.

    # Extracted properties with classification
    filter_keys: frozenset[str]           # keys used in filter
    filter_value_kind: ValueKind          # LITERAL, DYNAMIC, TENANT_SCOPED, etc.
    metadata_keys: frozenset[str]         # keys set in metadata
    metadata_value_kind: ValueKind
    collection_name: str | None
    collection_name_kind: ValueKind

    # Raw AST for downstream analysis
    filter_ast: ast.expr | None = None
    metadata_ast: ast.expr | None = None
```

```python
# Replaces MemoryConfig boolean flags
@dataclass(frozen=True)
class StoreProfile:
    """Complete security profile of one vector store instance."""
    store: Store                          # ASM node
    backend_model: StoreModel             # from framework model
    extractions: list[PropertyExtraction] # all operations on this store

    @property
    def isolation_strategy(self) -> IsolationStrategy:
        """Derived: how is tenant isolation achieved (if at all)?"""
        if self._collection_is_tenant_scoped:
            return IsolationStrategy.COLLECTION_PER_TENANT
        if self._all_reads_have_tenant_filter:
            return IsolationStrategy.FILTER_ON_READ
        if self._some_reads_have_tenant_filter:
            return IsolationStrategy.PARTIAL_FILTER  # finding: inconsistent
        return IsolationStrategy.NONE  # finding: no isolation
```

---

## 4. L2 Upgrade: Assignment-Based Call Graph + Composition Graph

### 4.1 Problem

Current L2 builds a call graph within a single file. Cross-file imports are collected by `_ImportResolver` but **never wired into call resolution** (TODO at line 212). Class method dispatch via variable types only works for direct `x = ClassName()` assignments in the same scope.

Real agent code has 5 patterns that break the current call graph, ranked by prevalence:

| # | Pattern | Prevalence | Example | Why It Breaks L2 |
|---|---------|-----------|---------|-------------------|
| 1 | **LCEL pipe `\|`** | Very high (40+ projects in BENCHMARK3000) | `chain = prompt \| llm \| retriever` | `\|` is `BinOp(BitOr)` in AST, not a `Call` node. L2 only walks `Call` nodes |
| 2 | **Factory methods** | Very high | `ConversationalRetrievalChain.from_llm(retriever=r)` | `retriever` is a kwarg value, not a callee. L2 doesn't track kwarg-mediated wiring |
| 3 | **Decorator `@tool`** | High | `@tool def search(): ...` | L2 doesn't connect decorated functions to the agent that uses them |
| 4 | **Class inheritance** | Medium-high | `class TenantChroma(Chroma): def similarity_search(...)` | L2 resolves `x.method()` via `_var_types` but doesn't walk class hierarchy for overrides |
| 5 | **Dynamic dispatch** | Medium | `getattr(obj, method_name)()`, plugin registries | Fundamentally unresolvable statically |

### 4.2 Scoping Decision: What L2 Will and Won't Handle

Based on analysis of real agent codebases:

```
L2 WILL handle:
  ✅ PyCG-style assignment tracking (variable → pointsto set)
  ✅ Cross-file import resolution (wire existing _ImportResolver)
  ✅ Composition patterns from framework model (pipe, factory, decorator)
  ✅ Single-level inheritance (class X(Y) → X extends Y, check for overrides)

L2 will NOT handle:
  ❌ Full type inference (Pyre) — overkill, heavy dependency
  ❌ Multi-level MRO resolution — rare in agent code
  ❌ Dynamic dispatch / getattr — fundamentally unresolvable, mark UNKNOWN
  ❌ JVM-style virtual dispatch tables — wrong language
```

**Why no Pyre/type inference:** The 4 patterns we need (pipe, factory, decorator, single-level inheritance) are all solvable with **assignment tracking + AST pattern matching**. Type inference solves dispatch for arbitrary Python code — we only need dispatch for known framework patterns declared in the model.

**Why no dynamic dispatch:** `getattr(obj, method_name)()` and plugin registries are fundamentally unresolvable without runtime info. The right answer is `UNKNOWN` confidence, not pretending we can resolve them.

### 4.3 Algorithm: PyCG Assignment-Based Approach

Reference: [PyCG: Practical Call Graph Generation in Python (ICSE '21)](https://arxiv.org/pdf/2103.00587)

PyCG's key insight: instead of type inference, track **all possible values** of every identifier through assignments. 99.2% precision on Python call graphs.

Core data structure — **assignment graph**:

```python
@dataclass
class IdentifierState:
    """All possible values an identifier can hold."""
    name: str                          # qualified name: "module.Class.method"
    pointsto: set[str]                 # set of possible callable targets
    scope: str                         # module/class/function scope

class AssignmentGraph:
    """Tracks identifier→value relationships across entire project."""
    identifiers: dict[str, IdentifierState]

    def process_assignment(self, target: str, value_pointsto: set[str]):
        """target = value → target can now point to anything value points to."""
        self.identifiers[target].pointsto |= value_pointsto

    def process_call(self, caller: str, callee_expr: str) -> set[str]:
        """Resolve callee_expr to all possible targets."""
        return self.identifiers.get(callee_expr, EMPTY).pointsto

    def process_import(self, local_name: str, module: str, imported_name: str):
        """from module import name as local_name."""
        qualified = f"{module}.{imported_name}"
        self.identifiers[local_name].pointsto.add(qualified)
```

**Two-pass algorithm:**

```
Pass 1: Collect all definitions and assignments across ALL files
  - Function/class defs → register in identifier graph
  - Imports → register in identifier graph (wire existing _ImportResolver)
  - Assignments → propagate pointsto sets
  - Class defs → record single-level parent: class X(Y) → extends[X] = Y

Pass 2: Resolve call sites using identifier graph
  - For each call `x.method()`:
    1. Look up x in identifier graph → possible classes
    2. For each class, check if it overrides method (direct def)
    3. If no override, check parent class (single level only)
    4. Create call edge from caller to resolved callee
```

**Iteration until fixpoint:** Assignments can be circular (`a = b; b = a`). Iterate passes until no new pointsto edges are added. In practice converges in 2-3 iterations for agent code.

### 4.4 Single-Level Inheritance: The Minimal Addition

The only case requiring inheritance resolution in practice:

```python
class TenantChroma(Chroma):
    def similarity_search(self, query, **kwargs):
        kwargs["filter"] = {"user_id": self.current_user}
        return super().similarity_search(query, **kwargs)

db = TenantChroma()
db.similarity_search(query)  # L1 flags — no filter kwarg visible!
```

Implementation — 3 additions to the assignment graph:

```python
# In Pass 1, when visiting ClassDef:
def process_class(self, name: str, bases: list[str]):
    """Record single-level inheritance."""
    for base in bases:
        self.extends[name] = base  # only first base (single-level)

# In Pass 2, when resolving x.method():
def resolve_method(self, class_name: str, method_name: str) -> str | None:
    """Resolve method, checking class then parent."""
    qualified = f"{class_name}.{method_name}"
    if qualified in self.identifiers:
        return qualified
    # Single-level parent check
    parent = self.extends.get(class_name)
    if parent:
        parent_qualified = f"{parent}.{method_name}"
        if parent_qualified in self.identifiers:
            return parent_qualified
    return None  # unresolved

# In L1, when analyzing the override body:
# TenantChroma.similarity_search body contains filter= → mark as filtered
```

No MRO. No `super()` resolution chain. No metaclass handling. Just: "does this class have a parent? does the parent define the method?"

### 4.5 Composition Graph

On top of the call graph, build a **composition graph** for framework-specific wiring that isn't function calls:

```python
class CompositionEdge:
    """A non-call-based connection between components."""
    source: str              # component that produces output
    target: str              # component that consumes input
    kind: CompositionKind    # PIPE, FACTORY, DECORATOR, TOOL_REGISTRATION
    provenance: Provenance

class CompositionKind(Enum):
    PIPE = "pipe"                    # a | b (LCEL)
    FACTORY = "factory"              # Class.from_llm(retriever=r)
    DECORATOR = "decorator"          # @tool → registered in agent
    TOOL_REGISTRATION = "tool_reg"   # agent.tools = [t1, t2]
```

Detection is model-driven, not hardcoded:

```python
# In FrameworkModel — engine reads these, not LangChain-specific code
composition_patterns = [
    PipePattern(operator="|"),           # detect BinOp(left, BitOr, right)
    FactoryPattern(
        method="from_llm",
        kwarg="retriever",
        role="read_source"               # marks retriever as data source
    ),
    DecoratorPattern(
        decorator="tool",
        registers_in="agent.tools"       # marks function as agent tool
    ),
]
```

The engine recognizes 3 AST patterns:
1. `BinOp` with `BitOr` → check if model declares a `PipePattern` → create composition edge
2. `Call` to a method name matching `FactoryPattern.method` → extract kwarg → create composition edge
3. Decorator matching `DecoratorPattern.decorator` → create tool registration edge

No hardcoded LangChain knowledge in the engine.

### 4.6 What About Dynamic Dispatch?

**We don't handle it. We mark it.**

```python
# When resolution fails:
@dataclass(frozen=True)
class UnresolvedCall:
    caller: Provenance
    callee_expr: str          # the expression we couldn't resolve
    reason: UnresolvedReason  # DYNAMIC_ATTR, PLUGIN_LOAD, VARIABLE_CALLEE, etc.

class UnresolvedReason(Enum):
    DYNAMIC_ATTR = "dynamic_attr"        # getattr(obj, name)
    PLUGIN_LOAD = "plugin_load"          # importlib.import_module(var)
    VARIABLE_CALLEE = "variable_callee"  # func = get_func(); func()
    EXTERNAL_MODULE = "external_module"  # call into unscanned dependency
```

This feeds into L3/L6: if a store access path goes through an unresolved call, the property verification result is `UNKNOWN`, not `VERIFIED` or `VIOLATED`. Honest uncertainty beats false confidence.

### 4.7 Impact

| What Breaks Today | After L2 Upgrade |
|-------------------|------------------|
| `from utils import get_retriever` → callee unresolved | Import resolved via assignment graph (wires existing `_ImportResolver`) |
| `chain = prompt \| llm \| retriever` → invisible | Composition edge: retriever → llm → prompt (via `PipePattern`) |
| `ConversationalRetrievalChain.from_llm(retriever=r)` → invisible | Factory edge: r feeds into chain (via `FactoryPattern`) |
| `x = Chroma(); y = x; y.similarity_search()` → x's type lost | Assignment graph: y pointsto same as x |
| `class TenantChroma(Chroma)` with filter override → flagged as unfiltered | Single-level inheritance: override body analyzed, filter detected |
| `getattr(obj, method)()` → silently unresolved | Explicitly marked `UNKNOWN` with `UnresolvedReason.DYNAMIC_ATTR` |
| O(n²) filter check re-parses all files per finding | Single-pass graph construction, O(1) lookup per finding |

### 4.8 Data Model Changes

```python
# Replaces current CallGraph
@dataclass
class ProjectGraph:
    """Unified call + composition graph for entire project."""

    # Call graph (PyCG-style)
    call_edges: list[CallEdge]              # function-calls-function
    identifiers: dict[str, IdentifierState] # assignment-based resolution
    extends: dict[str, str]                 # single-level inheritance: child → parent

    # Composition graph (framework-aware)
    composition_edges: list[CompositionEdge]  # pipe, factory, decorator, etc.

    # Unresolved calls (honest uncertainty)
    unresolved: list[UnresolvedCall]

    # Combined queries
    def all_readers_of(self, store_id: str) -> list[ReadOp]:
        """All code paths that read from a given store."""

    def all_writers_to(self, store_id: str) -> list[WriteOp]:
        """All code paths that write to a given store."""

    def path_from_entry_to_store(self, entry: EntryPoint, store: Store) -> list[Edge]:
        """Trace from HTTP handler to vector store access."""

    def components_feeding_into(self, node_id: str) -> list[str]:
        """What feeds into this component via call or composition edges."""

    def path_has_unresolved(self, path: list[Edge]) -> bool:
        """Does this path go through any unresolved call?"""
```

---

## 5. L3 Upgrade: Fixpoint Property Verification

### 5.1 Problem

Current L3 tracks taint within a single function. When `user_id` enters function A, gets passed to function B, which constructs the filter and passes it to function C which calls `similarity_search()` — L3 sees nothing. The taint resets at every function boundary.

This is the single biggest source of false positives: L1 flags `similarity_search()` without filter, but the filter is applied 2 function calls away.

### 5.2 Algorithm: Per-Function Summaries + Fixpoint

Reference: [Pysa fixpointAnalysis.ml](https://github.com/facebook/pyre-check/blob/main/source/interprocedural/fixpointAnalysis.ml)

**Key concept — function summary:**

A summary describes what a function does to tenant identity, without re-analyzing the function body every time:

```python
@dataclass(frozen=True)
class TenantFlowSummary:
    """What this function does with tenant identity."""
    function: str                     # qualified function name

    # Which parameters carry tenant identity to a store filter?
    # Maps: param_index → set of store operations where it's used as filter
    param_reaches_filter: dict[int, frozenset[str]]

    # Does this function return tenant-scoped data?
    returns_tenant_scoped: bool

    # Does this function contain an unfiltered store read?
    has_unfiltered_read: bool

    # Store operations performed (for cross-referencing)
    store_reads: list[StoreAccess]
    store_writes: list[StoreAccess]

@dataclass(frozen=True)
class StoreAccess:
    store_id: str
    method: str
    filter_kind: ValueKind          # from L1 value classification
    filter_param_source: int | None # which param (if any) feeds the filter
```

**Fixpoint algorithm:**

```
1. INITIALIZE: For each function, compute summary from function body alone
   (same as current L3, but output is a summary, not a finding)

2. PROPAGATE: For each call site in the call graph:
   - Look up callee's summary
   - If caller passes a tenant-scoped value as arg i,
     and callee's summary says param i reaches a filter → GOOD
   - If caller passes a tenant-scoped value as arg i,
     and callee's summary says param i does NOT reach a filter → propagate info

3. UPDATE: Recompute summaries incorporating callee summaries
   - If function B calls function C, and C's summary says "param 0 reaches filter",
     then B's summary can now say "param 0 reaches filter (via C)"

4. ITERATE: Repeat steps 2-3 until no summaries change (fixpoint reached)

5. EMIT: After fixpoint, check each store's complete access profile:
   - For each store, collect ALL read paths (from L2 graph)
   - For each read path, check: does a tenant-scoped value reach the filter?
   - Report: "Store X: 3/5 read paths have tenant-scoped filter, 2/5 do not"
```

**Convergence:** The lattice is finite (each function has a fixed number of parameters, each parameter either reaches or doesn't reach each store filter). Summaries can only grow (more reachability information). Monotonic growth on a finite lattice guarantees fixpoint in ≤ N iterations where N = number of functions.

### 5.3 Scoping: Why This Is Simpler Than Pysa

Pysa solves: "does ANY untrusted data reach ANY dangerous sink?" (arbitrary sources, arbitrary sinks, sanitizers, taint-through-collections, implicit flows).

AgentWall solves: "does tenant identity reach the store filter on EVERY read path?"

| Dimension | Pysa (general) | AgentWall L3 (scoped) |
|-----------|----------------|----------------------|
| Source kinds | Hundreds (user input, file reads, env vars, network...) | ~10 (request.user, session.user_id, jwt.sub, ...) |
| Sink kinds | Hundreds (SQL, shell, file write, redirect...) | ~5 (similarity_search filter, as_retriever filter, query filter, namespace, collection_name) |
| Sanitizers | Dozens (html.escape, parameterize, hash...) | 0 — tenant ID should NOT be sanitized |
| Taint-through | Full heap model (dict, list, object fields) | Limited — track through dict construction and f-strings only |
| Property | "exists a flow from source to sink" (bad) | "forall read paths, exists a flow from tenant source to filter sink" (inverted!) |

The inverted property ("forall paths" instead of "exists a path") is actually simpler to implement: you verify each path independently and report coverage.

### 5.4 Example

```python
# file: auth.py
def get_current_user(request):        # Summary: returns tenant-scoped value
    return request.user.id

# file: retriever.py
def search_docs(db, query, user_id):  # Summary: param 2 reaches filter on db
    return db.similarity_search(query, filter={"user_id": user_id})

# file: api.py
@app.post("/ask")
def ask_endpoint(request):
    user_id = get_current_user(request)   # tenant source (from summary)
    db = get_chroma_db()                   # store reference
    results = search_docs(db, request.body, user_id)  # param 2 = tenant → reaches filter ✓
    return format_response(results)
```

**Current L3:** Sees `search_docs()` has `user_id` param and `similarity_search(filter={"user_id": user_id})` in the same function → marks as reaching. But if `ask_endpoint` called `search_docs(db, request.body, "admin")` instead, current L3 wouldn't catch it because it doesn't look at the caller.

**Upgraded L3:**
- Iteration 1: `search_docs` summary = {param 2 reaches filter on `db`}
- Iteration 2: `ask_endpoint` calls `search_docs` with arg 2 = `user_id` (tenant-scoped from `get_current_user`) → verified
- If arg 2 were `"admin"` → `LITERAL`, not tenant-scoped → finding: "store read via `search_docs` at api.py:5 uses static identity, not authenticated user"

### 5.5 Data Model Changes

```python
# New: replaces TaintResult
@dataclass(frozen=True)
class PropertyVerification:
    """Result of verifying a security property on one access path."""
    store_id: str
    access: StoreAccess                    # the read/write operation
    property: SecurityProperty             # what we're checking
    verdict: Verdict                       # VERIFIED, VIOLATED, PARTIAL, UNKNOWN
    evidence: list[FlowStep]              # source → ... → sink trace

class Verdict(Enum):
    VERIFIED = "verified"     # property holds on this path
    VIOLATED = "violated"     # property does not hold
    PARTIAL = "partial"       # property holds conditionally (some branches)
    UNKNOWN = "unknown"       # cannot determine (unresolved calls, dynamic dispatch)

@dataclass(frozen=True)
class FlowStep:
    """One step in a tenant identity flow trace."""
    location: Provenance
    kind: str                 # "source", "propagation", "call_arg", "call_return", "sink"
    value_kind: ValueKind     # what kind of value at this step
    summary_used: str | None  # function summary that justified this step
```

---

## 6. L6 Upgrade: Interprocedural Path Coverage

### 6.1 Problem

Current L6 does path-sensitive analysis within one function: "does the filter exist on all branches of this if/else?" Good, but limited.

The real question is: "across ALL callers of this retriever, on ALL code paths, does the filter always have a tenant-scoped value?"

### 6.2 Algorithm: Caller Enumeration + Per-Caller Path Analysis

Reference: CodeQL's `DataFlow::GlobalWithState` — tracks a state lattice across interprocedural paths.

```
1. From L2 ProjectGraph, find all ReadOps for each store

2. For each ReadOp:
   a. Find all callers (transitively, up to entry points)
   b. For each caller → ReadOp path:
      - Run L6 path analysis on each function in the chain
      - Carry forward the filter state across function boundaries
      - Use L3 summaries to skip re-analysis of already-summarized functions

3. Compute coverage:
   - path_count: total number of entry_point → ReadOp paths
   - verified_count: paths where tenant-scoped filter confirmed on all branches
   - violated_count: paths where filter missing on at least one branch
   - unknown_count: paths with unresolved calls

4. Report:
   - verified_count == path_count → VERIFIED (suppress finding)
   - violated_count > 0 → finding with specific paths listed
   - unknown_count > 0 → finding with UNKNOWN confidence
```

### 6.3 Extension: Condition-Based Narrowing

Current L6 ignores `if` conditions. Upgrade to extract facts:

```python
def extract_condition_facts(test: ast.expr) -> set[Fact]:
    """Extract verifiable facts from an if-condition."""
    # if user_id is not None:
    if isinstance(test, ast.Compare) and isinstance(test.ops[0], ast.IsNot):
        if is_name(test.comparators[0], "None"):
            return {Fact(name=test.left.id, is_not_none=True)}

    # if request.user.is_authenticated:
    if isinstance(test, ast.Attribute) and test.attr == "is_authenticated":
        return {Fact(name=expr_to_str(test.value), is_authenticated=True)}

    return set()
```

When a branch condition establishes that a tenant variable is available, the filter analysis within that branch can use that fact.

### 6.4 Data Model Changes

```python
@dataclass(frozen=True)
class PathCoverage:
    """Coverage report for a security property across all access paths."""
    store_id: str
    property: SecurityProperty
    total_paths: int
    verified_paths: list[VerifiedPath]
    violated_paths: list[ViolatedPath]
    unknown_paths: list[UnknownPath]

    @property
    def coverage_ratio(self) -> float:
        return len(self.verified_paths) / self.total_paths if self.total_paths else 0.0

@dataclass(frozen=True)
class ViolatedPath:
    """A specific path where the property doesn't hold."""
    entry_point: Provenance          # where the path starts (HTTP handler, CLI, etc.)
    violation_point: Provenance      # where the filter is missing
    call_chain: list[Provenance]     # function calls from entry to violation
    branch_condition: str | None     # the if-condition that leads to the missing filter
```

---

## 7. Engine Architecture

### 7.1 Layer Execution Flow (Upgraded)

```
Framework Model (YAML/Python)
  │
  ▼
L1 Engine: Model-Driven Property Extractor
  │  Input:  AST + FrameworkModel
  │  Output: list[PropertyExtraction] + list[StoreProfile]
  │  Algorithm: AST visitor driven by model's store/method declarations
  │             Value classification on every extracted kwarg
  │             Write-read metadata consistency cross-check
  │
  ▼
L2 Engine: Assignment-Based Project Graph
  │  Input:  All source files (ASTs)
  │  Output: ProjectGraph (call edges + composition edges + identifier states)
  │  Algorithm: PyCG two-pass with fixpoint on assignments
  │             Composition patterns from FrameworkModel
  │
  ▼
L3 Engine: Fixpoint Property Verifier
  │  Input:  ProjectGraph + list[PropertyExtraction]
  │  Output: per-function TenantFlowSummary + list[PropertyVerification]
  │  Algorithm: Intraprocedural summary → interprocedural fixpoint
  │             Scoped to tenant isolation property
  │
  ▼
L6 Engine: Interprocedural Path Coverage
  │  Input:  ProjectGraph + TenantFlowSummaries + PropertyVerifications
  │  Output: list[PathCoverage] per store
  │  Algorithm: Caller enumeration + per-path lattice analysis
  │             Condition-based narrowing
  │
  ▼
Finding Synthesis
     Input:  StoreProfiles + PropertyVerifications + PathCoverages
     Output: list[Finding] with evidence_path and proof_strength
```

### 7.2 Module Structure

```
src/agentwall/
├── engine/                          # NEW: general analysis engines
│   ├── __init__.py
│   ├── extractor.py                 # L1: model-driven property extraction
│   ├── graph.py                     # L2: assignment-based project graph
│   ├── verifier.py                  # L3: fixpoint property verification
│   ├── pathcov.py                   # L6: interprocedural path coverage
│   └── models.py                    # ValueKind, PropertyExtraction, TenantFlowSummary, etc.
│
├── frameworks/                      # NEW: declarative framework models
│   ├── __init__.py
│   ├── base.py                      # FrameworkModel, StoreModel, CompositionPattern
│   ├── langchain.py                 # LangChain + all vector store models
│   ├── llamaindex.py                # LlamaIndex model (future)
│   ├── crewai.py                    # CrewAI model (future)
│   └── openai_agents.py             # OpenAI Agents SDK model (future)
│
├── analyzers/                       # EXISTING: adapted to use engines
│   ├── memory.py                    # consumes StoreProfile instead of MemoryConfig
│   ├── tools.py                     # unchanged (tool analysis is already self-contained)
│   ├── secrets.py                   # unchanged
│   ├── rag.py                       # consumes PropertyExtraction for deeper RAG analysis
│   ├── callgraph.py                 # THIN WRAPPER: delegates to engine/graph.py
│   ├── taint.py                     # THIN WRAPPER: delegates to engine/verifier.py
│   └── symbolic.py                  # THIN WRAPPER: delegates to engine/pathcov.py
```

### 7.3 Migration Strategy

Existing analyzers become thin wrappers that:
1. Call the engine
2. Convert engine output to `Finding` objects using existing rule definitions
3. Maintain backward compatibility with existing CLI output

This means: **no breaking changes to CLI, output formats, or rule IDs.** Users see better findings from the same rules.

---

## 8. What Changes Per Framework (The Abstraction Test)

To verify the engine/model split works, here's what adding LlamaIndex would require:

| Component | Work Required | Engine Changes? |
|-----------|---------------|-----------------|
| `frameworks/llamaindex.py` | ~200 lines: StoreModel entries for PineconeVectorStore, ChromaVectorStore, QdrantVectorStore, etc. | No |
| Composition patterns | LlamaIndex uses `QueryEngine(retriever=R)` not LCEL pipes. Add `FactoryPattern` entries | No |
| Auth sources | Same as LangChain (request.user, etc.) — shared | No |
| Isolation params | Pinecone uses `namespace`, not `collection_name`. Declared in StoreModel | No |
| L1 extraction | Engine reads model, extracts properties | No |
| L2 call graph | PyCG algorithm is language-level, not framework-specific | No |
| L3 verification | Same tenant isolation property, same fixpoint algorithm | No |
| L6 path coverage | Same path enumeration, same lattice | No |
| **Total engine changes** | **Zero** | **Zero** |

If this holds, the abstraction is correct.

---

## 9. Complexity Estimates

| Component | Algorithm Complexity | Estimated LOC | Dependencies |
|-----------|---------------------|---------------|--------------|
| `engine/extractor.py` | AST visitor + value classifier | ~400 | ast (stdlib) |
| `engine/graph.py` | PyCG two-pass + fixpoint + composition patterns + single-level inheritance. No type inference, no dynamic dispatch | ~600 | ast (stdlib) |
| `engine/verifier.py` | Per-function summary + fixpoint | ~500 | engine/graph |
| `engine/pathcov.py` | Caller enumeration + lattice | ~400 | engine/graph, engine/verifier |
| `engine/models.py` | Data classes | ~300 | pydantic |
| `frameworks/base.py` | Model schema | ~200 | pydantic |
| `frameworks/langchain.py` | LangChain model declarations | ~300 | frameworks/base |
| Analyzer wrappers (adapt existing) | Thin delegation | ~200 (net reduction) | engine/* |
| **Total new code** | | **~2,900** | |
| **Code replaced** | | **~1,500** (from current analyzers) | |
| **Net addition** | | **~1,400** | |

---

## 10. Verification Plan

### 10.1 Correctness: BENCHMARK3000 Regression

Run upgraded engine against all 107 BENCHMARK3000 projects. For each:
- **True positives must not decrease.** Every finding currently emitted must still be emitted (possibly with better evidence/confidence).
- **False positives should decrease.** Measure FP rate before/after on manually-labeled subset (10 projects).
- **New true positives.** Count findings that upgraded engine catches but current engine misses.

### 10.2 Performance: Must Not Regress

| Metric | Current | Target |
|--------|---------|--------|
| Scan time (Langflow, 1274 files) | ~8s | < 15s |
| Scan time (LangChain mono, 1669 files) | ~12s | < 20s |
| Memory usage | < 500MB | < 1GB |
| Fixpoint iterations (typical) | N/A | < 10 |

### 10.3 Abstraction Test

After LangChain model works:
1. Write LlamaIndex model (~200 lines)
2. Run against LlamaIndex project (2,382 files, 91 findings currently)
3. **Must produce ≥ 91 findings with zero engine changes**
4. If engine changes needed → abstraction is leaking → fix before proceeding

---

## 11. Implementation Order

| Phase | What | Depends On | Validates |
|-------|------|------------|-----------|
| **Phase 1** | `engine/models.py` + `frameworks/base.py` — data models and framework model schema | Nothing | Schema design |
| **Phase 2** | `frameworks/langchain.py` — declare LangChain model | Phase 1 | Model expressiveness |
| **Phase 3** | `engine/extractor.py` — L1 engine with value classification | Phase 1, 2 | Property extraction against BENCHMARK3000 |
| **Phase 4** | `engine/graph.py` — L2 PyCG-style call graph | Phase 1 | Import resolution, composition detection |
| **Phase 5** | `engine/verifier.py` — L3 fixpoint verification | Phase 3, 4 | Interprocedural tenant flow |
| **Phase 6** | `engine/pathcov.py` — L6 path coverage | Phase 4, 5 | Per-path reporting |
| **Phase 7** | Migrate analyzers to thin wrappers | Phase 3–6 | BENCHMARK3000 regression |
| **Phase 8** | `frameworks/llamaindex.py` — abstraction test | Phase 7 | Zero engine changes |

---

## 12. Risks

| Risk | Impact | Mitigation |
|------|--------|------------|
| PyCG algorithm doesn't handle LangChain's dynamic patterns (plugins, LCEL) | L2 misses composition edges | Composition graph is a separate layer on top of call graph — handles framework-specific patterns via model. Dynamic dispatch explicitly marked UNKNOWN, not silently dropped |
| Single-level inheritance misses deep hierarchies | Custom subclass of a subclass not resolved | Rare in agent code. If encountered, extend to 2-level. Do NOT build full MRO — YAGNI |
| Fixpoint doesn't converge on recursive agent patterns | L3 hangs | Cap iterations at 20. If not converged, mark affected functions as UNKNOWN |
| Framework model DSL can't express a real pattern | Abstraction leaks, requires engine change | Start with Python dataclasses, not YAML. Easier to extend. Graduate to YAML/TOML once stable |
| Performance regression from interprocedural analysis | Scan time > 30s on large projects | PyCG handles 1K LOC in 0.38s. AgentWall scans ~30K files total. Budget: 15s for graph construction |
| Migration breaks existing output | Users see different findings | Phase 7 runs both old and new in parallel, diffs output, fixes discrepancies before cutover |

---

## 13. References

- [PyCG: Practical Call Graph Generation in Python (ICSE '21)](https://arxiv.org/pdf/2103.00587) — L2 algorithm
- [Pysa fixpointAnalysis.ml](https://github.com/facebook/pyre-check/blob/main/source/interprocedural/fixpointAnalysis.ml) — L3 algorithm
- [CodeQL GlobalWithState](https://codeql.github.com/docs/codeql-language-guides/using-flow-labels-for-precise-data-flow-analysis/) — L6 concept
- [Semgrep Taint Mode](https://semgrep.dev/docs/writing-rules/data-flow/taint-mode/overview) — Declarative source/sink model
- [Joern CPG Specification 1.1](https://cpg.joern.io/) — Unified graph representation concept
