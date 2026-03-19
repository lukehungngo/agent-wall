# AgentWall Benchmark 3000

**Date:** 2026-03-20
**Version:** 0.1.0
**Layers enabled:** L0–L6 (default static analysis)
**Projects:** 107
**Reproduce:** `./scripts/benchmark3000.sh`

---

## 1. Tier 1 — LangChain Ecosystem (>2k stars)

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Langchain-Chatchat | ~37k | 239 | 24 | 15 | 5 | 3 | 1 | AW-MEM-001(15), AW-MEM-003(3), AW-MEM-005(3) |
| 2 | PrivateGPT | ~54k | 65 | 0 | 0 | 0 | 0 | 0 | — |
| 3 | Quivr | ~36k | 41 | 2 | 2 | 0 | 0 | 0 | AW-MEM-001(2) |
| 4 | LocalGPT | ~22k | 44 | 0 | 0 | 0 | 0 | 0 | — |
| 5 | DocsGPT | ~15k | 208 | 9 | 4 | 2 | 2 | 1 | AW-MEM-001(4), AW-MEM-003(1), AW-MEM-002(1) |
| 6 | GPT-Researcher | ~17k | 166 | 3 | 2 | 0 | 0 | 1 | AW-MEM-001(2), AW-TOOL-004(1) |
| 7 | Onyx/Danswer | ~12k | 1406 | 6 | 1 | 1 | 2 | 2 | AW-TOOL-004(2), AW-MEM-001(1), AW-MEM-003(1) |
| 8 | DB-GPT | ~17k | 1004 | 6 | 2 | 2 | 2 | 0 | AW-MEM-001(2), AW-TOOL-001(1), AW-MEM-003(1) |
| 9 | Chat-LangChain | ~6k | 11 | 0 | 0 | 0 | 0 | 0 | — |
| 10 | RasaGPT | ~2.4k | 11 | 0 | 0 | 0 | 0 | 0 | — |
| 11 | Langflow | ~48k | 1274 | 60 | 30 | 13 | 13 | 4 | AW-MEM-001(30), AW-MEM-003(11), AW-MEM-005(11) |
| 12 | Flowise | ~35k | - | - | - | - | - | - | not scanned |
| 13 | Open Interpreter | ~58k | - | - | - | - | - | - | not scanned |
| 14 | Chainlit | ~8k | 121 | 0 | 0 | 0 | 0 | 0 | — |
| 15 | Mem0/Embedchain | ~48k | 371 | 9 | 4 | 2 | 2 | 1 | AW-MEM-001(4), AW-MEM-003(2), AW-MEM-005(2) |
| 16 | LLM App (Pathway) | ~4k | 17 | 0 | 0 | 0 | 0 | 0 | — |
| 17 | Haystack | ~18k | - | - | - | - | - | - | not scanned |
| 18 | SuperAgent | ~5k | 22 | 0 | 0 | 0 | 0 | 0 | — |
| 19 | AgentGPT | ~32k | 85 | 0 | 0 | 0 | 0 | 0 | — |
| 20 | AutoGPT | ~172k | - | - | - | - | - | - | not scanned |
| 21 | LangGraph | ~45k | 173 | 0 | 0 | 0 | 0 | 0 | — |
| 22 | LangSmith SDK | ~1k | 81 | 0 | 0 | 0 | 0 | 0 | — |
| 23 | LangChain (mono) | ~100k | 1669 | 25 | 16 | 6 | 2 | 1 | AW-MEM-001(17), AW-MEM-002(3), AW-MEM-004(1) |
| 24 | OpenGPTs | ~6k | 28 | 15 | 0 | 2 | 0 | 13 | AW-TOOL-004(13), AW-CFG-no-tls(1), AW-MEM-002(1) |
| 25 | LangServe | ~2k | 13 | 0 | 0 | 0 | 0 | 0 | — |
| 26 | LangChain Extract | ~1k | 20 | 1 | 1 | 0 | 0 | 0 | AW-MEM-001(1) |
| 27 | Awesome LLM Apps | ~60k | - | - | - | - | - | - | not scanned |

**Totals: 160 findings (77 CRITICAL, 33 HIGH) across 7069 files. 11/27 have findings.**

---

## 2. Tier 2 — LlamaIndex Ecosystem

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | LlamaIndex | ~47k | 2382 | 38 | 31 | 3 | 3 | 1 | AW-MEM-001(31), AW-MEM-003(3), AW-MEM-005(3) |
| 2 | RAGS (LlamaIndex) | ~6k | 15 | 1 | 1 | 0 | 0 | 0 | AW-MEM-001(1) |
| 3 | LlamaParse | ~3k | - | - | - | - | - | - | not scanned |
| 4 | create-llama | ~2k | - | - | - | - | - | - | not scanned |
| 5 | SEC Insights | ~2k | - | - | - | - | - | - | not scanned |

**Totals: 39 findings (32 CRITICAL, 3 HIGH) across 2397 files. 2/5 have findings.**

---

## 3. Tier 3 — Multi-Agent Frameworks

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CrewAI | ~46k | 749 | 109 | 0 | 40 | 32 | 37 | AW-TOOL-004(37), AW-CFG-hardcoded-secret(33), AW-TOOL-002(25) |
| 2 | AutoGen | ~48k | - | - | - | - | - | - | not scanned |
| 3 | MetaGPT | ~58k | - | - | - | - | - | - | not scanned |
| 4 | ChatDev | ~25k | - | - | - | - | - | - | not scanned |
| 5 | CAMEL | ~10k | - | - | - | - | - | - | not scanned |
| 6 | BabyAGI | ~20k | - | - | - | - | - | - | not scanned |
| 7 | OpenAI Swarm | ~18k | - | - | - | - | - | - | not scanned |
| 8 | Swarms | ~4k | - | - | - | - | - | - | not scanned |
| 9 | TaskWeaver | ~5k | 136 | 2 | 2 | 0 | 0 | 0 | AW-MEM-001(2) |

**Totals: 111 findings (2 CRITICAL, 40 HIGH) across 885 files. 2/9 have findings.**

---

## 4. Tier 4 — RAG Applications

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | RAGFlow | ~70k | - | - | - | - | - | - | not scanned |
| 2 | Kotaemon | ~25k | 232 | 5 | 0 | 0 | 0 | 5 | AW-TOOL-004(5) |
| 3 | LightRAG | ~30k | 75 | 6 | 2 | 2 | 2 | 0 | AW-MEM-001(2), AW-MEM-003(2), AW-MEM-005(2) |
| 4 | FastGPT | ~27k | - | - | - | - | - | - | not scanned |
| 5 | QAnything | ~12k | 148 | 0 | 0 | 0 | 0 | 0 | — |
| 6 | R2R | ~4k | - | - | - | - | - | - | not scanned |
| 7 | FlashRAG | ~2k | - | - | - | - | - | - | not scanned |
| 8 | AutoRAG | ~3k | 177 | 0 | 0 | 0 | 0 | 0 | — |
| 9 | Canopy (Pinecone) | ~3k | 80 | 0 | 0 | 0 | 0 | 0 | — |
| 10 | Verba (Weaviate) | ~6k | 53 | 0 | 0 | 0 | 0 | 0 | — |
| 11 | Vanna | ~13k | 262 | 22 | 12 | 5 | 5 | 0 | AW-MEM-001(12), AW-MEM-003(5), AW-MEM-005(5) |
| 12 | Cognita | ~8k | 73 | 1 | 0 | 0 | 1 | 0 | AW-CFG-docker-no-auth(1) |
| 13 | ChatGPT Retrieval Plugin | ~21k | - | - | - | - | - | - | not scanned |
| 14 | txtai | ~10k | - | - | - | - | - | - | not scanned |

**Totals: 34 findings (14 CRITICAL, 7 HIGH) across 1100 files. 4/14 have findings.**

---

## 5. Tier 5 — Vector Store Ecosystems

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | ChromaDB | ~17k | 148 | 0 | 0 | 0 | 0 | 0 | — |
| 2 | Milvus Bootcamp | ~2k | 78 | 7 | 2 | 1 | 4 | 0 | AW-CFG-docker-no-auth(3), AW-MEM-001(2), AW-MEM-003(1) |
| 3 | Qdrant Examples | ~500 | - | - | - | - | - | - | not scanned |
| 4 | LanceDB | ~5k | - | - | - | - | - | - | not scanned |

**Totals: 7 findings (2 CRITICAL, 1 HIGH) across 226 files. 1/4 have findings.**

---

## 6. Tier 6 — Memory & Knowledge Systems

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Cognee | ~12k | 950 | 15 | 2 | 9 | 4 | 0 | AW-CFG-hardcoded-secret(5), AW-MEM-001(2), AW-CFG-no-password(2) |
| 2 | Graphiti (Zep) | ~14k | 178 | 0 | 0 | 0 | 0 | 0 | — |
| 3 | Letta (MemGPT) | ~22k | 690 | 6 | 1 | 1 | 1 | 3 | AW-TOOL-004(3), AW-MEM-001(1), AW-MEM-003(1) |
| 4 | GraphRAG (Microsoft) | ~22k | - | - | - | - | - | - | not scanned |
| 5 | nano-graphrag | ~5k | - | - | - | - | - | - | not scanned |
| 6 | Zep | ~3k | - | - | - | - | - | - | not scanned |

**Totals: 21 findings (3 CRITICAL, 10 HIGH) across 1818 files. 2/6 have findings.**

---

## 7. Tier 7 — Chatbot / Assistant Frameworks

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Open WebUI | ~124k | 163 | 4 | 1 | 1 | 1 | 1 | AW-MEM-001(1), AW-MEM-003(1), AW-MEM-005(1) |
| 2 | LibreChat | ~30k | - | - | - | - | - | - | not scanned |
| 3 | Khoj | ~33k | 110 | 0 | 0 | 0 | 0 | 0 | — |
| 4 | AnythingLLM | ~35k | - | - | - | - | - | - | not scanned |
| 5 | PyGPT | ~3k | 1190 | 23 | 3 | 0 | 2 | 18 | AW-TOOL-004(18), AW-MEM-001(3), AW-TOOL-002(2) |
| 6 | Jan | ~25k | - | - | - | - | - | - | not scanned |

**Totals: 27 findings (4 CRITICAL, 1 HIGH) across 1463 files. 2/6 have findings.**

---

## 8. Tier 8 — Code / Dev Agents

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | OpenHands (OpenDevin) | ~65k | - | - | - | - | - | - | not scanned |
| 2 | SWE-agent | ~15k | - | - | - | - | - | - | not scanned |
| 3 | Aider | ~36k | - | - | - | - | - | - | not scanned |
| 4 | Devika | ~18k | - | - | - | - | - | - | not scanned |
| 5 | GPT-Engineer | ~52k | 43 | 2 | 0 | 2 | 0 | 0 | AW-CFG-hardcoded-secret(2) |
| 6 | GPT-Pilot | ~32k | - | - | - | - | - | - | not scanned |

**Totals: 2 findings (0 CRITICAL, 2 HIGH) across 43 files. 1/6 have findings.**

---

## 9. Tier 9 — Production Agent Platforms

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Dify | ~129k | - | - | - | - | - | - | not scanned |
| 2 | Agno (Phidata) | ~19k | - | - | - | - | - | - | not scanned |
| 3 | Pydantic AI | ~15k | - | - | - | - | - | - | not scanned |
| 4 | smolagents (HF) | ~26k | - | - | - | - | - | - | not scanned |
| 5 | Semantic Kernel | ~22k | - | - | - | - | - | - | not scanned |
| 6 | OpenAI Agents SDK | ~7k | - | - | - | - | - | - | not scanned |
| 7 | DSPy | ~20k | 140 | 2 | 0 | 0 | 0 | 2 | AW-TOOL-004(2) |
| 8 | Google Agent Dev Kit | ~18k | 822 | 9 | 1 | 2 | 3 | 3 | AW-TOOL-004(3), AW-TOOL-001(2), AW-TOOL-003(2) |
| 9 | UFO (Microsoft) | ~5k | 291 | 2 | 1 | 1 | 0 | 0 | AW-MEM-001(1), AW-MEM-002(1) |
| 10 | AgentOps | ~3k | - | - | - | - | - | - | not scanned |
| 11 | ModelScope Agent | ~3k | - | - | - | - | - | - | not scanned |

**Totals: 13 findings (2 CRITICAL, 3 HIGH) across 1253 files. 3/11 have findings.**

---

## 10. Tier 10 — Small / Niche Projects

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | memory-agent | 416 | 7 | 0 | 0 | 0 | 0 | 0 | — |
| 2 | rag-research-agent-template | 295 | 17 | 0 | 0 | 0 | 0 | 0 | — |
| 3 | langchain-chatbot | 273 | 9 | 6 | 2 | 4 | 0 | 0 | AW-MEM-004(4), AW-MEM-001(2) |
| 4 | chat-with-websites | 260 | 1 | 1 | 1 | 0 | 0 | 0 | AW-MEM-001(1) |
| 5 | cohere-qdrant-doc-retrieval | 152 | 1 | 4 | 2 | 1 | 1 | 0 | AW-MEM-001(2), AW-MEM-003(1), AW-MEM-005(1) |
| 6 | RAG-chatbot-langchain | 133 | 1 | 6 | 2 | 3 | 1 | 0 | AW-MEM-001(2), AW-MEM-004(2), AW-MEM-003(1) |
| 7 | langchain-RAG-chroma | 8 | 1 | 4 | 2 | 1 | 1 | 0 | AW-MEM-001(2), AW-MEM-003(1), AW-MEM-005(1) |
| 8 | chat-with-pdf | 2 | 1 | 0 | 0 | 0 | 0 | 0 | — |
| 9 | langchain-multi-agent | 10 | 1 | 4 | 1 | 2 | 1 | 0 | AW-CFG-hardcoded-secret(2), AW-MEM-001(1), AW-TOOL-002(1) |
| 10 | objectbox-rag | 10 | 3 | 0 | 0 | 0 | 0 | 0 | — |
| 11 | AdalFlow | ~3k | - | - | - | - | - | - | not scanned |
| 12 | Hindsight | ~4k | - | - | - | - | - | - | not scanned |
| 13 | Vector Admin | ~2k | - | - | - | - | - | - | not scanned |
| 14 | HF Agents Course | ~5k | - | - | - | - | - | - | not scanned |
| 15 | Libre Chat | ~500 | - | - | - | - | - | - | not scanned |
| 16 | LangGraph BigTool | ~500 | 4 | 0 | 0 | 0 | 0 | 0 | — |
| 17 | RAG-Anything | ~1k | - | - | - | - | - | - | not scanned |
| 18 | OASIS (CAMEL) | ~2k | 45 | 3 | 1 | 1 | 1 | 0 | AW-MEM-001(1), AW-MEM-003(1), AW-MEM-005(1) |
| 19 | SWE-bench | ~4k | - | - | - | - | - | - | not scanned |

**Totals: 28 findings (11 CRITICAL, 12 HIGH) across 91 files. 7/19 have findings.**

---

## 11. Grand Summary

| Metric | Value |
|---|---|
| Total projects | 107 |
| Projects scanned | 58 |
| Projects with findings | 35 (60%) |
| Total files scanned | 16,345 |
| Total findings | 442 |
| CRITICAL | 147 |
| HIGH | 112 |
| Findings per file | 0.027 |

### Category Comparison

| Category | Projects | Scanned | With Findings | Findings | CRIT | HIGH | Files |
|---|---|---|---|---|---|---|---|
| LangChain Ecosystem (>2k stars) | 27 | 22 | 11 | 160 | 77 | 33 | 7,069 |
| LlamaIndex Ecosystem | 5 | 2 | 2 | 39 | 32 | 3 | 2,397 |
| Multi-Agent Frameworks | 9 | 2 | 2 | 111 | 2 | 40 | 885 |
| RAG Applications | 14 | 8 | 4 | 34 | 14 | 7 | 1,100 |
| Vector Store Ecosystems | 4 | 2 | 1 | 7 | 2 | 1 | 226 |
| Memory & Knowledge Systems | 6 | 3 | 2 | 21 | 3 | 10 | 1,818 |
| Chatbot / Assistant Frameworks | 6 | 3 | 2 | 27 | 4 | 1 | 1,463 |
| Code / Dev Agents | 6 | 1 | 1 | 2 | 0 | 2 | 43 |
| Production Agent Platforms | 11 | 3 | 3 | 13 | 2 | 3 | 1,253 |
| Small / Niche Projects | 19 | 12 | 7 | 28 | 11 | 12 | 91 |

---

## 12. Rule Distribution

| Rule | Count | % | Description |
|---|---|---|---|
| AW-MEM-001 | 148 | 33% | No tenant isolation in vector store |
| AW-TOOL-004 | 93 | 21% | Tool has no description |
| AW-CFG-hardcoded-secret | 42 | 10% | AW-CFG-hardcoded-secret |
| AW-MEM-003 | 39 | 9% | Memory backend has no access control |
| AW-MEM-005 | 39 | 9% | No sanitization on retrieved memory |
| AW-TOOL-002 | 29 | 7% | Tool accepts arbitrary code execution |
| AW-TOOL-001 | 12 | 3% | Destructive tool without approval gate |
| AW-TOOL-003 | 12 | 3% | High-risk tool lacks scope check |
| AW-MEM-002 | 9 | 2% | Shared collection without retrieval filter |
| AW-CFG-docker-no-auth | 9 | 2% | AW-CFG-docker-no-auth |
| AW-MEM-004 | 7 | 2% | Injection patterns in retrieval path |
| AW-CFG-no-password | 2 | 0% | AW-CFG-no-password |
| AW-CFG-no-tls | 1 | 0% | AW-CFG-no-tls |

---

## 13. Attack Vector Coverage (9 / 35 Detectable)

| Category | Detected | Total | Coverage |
|---|---|---|---|
| **MEM** — Memory Isolation | 4 | 4 | 100% |
| **POI** — Data Poisoning | 0 | 6 | 0% |
| **EMB** — Embedding Attacks | 0 | 5 | 0% |
| **INJ** — Prompt Injection | 1 | 3 | 33% |
| **EXF** — Exfiltration | 0 | 3 | 0% |
| **CFG** — Configuration | 3 | 6 | 50% |
| **DOS** — Denial of Service | 0 | 3 | 0% |
| **AGT** — Agentic Attacks | 1 | 5 | 20% |

### Attack Vectors Confirmed in Real-World Projects

| Attack Vector | Description | Projects Affected | Hits | Example Evidence |
|---|---|---|---|---|
| **AW-ATK-AGT-001** | Tool Poisoning / Unsafe Tool Access | CrewAI, DB-GPT, Google Agent Dev Kit, LangChain (mono), Langflow, PyGPT, langchain-multi-agent | 53 | `react_action.py:17` (AW-TOOL-001) |
| **AW-ATK-CFG-003** | No TLS / No Auth / Exposed Ports | Cognee, Cognita, DocsGPT, Langflow, Milvus Bootcamp, Onyx/Danswer, OpenGPTs | 12 | `docker-compose.yml:27` (AW-CFG-no-tls) |
| **AW-ATK-CFG-004** | Hardcoded API Keys | Cognee, CrewAI, GPT-Engineer, langchain-multi-agent | 42 | `.env.test:12` (AW-CFG-hardcoded-secret) |
| **AW-ATK-INJ-001** | Stored Prompt Injection | Cognee, DB-GPT, DocsGPT, LangChain (mono), Langchain-Chatchat, Langflow, Letta (MemGPT), LightRAG, LlamaIndex, Mem0/Embedchain (+8 more) | 39 | `chromadb_kb_service.py:67` (AW-MEM-005) |
| **AW-ATK-MEM-001** | Cross-Tenant Retrieval (No Filter) | Cognee, DB-GPT, DocsGPT, GPT-Researcher, Google Agent Dev Kit, LangChain (mono), LangChain Extract, Langchain-Chatchat, Langflow, Letta (MemGPT) (+19 more) | 148 | `chromadb_kb_service.py:67` (AW-MEM-001) |
| **AW-ATK-MEM-002** | Weak Tenant Isolation (Static Filter) | DocsGPT, LangChain (mono), Langchain-Chatchat, Langflow, OpenGPTs, UFO (Microsoft) | 9 | `ensemble.py:27` (AW-MEM-002) |
| **AW-ATK-MEM-003** | Namespace/Collection Confusion | Cognee, DB-GPT, DocsGPT, LangChain (mono), Langchain-Chatchat, Langflow, Letta (MemGPT), LightRAG, LlamaIndex, Mem0/Embedchain (+8 more) | 39 | `chromadb_kb_service.py:67` (AW-MEM-003) |
| **AW-ATK-MEM-004** | Partition Bypass via Direct API | LangChain (mono), RAG-chatbot-langchain, langchain-chatbot | 7 | `vectorstore_token_buffer_memory.py:120` (AW-MEM-004) |

### Vectors Not Detected (26 / 35)

| Vector | Description | Reason |
|---|---|---|
| AW-ATK-AGT-002 | Delegation Chain Escalation | Requires multi-agent delegation graph |
| AW-ATK-AGT-003 | Memory-Mediated Identity Hijacking | Requires agent identity redefinition detection |
| AW-ATK-AGT-004 | Cross-Agent Memory Contamination | Requires multi-agent shared memory provenance |
| AW-ATK-AGT-005 | Conversation History Replay | Requires session management analysis |
| AW-ATK-CFG-002 | No Encryption at Rest | Requires vector DB config schema inspection |
| AW-ATK-CFG-005 | Missing RBAC | Requires vector DB RBAC/ACL audit |
| AW-ATK-CFG-006 | No Row-Level Security | Requires PostgreSQL RLS policy inspection |
| AW-ATK-DOS-001 | Embedding Flood | Requires rate-limit config audit |
| AW-ATK-DOS-002 | Query Amplification | Requires parameter bounds checking |
| AW-ATK-DOS-003 | Collection Deletion via Admin | Requires admin endpoint auth audit |
| AW-ATK-EMB-001 | Vector Collision Attack | Requires embedding model invocation |
| AW-ATK-EMB-002 | Semantic Cache Poisoning | Requires semantic cache identification |
| AW-ATK-EMB-003 | Embedding Inversion | Requires embedding model + inversion validation |
| AW-ATK-EMB-004 | Adversarial Multi-Modal Embedding | Requires multi-modal model analysis |
| AW-ATK-EMB-005 | Vector Drift | Requires embedding lifecycle tracking |
| AW-ATK-EXF-001 | Membership Inference | Requires runtime: membership inference |
| AW-ATK-EXF-002 | Embedding Exfiltration via API | Requires runtime: embedding extraction |
| AW-ATK-EXF-003 | Timing Side-Channel | Requires runtime: timing measurement |
| AW-ATK-INJ-002 | Cross-Session Context Hijacking | Requires session identity tracking |
| AW-ATK-INJ-003 | EchoLeak | Requires action execution tracing |
| AW-ATK-POI-001 | PoisonedRAG | Requires runtime: inject docs, measure ranking |
| AW-ATK-POI-002 | CorruptRAG | Requires runtime: single-doc injection |
| AW-ATK-POI-003 | MINJA | Requires runtime: query-only memory injection |
| AW-ATK-POI-004 | Persistent Memory Poisoning | Requires runtime: time-delayed session analysis |
| AW-ATK-POI-005 | Document Loader Exploitation | Requires binary analysis: PDF/DOCX hidden content |
| AW-ATK-POI-006 | Training Data Backdoor | Requires tracking memory→fine-tuning pipeline |

---

## 14. Attack Vector Heatmap (Per Project)

| Project | AGT-001 | CFG-001 | CFG-003 | CFG-004 | INJ-001 | MEM-001 | MEM-002 | MEM-003 | MEM-004 | Total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Langchain-Chatchat | · | · | · | · | **3** | **15** | **2** | **3** | · | 23 |
| PrivateGPT | · | · | · | · | · | · | · | · | · | 0 |
| Quivr | · | · | · | · | · | **2** | · | · | · | 2 |
| LocalGPT | · | · | · | · | · | · | · | · | · | 0 |
| DocsGPT | · | · | **1** | · | **1** | **4** | **1** | **1** | · | 8 |
| GPT-Researcher | · | · | · | · | · | **2** | · | · | · | 2 |
| Onyx/Danswer | · | · | **1** | · | **1** | **1** | · | **1** | · | 4 |
| DB-GPT | **2** | · | · | · | **1** | **2** | · | **1** | · | 6 |
| Chat-LangChain | · | · | · | · | · | · | · | · | · | 0 |
| RasaGPT | · | · | · | · | · | · | · | · | · | 0 |
| Langflow | **2** | · | **1** | · | **11** | **30** | **1** | **11** | · | 56 |
| Flowise | — | — | — | — | — | — | — | — | — | — |
| Open Interpreter | — | — | — | — | — | — | — | — | — | — |
| Chainlit | · | · | · | · | · | · | · | · | · | 0 |
| Mem0/Embedchain | · | · | · | · | **2** | **4** | · | **2** | · | 8 |
| LLM App (Pathway) | · | · | · | · | · | · | · | · | · | 0 |
| Haystack | — | — | — | — | — | — | — | — | — | — |
| SuperAgent | · | · | · | · | · | · | · | · | · | 0 |
| AgentGPT | · | · | · | · | · | · | · | · | · | 0 |
| AutoGPT | — | — | — | — | — | — | — | — | — | — |
| LangGraph | · | · | · | · | · | · | · | · | · | 0 |
| LangSmith SDK | · | · | · | · | · | · | · | · | · | 0 |
| LangChain (mono) | **2** | · | · | · | **1** | **17** | **3** | **1** | **1** | 25 |
| OpenGPTs | · | · | **1** | · | · | · | **1** | · | · | 2 |
| LangServe | · | · | · | · | · | · | · | · | · | 0 |
| LangChain Extract | · | · | · | · | · | **1** | · | · | · | 1 |
| Awesome LLM Apps | — | — | — | — | — | — | — | — | — | — |
| LlamaIndex | · | · | · | · | **3** | **31** | · | **3** | · | 37 |
| RAGS (LlamaIndex) | · | · | · | · | · | **1** | · | · | · | 1 |
| LlamaParse | — | — | — | — | — | — | — | — | — | — |
| create-llama | — | — | — | — | — | — | — | — | — | — |
| SEC Insights | — | — | — | — | — | — | — | — | — | — |
| CrewAI | **39** | · | · | **33** | · | · | · | · | · | 72 |
| AutoGen | — | — | — | — | — | — | — | — | — | — |
| MetaGPT | — | — | — | — | — | — | — | — | — | — |
| ChatDev | — | — | — | — | — | — | — | — | — | — |
| CAMEL | — | — | — | — | — | — | — | — | — | — |
| BabyAGI | — | — | — | — | — | — | — | — | — | — |
| OpenAI Swarm | — | — | — | — | — | — | — | — | — | — |
| Swarms | — | — | — | — | — | — | — | — | — | — |
| TaskWeaver | · | · | · | · | · | **2** | · | · | · | 2 |
| RAGFlow | — | — | — | — | — | — | — | — | — | — |
| Kotaemon | · | · | · | · | · | · | · | · | · | 0 |
| LightRAG | · | · | · | · | **2** | **2** | · | **2** | · | 6 |
| FastGPT | — | — | — | — | — | — | — | — | — | — |
| QAnything | · | · | · | · | · | · | · | · | · | 0 |
| R2R | — | — | — | — | — | — | — | — | — | — |
| FlashRAG | — | — | — | — | — | — | — | — | — | — |
| AutoRAG | · | · | · | · | · | · | · | · | · | 0 |
| Canopy (Pinecone) | · | · | · | · | · | · | · | · | · | 0 |
| Verba (Weaviate) | · | · | · | · | · | · | · | · | · | 0 |
| Vanna | · | · | · | · | **5** | **12** | · | **5** | · | 22 |
| Cognita | · | · | **1** | · | · | · | · | · | · | 1 |
| ChatGPT Retrieval Plugin | — | — | — | — | — | — | — | — | — | — |
| txtai | — | — | — | — | — | — | — | — | — | — |
| ChromaDB | · | · | · | · | · | · | · | · | · | 0 |
| Milvus Bootcamp | · | · | **3** | · | **1** | **2** | · | **1** | · | 7 |
| Qdrant Examples | — | — | — | — | — | — | — | — | — | — |
| LanceDB | — | — | — | — | — | — | — | — | — | — |
| Cognee | · | · | **4** | **5** | **2** | **2** | · | **2** | · | 15 |
| Graphiti (Zep) | · | · | · | · | · | · | · | · | · | 0 |
| Letta (MemGPT) | · | · | · | · | **1** | **1** | · | **1** | · | 3 |
| GraphRAG (Microsoft) | — | — | — | — | — | — | — | — | — | — |
| nano-graphrag | — | — | — | — | — | — | — | — | — | — |
| Zep | — | — | — | — | — | — | — | — | — | — |
| Open WebUI | · | · | · | · | **1** | **1** | · | **1** | · | 3 |
| LibreChat | — | — | — | — | — | — | — | — | — | — |
| Khoj | · | · | · | · | · | · | · | · | · | 0 |
| AnythingLLM | — | — | — | — | — | — | — | — | — | — |
| PyGPT | **2** | · | · | · | · | **3** | · | · | · | 5 |
| Jan | — | — | — | — | — | — | — | — | — | — |
| OpenHands (OpenDevin) | — | — | — | — | — | — | — | — | — | — |
| SWE-agent | — | — | — | — | — | — | — | — | — | — |
| Aider | — | — | — | — | — | — | — | — | — | — |
| Devika | — | — | — | — | — | — | — | — | — | — |
| GPT-Engineer | · | · | · | **2** | · | · | · | · | · | 2 |
| GPT-Pilot | — | — | — | — | — | — | — | — | — | — |
| Dify | — | — | — | — | — | — | — | — | — | — |
| Agno (Phidata) | — | — | — | — | — | — | — | — | — | — |
| Pydantic AI | — | — | — | — | — | — | — | — | — | — |
| smolagents (HF) | — | — | — | — | — | — | — | — | — | — |
| Semantic Kernel | — | — | — | — | — | — | — | — | — | — |
| OpenAI Agents SDK | — | — | — | — | — | — | — | — | — | — |
| DSPy | · | · | · | · | · | · | · | · | · | 0 |
| Google Agent Dev Kit | **5** | · | · | · | · | **1** | · | · | · | 6 |
| UFO (Microsoft) | · | · | · | · | · | **1** | **1** | · | · | 2 |
| AgentOps | — | — | — | — | — | — | — | — | — | — |
| ModelScope Agent | — | — | — | — | — | — | — | — | — | — |
| memory-agent | · | · | · | · | · | · | · | · | · | 0 |
| rag-research-agent-template | · | · | · | · | · | · | · | · | · | 0 |
| langchain-chatbot | · | · | · | · | · | **2** | · | · | **4** | 6 |
| chat-with-websites | · | · | · | · | · | **1** | · | · | · | 1 |
| cohere-qdrant-doc-retrieval | · | · | · | · | **1** | **2** | · | **1** | · | 4 |
| RAG-chatbot-langchain | · | · | · | · | **1** | **2** | · | **1** | **2** | 6 |
| langchain-RAG-chroma | · | · | · | · | **1** | **2** | · | **1** | · | 4 |
| chat-with-pdf | · | · | · | · | · | · | · | · | · | 0 |
| langchain-multi-agent | **1** | · | · | **2** | · | **1** | · | · | · | 4 |
| objectbox-rag | · | · | · | · | · | · | · | · | · | 0 |
| AdalFlow | — | — | — | — | — | — | — | — | — | — |
| Hindsight | — | — | — | — | — | — | — | — | — | — |
| Vector Admin | — | — | — | — | — | — | — | — | — | — |
| HF Agents Course | — | — | — | — | — | — | — | — | — | — |
| Libre Chat | — | — | — | — | — | — | — | — | — | — |
| LangGraph BigTool | · | · | · | · | · | · | · | · | · | 0 |
| RAG-Anything | — | — | — | — | — | — | — | — | — | — |
| OASIS (CAMEL) | · | · | · | · | **1** | **1** | · | **1** | · | 3 |
| SWE-bench | — | — | — | — | — | — | — | — | — | — |

*Legend: number = findings count, · = not detected, — = not scanned*

---

## 15. How to Reproduce

```bash
pip install -e ".[dev]"
./scripts/benchmark3000.sh
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MAX_PARALLEL` | 4 | Parallel git clone jobs |
| `SCAN_TIMEOUT` | 300 | Per-project scan timeout (seconds) |
