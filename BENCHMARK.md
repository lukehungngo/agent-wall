# AgentWall Benchmark Report

**Date:** 2026-03-18
**Version:** 0.1.0 (Phase 1 complete)
**Layers enabled:** L0–L6 (default static analysis)
**Reproduce:** `./scripts/benchmark.sh`

---

## 1. Tier 1 — Established Projects (>2k stars)

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Langchain-Chatchat | ~37k | 239 | 23 | 14 | 5 | 3 | 1 | AW-MEM-001(14), AW-MEM-003(3), AW-MEM-005(3) |
| 2 | PrivateGPT | ~54k | 65 | 0 | 0 | 0 | 0 | 0 | — |
| 3 | Quivr | ~36k | 41 | 2 | 2 | 0 | 0 | 0 | AW-MEM-001(2) |
| 4 | LocalGPT | ~22k | 44 | 0 | 0 | 0 | 0 | 0 | — |
| 5 | DocsGPT | ~15k | 208 | 8 | 3 | 2 | 2 | 1 | AW-MEM-001(3), AW-MEM-003(1), AW-MEM-002(1) |
| 6 | GPT-Researcher | ~17k | 166 | 3 | 2 | 0 | 0 | 1 | AW-MEM-001(2), AW-TOOL-004(1) |
| 7 | Onyx/Danswer | ~12k | 1406 | 6 | 1 | 1 | 2 | 2 | AW-TOOL-004(2), AW-MEM-001(1), AW-MEM-003(1) |
| 8 | DB-GPT | ~17k | 1004 | 6 | 2 | 2 | 2 | 0 | AW-MEM-001(2), AW-TOOL-001(1), AW-MEM-003(1) |
| 9 | Chat-LangChain | ~6k | 11 | 0 | 0 | 0 | 0 | 0 | — |
| 10 | RasaGPT | ~2.4k | 11 | 0 | 0 | 0 | 0 | 0 | — |
| 11 | Langflow | ~48k | 1274 | 59 | 29 | 13 | 13 | 4 | AW-MEM-001(29), AW-MEM-003(11), AW-MEM-005(11) |
| 12 | Flowise | ~35k | - | - | - | - | - | - | not scanned |
| 13 | Open Interpreter | ~58k | - | - | - | - | - | - | not scanned |
| 14 | Chainlit | ~8k | 121 | 0 | 0 | 0 | 0 | 0 | — |
| 15 | Mem0/Embedchain | ~25k | 371 | 9 | 4 | 2 | 2 | 1 | AW-MEM-001(4), AW-MEM-003(2), AW-MEM-005(2) |
| 16 | LLM App (Pathway) | ~4k | 17 | 0 | 0 | 0 | 0 | 0 | — |
| 17 | Haystack | ~18k | - | - | - | - | - | - | not scanned |
| 18 | SuperAgent | ~5k | 22 | 0 | 0 | 0 | 0 | 0 | — |
| 19 | AgentGPT | ~32k | 85 | 0 | 0 | 0 | 0 | 0 | — |
| 20 | AutoGPT | ~172k | - | - | - | - | - | - | not scanned |

**Totals: 116 findings (57 CRITICAL, 25 HIGH) across 5085 files. 8/20 have findings.**

---

## 2. Tier 2 — Small Projects (<500 stars)

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | memory-agent | 416 | 7 | 0 | 0 | 0 | 0 | 0 | — |
| 2 | rag-research-agent-template | 295 | 17 | 0 | 0 | 0 | 0 | 0 | — |
| 3 | langchain-chatbot | 273 | 9 | 6 | 2 | 4 | 0 | 0 | AW-MEM-004(4), AW-MEM-001(2) |
| 4 | chat-with-websites | 260 | 1 | 1 | 1 | 0 | 0 | 0 | AW-MEM-001(1) |
| 5 | cohere-qdrant-doc-retrieval | 152 | 1 | 4 | 2 | 1 | 1 | 0 | AW-MEM-001(2), AW-MEM-003(1), AW-MEM-005(1) |
| 6 | RAG-chatbot-langchain | 133 | 1 | 6 | 2 | 3 | 1 | 0 | AW-MEM-001(2), AW-MEM-004(2), AW-MEM-003(1) |
| 7 | langchain-RAG-chroma | 8 | 1 | 3 | 1 | 1 | 1 | 0 | AW-MEM-001(1), AW-MEM-003(1), AW-MEM-005(1) |
| 8 | chat-with-pdf | 2 | 1 | 0 | 0 | 0 | 0 | 0 | — |
| 9 | langchain-multi-agent | 10 | 1 | 4 | 1 | 2 | 1 | 0 | AW-CFG-hardcoded-secret(2), AW-MEM-001(1), AW-TOOL-002(1) |
| 10 | objectbox-rag | 10 | 3 | 0 | 0 | 0 | 0 | 0 | — |

**Totals: 24 findings (9 CRITICAL, 11 HIGH) across 42 files. 6/10 have findings.**

### Tier Comparison

| Metric | Tier 1 (>2k stars) | Tier 2 (<500 stars) |
|---|---|---|
| Projects with findings | 8/16 (50%) | 6/10 (60%) |
| Findings per file | 116 / 5085 = **0.023** | 24 / 42 = **0.571** |
| CRITICAL rate | 57/116 = **49%** | 9/24 = **37%** |

---

## 3. Rule Distribution

| Rule | Count | % | Description |
|---|---|---|---|
| AW-MEM-001 | 66 | 47% | No tenant isolation in vector store |
| AW-MEM-003 | 22 | 16% | Memory backend has no access control |
| AW-MEM-005 | 22 | 16% | No sanitization on retrieved memory |
| AW-TOOL-004 | 10 | 7% | Tool has no description |
| AW-MEM-004 | 6 | 4% | Injection patterns in retrieval path |
| AW-MEM-002 | 4 | 3% | Shared collection without retrieval filter |
| AW-CFG-docker-no-auth | 3 | 2% | AW-CFG-docker-no-auth |
| AW-TOOL-001 | 2 | 1% | Destructive tool without approval gate |
| AW-TOOL-003 | 2 | 1% | High-risk tool lacks scope check |
| AW-CFG-hardcoded-secret | 2 | 1% | AW-CFG-hardcoded-secret |
| AW-TOOL-002 | 1 | 1% | Tool accepts arbitrary code execution |

---

## 4. Attack Vector Coverage (10 / 32 Detectable)

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
| **AW-ATK-AGT-001** | Tool Poisoning / Unsafe Tool Access | DB-GPT, Langflow, langchain-multi-agent | 5 | `react_action.py:17` (AW-TOOL-001) |
| **AW-ATK-CFG-003** | No TLS / No Auth / Exposed Ports | DocsGPT, Langflow, Onyx/Danswer | 3 | `docker-compose.yaml:59` (AW-CFG-docker-no-auth) |
| **AW-ATK-CFG-004** | Hardcoded API Keys | langchain-multi-agent | 2 | `.env.sample:1` (AW-CFG-hardcoded-secret) |
| **AW-ATK-INJ-001** | Stored Prompt Injection | DB-GPT, DocsGPT, Langchain-Chatchat, Langflow, Mem0/Embedchain, Onyx/Danswer, RAG-chatbot-langchain, cohere-qdrant-doc-retrieval, langchain-RAG-chroma | 22 | `chromadb_kb_service.py:67` (AW-MEM-005) |
| **AW-ATK-MEM-001** | Cross-Tenant Retrieval (No Filter) | DB-GPT, DocsGPT, GPT-Researcher, Langchain-Chatchat, Langflow, Mem0/Embedchain, Onyx/Danswer, Quivr, RAG-chatbot-langchain, chat-with-websites, cohere-qdrant-doc-retrieval, langchain-RAG-chroma, langchain-chatbot, langchain-multi-agent | 66 | `chromadb_kb_service.py:67` (AW-MEM-001) |
| **AW-ATK-MEM-002** | Weak Tenant Isolation (Static Filter) | DocsGPT, Langchain-Chatchat, Langflow | 4 | `ensemble.py:27` (AW-MEM-002) |
| **AW-ATK-MEM-003** | Namespace/Collection Confusion | DB-GPT, DocsGPT, Langchain-Chatchat, Langflow, Mem0/Embedchain, Onyx/Danswer, RAG-chatbot-langchain, cohere-qdrant-doc-retrieval, langchain-RAG-chroma | 22 | `chromadb_kb_service.py:67` (AW-MEM-003) |
| **AW-ATK-MEM-004** | Partition Bypass via Direct API | RAG-chatbot-langchain, langchain-chatbot | 6 | `2_⭐_context_aware_chatbot.py:21` (AW-MEM-004) |

### Vectors Not Detected (22 / 32)

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

## 5. Attack Vector Heatmap (Per Project)

| Project | AGT-001 | CFG-001 | CFG-003 | CFG-004 | INJ-001 | MEM-001 | MEM-002 | MEM-003 | MEM-004 | Total |
|---|---|---|---|---|---|---|---|---|---|---|
| Langchain-Chatchat | · | · | · | · | **3** | **14** | **2** | **3** | · | 22 |
| PrivateGPT | · | · | · | · | · | · | · | · | · | 0 |
| Quivr | · | · | · | · | · | **2** | · | · | · | 2 |
| LocalGPT | · | · | · | · | · | · | · | · | · | 0 |
| DocsGPT | · | · | **1** | · | **1** | **3** | **1** | **1** | · | 7 |
| GPT-Researcher | · | · | · | · | · | **2** | · | · | · | 2 |
| Onyx/Danswer | · | · | **1** | · | **1** | **1** | · | **1** | · | 4 |
| DB-GPT | **2** | · | · | · | **1** | **2** | · | **1** | · | 6 |
| Chat-LangChain | · | · | · | · | · | · | · | · | · | 0 |
| RasaGPT | · | · | · | · | · | · | · | · | · | 0 |
| Langflow | **2** | · | **1** | · | **11** | **29** | **1** | **11** | · | 55 |
| Flowise | — | — | — | — | — | — | — | — | — | — |
| Open Interpreter | — | — | — | — | — | — | — | — | — | — |
| Chainlit | · | · | · | · | · | · | · | · | · | 0 |
| Mem0/Embedchain | · | · | · | · | **2** | **4** | · | **2** | · | 8 |
| LLM App (Pathway) | · | · | · | · | · | · | · | · | · | 0 |
| Haystack | — | — | — | — | — | — | — | — | — | — |
| SuperAgent | · | · | · | · | · | · | · | · | · | 0 |
| AgentGPT | · | · | · | · | · | · | · | · | · | 0 |
| AutoGPT | — | — | — | — | — | — | — | — | — | — |
| memory-agent | · | · | · | · | · | · | · | · | · | 0 |
| rag-research-agent-template | · | · | · | · | · | · | · | · | · | 0 |
| langchain-chatbot | · | · | · | · | · | **2** | · | · | **4** | 6 |
| chat-with-websites | · | · | · | · | · | **1** | · | · | · | 1 |
| cohere-qdrant-doc-retrieval | · | · | · | · | **1** | **2** | · | **1** | · | 4 |
| RAG-chatbot-langchain | · | · | · | · | **1** | **2** | · | **1** | **2** | 6 |
| langchain-RAG-chroma | · | · | · | · | **1** | **1** | · | **1** | · | 3 |
| chat-with-pdf | · | · | · | · | · | · | · | · | · | 0 |
| langchain-multi-agent | **1** | · | · | **2** | · | **1** | · | · | · | 4 |
| objectbox-rag | · | · | · | · | · | · | · | · | · | 0 |

*Legend: number = findings count, · = not detected, — = not scanned*

---

## 6. How to Reproduce

```bash
pip install -e ".[dev]"
./scripts/benchmark.sh
```
