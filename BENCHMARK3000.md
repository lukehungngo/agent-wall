# AgentWall Benchmark 3000

**Date:** 2026-03-21
**Version:** AgentWall v0.1.0
**Layers enabled:** L0–L6 (default static analysis) + V5 engine
**Projects:** 349
**Reproduce:** `./scripts/benchmark3000.sh`

---

## 1. Tier 1 — LangChain Ecosystem (>2k stars)

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Langchain-Chatchat | ~37k | 239 | 50 | 12 | 28 | 9 | 1 | AW-MEM-001(15), AW-RAG-001(10), AW-SEC-001(6) |
| 2 | PrivateGPT | ~54k | 65 | 6 | 0 | 5 | 1 | 0 | AW-RAG-004(2), AW-MEM-003(2), AW-SEC-001(1) |
| 3 | Quivr | ~36k | 41 | 7 | 0 | 2 | 3 | 2 | AW-RAG-001(2), AW-RAG-003(2), AW-MEM-001(2) |
| 4 | LocalGPT | ~22k | 44 | 18 | 0 | 0 | 16 | 2 | AW-TOOL-002(14), AW-SEC-003(2), AW-TOOL-004(2) |
| 5 | DocsGPT | ~15k | 208 | 24 | 3 | 11 | 9 | 1 | AW-RAG-003(5), AW-MEM-001(4), AW-SEC-001(3) |
| 6 | GPT-Researcher | ~17k | 167 | 7 | 2 | 3 | 1 | 1 | AW-MEM-001(2), AW-RAG-001(2), AW-SER-001(1) |
| 7 | Onyx/Danswer | ~12k | 1420 | 23 | 0 | 12 | 9 | 2 | AW-SER-001(9), AW-SER-003(7), AW-TOOL-004(2) |
| 8 | DB-GPT | ~17k | 1004 | 218 | 0 | 26 | 154 | 38 | AW-TOOL-002(120), AW-TOOL-004(38), AW-TOOL-001(15) |
| 9 | Chat-LangChain | ~6k | 11 | 0 | 0 | 0 | 0 | 0 | — |
| 10 | RasaGPT | ~2.4k | 11 | 0 | 0 | 0 | 0 | 0 | — |
| 11 | Langflow | ~48k | 1274 | 97 | 19 | 36 | 38 | 4 | AW-SER-003(25), AW-MEM-001(21), AW-RAG-001(11) |
| 12 | Flowise | ~35k | 0 | 0 | 0 | 0 | 0 | 0 | — |
| 13 | Open Interpreter | ~58k | 136 | 80 | 0 | 2 | 48 | 30 | AW-TOOL-002(42), AW-TOOL-004(30), AW-SER-003(5) |
| 14 | Chainlit | ~8k | 121 | 11 | 0 | 2 | 6 | 3 | AW-TOOL-002(4), AW-TOOL-004(3), AW-SER-003(2) |
| 15 | Mem0/Embedchain | ~48k | 374 | 16 | 2 | 8 | 5 | 1 | AW-RAG-001(3), AW-SER-003(3), AW-MEM-001(2) |
| 16 | LLM App (Pathway) | ~4k | 17 | 20 | 0 | 0 | 10 | 10 | AW-TOOL-002(10), AW-TOOL-004(10) |
| 17 | Haystack | ~18k | 296 | 40 | 0 | 1 | 35 | 4 | AW-TOOL-002(33), AW-TOOL-004(4), AW-SER-003(2) |
| 18 | SuperAgent | ~5k | 22 | 0 | 0 | 0 | 0 | 0 | — |
| 19 | AgentGPT | ~32k | 85 | 14 | 0 | 2 | 7 | 5 | AW-TOOL-002(6), AW-TOOL-004(5), AW-MEM-003(2) |
| 20 | AutoGPT | ~172k | 918 | 74 | 0 | 6 | 48 | 20 | AW-TOOL-002(45), AW-TOOL-004(20), AW-SEC-001(4) |
| 21 | LangGraph | ~45k | 173 | 32 | 0 | 3 | 19 | 10 | AW-TOOL-002(12), AW-TOOL-004(10), AW-SER-003(7) |
| 22 | LangSmith SDK | ~1k | 81 | 26 | 0 | 1 | 17 | 8 | AW-TOOL-002(17), AW-TOOL-004(8), AW-SEC-001(1) |
| 23 | LangChain (mono) | ~100k | 1669 | 42 | 0 | 16 | 9 | 17 | AW-MEM-001(17), AW-SER-003(6), AW-AGT-004(4) |
| 24 | OpenGPTs | ~6k | 28 | 16 | 0 | 3 | 0 | 13 | AW-TOOL-004(13), AW-CFG-no-tls(1), AW-SER-001(1) |
| 25 | LangServe | ~2k | 13 | 1 | 0 | 0 | 1 | 0 | AW-TOOL-002(1) |
| 26 | LangChain Extract | ~1k | 20 | 1 | 1 | 0 | 0 | 0 | AW-MEM-001(1) |
| 27 | Awesome LLM Apps | ~60k | 444 | 313 | 0 | 58 | 184 | 71 | AW-TOOL-002(175), AW-TOOL-004(71), AW-MEM-003(14) |

**Totals: 1136 findings (39 CRITICAL, 225 HIGH) across 8881 files. 23/27 have findings.**

---

## 2. Tier 2 — LlamaIndex Ecosystem

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | LlamaIndex | ~47k | - | - | - | - | - | - | not scanned |
| 2 | RAGS (LlamaIndex) | ~6k | 15 | 2 | 0 | 1 | 0 | 1 | AW-RAG-001(1), AW-MEM-001(1) |
| 3 | LlamaParse | ~3k | 41 | 16 | 0 | 0 | 12 | 4 | AW-TOOL-002(12), AW-TOOL-004(3), AW-MEM-001(1) |
| 4 | create-llama | ~2k | 172 | 28 | 0 | 21 | 2 | 5 | AW-MEM-003(11), AW-MEM-004(6), AW-RAG-001(3) |
| 5 | SEC Insights | ~2k | 36 | 6 | 0 | 2 | 3 | 1 | AW-TOOL-002(2), AW-RAG-002(1), AW-MEM-003(1) |
| 6 | LlamaDeploy | ~2k | 60 | 27 | 0 | 1 | 16 | 10 | AW-TOOL-002(15), AW-TOOL-004(10), AW-CFG-hardcoded-secret(1) |
| 7 | LlamaIndex.TS | ~3k | 0 | 1 | 0 | 1 | 0 | 0 | AW-CFG-hardcoded-secret(1) |
| 8 | LlamaAgents | ~1k | 60 | 27 | 0 | 1 | 16 | 10 | AW-TOOL-002(15), AW-TOOL-004(10), AW-CFG-hardcoded-secret(1) |
| 9 | LlamaHub | ~3k | 593 | 108 | 14 | 74 | 19 | 1 | AW-MEM-003(50), AW-MEM-001(30), AW-MEM-005(17) |
| 10 | LlamaLab | ~1k | 26 | 0 | 0 | 0 | 0 | 0 | — |
| 11 | Multi-Agent Concierge | ~500 | 3 | 3 | 0 | 2 | 1 | 0 | AW-MEM-004(1), AW-MEM-003(1), AW-TOOL-002(1) |
| 12 | PR Manager (LlamaIndex) | ~11 | 14 | 6 | 0 | 0 | 3 | 3 | AW-TOOL-002(3), AW-TOOL-004(3) |

**Totals: 224 findings (14 CRITICAL, 103 HIGH) across 1020 files. 10/12 have findings.**

---

## 3. Tier 3 — Multi-Agent Frameworks

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | CrewAI | ~46k | 752 | 128 | 0 | 46 | 45 | 37 | AW-TOOL-004(37), AW-MEM-003(32), AW-TOOL-002(25) |
| 2 | AutoGen | ~48k | 406 | 64 | 0 | 10 | 43 | 11 | AW-TOOL-002(37), AW-TOOL-004(11), AW-SER-003(5) |
| 3 | MetaGPT | ~58k | 494 | 208 | 0 | 18 | 120 | 70 | AW-TOOL-002(101), AW-TOOL-004(63), AW-SER-003(12) |
| 4 | ChatDev | ~25k | 186 | 26 | 0 | 4 | 13 | 9 | AW-TOOL-002(12), AW-TOOL-004(9), AW-SER-001(2) |
| 5 | CAMEL | ~10k | 498 | 101 | 0 | 19 | 80 | 2 | AW-TOOL-002(67), AW-MEM-003(8), AW-SEC-003(7) |
| 6 | BabyAGI | ~20k | 35 | 8 | 0 | 0 | 5 | 3 | AW-TOOL-002(3), AW-TOOL-004(3), AW-SER-003(2) |
| 7 | OpenAI Swarm | ~18k | 6 | 2 | 0 | 0 | 1 | 1 | AW-TOOL-002(1), AW-TOOL-004(1) |
| 8 | Swarms | ~4k | 215 | 222 | 0 | 2 | 210 | 10 | AW-TOOL-002(207), AW-TOOL-004(10), AW-TOOL-001(1) |
| 9 | TaskWeaver | ~5k | 136 | 17 | 0 | 1 | 8 | 8 | AW-TOOL-002(6), AW-TOOL-004(6), AW-MEM-001(2) |

**Totals: 776 findings (0 CRITICAL, 100 HIGH) across 2728 files. 9/9 have findings.**

---

## 4. Tier 4 — RAG Applications

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | RAGFlow | ~70k | 463 | 143 | 0 | 22 | 68 | 53 | AW-TOOL-002(60), AW-TOOL-004(53), AW-CFG-hardcoded-secret(10) |
| 2 | Kotaemon | ~25k | 232 | 22 | 0 | 17 | 0 | 5 | AW-SER-001(15), AW-TOOL-004(5), AW-MEM-003(2) |
| 3 | LightRAG | ~30k | 77 | 102 | 0 | 16 | 72 | 14 | AW-TOOL-002(60), AW-TOOL-004(14), AW-TOOL-001(10) |
| 4 | FastGPT | ~27k | 16 | 5 | 0 | 1 | 2 | 2 | AW-TOOL-002(2), AW-TOOL-004(2), AW-CFG-hardcoded-secret(1) |
| 5 | QAnything | ~12k | 148 | 46 | 0 | 10 | 21 | 15 | AW-TOOL-002(17), AW-TOOL-004(15), AW-SER-001(5) |
| 6 | R2R | ~4k | 224 | 6 | 0 | 0 | 6 | 0 | AW-TOOL-002(3), AW-SER-003(2), AW-SEC-003(1) |
| 7 | FlashRAG | ~2k | 75 | 24 | 0 | 5 | 11 | 8 | AW-TOOL-002(10), AW-TOOL-004(8), AW-MEM-003(3) |
| 8 | AutoRAG | ~3k | 177 | 25 | 0 | 9 | 10 | 6 | AW-TOOL-002(9), AW-MEM-003(6), AW-TOOL-004(6) |
| 9 | Canopy (Pinecone) | ~3k | 80 | 6 | 0 | 4 | 1 | 1 | AW-MEM-003(4), AW-TOOL-002(1), AW-TOOL-004(1) |
| 10 | Verba (Weaviate) | ~6k | 53 | 9 | 0 | 6 | 3 | 0 | AW-MEM-003(5), AW-TOOL-002(2), AW-RAG-004(1) |
| 11 | Vanna | ~13k | 262 | 30 | 10 | 9 | 11 | 0 | AW-MEM-001(10), AW-MEM-003(5), AW-TOOL-002(5) |
| 12 | Cognita | ~8k | 73 | 11 | 0 | 10 | 1 | 0 | AW-MEM-003(6), AW-RAG-004(3), AW-RAG-001(1) |
| 13 | ChatGPT Retrieval Plugin | ~21k | 30 | 11 | 0 | 6 | 3 | 2 | AW-MEM-003(6), AW-TOOL-002(2), AW-TOOL-004(2) |
| 14 | txtai | ~10k | 261 | 17 | 0 | 5 | 12 | 0 | AW-TOOL-002(10), AW-MEM-003(3), AW-SER-001(2) |

**Totals: 457 findings (10 CRITICAL, 120 HIGH) across 2171 files. 14/14 have findings.**

---

## 5. Tier 5 — Vector Store Ecosystems

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | ChromaDB | ~17k | 148 | 116 | 0 | 113 | 3 | 0 | AW-MEM-003(111), AW-SER-003(2), AW-SEC-001(1) |
| 2 | Milvus Bootcamp | ~2k | 78 | 10 | 1 | 6 | 3 | 0 | AW-SER-001(5), AW-CFG-docker-no-auth(3), AW-MEM-001(1) |
| 3 | Qdrant Examples | ~500 | 4 | 6 | 0 | 3 | 2 | 1 | AW-MEM-003(3), AW-TOOL-002(2), AW-TOOL-004(1) |
| 4 | LanceDB | ~5k | 71 | 189 | 0 | 13 | 135 | 41 | AW-TOOL-002(120), AW-TOOL-004(41), AW-TOOL-001(13) |

**Totals: 321 findings (1 CRITICAL, 135 HIGH) across 301 files. 4/4 have findings.**

---

## 6. Tier 6 — Memory & Knowledge Systems

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Cognee | ~12k | 950 | 59 | 0 | 4 | 45 | 10 | AW-TOOL-002(42), AW-TOOL-004(10), AW-MCP-001(2) |
| 2 | Graphiti (Zep) | ~14k | 178 | 482 | 0 | 98 | 239 | 145 | AW-TOOL-002(147), AW-TOOL-004(145), AW-TOOL-001(92) |
| 3 | Letta (MemGPT) | ~22k | 692 | 23 | 0 | 7 | 11 | 5 | AW-SEC-003(6), AW-SER-001(5), AW-TOOL-004(5) |
| 4 | GraphRAG (Microsoft) | ~22k | 444 | 21 | 0 | 5 | 12 | 4 | AW-TOOL-002(12), AW-RAG-001(5), AW-TOOL-004(4) |
| 5 | nano-graphrag | ~5k | 19 | 31 | 0 | 4 | 14 | 13 | AW-TOOL-002(13), AW-TOOL-004(13), AW-CFG-hardcoded-secret(2) |
| 6 | Zep | ~3k | 19 | 0 | 0 | 0 | 0 | 0 | — |

**Totals: 616 findings (0 CRITICAL, 118 HIGH) across 2302 files. 5/6 have findings.**

---

## 7. Tier 7 — Chatbot / Assistant Frameworks

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Open WebUI | ~124k | 163 | 8 | 0 | 7 | 0 | 1 | AW-RAG-004(5), AW-RAG-001(1), AW-MEM-003(1) |
| 2 | LibreChat | ~30k | 1 | 0 | 0 | 0 | 0 | 0 | — |
| 3 | Khoj | ~33k | 110 | 10 | 0 | 3 | 6 | 1 | AW-TOOL-002(4), AW-SER-001(2), AW-SEC-003(2) |
| 4 | AnythingLLM | ~35k | 0 | 0 | 0 | 0 | 0 | 0 | — |
| 5 | PyGPT | ~3k | 1190 | 33 | 0 | 8 | 4 | 21 | AW-TOOL-004(18), AW-SEC-001(5), AW-MEM-001(3) |
| 6 | Jan | ~25k | 5 | 6 | 0 | 0 | 6 | 0 | AW-TOOL-002(6) |

**Totals: 57 findings (0 CRITICAL, 18 HIGH) across 1469 files. 4/6 have findings.**

---

## 8. Tier 8 — Code / Dev Agents

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | OpenHands (OpenDevin) | ~65k | 710 | 52 | 0 | 5 | 34 | 13 | AW-TOOL-002(30), AW-TOOL-004(13), AW-SER-001(5) |
| 2 | SWE-agent | ~15k | 68 | 37 | 0 | 0 | 25 | 12 | AW-TOOL-002(24), AW-TOOL-004(12), AW-SER-003(1) |
| 3 | Aider | ~36k | 90 | 39 | 0 | 2 | 22 | 15 | AW-TOOL-002(19), AW-TOOL-004(13), AW-SER-003(2) |
| 4 | Devika | ~18k | 70 | 3 | 0 | 1 | 1 | 1 | AW-SEC-001(1), AW-TOOL-002(1), AW-TOOL-004(1) |
| 5 | GPT-Engineer | ~52k | 43 | 24 | 0 | 0 | 15 | 9 | AW-TOOL-002(11), AW-TOOL-004(9), AW-SEC-003(3) |
| 6 | GPT-Pilot | ~32k | 94 | 10 | 0 | 5 | 4 | 1 | AW-CFG-hardcoded-secret(5), AW-TOOL-002(4), AW-TOOL-004(1) |

**Totals: 165 findings (0 CRITICAL, 13 HIGH) across 1075 files. 6/6 have findings.**

---

## 9. Tier 9 — Production Agent Platforms

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | Dify | ~129k | 1577 | 70 | 0 | 14 | 41 | 15 | AW-TOOL-002(38), AW-TOOL-004(15), AW-MEM-003(6) |
| 2 | Agno (Phidata) | ~19k | 2626 | 274 | 0 | 32 | 165 | 77 | AW-TOOL-002(150), AW-TOOL-004(77), AW-MEM-003(9) |
| 3 | Pydantic AI | ~15k | 236 | 44 | 0 | 0 | 33 | 11 | AW-TOOL-002(33), AW-TOOL-004(11) |
| 4 | smolagents (HF) | ~26k | 18 | 22 | 0 | 3 | 13 | 6 | AW-TOOL-002(11), AW-TOOL-004(6), AW-SER-001(3) |
| 5 | Semantic Kernel | ~22k | 923 | 70 | 0 | 26 | 27 | 17 | AW-TOOL-002(24), AW-TOOL-004(17), AW-MEM-003(12) |
| 6 | OpenAI Agents SDK | ~7k | 165 | 29 | 0 | 0 | 18 | 11 | AW-TOOL-002(18), AW-TOOL-004(11) |
| 7 | DSPy | ~20k | 140 | 7 | 0 | 2 | 3 | 2 | AW-MEM-003(2), AW-SEC-003(2), AW-TOOL-004(2) |
| 8 | Google Agent Dev Kit | ~18k | 835 | 32 | 1 | 13 | 15 | 3 | AW-SER-003(13), AW-SEC-001(5), AW-RAG-001(3) |
| 9 | UFO (Microsoft) | ~5k | 291 | 40 | 1 | 2 | 36 | 1 | AW-TOOL-002(25), AW-RAG-003(9), AW-MEM-001(1) |
| 10 | AgentOps | ~3k | 303 | 36 | 0 | 9 | 21 | 6 | AW-TOOL-002(14), AW-SEC-001(7), AW-TOOL-004(6) |
| 11 | ModelScope Agent | ~3k | 204 | 104 | 0 | 4 | 64 | 36 | AW-TOOL-002(55), AW-TOOL-004(36), AW-SER-003(5) |

**Totals: 728 findings (2 CRITICAL, 105 HIGH) across 7318 files. 11/11 have findings.**

---

## 10. Tier 10 — Small / Niche Projects

| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |
|---|---|---|---|---|---|---|---|---|---|
| 1 | memory-agent | 416 | 7 | 0 | 0 | 0 | 0 | 0 | — |
| 2 | rag-research-agent-template | 295 | 17 | 1 | 0 | 1 | 0 | 0 | AW-RAG-001(1) |
| 3 | langchain-chatbot | 273 | 9 | 9 | 0 | 7 | 0 | 2 | AW-MEM-004(4), AW-RAG-001(2), AW-MEM-001(2) |
| 4 | chat-with-websites | 260 | 1 | 1 | 0 | 0 | 0 | 1 | AW-MEM-001(1) |
| 5 | cohere-qdrant-doc-retrieval | 152 | 1 | 5 | 1 | 3 | 1 | 0 | AW-MEM-001(2), AW-RAG-001(1), AW-MEM-003(1) |
| 6 | RAG-chatbot-langchain | 133 | 1 | 8 | 0 | 3 | 3 | 2 | AW-MEM-004(2), AW-RAG-003(2), AW-MEM-001(2) |
| 7 | langchain-RAG-chroma | 8 | 1 | 7 | 1 | 3 | 2 | 1 | AW-MEM-001(2), AW-RAG-001(1), AW-AGT-004(1) |
| 8 | chat-with-pdf | 2 | 1 | 2 | 0 | 0 | 2 | 0 | AW-RAG-003(2) |
| 9 | langchain-multi-agent | 10 | 1 | 5 | 0 | 3 | 1 | 1 | AW-AGT-001(2), AW-RAG-001(1), AW-TOOL-002(1) |
| 10 | objectbox-rag | 10 | 3 | 0 | 0 | 0 | 0 | 0 | — |
| 11 | AdalFlow | ~3k | 231 | 150 | 0 | 10 | 98 | 42 | AW-TOOL-002(93), AW-TOOL-004(42), AW-SER-001(6) |
| 12 | Hindsight | ~4k | - | - | - | - | - | - | not scanned |
| 13 | Vector Admin | ~2k | 2 | 0 | 0 | 0 | 0 | 0 | — |
| 14 | HF Agents Course | ~5k | 1 | 0 | 0 | 0 | 0 | 0 | — |
| 15 | Libre Chat | ~500 | 9 | 7 | 0 | 1 | 5 | 1 | AW-RAG-003(2), AW-RAG-001(1), AW-SER-002(1) |
| 16 | LangGraph BigTool | ~500 | 4 | 0 | 0 | 0 | 0 | 0 | — |
| 17 | RAG-Anything | ~1k | 15 | 8 | 0 | 0 | 8 | 0 | AW-TOOL-002(8) |
| 18 | OASIS (CAMEL) | ~2k | 45 | 40 | 0 | 7 | 18 | 15 | AW-TOOL-002(14), AW-TOOL-004(14), AW-TOOL-001(2) |
| 19 | SWE-bench | ~4k | 84 | 21 | 0 | 2 | 15 | 4 | AW-TOOL-002(13), AW-TOOL-004(4), AW-TOOL-001(2) |

**Totals: 264 findings (2 CRITICAL, 40 HIGH) across 433 files. 13/19 have findings.**

---

## 11. Grand Summary

| Metric | Value |
|---|---|
| Total projects | 349 |
| Projects scanned | 112 |
| Projects with findings | 99 (88%) |
| Total files scanned | 27,698 |
| Total findings | 4744 |
| CRITICAL | 68 |
| HIGH | 977 |
| Findings per file | 0.171 |

### Category Comparison

| Category | Projects | Scanned | With Findings | Findings | CRIT | HIGH | Files |
|---|---|---|---|---|---|---|---|
| LangChain Ecosystem (>2k stars) | 27 | 27 | 23 | 1136 | 39 | 225 | 8,881 |
| LlamaIndex Ecosystem | 12 | 11 | 10 | 224 | 14 | 103 | 1,020 |
| Multi-Agent Frameworks | 9 | 9 | 9 | 776 | 0 | 100 | 2,728 |
| RAG Applications | 14 | 14 | 14 | 457 | 10 | 120 | 2,171 |
| Vector Store Ecosystems | 4 | 4 | 4 | 321 | 1 | 135 | 301 |
| Memory & Knowledge Systems | 6 | 6 | 5 | 616 | 0 | 118 | 2,302 |
| Chatbot / Assistant Frameworks | 6 | 6 | 4 | 57 | 0 | 18 | 1,469 |
| Code / Dev Agents | 6 | 6 | 6 | 165 | 0 | 13 | 1,075 |
| Production Agent Platforms | 11 | 11 | 11 | 728 | 2 | 105 | 7,318 |
| Small / Niche Projects | 19 | 18 | 13 | 264 | 2 | 40 | 433 |

---

## 12. Rule Distribution

| Rule | Count | % | Description |
|---|---|---|---|
| AW-TOOL-002 | 2103 | 44% | Tool accepts arbitrary code execution |
| AW-TOOL-004 | 1037 | 22% | Tool has no description |
| AW-MEM-003 | 365 | 8% | Memory backend has no access control |
| AW-SER-003 | 183 | 4% | Dynamic import with variable argument |
| AW-TOOL-001 | 159 | 3% | Destructive tool without approval gate |
| AW-TOOL-003 | 159 | 3% | High-risk tool lacks scope check |
| AW-MEM-001 | 145 | 3% | No tenant isolation in vector store |
| AW-SER-001 | 102 | 2% | Unsafe deserialization |
| AW-RAG-001 | 98 | 2% | Retrieved context without delimiters |
| AW-SEC-001 | 85 | 2% | Hardcoded API key/secret in agent config |
| AW-RAG-003 | 56 | 1% | Unencrypted local vector store |
| AW-SEC-003 | 54 | 1% | Agent context logged at DEBUG level |
| AW-MEM-005 | 45 | 1% | No sanitization on retrieved memory |
| AW-RAG-004 | 41 | 1% | Vector store exposed without auth |
| AW-CFG-hardcoded-secret | 21 | 0% | AW-CFG-hardcoded-secret |
| AW-AGT-004 | 19 | 0% | LLM output stored to memory without validation |
| AW-MEM-004 | 15 | 0% | Injection patterns in retrieval path |
| AW-RAG-002 | 12 | 0% | Ingestion from untrusted source |
| AW-CFG-docker-no-auth | 10 | 0% | AW-CFG-docker-no-auth |
| AW-MEM-002 | 9 | 0% | Shared collection without retrieval filter |
| AW-AGT-001 | 8 | 0% | Sub-agent inherits full parent tool set |
| AW-MCP-001 | 8 | 0% | MCP server without authentication |
| AW-SER-002 | 5 | 0% | Unpinned agent framework dependency |
| AW-MCP-002 | 2 | 0% | Static token in MCP config |
| AW-CFG-no-tls | 1 | 0% | AW-CFG-no-tls |
| AW-CFG-debug-mode | 1 | 0% | AW-CFG-debug-mode |
| AW-AGT-003 | 1 | 0% | Agent has read+write+delete without approval |

---

## 13. False Positive Estimation

Based on manual triage of 98 findings against real source code (2026-03-20).

| Rule | Count | Sampled | TP | FP | FP Rate | Est. FP in Benchmark | Mitigation |
|---|---|---|---|---|---|---|---|
| AW-TOOL-002 | 2103 | — | — | — | ~15% (est.) | ~315 | Not triaged |
| AW-TOOL-004 | 1037 | — | — | — | ~15% (est.) | ~155 | Not triaged |
| AW-MEM-003 | 365 | — | — | — | ~15% (est.) | ~54 | Not triaged |
| AW-SER-003 | 183 | 30 | 16 | 14 | 47% | ~85 | Suppress dict-lookup imports, variable indirection |
| AW-TOOL-001 | 159 | — | — | — | ~15% (est.) | ~23 | Not triaged |
| AW-TOOL-003 | 159 | — | — | — | ~15% (est.) | ~23 | Not triaged |
| AW-MEM-001 | 145 | 13 | 0 | 13 | 100% | ~145 | Skip library code, require multi-tenant evidence |
| AW-SER-001 | 102 | — | — | — | ~15% (est.) | ~15 | Not triaged |
| AW-RAG-001 | 98 | — | — | — | ~15% (est.) | ~14 | Not triaged |
| AW-SEC-001 | 85 | — | — | — | ~15% (est.) | ~12 | Not triaged |
| AW-RAG-003 | 56 | — | — | — | ~15% (est.) | ~8 | Not triaged |
| AW-SEC-003 | 54 | 30 | 14 | 16 | 53% | ~28 | Require content reference, not metadata access |
| AW-MEM-005 | 45 | 9 | 2 | 7 | 78% | ~35 | Require retrieval-to-sink path |
| AW-RAG-004 | 41 | — | — | — | ~15% (est.) | ~6 | Not triaged |
| AW-CFG-hardcoded-secret | 21 | 16 | 4 | 12 | 75% | ~15 | Skip templates, placeholders, non-secret keys |
| AW-AGT-004 | 19 | — | — | — | ~15% (est.) | ~2 | Not triaged |
| AW-MEM-004 | 15 | — | — | — | ~15% (est.) | ~2 | Not triaged |
| AW-RAG-002 | 12 | — | — | — | ~15% (est.) | ~1 | Not triaged |
| AW-CFG-docker-no-auth | 10 | — | — | — | ~15% (est.) | ~1 | Not triaged |
| AW-MEM-002 | 9 | — | — | — | ~15% (est.) | ~1 | Not triaged |
| AW-AGT-001 | 8 | — | — | — | ~15% (est.) | ~1 | Not triaged |
| AW-MCP-001 | 8 | — | — | — | ~15% (est.) | ~1 | Not triaged |
| AW-SER-002 | 5 | — | — | — | ~15% (est.) | ~0 | Not triaged |
| AW-MCP-002 | 2 | — | — | — | ~15% (est.) | ~0 | Not triaged |
| AW-CFG-no-tls | 1 | — | — | — | ~15% (est.) | ~0 | Not triaged |
| AW-CFG-debug-mode | 1 | — | — | — | ~15% (est.) | ~0 | Not triaged |
| AW-AGT-003 | 1 | — | — | — | ~15% (est.) | ~0 | Not triaged |

**Estimated totals:** 4744 findings → ~3802 true positives, ~942 false positives (19% est. FP rate)

*FP rates for triaged rules are based on manual verification of real source code.
Untriaged rules use 15% conservative estimate. Actual FP rate may vary.*

---

## 14. Attack Vector Coverage (9 / 35 Detectable)

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
| **AW-ATK-AGT-001** | Tool Poisoning / Unsafe Tool Access | AdalFlow, AgentGPT, AgentOps, Agno (Phidata), Aider, AutoGPT, AutoGen, AutoRAG, Awesome LLM Apps, BabyAGI (+65 more) | 2430 | `agents_registry.py:140` (AW-AGT-001) |
| **AW-ATK-AGT-004** | Cross-Agent Memory Contamination | AdalFlow, Awesome LLM Apps, LangChain (mono), create-llama, langchain-RAG-chroma | 19 | `vectorstore.py:107` (AW-AGT-004) |
| **AW-ATK-CFG-001** | Unsafe Reset Enabled | LanceDB | 1 | `docker-compose.yml:9` (AW-CFG-debug-mode) |
| **AW-ATK-CFG-003** | No TLS / No Auth / Exposed Ports | AgentOps, Agno (Phidata), AutoGen, AutoRAG, Awesome LLM Apps, CAMEL, Cognee, Cognita, CrewAI, Dify (+18 more) | 60 | `vector_store_component.py:112` (AW-RAG-004) |
| **AW-ATK-CFG-004** | Hardcoded API Keys | AdalFlow, AgentOps, Agno (Phidata), AutoGPT, AutoGen, Awesome LLM Apps, CAMEL, Chainlit, ChromaDB, CrewAI (+23 more) | 108 | `settings.py:452` (AW-SEC-001) |
| **AW-ATK-INJ-001** | Stored Prompt Injection | Agno (Phidata), Aider, Awesome LLM Apps, Cognita, DB-GPT, Dify, DocsGPT, GPT-Researcher, Google Agent Dev Kit, GraphRAG (Microsoft) (+24 more) | 143 | `file_chat.py:66` (AW-RAG-001) |
| **AW-ATK-MEM-001** | Cross-Tenant Retrieval (No Filter) | Agno (Phidata), Aider, Awesome LLM Apps, DocsGPT, GPT-Researcher, Google Agent Dev Kit, LangChain (mono), LangChain Extract, Langchain-Chatchat, Langflow (+19 more) | 145 | `milvus_kb_service.py:100` (AW-MEM-001) |
| **AW-ATK-MEM-002** | Weak Tenant Isolation (Static Filter) | DocsGPT, LangChain (mono), Langchain-Chatchat, Langflow, OpenGPTs, UFO (Microsoft) | 9 | `ensemble.py:27` (AW-MEM-002) |
| **AW-ATK-MEM-003** | Namespace/Collection Confusion | AdalFlow, AgentGPT, Agno (Phidata), Aider, AutoGPT, AutoGen, AutoRAG, Awesome LLM Apps, CAMEL, Canopy (Pinecone) (+39 more) | 365 | `chromadb_kb_service.py:67` (AW-MEM-003) |
| **AW-ATK-MEM-004** | Partition Bypass via Direct API | LangChain (mono), LlamaHub, Multi-Agent Concierge, RAG-chatbot-langchain, create-llama, langchain-chatbot | 15 | `vectorstore_token_buffer_memory.py:120` (AW-MEM-004) |
| **AW-ATK-POI-005** | Document Loader Exploitation | Agno (Phidata), Awesome LLM Apps, Dify, SEC Insights | 12 | `qwen_local_rag_agent.py:234` (AW-RAG-002) |

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

## 15. Attack Vector Heatmap (Per Project)

| Project | AGT-001 | CFG-001 | CFG-003 | CFG-004 | INJ-001 | MEM-001 | MEM-002 | MEM-003 | MEM-004 | Total |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Langchain-Chatchat | **3** | · | · | **6** | **13** | **15** | **2** | **3** | · | 42 |
| PrivateGPT | · | · | **2** | **1** | · | · | · | **2** | · | 5 |
| Quivr | · | · | · | · | **2** | **2** | · | · | · | 4 |
| LocalGPT | **14** | · | · | · | · | · | · | · | · | 14 |
| DocsGPT | · | · | **1** | **5** | **4** | **4** | **1** | **1** | · | 16 |
| GPT-Researcher | · | · | · | · | **2** | **2** | · | · | · | 4 |
| Onyx/Danswer | · | · | **1** | **1** | **1** | · | · | **1** | · | 4 |
| DB-GPT | **150** | · | · | · | **8** | · | · | **3** | · | 161 |
| Chat-LangChain | · | · | · | · | · | · | · | · | · | 0 |
| RasaGPT | · | · | · | · | · | · | · | · | · | 0 |
| Langflow | **2** | · | **4** | **2** | **13** | **21** | **1** | **11** | · | 54 |
| Flowise | · | · | · | · | · | · | · | · | · | 0 |
| Open Interpreter | **44** | · | · | · | · | · | · | · | · | 44 |
| Chainlit | **4** | · | · | **1** | · | · | · | · | · | 5 |
| Mem0/Embedchain | · | · | **2** | · | **3** | **2** | · | **2** | · | 9 |
| LLM App (Pathway) | **10** | · | · | · | · | · | · | · | · | 10 |
| Haystack | **33** | · | · | · | · | · | · | · | · | 33 |
| SuperAgent | · | · | · | · | · | · | · | · | · | 0 |
| AgentGPT | **6** | · | · | · | · | · | · | **2** | · | 8 |
| AutoGPT | **45** | · | · | **4** | · | · | · | **1** | · | 50 |
| LangGraph | **12** | · | **1** | **1** | · | · | · | · | · | 14 |
| LangSmith SDK | **17** | · | · | **1** | · | · | · | · | · | 18 |
| LangChain (mono) | **3** | · | **2** | · | **3** | **17** | **3** | **1** | **1** | 30 |
| OpenGPTs | · | · | **1** | · | · | · | **1** | · | · | 2 |
| LangServe | **1** | · | · | · | · | · | · | · | · | 1 |
| LangChain Extract | · | · | · | · | · | **1** | · | · | · | 1 |
| Awesome LLM Apps | **175** | · | **3** | **3** | **17** | **8** | · | **14** | · | 220 |
| LlamaIndex | — | — | — | — | — | — | — | — | — | — |
| RAGS (LlamaIndex) | · | · | · | · | **1** | **1** | · | · | · | 2 |
| LlamaParse | **12** | · | · | · | · | **1** | · | · | · | 13 |
| create-llama | · | · | · | · | **3** | **2** | · | **11** | **6** | 22 |
| SEC Insights | **2** | · | · | · | · | · | · | **1** | · | 3 |
| CrewAI | **40** | · | **1** | **4** | · | · | · | **32** | · | 77 |
| AutoGen | **37** | · | **1** | **3** | · | · | · | **4** | · | 45 |
| MetaGPT | **103** | · | **1** | · | **9** | **7** | · | **8** | · | 128 |
| ChatDev | **12** | · | · | · | · | · | · | **2** | · | 14 |
| CAMEL | **71** | · | **3** | **5** | · | · | · | **8** | · | 87 |
| BabyAGI | **3** | · | · | · | · | · | · | · | · | 3 |
| OpenAI Swarm | **1** | · | · | · | · | · | · | · | · | 1 |
| Swarms | **209** | · | · | · | · | · | · | · | · | 209 |
| TaskWeaver | **6** | · | · | · | · | **2** | · | · | · | 8 |
| RAGFlow | **60** | · | **2** | **18** | · | · | · | · | · | 80 |
| Kotaemon | · | · | · | · | · | · | · | **2** | · | 2 |
| LightRAG | **80** | · | **1** | · | · | · | · | **5** | · | 86 |
| FastGPT | **2** | · | · | **1** | · | · | · | · | · | 3 |
| QAnything | **17** | · | · | · | **2** | · | · | **3** | · | 22 |
| R2R | **3** | · | · | · | · | · | · | · | · | 3 |
| FlashRAG | **10** | · | · | · | · | · | · | **3** | · | 13 |
| AutoRAG | **9** | · | **1** | · | · | · | · | **6** | · | 16 |
| Canopy (Pinecone) | **1** | · | · | · | · | · | · | **4** | · | 5 |
| Verba (Weaviate) | **2** | · | **1** | · | · | · | · | **5** | · | 8 |
| Vanna | **5** | · | **1** | · | **5** | **10** | · | **5** | · | 26 |
| Cognita | · | · | **4** | · | **1** | · | · | **6** | · | 11 |
| ChatGPT Retrieval Plugin | **2** | · | · | · | · | · | · | **6** | · | 8 |
| txtai | **10** | · | · | · | · | · | · | **3** | · | 13 |
| ChromaDB | **1** | · | · | **1** | · | · | · | **111** | · | 113 |
| Milvus Bootcamp | · | · | **3** | · | · | **1** | · | **1** | · | 5 |
| Qdrant Examples | **2** | · | · | · | · | · | · | **3** | · | 5 |
| LanceDB | **146** | **1** | · | · | · | · | · | · | · | 147 |
| Cognee | **42** | · | **4** | · | · | · | · | **2** | · | 48 |
| Graphiti (Zep) | **331** | · | · | · | **6** | · | · | · | · | 337 |
| Letta (MemGPT) | · | · | · | **1** | · | · | · | **1** | · | 2 |
| GraphRAG (Microsoft) | **12** | · | · | · | **5** | · | · | · | · | 17 |
| nano-graphrag | **15** | · | · | **2** | · | · | · | · | · | 17 |
| Zep | · | · | · | · | · | · | · | · | · | 0 |
| Open WebUI | · | · | **5** | · | **1** | · | · | **1** | · | 7 |
| LibreChat | · | · | · | · | · | · | · | · | · | 0 |
| Khoj | **4** | · | · | **1** | · | · | · | · | · | 5 |
| AnythingLLM | · | · | · | · | · | · | · | · | · | 0 |
| PyGPT | **2** | · | · | **5** | **1** | **3** | · | **2** | · | 13 |
| Jan | **6** | · | · | · | · | · | · | · | · | 6 |
| OpenHands (OpenDevin) | **30** | · | · | · | · | · | · | · | · | 30 |
| SWE-agent | **24** | · | · | · | · | · | · | · | · | 24 |
| Aider | **19** | · | · | · | **2** | **2** | · | **1** | · | 24 |
| Devika | **1** | · | · | **1** | · | · | · | · | · | 2 |
| GPT-Engineer | **11** | · | · | · | · | · | · | · | · | 11 |
| GPT-Pilot | **4** | · | · | **5** | · | · | · | · | · | 9 |
| Dify | **38** | · | **4** | **1** | **1** | · | · | **6** | · | 50 |
| Agno (Phidata) | **165** | · | **3** | **8** | **3** | **1** | · | **9** | · | 189 |
| Pydantic AI | **33** | · | · | · | · | · | · | · | · | 33 |
| smolagents (HF) | **11** | · | · | · | · | · | · | · | · | 11 |
| Semantic Kernel | **24** | · | **5** | **9** | · | · | · | **12** | · | 50 |
| OpenAI Agents SDK | **18** | · | · | · | · | · | · | · | · | 18 |
| DSPy | · | · | · | · | · | · | · | **2** | · | 2 |
| Google Agent Dev Kit | **4** | · | **1** | **5** | **3** | **1** | · | · | · | 14 |
| UFO (Microsoft) | **25** | · | · | · | **1** | **1** | **1** | · | · | 28 |
| AgentOps | **14** | · | **1** | **7** | · | · | · | · | · | 22 |
| ModelScope Agent | **57** | · | · | **1** | · | · | · | **2** | · | 60 |
| memory-agent | · | · | · | · | · | · | · | · | · | 0 |
| rag-research-agent-template | · | · | · | · | **1** | · | · | · | · | 1 |
| langchain-chatbot | **1** | · | · | · | **2** | **2** | · | · | **4** | 9 |
| chat-with-websites | · | · | · | · | · | **1** | · | · | · | 1 |
| cohere-qdrant-doc-retrieval | · | · | · | · | **2** | **2** | · | **1** | · | 5 |
| RAG-chatbot-langchain | · | · | · | · | **1** | **2** | · | **1** | **2** | 6 |
| langchain-RAG-chroma | · | · | · | · | **2** | **2** | · | **1** | · | 5 |
| chat-with-pdf | · | · | · | · | · | · | · | · | · | 0 |
| langchain-multi-agent | **3** | · | · | · | **1** | **1** | · | · | · | 5 |
| objectbox-rag | · | · | · | · | · | · | · | · | · | 0 |
| AdalFlow | **93** | · | · | **1** | · | · | · | **2** | · | 96 |
| Hindsight | — | — | — | — | — | — | — | — | — | — |
| Vector Admin | · | · | · | · | · | · | · | · | · | 0 |
| HF Agents Course | · | · | · | · | · | · | · | · | · | 0 |
| Libre Chat | **1** | · | **1** | · | **1** | · | · | · | · | 3 |
| LangGraph BigTool | · | · | · | · | · | · | · | · | · | 0 |
| RAG-Anything | **8** | · | · | · | · | · | · | · | · | 8 |
| OASIS (CAMEL) | **18** | · | · | **1** | **2** | **1** | · | **1** | · | 23 |
| SWE-bench | **17** | · | · | · | · | · | · | · | · | 17 |
| LlamaDeploy | **15** | · | · | **1** | · | · | · | · | · | 16 |
| LlamaIndex.TS | · | · | · | **1** | · | · | · | · | · | 1 |
| LlamaAgents | **15** | · | · | **1** | · | · | · | · | · | 16 |
| LlamaHub | · | · | · | · | **21** | **30** | · | **50** | **1** | 102 |
| LlamaLab | · | · | · | · | · | · | · | · | · | 0 |
| Multi-Agent Concierge | **1** | · | · | · | · | · | · | **1** | **1** | 3 |
| PR Manager (LlamaIndex) | **3** | · | · | · | · | · | · | · | · | 3 |
| LazyLLM | **36** | · | **1** | **7** | · | · | · | · | · | 44 |
| ThinkRAG | **4** | · | · | · | · | · | · | **4** | **2** | 10 |
| Delphic | · | · | · | · | · | · | · | · | · | 0 |
| local_llama | **4** | · | · | · | · | · | · | · | · | 4 |
| Awesome-RAG (lucifertrj) | · | · | · | **1** | **2** | **2** | · | **2** | · | 7 |
| VeritasGraph | **4** | · | · | **1** | · | · | · | · | · | 5 |
| CorpusOS | **23** | · | · | · | **4** | **1** | **2** | · | · | 30 |
| Hello Wordsmith | · | · | · | · | · | **1** | · | **2** | · | 3 |
| PapersChat | · | · | **1** | · | · | · | · | **3** | · | 4 |
| LlamaIndex Omakase RAG | · | · | **1** | **1** | · | · | · | · | · | 2 |
| local-rag-llamaindex | · | · | **4** | · | · | · | · | **3** | · | 7 |
| XRAG | · | · | · | · | **3** | **4** | · | **8** | · | 15 |
| flexible-graphrag | **16** | · | **2** | · | **3** | **3** | · | **2** | · | 26 |
| Vector Cookbook (Timescale) | · | · | · | · | **4** | · | · | · | · | 4 |
| DocMind AI | · | · | **11** | **3** | **1** | **1** | · | **14** | · | 30 |
| RAGArch | · | · | **1** | · | · | · | · | **3** | · | 4 |
| RAG-LlamaIndex (Pinecone) | · | · | · | · | · | · | · | **10** | · | 10 |
| RAG Job Search Assistant | **1** | · | · | · | · | · | · | **1** | · | 2 |
| ingest-anything | **1** | · | · | · | · | · | · | **3** | · | 4 |
| OpenInference (Arize) | **5** | · | · | · | **1** | · | · | · | · | 6 |
| MCPAdapt | · | · | · | · | · | · | · | · | · | 0 |
| PlanExe | **35** | · | **3** | **15** | · | · | · | · | · | 53 |
| LlamaIndex Docs Agent | · | · | · | · | **2** | **1** | · | **1** | · | 4 |
| LlamaIndex Trip Planner | **1** | · | · | · | · | · | · | · | · | 1 |
| User-Centric RAG (LlamaIndex+Qdrant) | · | · | · | · | · | · | · | **2** | **2** | 4 |
| AgentServe | **1** | · | · | · | · | · | · | · | · | 1 |
| Agentic RAG (LlamaIndex) | · | · | · | · | **2** | **2** | · | **5** | · | 9 |
| Agent-as-a-Service | · | · | · | · | · | · | · | **1** | · | 1 |
| Workflows ACP | **12** | · | · | · | · | · | · | · | · | 12 |
| Agentic AI Chatbot (LlamaIndex) | · | · | · | · | · | · | · | · | · | 0 |
| Llama-4 Researcher | **1** | · | · | · | · | · | · | · | · | 1 |
| e-Library Agent | **2** | · | **1** | · | · | · | · | **1** | · | 4 |
| ragcoon | **4** | · | **1** | · | · | · | · | **3** | · | 8 |
| diRAGnosis | · | · | **1** | · | **9** | **10** | · | **8** | · | 28 |
| Agentic PRD Generation | **1** | · | **1** | · | · | · | · | · | · | 2 |
| LlamaIndexChat | · | · | · | · | · | · | · | **1** | · | 1 |
| LlamaIndex Ollama Chainlit | · | · | · | · | · | · | · | **3** | · | 3 |
| RAGIndex | **2** | · | **1** | · | · | · | · | · | · | 3 |
| RAG Application (LlamaIndex) | · | · | · | · | · | · | · | · | · | 0 |
| LlamaIndex-with-Llama2 | · | · | · | · | · | · | · | · | · | 0 |
| SQL Agent LlamaIndex | · | · | · | · | · | · | · | · | · | 0 |
| LlamaIndex Knowledge Graph | · | · | · | · | · | · | · | · | · | 0 |
| LlamaIndex Agent (Swastik) | **2** | · | · | · | · | · | · | **1** | · | 3 |
| Azure LlamaIndex Sample | · | · | · | · | · | · | · | **1** | · | 1 |
| Brainiac | **1** | · | · | · | · | · | · | · | · | 1 |
| RAG-TUI | **6** | · | · | · | · | · | · | · | · | 6 |
| Chat-RAG | · | · | · | · | · | · | · | **3** | · | 3 |
| ToK | **2** | · | · | · | · | · | · | **8** | **8** | 18 |
| Multimodal Semantic RAG | · | · | · | · | **2** | **2** | · | **1** | · | 5 |
| M2M Vector Search | **1** | · | · | · | · | · | · | · | · | 1 |
| RAG Performance | **3** | · | · | · | · | · | · | **1** | · | 4 |
| RAG Firewall | · | · | · | **3** | **1** | **1** | · | · | · | 5 |
| RAG Framework Evaluation | · | · | · | · | **3** | **1** | · | **1** | · | 5 |
| RAG Ingest | · | · | · | · | · | · | · | **3** | · | 3 |
| GPTStonks | **8** | · | · | · | · | · | · | **3** | · | 11 |
| Quackling | · | · | · | · | · | · | · | · | · | 0 |
| GUT | **7** | · | · | · | · | · | · | · | · | 7 |
| AI Equity Research Analyst | · | · | · | · | · | · | · | · | · | 0 |
| Opik (Comet) | **4** | · | · | · | · | · | · | **1** | · | 5 |
| GPTCache | **9** | · | **1** | · | · | · | · | **1** | · | 11 |
| All-in-RAG | **11** | · | **2** | · | **10** | **4** | **3** | **8** | · | 38 |
| Gerev | · | · | · | · | · | · | · | **1** | · | 1 |
| PyGPT (LlamaIndex) | **2** | · | · | **5** | **1** | **3** | · | **2** | · | 13 |
| Judgeval | **7** | · | · | · | · | · | · | · | · | 7 |
| AutoLLM | · | · | · | · | · | · | · | **3** | · | 3 |
| RepoAgent | **4** | · | · | · | · | · | · | **2** | · | 6 |
| RAG Chatbot (datvodinh) | · | · | **1** | · | · | · | · | **3** | · | 4 |
| GraphRAG Toolkit (AWS) | **7** | · | · | · | · | · | · | **1** | · | 8 |
| Agent-Wiz | · | · | · | · | · | · | · | · | · | 0 |
| Agentic AI Systems | **3** | · | · | **13** | **17** | **15** | **8** | **4** | **1** | 61 |
| RESTai | · | · | **1** | · | · | · | · | **2** | · | 3 |
| SlideSpeak | **2** | · | · | · | · | · | · | **2** | · | 4 |
| Whisk | **7** | · | · | · | · | · | · | · | · | 7 |
| Airgapped Offline RAG | · | · | · | · | **1** | **1** | · | · | · | 2 |
| FastAPI Agents | **7** | · | · | · | · | · | · | · | · | 7 |
| BentoML RAG Tutorials | · | · | · | **2** | · | · | · | **6** | · | 8 |
| Reliable RAG | · | · | **1** | · | · | · | · | **2** | · | 3 |
| LLM Ollama LlamaIndex Bootstrap | · | · | · | · | · | · | · | **1** | · | 1 |
| AI Playground (rokbenko) | · | · | **1** | **1** | **2** | · | · | **2** | · | 6 |
| Applied AI RAG Assistant | **3** | · | · | · | **4** | **6** | · | **1** | **2** | 16 |
| DSPy RAG + LlamaIndex | · | · | · | **2** | · | · | · | **1** | · | 3 |
| ATO Chatbot | **1** | · | **2** | · | **1** | **2** | · | **5** | · | 11 |
| Ragtag Tiger | · | · | · | · | · | · | · | **1** | · | 1 |
| LlamaIndex Zoom Assistant | **1** | · | · | · | · | · | · | · | · | 1 |
| LlamaIndex Retrieval API | · | · | · | · | · | · | · | **2** | · | 2 |
| Multimodal RAG Plugin | · | · | · | · | · | · | · | · | · | 0 |
| ChatGPT Custom Knowledge | · | · | · | · | · | · | · | · | · | 0 |
| chatPDF | · | · | · | · | · | · | · | · | · | 0 |
| Smart LLM Loader | **2** | · | · | · | · | · | · | · | · | 2 |
| ChatGPT Long-Term Memory | · | · | · | · | · | · | · | **1** | · | 1 |
| LlamaIndex Examples (alphasecio) | · | · | · | · | · | · | · | **1** | · | 1 |
| Agentic Playground | **1** | · | · | · | · | · | · | · | · | 1 |
| IntelliWeb GPT | · | · | · | **2** | · | · | · | **1** | · | 3 |
| LlamaIndex Supervisor | **1** | · | · | · | · | · | · | · | · | 1 |
| Contextual Retrieval (Anthropic) | **1** | · | · | · | **1** | **2** | · | **3** | · | 7 |
| Streaming LLM Chat | · | · | · | · | · | · | · | **2** | **1** | 3 |
| Docs-n-Data Knowledge App | **1** | · | · | · | · | · | · | **2** | · | 3 |
| LlamaIndex Flask Demo | · | · | · | · | · | · | · | · | · | 0 |
| AgenticAI Coach | **13** | · | · | · | · | · | · | **1** | · | 14 |
| GemInsights | · | · | · | · | · | · | · | · | · | 0 |
| LLM RAG | · | · | · | · | · | · | · | **2** | **1** | 3 |
| QuickDigest | **3** | · | · | · | · | · | · | **1** | · | 4 |
| AItrika | · | · | · | · | · | · | · | **7** | · | 7 |
| LangChain RAG DevKit | **2** | · | · | · | **4** | **3** | · | **2** | **3** | 14 |
| RAG AI Voice Assistant | · | · | **1** | · | · | · | · | **3** | **1** | 5 |
| Translation Agent WebUI | · | · | · | · | · | · | · | · | · | 0 |
| Hiflylabs Agent Demo | · | · | · | · | · | **1** | · | · | · | 1 |
| RAG KnowledgeLLM Bot | · | · | · | · | · | · | · | **1** | · | 1 |
| PyQt LlamaIndex | · | · | · | · | · | · | · | **1** | · | 1 |
| Doppalf | · | · | · | **2** | · | · | · | **2** | · | 4 |
| Bot-the-Defect | **2** | · | · | · | · | · | · | **2** | **2** | 6 |
| EduRAG Network Assistant | · | · | · | · | **4** | **4** | · | **3** | · | 11 |
| LlamaIndex Agent Workflow Browse | **1** | · | · | · | · | · | · | · | · | 1 |
| LlamaIndex Chatbot Advanced | · | · | · | · | · | · | · | **3** | · | 3 |
| LEANN | **22** | · | · | · | · | · | · | **1** | · | 23 |
| LlamaIndex RAG (romilandc) | · | · | **1** | · | · | · | · | **2** | · | 3 |
| MCP Toolbox SDK (Google) | · | · | · | · | · | · | · | · | · | 0 |
| PromptPilot | **1** | · | · | · | · | · | · | · | · | 1 |
| Jetson Orin Nano RAG Kit | **17** | · | · | **2** | · | · | · | · | · | 19 |
| CrewAI Examples | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI Tools | **37** | · | · | **1** | · | · | · | **3** | · | 41 |
| Awesome CrewAI | · | · | · | · | · | · | · | · | · | 0 |
| AutoGroq | **1** | · | · | · | · | · | · | · | · | 1 |
| MCP Memory Service | **32** | · | **3** | **5** | · | · | · | · | · | 40 |
| CrewAI Studio | **2** | · | · | · | · | · | · | · | · | 2 |
| Full Stack AI Agent Template | · | **7** | **1** | · | · | · | · | · | · | 8 |
| Viral Clips Crew | **2** | · | · | · | · | · | · | · | · | 2 |
| AIWriteX | **4** | · | · | · | · | · | · | · | · | 4 |
| Tiger (Upsonic) | **7** | · | · | · | · | · | · | · | · | 7 |
| Easy Investment Agent | · | · | · | · | · | · | · | · | · | 0 |
| Claude Data Analysis | · | · | · | · | · | · | · | · | · | 0 |
| Devyan | · | · | · | · | · | · | · | · | · | 0 |
| OpenPlexity Pages | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI Test (NanGePlus) | · | · | · | **24** | · | · | · | **2** | · | 26 |
| CrewAI GUI Qt | **1** | · | · | · | · | · | · | · | · | 1 |
| Wavefront | **9** | · | **1** | **5** | · | · | · | · | · | 15 |
| CrewAI UI Business Launch | · | · | · | **1** | · | · | · | · | · | 1 |
| Open Extract | **2** | · | **1** | · | · | · | · | · | · | 3 |
| CrewAI Gmail Automation | · | · | · | · | · | · | · | · | · | 0 |
| Value | **2** | · | **1** | **2** | · | · | · | · | · | 5 |
| Resume Optimization Crew | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI Stock Analysis | · | · | · | · | · | · | · | · | · | 0 |
| Geo AI Agent | **1** | · | · | · | · | · | · | · | · | 1 |
| Trip Planner Agent | **1** | · | · | · | · | · | · | · | · | 1 |
| Paper Summarizer | · | · | · | **1** | · | · | · | · | · | 1 |
| Real Estate AI Agent | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI Flows FullStack | · | · | · | **4** | · | · | · | · | · | 4 |
| Agent Audit | **1** | · | · | **26** | · | · | · | · | · | 27 |
| Mengram | **9** | · | **2** | · | **2** | · | · | · | · | 13 |
| Watsonx CrewAI | · | · | · | · | · | · | · | · | · | 0 |
| FenixAI Trading Bot | · | · | **1** | · | · | · | · | · | · | 1 |
| Jambo | · | · | · | · | · | · | · | · | · | 0 |
| Aitino | **4** | · | · | · | · | · | · | · | · | 4 |
| Awesome AI Agents HUB | **2** | · | · | · | · | · | · | · | · | 2 |
| Workshop AI Agent | **7** | · | · | · | **5** | **3** | **4** | **2** | · | 21 |
| Spotify Playlist (CrewAI) | **1** | · | · | · | · | · | · | · | · | 1 |
| CrewAI Sheets UI | **1** | · | · | · | · | · | · | · | · | 1 |
| AI Agents with CrewAI | **2** | · | · | · | · | · | · | · | · | 2 |
| AI Agile Team | · | · | · | · | · | · | · | · | · | 0 |
| AI Agents (whyash) | — | — | — | — | — | — | — | — | — | — |
| CrewAI Streamlit Demo | · | · | · | · | · | · | · | · | · | 0 |
| Agent OS | **23** | · | **4** | **4** | · | · | · | · | · | 31 |
| Eval View | **2** | · | · | **4** | · | · | · | · | · | 6 |
| Multi-Agents System from Scratch | · | · | · | · | · | · | · | · | · | 0 |
| RAG Boilerplate | **3** | · | **1** | · | · | **3** | · | **4** | · | 11 |
| YouTube Yapper Trapper | · | · | · | **1** | · | · | · | · | · | 1 |
| RoboCrew | **6** | · | · | · | · | · | · | · | · | 6 |
| AISquare Studio QA | **13** | · | · | · | · | · | · | · | · | 13 |
| VN Stock Advisor | · | · | · | · | · | · | · | · | · | 0 |
| ComfyUI-CrewAI | · | · | · | · | · | · | · | · | · | 0 |
| TravelPlanner CrewAI | **1** | · | · | · | · | · | · | · | · | 1 |
| Multi-Agent RAG Template | · | · | · | · | · | · | · | **1** | · | 1 |
| Investment Agent (LangGraph+CrewAI) | **4** | · | · | · | · | · | · | · | · | 4 |
| AI Agent Crew (Bitcoin) | **3** | · | · | · | **2** | **2** | · | **1** | · | 8 |
| AI Trading Crew | **5** | · | · | · | · | · | · | · | · | 5 |
| Multi-AI-Agent Systems (CrewAI) | · | · | · | · | · | · | · | · | · | 0 |
| Multi-AI-Agent Systems (ksm) | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI MCP | **6** | · | · | · | · | · | · | · | · | 6 |
| Email Agent | **42** | · | · | · | · | · | · | · | · | 42 |
| Jira Tiger | · | · | · | · | · | · | · | · | · | 0 |
| KAI | **1** | · | · | · | · | · | · | · | · | 1 |
| CrewAI Essay Writer | · | · | · | · | · | · | · | · | · | 0 |
| LLM Agents Example | **4** | · | · | **1** | · | · | · | · | · | 5 |
| Crew Llamafile | · | · | · | · | · | · | · | · | · | 0 |
| Crew News | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI Multi-Agent (Financial) | · | · | · | · | **1** | **1** | · | · | · | 2 |
| AI News Researcher & Blog Writer | · | · | · | · | · | · | · | · | · | 0 |
| Multiagent Debugger | **4** | · | · | · | · | · | · | · | · | 4 |
| Personal Brand Team | · | · | · | · | · | · | · | · | · | 0 |
| AgentFacts | · | · | · | · | · | · | · | · | · | 0 |
| AI Book Writer | **1** | · | · | **2** | · | · | · | · | · | 3 |
| Smart Marketing Assistant | **1** | · | · | · | · | · | · | · | · | 1 |
| Operagents | **3** | · | · | · | · | · | · | · | · | 3 |
| ContextLoom | **3** | · | · | · | · | · | · | · | · | 3 |
| Multi-Agent Travel Advisor | · | · | · | · | **2** | **2** | · | **1** | · | 5 |
| CrewAI Qdrant Obsidian | · | · | · | · | · | · | · | **1** | · | 1 |
| Multi-Agent AI Newsletter | · | · | · | · | · | · | · | · | · | 0 |
| PMO CrewAI | · | · | · | · | · | · | · | · | · | 0 |
| CV Agents | **2** | · | · | · | · | · | · | · | · | 2 |
| Smart Nutritional App | · | · | · | · | · | · | · | · | · | 0 |
| Crewlit | **1** | · | · | · | · | · | · | · | · | 1 |
| RAG-based AI Agents | · | · | · | · | · | · | · | · | · | 0 |
| Healthcare Assistant | **2** | · | · | · | **1** | · | · | · | · | 3 |
| Agent Kernel | **24** | · | · | **1** | · | · | · | · | · | 25 |
| CrewAI Stock Trader | · | · | · | · | · | · | · | · | · | 0 |
| Compliance Assistant (AWS) | · | · | · | **1** | · | · | · | · | · | 1 |
| Kalibr SDK | **5** | · | · | · | · | · | · | · | · | 5 |
| Coral AI | · | · | · | · | · | · | · | · | · | 0 |
| Agentic Stock Analysis Crew | **1** | · | · | · | · | · | · | · | · | 1 |
| Newsletter Agent | · | · | · | · | · | · | · | · | · | 0 |
| Yaitec Hub Templates | **1** | · | · | · | **2** | · | · | · | · | 3 |
| Agentic AI Projects | **8** | · | · | · | · | · | · | · | · | 8 |
| BentoCrewAI | **1** | · | · | · | · | · | · | · | · | 1 |
| CrewAI Agentic Jira | · | · | · | · | · | · | · | · | · | 0 |
| News AI Agents (Gemini) | · | · | · | · | · | · | · | · | · | 0 |
| Python Coding Agent | **2** | · | · | · | · | · | · | · | · | 2 |
| Market Research Agent | · | · | · | · | · | · | · | · | · | 0 |
| Mistral Backlinker | · | · | · | · | · | · | · | · | · | 0 |
| TaskForce | **1** | · | · | · | **1** | **1** | · | · | · | 3 |
| Graphlit Tools | **4** | · | · | · | · | · | · | · | · | 4 |
| InsAIts | **5** | · | **1** | **5** | · | · | · | · | · | 11 |
| LangCrew | **22** | · | · | **1** | · | · | · | · | · | 23 |
| PagePod | · | · | · | · | · | · | · | · | · | 0 |
| Doctor Assist (CrewAI) | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI Projects (hmnajam) | **1** | · | · | **1** | · | · | · | · | · | 2 |
| CrewAI Projects (lakshya) | — | — | — | — | — | — | — | — | — | — |
| CrewAI Multi-Agent Debate | · | · | · | · | · | · | · | · | · | 0 |
| MultiAgent CrewAI (Indicium) | · | · | · | · | · | · | · | · | · | 0 |
| Investor Crew | · | · | · | · | · | · | · | · | · | 0 |
| AIForge | **18** | · | · | · | · | · | · | · | · | 18 |
| Prompt Maker | **3** | · | · | · | · | · | · | · | · | 3 |
| Awesome CrewAI (zinyando) | · | · | · | · | · | · | · | · | · | 0 |
| 500 AI Agents Projects | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI Lab | · | · | · | · | · | · | · | · | · | 0 |
| CrewAI Research Assistant | · | · | · | · | · | · | · | · | · | 0 |

*Legend: number = findings count, · = not detected, — = not scanned*

---

## 16. How to Reproduce

```bash
pip install -e ".[dev]"
./scripts/benchmark3000.sh
```

### Environment Variables

| Variable | Default | Description |
|---|---|---|
| `MAX_PARALLEL` | 4 | Parallel git clone jobs |
| `SCAN_TIMEOUT` | 300 | Per-project scan timeout (seconds) |
