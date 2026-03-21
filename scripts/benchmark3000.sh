#!/usr/bin/env bash
# AgentWall Benchmark 3000 — comprehensive scan of 300+ AI agent projects
# Usage: ./scripts/benchmark3000.sh [targets_dir] [results_dir]
#
# Massively expanded version of benchmark.sh. Clones projects (shallow),
# runs agentwall scan on each, maps findings to attack vectors, and
# generates BENCHMARK3000.md.

set -euo pipefail

TARGETS_DIR="${1:-/tmp/agentwall-bench3k}"
RESULTS_DIR="${2:-/tmp/agentwall-results3k}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BENCHMARK_MD="$PROJECT_ROOT/BENCHMARK3000.md"
LOG_DIR="$PROJECT_ROOT/logs"
RUN_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
RUN_LOG="$LOG_DIR/benchmark3k_${RUN_TIMESTAMP}.log"
MAX_PARALLEL="${MAX_PARALLEL:-4}"       # parallel clone jobs
SCAN_TIMEOUT="${SCAN_TIMEOUT:-300}"     # per-project scan timeout (seconds)

mkdir -p "$TARGETS_DIR" "$RESULTS_DIR" "$LOG_DIR"

# Start run log
{
  echo "═══════════════════════════════════════════════════════"
  echo "AgentWall Benchmark 3000 — $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "═══════════════════════════════════════════════════════"
  echo "Targets: $TARGETS_DIR"
  echo "Results: $RESULTS_DIR"
  echo "Max parallel clones: $MAX_PARALLEL"
  echo "Scan timeout: ${SCAN_TIMEOUT}s"
  echo "AgentWall version: $(agentwall version 2>/dev/null || echo 'unknown')"
  echo ""
} > "$RUN_LOG"

# ══════════════════════════════════════════════════════════════════════════
# Repository Registry
# ══════════════════════════════════════════════════════════════════════════
# Format: REPO_NAMES[] for order, REPOS[] for URLs, REPO_META[] for display

REPO_NAMES=()

declare -A REPOS
declare -A REPO_META        # "display_name|stars|category"
declare -A FORCE_FRAMEWORK

# Helper: register a repo
reg() {
  local key="$1" url="$2" display="$3" stars="$4" category="$5"
  REPO_NAMES+=("$key")
  REPOS[$key]="$url"
  REPO_META[$key]="$display|$stars|$category"
}

# ── Tier 1: Established LangChain ecosystem (>2k stars) ─────────────────

reg langchain-chatchat "https://github.com/chatchat-space/Langchain-Chatchat.git" \
    "Langchain-Chatchat" "~37k" "tier1-langchain"
reg private-gpt "https://github.com/zylon-ai/private-gpt.git" \
    "PrivateGPT" "~54k" "tier1-langchain"
reg quivr "https://github.com/QuivrHQ/quivr.git" \
    "Quivr" "~36k" "tier1-langchain"
reg localgpt "https://github.com/PromtEngineer/localGPT.git" \
    "LocalGPT" "~22k" "tier1-langchain"
reg docsgpt "https://github.com/arc53/DocsGPT.git" \
    "DocsGPT" "~15k" "tier1-langchain"
reg gpt-researcher "https://github.com/assafelovic/gpt-researcher.git" \
    "GPT-Researcher" "~17k" "tier1-langchain"
reg onyx "https://github.com/onyx-dot-app/onyx.git" \
    "Onyx/Danswer" "~12k" "tier1-langchain"
reg db-gpt "https://github.com/eosphoros-ai/DB-GPT.git" \
    "DB-GPT" "~17k" "tier1-langchain"
reg chat-langchain "https://github.com/langchain-ai/chat-langchain.git" \
    "Chat-LangChain" "~6k" "tier1-langchain"
reg rasagpt "https://github.com/paulpierre/RasaGPT.git" \
    "RasaGPT" "~2.4k" "tier1-langchain"
reg langflow "https://github.com/langflow-ai/langflow.git" \
    "Langflow" "~48k" "tier1-langchain"
reg flowise "https://github.com/FlowiseAI/Flowise.git" \
    "Flowise" "~35k" "tier1-langchain"
reg open-interpreter "https://github.com/OpenInterpreter/open-interpreter.git" \
    "Open Interpreter" "~58k" "tier1-langchain"
reg chainlit "https://github.com/Chainlit/chainlit.git" \
    "Chainlit" "~8k" "tier1-langchain"
reg embedchain "https://github.com/mem0ai/mem0.git" \
    "Mem0/Embedchain" "~48k" "tier1-langchain"
reg llm-app "https://github.com/pathwaycom/llm-app.git" \
    "LLM App (Pathway)" "~4k" "tier1-langchain"
reg haystack "https://github.com/deepset-ai/haystack.git" \
    "Haystack" "~18k" "tier1-langchain"
reg superagent "https://github.com/superagent-ai/superagent.git" \
    "SuperAgent" "~5k" "tier1-langchain"
reg agentgpt "https://github.com/reworkd/AgentGPT.git" \
    "AgentGPT" "~32k" "tier1-langchain"
reg auto-gpt-web "https://github.com/Significant-Gravitas/AutoGPT.git" \
    "AutoGPT" "~172k" "tier1-langchain"

# ── Tier 1 expanded: LangChain ecosystem ────────────────────────────────

reg langgraph "https://github.com/langchain-ai/langgraph.git" \
    "LangGraph" "~45k" "tier1-langchain"
reg langsmith-sdk "https://github.com/langchain-ai/langsmith-sdk.git" \
    "LangSmith SDK" "~1k" "tier1-langchain"
reg langchain-mono "https://github.com/langchain-ai/langchain.git" \
    "LangChain (mono)" "~100k" "tier1-langchain"
reg opengpts "https://github.com/langchain-ai/opengpts.git" \
    "OpenGPTs" "~6k" "tier1-langchain"
reg langserve "https://github.com/langchain-ai/langserve.git" \
    "LangServe" "~2k" "tier1-langchain"
reg langchain-extract "https://github.com/langchain-ai/langchain-extract.git" \
    "LangChain Extract" "~1k" "tier1-langchain"
reg awesome-llm-apps "https://github.com/Shubhamsaboo/awesome-llm-apps.git" \
    "Awesome LLM Apps" "~60k" "tier1-langchain"

# ── LlamaIndex ecosystem ────────────────────────────────────────────────

reg llama-index "https://github.com/run-llama/llama_index.git" \
    "LlamaIndex" "~47k" "llamaindex"
reg rags-llamaindex "https://github.com/run-llama/rags.git" \
    "RAGS (LlamaIndex)" "~6k" "llamaindex"
reg llama-parse "https://github.com/run-llama/llama_parse.git" \
    "LlamaParse" "~3k" "llamaindex"
reg create-llama "https://github.com/run-llama/create-llama.git" \
    "create-llama" "~2k" "llamaindex"
reg sec-insights "https://github.com/run-llama/sec-insights.git" \
    "SEC Insights" "~2k" "llamaindex"

# ── Multi-agent frameworks ──────────────────────────────────────────────

reg crewai "https://github.com/crewAIInc/crewAI.git" \
    "CrewAI" "~46k" "multi-agent"
reg autogen "https://github.com/microsoft/autogen.git" \
    "AutoGen" "~48k" "multi-agent"
reg metagpt "https://github.com/geekan/MetaGPT.git" \
    "MetaGPT" "~58k" "multi-agent"
reg chatdev "https://github.com/OpenBMB/ChatDev.git" \
    "ChatDev" "~25k" "multi-agent"
reg camel "https://github.com/camel-ai/camel.git" \
    "CAMEL" "~10k" "multi-agent"
reg babyagi "https://github.com/yoheinakajima/babyagi.git" \
    "BabyAGI" "~20k" "multi-agent"
reg openai-swarm "https://github.com/openai/swarm.git" \
    "OpenAI Swarm" "~18k" "multi-agent"
reg swarms "https://github.com/kyegomez/swarms.git" \
    "Swarms" "~4k" "multi-agent"
reg taskweaver "https://github.com/microsoft/TaskWeaver.git" \
    "TaskWeaver" "~5k" "multi-agent"

# ── RAG applications ────────────────────────────────────────────────────

reg ragflow "https://github.com/infiniflow/ragflow.git" \
    "RAGFlow" "~70k" "rag-app"
reg kotaemon "https://github.com/Cinnamon/kotaemon.git" \
    "Kotaemon" "~25k" "rag-app"
reg lightrag "https://github.com/HKUDS/LightRAG.git" \
    "LightRAG" "~30k" "rag-app"
reg fastgpt "https://github.com/labring/FastGPT.git" \
    "FastGPT" "~27k" "rag-app"
reg qanything "https://github.com/netease-youdao/QAnything.git" \
    "QAnything" "~12k" "rag-app"
reg r2r "https://github.com/SciPhi-AI/R2R.git" \
    "R2R" "~4k" "rag-app"
reg flashrag "https://github.com/RUC-NLPIR/FlashRAG.git" \
    "FlashRAG" "~2k" "rag-app"
reg autorag "https://github.com/Marker-Inc-Korea/AutoRAG.git" \
    "AutoRAG" "~3k" "rag-app"
reg canopy "https://github.com/pinecone-io/canopy.git" \
    "Canopy (Pinecone)" "~3k" "rag-app"
reg verba "https://github.com/weaviate/Verba.git" \
    "Verba (Weaviate)" "~6k" "rag-app"
reg vanna "https://github.com/vanna-ai/vanna.git" \
    "Vanna" "~13k" "rag-app"
reg cognita "https://github.com/truefoundry/cognita.git" \
    "Cognita" "~8k" "rag-app"
reg chatgpt-retrieval-plugin "https://github.com/openai/chatgpt-retrieval-plugin.git" \
    "ChatGPT Retrieval Plugin" "~21k" "rag-app"
reg txtai "https://github.com/neuml/txtai.git" \
    "txtai" "~10k" "rag-app"

# ── Vector store ecosystems ─────────────────────────────────────────────

reg chromadb "https://github.com/chroma-core/chroma.git" \
    "ChromaDB" "~17k" "vector-store"
reg milvus-bootcamp "https://github.com/milvus-io/bootcamp.git" \
    "Milvus Bootcamp" "~2k" "vector-store"
reg qdrant-examples "https://github.com/qdrant/examples.git" \
    "Qdrant Examples" "~500" "vector-store"
reg lancedb "https://github.com/lancedb/lancedb.git" \
    "LanceDB" "~5k" "vector-store"

# ── Memory / knowledge graph systems ───────────────────────────────────

reg cognee "https://github.com/topoteretes/cognee.git" \
    "Cognee" "~12k" "memory-knowledge"
reg graphiti "https://github.com/getzep/graphiti.git" \
    "Graphiti (Zep)" "~14k" "memory-knowledge"
reg letta "https://github.com/letta-ai/letta.git" \
    "Letta (MemGPT)" "~22k" "memory-knowledge"
reg graphrag "https://github.com/microsoft/graphrag.git" \
    "GraphRAG (Microsoft)" "~22k" "memory-knowledge"
reg nano-graphrag "https://github.com/gusye1234/nano-graphrag.git" \
    "nano-graphrag" "~5k" "memory-knowledge"
reg zep "https://github.com/getzep/zep.git" \
    "Zep" "~3k" "memory-knowledge"

# ── Chatbot / assistant frameworks ──────────────────────────────────────

reg open-webui "https://github.com/open-webui/open-webui.git" \
    "Open WebUI" "~124k" "chatbot-assistant"
reg librechat "https://github.com/danny-avila/LibreChat.git" \
    "LibreChat" "~30k" "chatbot-assistant"
reg khoj "https://github.com/khoj-ai/khoj.git" \
    "Khoj" "~33k" "chatbot-assistant"
reg anything-llm "https://github.com/Mintplex-Labs/anything-llm.git" \
    "AnythingLLM" "~35k" "chatbot-assistant"
reg py-gpt "https://github.com/szczyglis-dev/py-gpt.git" \
    "PyGPT" "~3k" "chatbot-assistant"
reg jan "https://github.com/janhq/jan.git" \
    "Jan" "~25k" "chatbot-assistant"

# ── Code / dev agents ───────────────────────────────────────────────────

reg openhands "https://github.com/All-Hands-AI/OpenHands.git" \
    "OpenHands (OpenDevin)" "~65k" "code-dev-agent"
reg swe-agent "https://github.com/SWE-agent/SWE-agent.git" \
    "SWE-agent" "~15k" "code-dev-agent"
reg aider "https://github.com/Aider-AI/aider.git" \
    "Aider" "~36k" "code-dev-agent"
reg devika "https://github.com/stitionai/devika.git" \
    "Devika" "~18k" "code-dev-agent"
reg gpt-engineer "https://github.com/gpt-engineer-org/gpt-engineer.git" \
    "GPT-Engineer" "~52k" "code-dev-agent"
reg gpt-pilot "https://github.com/Pythagora-io/gpt-pilot.git" \
    "GPT-Pilot" "~32k" "code-dev-agent"

# ── Production agent platforms ──────────────────────────────────────────

reg dify "https://github.com/langgenius/dify.git" \
    "Dify" "~129k" "production-platform"
reg agno "https://github.com/agno-agi/agno.git" \
    "Agno (Phidata)" "~19k" "production-platform"
reg pydantic-ai "https://github.com/pydantic/pydantic-ai.git" \
    "Pydantic AI" "~15k" "production-platform"
reg smolagents "https://github.com/huggingface/smolagents.git" \
    "smolagents (HF)" "~26k" "production-platform"
reg semantic-kernel "https://github.com/microsoft/semantic-kernel.git" \
    "Semantic Kernel" "~22k" "production-platform"
reg openai-agents-sdk "https://github.com/openai/openai-agents-python.git" \
    "OpenAI Agents SDK" "~7k" "production-platform"
reg dspy "https://github.com/stanfordnlp/dspy.git" \
    "DSPy" "~20k" "production-platform"
reg google-adk "https://github.com/google/adk-python.git" \
    "Google Agent Dev Kit" "~18k" "production-platform"
reg ufo "https://github.com/microsoft/UFO.git" \
    "UFO (Microsoft)" "~5k" "production-platform"
reg agentops "https://github.com/AgentOps-AI/agentops.git" \
    "AgentOps" "~3k" "production-platform"
reg modelscope-agent "https://github.com/modelscope/modelscope-agent.git" \
    "ModelScope Agent" "~3k" "production-platform"

# ── Tier 2: Small projects (<500 stars) — original ──────────────────────

reg memory-agent "https://github.com/langchain-ai/memory-agent.git" \
    "memory-agent" "416" "tier2-small"
reg rag-research-agent "https://github.com/langchain-ai/rag-research-agent-template.git" \
    "rag-research-agent-template" "295" "tier2-small"
reg langchain-chatbot "https://github.com/shashankdeshpande/langchain-chatbot.git" \
    "langchain-chatbot" "273" "tier2-small"
reg chat-with-websites "https://github.com/alejandro-ao/chat-with-websites.git" \
    "chat-with-websites" "260" "tier2-small"
reg cohere-qdrant-retrieval "https://github.com/menloparklab/langchain-cohere-qdrant-doc-retrieval.git" \
    "cohere-qdrant-doc-retrieval" "152" "tier2-small"
reg rag-chatbot-langchain "https://github.com/AlaGrine/RAG_chatabot_with_Langchain.git" \
    "RAG-chatbot-langchain" "133" "tier2-small"
reg langchain-rag-chroma "https://github.com/romilandc/langchain-RAG.git" \
    "langchain-RAG-chroma" "8" "tier2-small"
reg chat-with-pdf "https://github.com/ashutoshvct/chat-with-pdf.git" \
    "chat-with-pdf" "2" "tier2-small"
reg langchain-multi-agent "https://github.com/Hegazy360/langchain-multi-agent.git" \
    "langchain-multi-agent" "10" "tier2-small"
reg objectbox-rag "https://github.com/NebeyouMusie/End-to-End-RAG-Project-using-ObjectBox-and-LangChain.git" \
    "objectbox-rag" "10" "tier2-small"

# ── Tier 2 expanded: More small/niche projects ─────────────────────────

reg adalflow "https://github.com/SylphAI-Inc/AdalFlow.git" \
    "AdalFlow" "~3k" "tier2-small"
reg hindsight "https://github.com/palisaderesearch/hindsight.git" \
    "Hindsight" "~4k" "tier2-small"
reg vector-admin "https://github.com/Mintplex-Labs/vector-admin.git" \
    "Vector Admin" "~2k" "tier2-small"
reg agents-course "https://github.com/huggingface/agents-course.git" \
    "HF Agents Course" "~5k" "tier2-small"
reg libre-chat "https://github.com/vemonet/libre-chat.git" \
    "Libre Chat" "~500" "tier2-small"
reg langgraph-bigtool "https://github.com/langchain-ai/langgraph-bigtool.git" \
    "LangGraph BigTool" "~500" "tier2-small"
reg rag-anything "https://github.com/HKUDS/RAG-Anything.git" \
    "RAG-Anything" "~1k" "tier2-small"
reg camel-oasis "https://github.com/camel-ai/oasis.git" \
    "OASIS (CAMEL)" "~2k" "tier2-small"
reg swe-bench "https://github.com/SWE-bench/SWE-bench.git" \
    "SWE-bench" "~4k" "tier2-small"

# ══════════════════════════════════════════════════════════════════════════
# LlamaIndex & CrewAI ecosystem expansion (200+ repos)
# ══════════════════════════════════════════════════════════════════════════

# ── LlamaIndex: Official / Core ──────────────────────────────────────────

reg llama-deploy "https://github.com/run-llama/llama_deploy.git" \
    "LlamaDeploy" "~2k" "llamaindex"
reg llamaindex-ts "https://github.com/run-llama/LlamaIndexTS.git" \
    "LlamaIndex.TS" "~3k" "llamaindex"
reg llama-agents "https://github.com/run-llama/llama-agents.git" \
    "LlamaAgents" "~1k" "llamaindex"
reg llama-hub "https://github.com/run-llama/llama-hub.git" \
    "LlamaHub" "~3k" "llamaindex"
reg llama-lab "https://github.com/run-llama/llama-lab.git" \
    "LlamaLab" "~1k" "llamaindex"
reg multi-agent-concierge "https://github.com/run-llama/multi-agent-concierge.git" \
    "Multi-Agent Concierge" "~500" "llamaindex"
reg pr-manager-llama "https://github.com/run-llama/pr-manager.git" \
    "PR Manager (LlamaIndex)" "~11" "llamaindex"

# ── LlamaIndex: RAG Applications ────────────────────────────────────────

reg lazyllm "https://github.com/LazyAGI/LazyLLM.git" \
    "LazyLLM" "~3.7k" "llamaindex-rag"
reg thinkrag "https://github.com/wzdavid/ThinkRAG.git" \
    "ThinkRAG" "~322" "llamaindex-rag"
reg delphic "https://github.com/JSv4/Delphic.git" \
    "Delphic" "~318" "llamaindex-rag"
reg local-llama "https://github.com/jlonge4/local_llama.git" \
    "local_llama" "~297" "llamaindex-rag"
reg awesome-rag-lucifertrj "https://github.com/lucifertrj/Awesome-RAG.git" \
    "Awesome-RAG (lucifertrj)" "~278" "llamaindex-rag"
reg veritasgraph "https://github.com/bibinprathap/VeritasGraph.git" \
    "VeritasGraph" "~254" "llamaindex-rag"
reg corpusos "https://github.com/Corpus-OS/corpusos.git" \
    "CorpusOS" "~174" "llamaindex-rag"
reg hello-wordsmith "https://github.com/wordsmith-ai/hello-wordsmith.git" \
    "Hello Wordsmith" "~167" "llamaindex-rag"
reg paperschat "https://github.com/AstraBert/PapersChat.git" \
    "PapersChat" "~153" "llamaindex-rag"
reg llamaindex-omakase-rag "https://github.com/ammirsm/llamaindex-omakase-rag.git" \
    "LlamaIndex Omakase RAG" "~147" "llamaindex-rag"
reg local-rag-llamaindex "https://github.com/Otman404/local-rag-llamaindex.git" \
    "local-rag-llamaindex" "~132" "llamaindex-rag"
reg xrag "https://github.com/DocAILab/XRAG.git" \
    "XRAG" "~118" "llamaindex-rag"
reg flexible-graphrag "https://github.com/stevereiner/flexible-graphrag.git" \
    "flexible-graphrag" "~114" "llamaindex-rag"
reg vector-cookbook "https://github.com/timescale/vector-cookbook.git" \
    "Vector Cookbook (Timescale)" "~125" "llamaindex-rag"
reg docmind-ai "https://github.com/BjornMelin/docmind-ai-llm.git" \
    "DocMind AI" "~102" "llamaindex-rag"
reg ragarch "https://github.com/AI-ANK/RAGArch.git" \
    "RAGArch" "~87" "llamaindex-rag"
reg rag-llamaindex-pinecone "https://github.com/felipearosr/RAG-LlamaIndex.git" \
    "RAG-LlamaIndex (Pinecone)" "~81" "llamaindex-rag"
reg kyosek-job-search "https://github.com/kyosek/RAG-based-job-search-assistant.git" \
    "RAG Job Search Assistant" "~86" "llamaindex-rag"
reg ingest-anything "https://github.com/AstraBert/ingest-anything.git" \
    "ingest-anything" "~89" "llamaindex-rag"

# ── LlamaIndex: Agents & Workflows ──────────────────────────────────────

reg openinference "https://github.com/Arize-ai/openinference.git" \
    "OpenInference (Arize)" "~891" "llamaindex-agent"
reg mcpadapt "https://github.com/grll/mcpadapt.git" \
    "MCPAdapt" "~420" "llamaindex-agent"
reg planexe "https://github.com/PlanExeOrg/PlanExe.git" \
    "PlanExe" "~361" "llamaindex-agent"
reg llamaindex-docs-agent "https://github.com/rsrohan99/llamaindex-docs-agent.git" \
    "LlamaIndex Docs Agent" "~156" "llamaindex-agent"
reg llamaindex-trip-planner "https://github.com/rsrohan99/llamaindex-trip-planner.git" \
    "LlamaIndex Trip Planner" "~49" "llamaindex-agent"
reg user-centric-rag "https://github.com/pavannagula/User-Centric-RAG-Using-Llamaindex-Multi-Agent-System-and-Qdrant.git" \
    "User-Centric RAG (LlamaIndex+Qdrant)" "~55" "llamaindex-agent"
reg agentserve "https://github.com/PropsAI/agentserve.git" \
    "AgentServe" "~40" "llamaindex-agent"
reg agentic-rag-llamaindex "https://github.com/PatrickAttankurugu/Agentic-RAG-with-Llamaindex.git" \
    "Agentic RAG (LlamaIndex)" "~8" "llamaindex-agent"
reg logan-agent-as-service "https://github.com/logan-markewich/agent-as-a-service.git" \
    "Agent-as-a-Service" "~24" "llamaindex-agent"
reg workflows-acp "https://github.com/AstraBert/workflows-acp.git" \
    "Workflows ACP" "~45" "llamaindex-agent"
reg agentic-chatbot-llamaindex "https://github.com/sachink1729/Agentic-AI-Chatbot-Llamaindex.git" \
    "Agentic AI Chatbot (LlamaIndex)" "~15" "llamaindex-agent"
reg llama4-researcher "https://github.com/AstraBert/llama-4-researcher.git" \
    "Llama-4 Researcher" "~192" "llamaindex-agent"
reg e-library-agent "https://github.com/AstraBert/e-library-agent.git" \
    "e-Library Agent" "~48" "llamaindex-agent"
reg ragcoon "https://github.com/AstraBert/ragcoon.git" \
    "ragcoon" "~56" "llamaindex-agent"
reg diragnosis "https://github.com/AstraBert/diRAGnosis.git" \
    "diRAGnosis" "~42" "llamaindex-agent"
reg agentic-prd-generation "https://github.com/SeeknnDestroy/agentic-prd-generation.git" \
    "Agentic PRD Generation" "~11" "llamaindex-agent"

# ── LlamaIndex: Chatbots & Assistants ───────────────────────────────────

reg llamaindexchat "https://github.com/dcarpintero/llamaindexchat.git" \
    "LlamaIndexChat" "~45" "llamaindex-chatbot"
reg llamaindex-ollama-chainlit "https://github.com/rauni-iitr/llamaindex_ollama_chainlit.git" \
    "LlamaIndex Ollama Chainlit" "~20" "llamaindex-chatbot"
reg ragindex "https://github.com/rigvedrs/RAGIndex.git" \
    "RAGIndex" "~12" "llamaindex-chatbot"
reg rag-application-llamaindex "https://github.com/VaradDeshmukh97/rag-application-with-llamaindex.git" \
    "RAG Application (LlamaIndex)" "~10" "llamaindex-chatbot"
reg llamaindex-with-llama2 "https://github.com/prashant022/LlamaIndex-with-Llama2.git" \
    "LlamaIndex-with-Llama2" "~20" "llamaindex-chatbot"
reg sql-agent-llamaindex "https://github.com/m13v/sql_agent_llamaindex.git" \
    "SQL Agent LlamaIndex" "~15" "llamaindex-chatbot"
reg llamaindex-knowledge-graph "https://github.com/hasanmehmood/llamaindex-knowledge-graph.git" \
    "LlamaIndex Knowledge Graph" "~15" "llamaindex-chatbot"
reg llamaindex-agent-swastik "https://github.com/swastikmaiti/LlamaIndex-Agent.git" \
    "LlamaIndex Agent (Swastik)" "~10" "llamaindex-chatbot"
reg azure-llamaindex "https://github.com/Azure-Samples/llama-index-python.git" \
    "Azure LlamaIndex Sample" "~20" "llamaindex-chatbot"
reg brainiac-llamaindex "https://github.com/jdhruv1503/Brainiac.git" \
    "Brainiac" "~45" "llamaindex-chatbot"
reg rag-tui "https://github.com/rasinmuhammed/rag-tui.git" \
    "RAG-TUI" "~21" "llamaindex-chatbot"
reg chat-rag-llamaindex "https://github.com/JakeFurtaw/Chat-RAG.git" \
    "Chat-RAG" "~23" "llamaindex-chatbot"
reg tok-llamaindex "https://github.com/gurveervirk/ToK.git" \
    "ToK" "~28" "llamaindex-chatbot"
reg multimodal-semantic-rag "https://github.com/AhmedAl93/multimodal-semantic-RAG.git" \
    "Multimodal Semantic RAG" "~26" "llamaindex-chatbot"
reg m2m-vector-search "https://github.com/schwabauerbriantomas-gif/m2m-vector-search.git" \
    "M2M Vector Search" "~24" "llamaindex-chatbot"

# ── LlamaIndex: Data & Evaluation ───────────────────────────────────────

reg rag-performance "https://github.com/SciPhi-AI/RAG-Performance.git" \
    "RAG Performance" "~20" "llamaindex-eval"
reg rag-firewall "https://github.com/taladari/rag-firewall.git" \
    "RAG Firewall" "~19" "llamaindex-eval"
reg rag-framework-eval "https://github.com/oztrkoguz/RAG-Framework-Evaluation.git" \
    "RAG Framework Evaluation" "~14" "llamaindex-eval"
reg rag-ingest "https://github.com/iamarunbrahma/rag-ingest.git" \
    "RAG Ingest" "~13" "llamaindex-eval"
reg gptstonks "https://github.com/GPTStonks/gptstonks.git" \
    "GPTStonks" "~57" "llamaindex-eval"
reg quackling "https://github.com/DS4SD/quackling.git" \
    "Quackling" "~57" "llamaindex-eval"
reg gut-llamaindex "https://github.com/AstraBert/gut.git" \
    "GUT" "~62" "llamaindex-eval"
reg ai-equity-research "https://github.com/AI-ANK/ai-equity-research-analyst.git" \
    "AI Equity Research Analyst" "~36" "llamaindex-eval"

# ── LlamaIndex: Production & Integrations ───────────────────────────────

reg opik "https://github.com/comet-ml/opik.git" \
    "Opik (Comet)" "~18k" "llamaindex-prod"
reg gptcache "https://github.com/zilliztech/GPTCache.git" \
    "GPTCache" "~8k" "llamaindex-prod"
reg all-in-rag "https://github.com/datawhalechina/all-in-rag.git" \
    "All-in-RAG" "~5k" "llamaindex-prod"
reg gerev "https://github.com/GerevAI/gerev.git" \
    "Gerev" "~2.8k" "llamaindex-prod"
reg py-gpt-llamaindex "https://github.com/szczyglis-dev/py-gpt.git" \
    "PyGPT (LlamaIndex)" "~1.7k" "llamaindex-prod"
reg judgeval "https://github.com/JudgmentLabs/judgeval.git" \
    "Judgeval" "~1k" "llamaindex-prod"
reg autollm "https://github.com/viddexa/autollm.git" \
    "AutoLLM" "~1k" "llamaindex-prod"
reg repoagent "https://github.com/OpenBMB/RepoAgent.git" \
    "RepoAgent" "~923" "llamaindex-prod"
reg datvodinh-rag-chatbot "https://github.com/datvodinh/rag-chatbot.git" \
    "RAG Chatbot (datvodinh)" "~638" "llamaindex-prod"
reg graphrag-toolkit "https://github.com/awslabs/graphrag-toolkit.git" \
    "GraphRAG Toolkit (AWS)" "~367" "llamaindex-prod"
reg agent-wiz "https://github.com/Repello-AI/Agent-Wiz.git" \
    "Agent-Wiz" "~369" "llamaindex-prod"
reg agentic-ai-systems "https://github.com/alirezadir/Agentic-AI-Systems.git" \
    "Agentic AI Systems" "~261" "llamaindex-prod"
reg restai "https://github.com/apocas/restai.git" \
    "RESTai" "~200" "llamaindex-prod"
reg slidespeak "https://github.com/SlideSpeak/slidespeak-backend.git" \
    "SlideSpeak" "~92" "llamaindex-prod"
reg epuerta-whisk "https://github.com/epuerta9/whisk.git" \
    "Whisk" "~88" "llamaindex-prod"
reg vincentkoc-airgapped-rag "https://github.com/vincentkoc/airgapped-offfline-rag.git" \
    "Airgapped Offline RAG" "~81" "llamaindex-prod"
reg fastapi-agents "https://github.com/blairhudson/fastapi-agents.git" \
    "FastAPI Agents" "~47" "llamaindex-prod"
reg bentoml-rag-tutorials "https://github.com/bentoml/rag-tutorials.git" \
    "BentoML RAG Tutorials" "~49" "llamaindex-prod"

# ── LlamaIndex: Small/Niche ─────────────────────────────────────────────

reg reliable-rag "https://github.com/Lokesh-Chimakurthi/Reliable_RAG.git" \
    "Reliable RAG" "~41" "llamaindex-small"
reg llm-ollama-bootstrap "https://github.com/tyrell/llm-ollama-llamaindex-bootstrap.git" \
    "LLM Ollama LlamaIndex Bootstrap" "~47" "llamaindex-small"
reg ai-playground-rokbenko "https://github.com/rokbenko/ai-playground.git" \
    "AI Playground (rokbenko)" "~321" "llamaindex-small"
reg applied-ai-rag "https://github.com/BittnerPierre/applied-ai-rag-assistant.git" \
    "Applied AI RAG Assistant" "~26" "llamaindex-small"
reg ronoh-dspy-rag "https://github.com/Ronoh4/A-DSPy-based-RAG-with-LlamaIndex.git" \
    "DSPy RAG + LlamaIndex" "~27" "llamaindex-small"
reg ato-chatbot "https://github.com/tedzhao226/ato_chatbot.git" \
    "ATO Chatbot" "~21" "llamaindex-small"
reg ragtag-tiger "https://github.com/StuartRiffle/ragtag-tiger.git" \
    "Ragtag Tiger" "~21" "llamaindex-small"
reg llama-index-zoom "https://github.com/TuanaCelik/llama_index_zoom_assistant.git" \
    "LlamaIndex Zoom Assistant" "~15" "llamaindex-small"
reg llamaindex-retrieval-api "https://github.com/Haste171/llamaindex-retrieval-api.git" \
    "LlamaIndex Retrieval API" "~14" "llamaindex-small"
reg multimodal-rag-plugin "https://github.com/jacobmarks/fiftyone-multimodal-rag-plugin.git" \
    "Multimodal RAG Plugin" "~21" "llamaindex-small"
reg chatgpt-custom-knowledge "https://github.com/robindekoster/chatgpt-custom-knowledge-chatbot.git" \
    "ChatGPT Custom Knowledge" "~136" "llamaindex-small"
reg chatpdf-llamaindex "https://github.com/gabacode/chatPDF.git" \
    "chatPDF" "~101" "llamaindex-small"
reg smart-llm-loader "https://github.com/drmingler/smart-llm-loader.git" \
    "Smart LLM Loader" "~75" "llamaindex-small"
reg chatgpt-longterm-memory "https://github.com/ElmiraGhorbani/chatgpt-long-term-memory.git" \
    "ChatGPT Long-Term Memory" "~62" "llamaindex-small"
reg alphasecio-llamaindex "https://github.com/alphasecio/llama-index.git" \
    "LlamaIndex Examples (alphasecio)" "~55" "llamaindex-small"
reg dennisz-agentic-playground "https://github.com/denniszielke/agentic-playground.git" \
    "Agentic Playground" "~53" "llamaindex-small"
reg intelliweb-gpt "https://github.com/AdirthaBorgohain/intelliweb-GPT.git" \
    "IntelliWeb GPT" "~36" "llamaindex-small"
reg johnmalek-supervisor "https://github.com/johnmalek312/llama-index-supervisor.git" \
    "LlamaIndex Supervisor" "~33" "llamaindex-small"
reg contextual-retrieval-anthropic "https://github.com/RionDsilvaCS/contextual-retrieval-by-anthropic.git" \
    "Contextual Retrieval (Anthropic)" "~27" "llamaindex-small"
reg streaming-llm-chat "https://github.com/mickymultani/Streaming-LLM-Chat.git" \
    "Streaming LLM Chat" "~25" "llamaindex-small"
reg docs-n-data "https://github.com/asehmi/docs-n-data-knowledge-app.git" \
    "Docs-n-Data Knowledge App" "~24" "llamaindex-small"
reg llamaindex-flask-demo "https://github.com/mewmix/llama-index-flask-demo.git" \
    "LlamaIndex Flask Demo" "~22" "llamaindex-small"
reg agenticaicoach-li "https://github.com/Agentic-AI-Coach/AgenticAICoach.git" \
    "AgenticAI Coach" "~22" "llamaindex-small"
reg geminsights "https://github.com/izam-mohammed/GemInsights.git" \
    "GemInsights" "~20" "llamaindex-small"
reg j4nn0-llm-rag "https://github.com/J4NN0/llm-rag.git" \
    "LLM RAG" "~20" "llamaindex-small"
reg quickdigest "https://github.com/codingis4noobs2/QuickDigest.git" \
    "QuickDigest" "~44" "llamaindex-small"
reg aitrika "https://github.com/dSupertramp/AItrika.git" \
    "AItrika" "~36" "llamaindex-small"
reg vargha-langchain-rag "https://github.com/Vargha-Kh/Langchain-RAG-DevelopmentKit.git" \
    "LangChain RAG DevKit" "~49" "llamaindex-small"
reg adii-rag-voice "https://github.com/Adii2202/RAG-AI-Voice-assistant-.git" \
    "RAG AI Voice Assistant" "~46" "llamaindex-small"
reg translation-agent-webui "https://github.com/snekkenull/translation-agent-webui.git" \
    "Translation Agent WebUI" "~30" "llamaindex-small"
reg hiflylabs-agent-demo "https://github.com/Hiflylabs/agent-demo.git" \
    "Hiflylabs Agent Demo" "~10" "llamaindex-small"
reg hk-rag-knowledgellm "https://github.com/hk3427/RAG-KnowledgeLLM-LlamaIndex-BOT.git" \
    "RAG KnowledgeLLM Bot" "~13" "llamaindex-small"
reg pyqt-llamaindex "https://github.com/yjg30737/pyqt-llamaindex.git" \
    "PyQt LlamaIndex" "~8" "llamaindex-small"
reg santhalakshminarayana-doppalf "https://github.com/santhalakshminarayana/doppalf.git" \
    "Doppalf" "~9" "llamaindex-small"
reg fltb-bot-the-defect "https://github.com/fltb/bot-the-defect.git" \
    "Bot-the-Defect" "~6" "llamaindex-small"
reg edurag "https://github.com/userHanlh/EduRAG-NetworkAssistant.git" \
    "EduRAG Network Assistant" "~15" "llamaindex-small"
reg llamaindex-ollama-bootstrap2 "https://github.com/lesteroliver911/llamaindex-agentworkflow-browse-agent.git" \
    "LlamaIndex Agent Workflow Browse" "~15" "llamaindex-small"
reg sulaiman-llamaindex-chatbot "https://github.com/sulaiman-shamasna/LlamaIndex-chatbot-with-advanced-search-and-RAG.git" \
    "LlamaIndex Chatbot Advanced" "~20" "llamaindex-small"
reg leann-llamaindex "https://github.com/yichuan-w/LEANN.git" \
    "LEANN" "~10k" "llamaindex-small"
reg romplex-llama-index-rag "https://github.com/romilandc/llama-index-RAG.git" \
    "LlamaIndex RAG (romilandc)" "~15" "llamaindex-small"
reg mcp-toolbox-sdk "https://github.com/googleapis/mcp-toolbox-sdk-python.git" \
    "MCP Toolbox SDK (Google)" "~167" "llamaindex-small"
reg doganarif-promptpilot "https://github.com/doganarif/promptpilot.git" \
    "PromptPilot" "~71" "llamaindex-small"
reg implyinfer-jetson "https://github.com/implyinfer/jetson-orin-nano-field-kit.git" \
    "Jetson Orin Nano RAG Kit" "~149" "llamaindex-small"

# ── CrewAI: Official / Core ──────────────────────────────────────────────

reg crewai-examples "https://github.com/crewAIInc/crewAI-examples.git" \
    "CrewAI Examples" "~3k" "crewai"
reg crewai-tools "https://github.com/crewAIInc/crewAI-tools.git" \
    "CrewAI Tools" "~1.4k" "crewai"
reg awesome-crewai "https://github.com/crewAIInc/awesome-crewai.git" \
    "Awesome CrewAI" "~500" "crewai"

# ── CrewAI: High-Star Applications ──────────────────────────────────────

reg autogroq "https://github.com/jgravelle/AutoGroq.git" \
    "AutoGroq" "~1.5k" "crewai-app"
reg mcp-memory-service "https://github.com/doobidoo/mcp-memory-service.git" \
    "MCP Memory Service" "~1.5k" "crewai-app"
reg crewai-studio "https://github.com/strnad/CrewAI-Studio.git" \
    "CrewAI Studio" "~1.2k" "crewai-app"
reg fullstack-ai-agent "https://github.com/vstorm-co/full-stack-ai-agent-template.git" \
    "Full Stack AI Agent Template" "~808" "crewai-app"
reg viral-clips-crew "https://github.com/alexfazio/viral-clips-crew.git" \
    "Viral Clips Crew" "~749" "crewai-app"
reg aiwritex "https://github.com/iniwap/AIWriteX.git" \
    "AIWriteX" "~700" "crewai-app"
reg upsonic-tiger "https://github.com/Upsonic/Tiger.git" \
    "Tiger (Upsonic)" "~465" "crewai-app"
reg easy-investment-agent "https://github.com/liangdabiao/easy_investment_Agent_crewai.git" \
    "Easy Investment Agent" "~383" "crewai-app"
reg claude-data-analysis "https://github.com/liangdabiao/claude-data-analysis.git" \
    "Claude Data Analysis" "~346" "crewai-app"
reg devyan "https://github.com/theyashwanthsai/Devyan.git" \
    "Devyan" "~290" "crewai-app"
reg openplexity-pages "https://github.com/alexfazio/OpenPlexity-Pages.git" \
    "OpenPlexity Pages" "~253" "crewai-app"
reg nangeplus-crewai "https://github.com/NanGePlus/CrewAITest.git" \
    "CrewAI Test (NanGePlus)" "~226" "crewai-app"
reg crewai-gui-qt "https://github.com/LangGraph-GUI/CrewAI-GUI-Qt.git" \
    "CrewAI GUI Qt" "~206" "crewai-app"
reg wavefront "https://github.com/rootflo/wavefront.git" \
    "Wavefront" "~200" "crewai-app"

# ── CrewAI: Automation & Workflow ────────────────────────────────────────

reg crewai-ui-business-launch "https://github.com/AbubakrChan/crewai-UI-business-product-launch.git" \
    "CrewAI UI Business Launch" "~188" "crewai-workflow"
reg open-extract "https://github.com/velocitybolt/open-extract.git" \
    "Open Extract" "~184" "crewai-workflow"
reg crewai-gmail-automation "https://github.com/tonykipkemboi/crewai-gmail-automation.git" \
    "CrewAI Gmail Automation" "~182" "crewai-workflow"
reg value-crewai "https://github.com/valmi-io/value.git" \
    "Value" "~169" "crewai-workflow"
reg resume-optimization-crew "https://github.com/tonykipkemboi/resume-optimization-crew.git" \
    "Resume Optimization Crew" "~146" "crewai-workflow"
reg crewai-stock-analysis "https://github.com/liangdabiao/crewai_stock_analysis_system.git" \
    "CrewAI Stock Analysis" "~147" "crewai-workflow"
reg geo-ai-agent "https://github.com/brightdata/geo-ai-agent.git" \
    "Geo AI Agent" "~145" "crewai-workflow"
reg trip-planner-agent "https://github.com/tonykipkemboi/trip_planner_agent.git" \
    "Trip Planner Agent" "~139" "crewai-workflow"
reg paper-summarizer "https://github.com/zhangleino1/paper-summarizer.git" \
    "Paper Summarizer" "~126" "crewai-workflow"
reg real-estate-ai-agent "https://github.com/brightdata/real-estate-ai-agent.git" \
    "Real Estate AI Agent" "~121" "crewai-workflow"
reg crewai-flows-fullstack "https://github.com/NanGePlus/CrewAIFlowsFullStack.git" \
    "CrewAI Flows FullStack" "~119" "crewai-workflow"
reg agent-audit "https://github.com/HeadyZhang/agent-audit.git" \
    "Agent Audit" "~117" "crewai-workflow"
reg mengram "https://github.com/alibaizhanov/mengram.git" \
    "Mengram" "~112" "crewai-workflow"
reg nicknochnack-watsonx "https://github.com/nicknochnack/WatsonxCrewAI.git" \
    "Watsonx CrewAI" "~100" "crewai-workflow"
reg fenixai-tradingbot "https://github.com/Ganador1/FenixAI_tradingBot.git" \
    "FenixAI Trading Bot" "~99" "crewai-workflow"
reg jambo-crewai "https://github.com/HideyoshiNakazone/jambo.git" \
    "Jambo" "~93" "crewai-workflow"
reg aitino "https://github.com/startino/aitino.git" \
    "Aitino" "~91" "crewai-workflow"
reg awesome-ai-agents-hub "https://github.com/OneDuckyBoy/Awesome-AI-Agents-HUB-for-CrewAI.git" \
    "Awesome AI Agents HUB" "~90" "crewai-workflow"
reg workshop-ai-agent "https://github.com/caio-moliveira/workshop-ai-agent.git" \
    "Workshop AI Agent" "~88" "crewai-workflow"
reg spotify-playlist-crewai "https://github.com/NTTLuke/spotify-playlist-old.git" \
    "Spotify Playlist (CrewAI)" "~81" "crewai-workflow"

# ── CrewAI: Multi-Agent Systems ──────────────────────────────────────────

reg crewai-sheets-ui "https://github.com/yuriwa/crewai-sheets-ui.git" \
    "CrewAI Sheets UI" "~76" "crewai-multiagent"
reg custom-build-crewai "https://github.com/custom-build-robots/ai-agents-with-CrewAI.git" \
    "AI Agents with CrewAI" "~73" "crewai-multiagent"
reg ai-agile-team "https://github.com/jeanjerome/ai-agile-team.git" \
    "AI Agile Team" "~70" "crewai-multiagent"
reg ai-agents-whyash "https://github.com/whyashthakker/ai-agents.git" \
    "AI Agents (whyash)" "~69" "crewai-multiagent"
reg crewai-streamlit-demo "https://github.com/tonykipkemboi/crewai-streamlit-demo.git" \
    "CrewAI Streamlit Demo" "~69" "crewai-multiagent"
reg agent-os "https://github.com/imran-siddique/agent-os.git" \
    "Agent OS" "~68" "crewai-multiagent"
reg eval-view "https://github.com/hidai25/eval-view.git" \
    "Eval View" "~68" "crewai-multiagent"
reg multi-agents-scratch "https://github.com/AIAnytime/Multi-Agents-System-from-Scratch.git" \
    "Multi-Agents System from Scratch" "~67" "crewai-multiagent"
reg rag-boilerplate "https://github.com/mburaksayici/RAG-Boilerplate.git" \
    "RAG Boilerplate" "~66" "crewai-multiagent"
reg youtube-yapper-trapper "https://github.com/tonykipkemboi/youtube_yapper_trapper.git" \
    "YouTube Yapper Trapper" "~66" "crewai-multiagent"
reg robocrew "https://github.com/Grigorij-Dudnik/RoboCrew.git" \
    "RoboCrew" "~63" "crewai-multiagent"
reg aisquare-studio-qa "https://github.com/AISquare-Studio/AISquare-Studio-QA.git" \
    "AISquare Studio QA" "~63" "crewai-multiagent"
reg abcxyz-vn-stock "https://github.com/abcxyz91/vn_stock_advisor.git" \
    "VN Stock Advisor" "~62" "crewai-multiagent"
reg comfyui-crewai "https://github.com/luandev/ComfyUI-CrewAI.git" \
    "ComfyUI-CrewAI" "~60" "crewai-multiagent"
reg travelplanner-crewai "https://github.com/AdritPal08/TravelPlanner-CrewAi-Agents-Streamlit.git" \
    "TravelPlanner CrewAI" "~54" "crewai-multiagent"
reg multi-agent-rag-template "https://github.com/The-Swarm-Corporation/Multi-Agent-RAG-Template.git" \
    "Multi-Agent RAG Template" "~53" "crewai-multiagent"
reg investment-agent-langgraph "https://github.com/liangdabiao/investment_Agent_langgraph_crewai.git" \
    "Investment Agent (LangGraph+CrewAI)" "~51" "crewai-multiagent"
reg aibtcdev-crew "https://github.com/aibtcdev/ai-agent-crew.git" \
    "AI Agent Crew (Bitcoin)" "~47" "crewai-multiagent"
reg philippe-aitrading "https://github.com/philippe-ostiguy/AITradingCrew.git" \
    "AI Trading Crew" "~47" "crewai-multiagent"
reg akj-multi-ai-crewai "https://github.com/akj2018/Multi-AI-Agent-Systems-with-crewAI.git" \
    "Multi-AI-Agent Systems (CrewAI)" "~50" "crewai-multiagent"
reg ksm-multi-ai-crewai "https://github.com/ksm26/Multi-AI-Agent-Systems-with-crewAI.git" \
    "Multi-AI-Agent Systems (ksm)" "~30" "crewai-multiagent"

# ── CrewAI: Small/Niche ─────────────────────────────────────────────────

reg crewai-mcp "https://github.com/plaban1981/Crewai-MCP.git" \
    "CrewAI MCP" "~40" "crewai-small"
reg haasonsaas-email "https://github.com/haasonsaas/email-agent.git" \
    "Email Agent" "~43" "crewai-small"
reg hugozanini-jira "https://github.com/hugozanini/jira-tiger.git" \
    "Jira Tiger" "~43" "crewai-small"
reg korucutech-kai "https://github.com/KorucuTech/kai.git" \
    "KAI" "~42" "crewai-small"
reg mesutdmn-essay "https://github.com/mesutdmn/Autonomous-Multi-Agent-Systems-with-CrewAI-Essay-Writer.git" \
    "CrewAI Essay Writer" "~40" "crewai-small"
reg mstryoda-agents "https://github.com/mstrYoda/llm-agents-example.git" \
    "LLM Agents Example" "~40" "crewai-small"
reg crew-llamafile "https://github.com/heaversm/crew-llamafile.git" \
    "Crew Llamafile" "~39" "crewai-small"
reg crew-news "https://github.com/rokbenko/crew-news.git" \
    "Crew News" "~39" "crewai-small"
reg botextractai-crewai "https://github.com/botextractai/ai-crewai-multi-agent.git" \
    "CrewAI Multi-Agent (Financial)" "~37" "crewai-small"
reg ainews-blogwriter "https://github.com/LikithMeruvu/AINewsResearcher-and-BlogWriter.git" \
    "AI News Researcher & Blog Writer" "~36" "crewai-small"
reg multiagent-debugger "https://github.com/VishApp/multiagent-debugger.git" \
    "Multiagent Debugger" "~35" "crewai-small"
reg personal-brand-team "https://github.com/AshAIDevelopment/PersonalBrandTeam.git" \
    "Personal Brand Team" "~37" "crewai-small"
reg agentfacts "https://github.com/soth-ai/agentfacts-py.git" \
    "AgentFacts" "~33" "crewai-small"
reg ai-book-writer "https://github.com/agruai/ai-book-writer.git" \
    "AI Book Writer" "~33" "crewai-small"
reg smart-marketing-crewai "https://github.com/praj2408/Smart-Marketing-Assistant-Crew-AI.git" \
    "Smart Marketing Assistant" "~32" "crewai-small"
reg operagents "https://github.com/yanyongyu/operagents.git" \
    "Operagents" "~31" "crewai-small"
reg contextloom "https://github.com/danielckv/ContextLoom.git" \
    "ContextLoom" "~31" "crewai-small"
reg kbhujbal-travel "https://github.com/kbhujbal/Multi-Agent-AI-Travel-Advisor.git" \
    "Multi-Agent Travel Advisor" "~30" "crewai-small"
reg qdrant-crewai-obsidian "https://github.com/qdrant/webinar-crewai-qdrant-obsidian.git" \
    "CrewAI Qdrant Obsidian" "~29" "crewai-small"
reg multi-agent-newsletter "https://github.com/felixggj/multi-agent-ai-newsletter.git" \
    "Multi-Agent AI Newsletter" "~28" "crewai-small"
reg ai-in-pm-pmo "https://github.com/ai-in-pm/PMO-CrewAI.git" \
    "PMO CrewAI" "~28" "crewai-small"
reg cv-agents "https://github.com/0xrushi/cv-agents.git" \
    "CV Agents" "~27" "crewai-small"
reg smart-nutritional "https://github.com/HaileyTQuach/Smart-Nutritional-App.git" \
    "Smart Nutritional App" "~26" "crewai-small"
reg alexnodeland-crewlit "https://github.com/alexnodeland/crewlit.git" \
    "Crewlit" "~26" "crewai-small"
reg maryam-rag-agents "https://github.com/Maryam-Nasseri/RAG-based-AI-Agents.git" \
    "RAG-based AI Agents" "~25" "crewai-small"
reg healthcare-assistant "https://github.com/Dharm3438/Healthcare-Assistant.git" \
    "Healthcare Assistant" "~25" "crewai-small"
reg yaalalabs-agent-kernel "https://github.com/yaalalabs/agent-kernel.git" \
    "Agent Kernel" "~25" "crewai-small"
reg siddhardhan-stock-trader "https://github.com/siddhardhan2323/crewai-stock-trader-agents.git" \
    "CrewAI Stock Trader" "~25" "crewai-small"
reg aws-compliance-crew "https://github.com/aws-samples/sample-compliance-assistant-with-agents.git" \
    "Compliance Assistant (AWS)" "~24" "crewai-small"
reg kalibr-sdk "https://github.com/kalibr-ai/kalibr-sdk-python.git" \
    "Kalibr SDK" "~24" "crewai-small"
reg coral-ai "https://github.com/Coral-Bricks-AI/coral-ai.git" \
    "Coral AI" "~23" "crewai-small"
reg ebrown-stock-analysis "https://github.com/ebrown-32/Agentic-AI-Stock-Analysis-Crew.git" \
    "Agentic Stock Analysis Crew" "~23" "crewai-small"
reg newsletter-agent "https://github.com/ananeridev/newsletter-agent.git" \
    "Newsletter Agent" "~23" "crewai-small"
reg yaitec-hub "https://github.com/yaitec/yaitec-hub-templates.git" \
    "Yaitec Hub Templates" "~23" "crewai-small"
reg asharib-agentic "https://github.com/AsharibAli/agentic-ai-projects.git" \
    "Agentic AI Projects" "~22" "crewai-small"
reg bentoml-bentocrewai "https://github.com/bentoml/BentoCrewAI.git" \
    "BentoCrewAI" "~22" "crewai-small"
reg rosidotidev-jira "https://github.com/rosidotidev/CrewAI-Agentic-Jira.git" \
    "CrewAI Agentic Jira" "~22" "crewai-small"
reg nebeyou-news-agents "https://github.com/NebeyouMusie/News-AI-Agents-Using-CrewAI-And-Google-Gemini-Pro-LLM-Models.git" \
    "News AI Agents (Gemini)" "~22" "crewai-small"
reg python-coding-agent "https://github.com/LikithMeruvu/Python-coding-Agent.git" \
    "Python Coding Agent" "~22" "crewai-small"
reg psrane-market-research "https://github.com/psrane8/Market-Research-Agent.git" \
    "Market Research Agent" "~21" "crewai-small"
reg nighttrek-backlinker "https://github.com/NightTrek/mistral-backlinker.git" \
    "Mistral Backlinker" "~21" "crewai-small"
reg uriafranko-taskforce "https://github.com/uriafranko/TaskForce.git" \
    "TaskForce" "~21" "crewai-small"
reg graphlit-tools "https://github.com/graphlit/graphlit-tools-python.git" \
    "Graphlit Tools" "~20" "crewai-small"
reg nomadu-insaits "https://github.com/Nomadu27/InsAIts.git" \
    "InsAIts" "~20" "crewai-small"
reg langcrew "https://github.com/01-ai/langcrew.git" \
    "LangCrew" "~113" "crewai-small"
reg aipagepad "https://github.com/AjayK47/PagePod.git" \
    "PagePod" "~19" "crewai-small"
reg doctor-assist-crewai "https://github.com/shaadclt/Doctor-Assist-crewAI.git" \
    "Doctor Assist (CrewAI)" "~14" "crewai-small"
reg hmnajam-crewai "https://github.com/hmnajam/crewAI-projects.git" \
    "CrewAI Projects (hmnajam)" "~10" "crewai-small"
reg lakshya-crewai "https://github.com/lakshyakumar/crewAI-projects.git" \
    "CrewAI Projects (lakshya)" "~10" "crewai-small"
reg crewai-debate "https://github.com/rajeswarandhandapani/crewai_multi_agent_debate.git" \
    "CrewAI Multi-Agent Debate" "~5" "crewai-small"
reg techindicium-multiagent "https://github.com/techindicium/MultiAgent-CrewAI.git" \
    "MultiAgent CrewAI (Indicium)" "~5" "crewai-small"
reg minhosong-investor "https://github.com/minhosong88/Investor-Crew.git" \
    "Investor Crew" "~10" "crewai-small"
reg aiforge-crewai "https://github.com/iniwap/AIForge.git" \
    "AIForge" "~48" "crewai-small"
reg prompt-maker "https://github.com/adamjen/Prompt_Maker.git" \
    "Prompt Maker" "~46" "crewai-small"
reg zinyando-awesome-crewai "https://github.com/zinyando/awesome-crewai.git" \
    "Awesome CrewAI (zinyando)" "~15" "crewai-small"
reg 500-ai-agents "https://github.com/ashishpatel26/500-AI-Agents-Projects.git" \
    "500 AI Agents Projects" "~100" "crewai-small"
reg harehimself-crewai-lab "https://github.com/harehimself/crewai-lab.git" \
    "CrewAI Lab" "~9" "crewai-small"
reg billy-crewai-research "https://github.com/billy-enrizky/crewai-research-assistant.git" \
    "CrewAI Research Assistant" "~8" "crewai-small"

# ── Force framework overrides ───────────────────────────────────────────

FORCE_FRAMEWORK=(
  [localgpt]="langchain"
  [private-gpt]="langchain"
  [embedchain]="langchain"
  [llm-app]="langchain"
  [superagent]="langchain"
  [chat-with-pdf]="langchain"
  [objectbox-rag]="langchain"
  [cohere-qdrant-retrieval]="langchain"
  [langchain-rag-chroma]="langchain"
  [rag-chatbot-langchain]="langchain"
  [canopy]="langchain"
  [libre-chat]="llamaindex"
  # LlamaIndex force overrides
  [lazyllm]="llamaindex"
  [thinkrag]="llamaindex"
  [delphic]="llamaindex"
  [local-llama]="llamaindex"
  [veritasgraph]="llamaindex"
  [corpusos]="llamaindex"
  [hello-wordsmith]="llamaindex"
  [paperschat]="llamaindex"
  [llamaindex-omakase-rag]="llamaindex"
  [local-rag-llamaindex]="llamaindex"
  [xrag]="llamaindex"
  [flexible-graphrag]="llamaindex"
  [ragarch]="llamaindex"
  [rag-llamaindex-pinecone]="llamaindex"
  [kyosek-job-search]="llamaindex"
  [ingest-anything]="llamaindex"
  [openinference]="llamaindex"
  [planexe]="llamaindex"
  [llamaindex-docs-agent]="llamaindex"
  [llamaindex-trip-planner]="llamaindex"
  [user-centric-rag]="llamaindex"
  [agentserve]="llamaindex"
  [agentic-rag-llamaindex]="llamaindex"
  [logan-agent-as-service]="llamaindex"
  [agentic-chatbot-llamaindex]="llamaindex"
  [llama4-researcher]="llamaindex"
  [e-library-agent]="llamaindex"
  [ragcoon]="llamaindex"
  [diragnosis]="llamaindex"
  [llamaindexchat]="llamaindex"
  [llamaindex-ollama-chainlit]="llamaindex"
  [ragindex]="llamaindex"
  [rag-application-llamaindex]="llamaindex"
  [llamaindex-with-llama2]="llamaindex"
  [sql-agent-llamaindex]="llamaindex"
  [llamaindex-knowledge-graph]="llamaindex"
  [llamaindex-agent-swastik]="llamaindex"
  [azure-llamaindex]="llamaindex"
  [brainiac-llamaindex]="llamaindex"
  [rag-tui]="llamaindex"
  [chat-rag-llamaindex]="llamaindex"
  [tok-llamaindex]="llamaindex"
  [multimodal-semantic-rag]="llamaindex"
  [m2m-vector-search]="llamaindex"
  [rag-performance]="llamaindex"
  [rag-firewall]="llamaindex"
  [rag-framework-eval]="llamaindex"
  [rag-ingest]="llamaindex"
  [gptstonks]="llamaindex"
  [quackling]="llamaindex"
  [gut-llamaindex]="llamaindex"
  [ai-equity-research]="llamaindex"
  [opik]="llamaindex"
  [gptcache]="llamaindex"
  [gerev]="llamaindex"
  [autollm]="llamaindex"
  [repoagent]="llamaindex"
  [datvodinh-rag-chatbot]="llamaindex"
  [graphrag-toolkit]="llamaindex"
  [restai]="llamaindex"
  [slidespeak]="llamaindex"
  [vincentkoc-airgapped-rag]="llamaindex"
  [fastapi-agents]="llamaindex"
  [bentoml-rag-tutorials]="llamaindex"
  [reliable-rag]="llamaindex"
  [llm-ollama-bootstrap]="llamaindex"
  [chatgpt-custom-knowledge]="llamaindex"
  [chatpdf-llamaindex]="llamaindex"
  [smart-llm-loader]="llamaindex"
  [chatgpt-longterm-memory]="llamaindex"
  [alphasecio-llamaindex]="llamaindex"
  [intelliweb-gpt]="llamaindex"
  [llamaindex-flask-demo]="llamaindex"
  [quickdigest]="llamaindex"
  [aitrika]="llamaindex"
  [adii-rag-voice]="llamaindex"
  [translation-agent-webui]="llamaindex"
  [hk-rag-knowledgellm]="llamaindex"
  [pyqt-llamaindex]="llamaindex"
  [doganarif-promptpilot]="llamaindex"
  # CrewAI force overrides
  [crewai-examples]="crewai"
  [crewai-tools]="crewai"
  [awesome-crewai]="crewai"
  [autogroq]="crewai"
  [mcp-memory-service]="crewai"
  [crewai-studio]="crewai"
  [fullstack-ai-agent]="crewai"
  [viral-clips-crew]="crewai"
  [aiwritex]="crewai"
  [easy-investment-agent]="crewai"
  [claude-data-analysis]="crewai"
  [devyan]="crewai"
  [openplexity-pages]="crewai"
  [nangeplus-crewai]="crewai"
  [crewai-gui-qt]="crewai"
  [wavefront]="crewai"
  [crewai-ui-business-launch]="crewai"
  [open-extract]="crewai"
  [crewai-gmail-automation]="crewai"
  [resume-optimization-crew]="crewai"
  [crewai-stock-analysis]="crewai"
  [geo-ai-agent]="crewai"
  [trip-planner-agent]="crewai"
  [paper-summarizer]="crewai"
  [real-estate-ai-agent]="crewai"
  [crewai-flows-fullstack]="crewai"
  [agent-audit]="crewai"
  [mengram]="crewai"
  [nicknochnack-watsonx]="crewai"
  [fenixai-tradingbot]="crewai"
  [jambo-crewai]="crewai"
  [aitino]="crewai"
  [awesome-ai-agents-hub]="crewai"
  [workshop-ai-agent]="crewai"
  [crewai-sheets-ui]="crewai"
  [custom-build-crewai]="crewai"
  [ai-agile-team]="crewai"
  [crewai-streamlit-demo]="crewai"
  [multi-agents-scratch]="crewai"
  [rag-boilerplate]="crewai"
  [youtube-yapper-trapper]="crewai"
  [robocrew]="crewai"
  [travelplanner-crewai]="crewai"
  [multi-agent-rag-template]="crewai"
  [investment-agent-langgraph]="crewai"
  [philippe-aitrading]="crewai"
  [akj-multi-ai-crewai]="crewai"
  [ksm-multi-ai-crewai]="crewai"
  [crewai-mcp]="crewai"
  [haasonsaas-email]="crewai"
  [mesutdmn-essay]="crewai"
  [botextractai-crewai]="crewai"
  [ainews-blogwriter]="crewai"
  [multiagent-debugger]="crewai"
  [smart-marketing-crewai]="crewai"
  [ebrown-stock-analysis]="crewai"
  [newsletter-agent]="crewai"
  [bentoml-bentocrewai]="crewai"
  [rosidotidev-jira]="crewai"
  [doctor-assist-crewai]="crewai"
  [crewai-debate]="crewai"
  [techindicium-multiagent]="crewai"
  [minhosong-investor]="crewai"
  [langcrew]="crewai"
)

TOTAL_REPOS=${#REPO_NAMES[@]}
echo "=== AgentWall Benchmark 3000 ==="
echo "    $TOTAL_REPOS repositories registered"
echo ""

# ── Clone (parallel) ────────────────────────────────────────────────────

echo "=== Phase 1: Cloning projects (max $MAX_PARALLEL parallel) ==="
clone_count=0
clone_skip=0
clone_fail=0
job_count=0

for name in "${REPO_NAMES[@]}"; do
  dir="$TARGETS_DIR/$name"
  if [ -d "$dir" ]; then
    ((clone_skip++)) || true
    continue
  fi

  # Run clone in background, limit parallelism
  (
    git clone --depth 1 --single-branch "${REPOS[$name]}" "$dir" 2>/dev/null \
      && echo "  ✓ $name" \
      || echo "  ✗ $name (clone failed)"
  ) &
  ((job_count++)) || true

  if (( job_count >= MAX_PARALLEL )); then
    wait -n 2>/dev/null || wait
    ((job_count--)) || true
  fi
done

# Wait for remaining clone jobs
wait
echo "  Cloned: new=$((TOTAL_REPOS - clone_skip)), cached=$clone_skip"
echo ""

# ── Scan ─────────────────────────────────────────────────────────────────

echo "=== Phase 2: Scanning $TOTAL_REPOS projects ==="
scan_done=0
scan_fail=0
scan_skip=0

for name in "${REPO_NAMES[@]}"; do
  dir="$TARGETS_DIR/$name"
  out="$RESULTS_DIR/$name.json"

  if [ ! -d "$dir" ]; then
    echo "  $name: skipped (not cloned)"
    ((scan_skip++)) || true
    continue
  fi

  # Skip if already scanned (idempotent reruns)
  if [ -f "$out" ] && [ -s "$out" ]; then
    echo "  $name: cached"
    ((scan_done++)) || true
    continue
  fi

  echo -n "  [$((scan_done + scan_fail + scan_skip + 1))/$TOTAL_REPOS] $name: scanning..."

  fw_flag=""
  if [[ -v "FORCE_FRAMEWORK[$name]" ]]; then
    fw_flag="--framework ${FORCE_FRAMEWORK[$name]}"
  fi

  scan_start="$(date +%s)"
  # shellcheck disable=SC2086
  if timeout "$SCAN_TIMEOUT" agentwall scan "$dir" $fw_flag --fail-on none --confidence medium --output "$out" >/dev/null 2>&1; then
    scan_exit=0
    echo " done"
  else
    scan_exit=$?
    if [ "$scan_exit" -eq 124 ]; then
      echo " TIMEOUT (${SCAN_TIMEOUT}s)"
    else
      echo " done (exit $scan_exit)"
    fi
  fi
  scan_end="$(date +%s)"
  scan_dur=$((scan_end - scan_start))
  ((scan_done++)) || true

  # Write per-project log entry
  {
    echo "───────────────────────────────────────────────────────"
    echo "Project: $name"
    echo "Path:    $dir"
    echo "Result:  $out"
    echo "Exit:    $scan_exit"
    echo "Duration: ${scan_dur}s"
    if [ -f "$out" ]; then
      python3 -c "
import json, sys
data = json.loads(open('$out').read())
findings = data.get('findings', [])
files = data.get('scanned_files', 0)
errors = data.get('errors', [])
framework = data.get('framework', '?')
print(f'Framework: {framework}')
print(f'Files scanned: {files}')
print(f'Findings: {len(findings)}')
if errors:
    print(f'Errors: {errors}')
sev = {}
for f in findings:
    s = f.get('severity', '?')
    sev[s] = sev.get(s, 0) + 1
if sev:
    print(f'  Severity: {dict(sorted(sev.items()))}')
" 2>/dev/null || echo "  (could not parse result)"
    else
      echo "No output file produced"
    fi
  } >> "$RUN_LOG"
done

echo ""
echo "  Scanned: $scan_done / Skipped: $scan_skip"
echo ""

# ── Generate BENCHMARK3000.md ───────────────────────────────────────────

echo "=== Phase 3: Generating BENCHMARK3000.md ==="

# Export metadata so Python can reconstruct project info
REPO_META_JSON="{"
first=true
for name in "${REPO_NAMES[@]}"; do
  if $first; then first=false; else REPO_META_JSON+=","; fi
  REPO_META_JSON+="\"$name\":\"${REPO_META[$name]}\""
done
REPO_META_JSON+="}"
export REPO_META_JSON

# Export ordered list
REPO_ORDER_CSV=""
for name in "${REPO_NAMES[@]}"; do
  if [ -n "$REPO_ORDER_CSV" ]; then REPO_ORDER_CSV+=","; fi
  REPO_ORDER_CSV+="$name"
done
export REPO_ORDER="$REPO_ORDER_CSV"
export RESULTS_DIR
export BENCHMARK_MD

python3 << 'PYEOF'
import json, sys, os
from pathlib import Path
from datetime import date
from collections import defaultdict

RESULTS_DIR = Path(os.environ.get("RESULTS_DIR", "/tmp/agentwall-results3k"))
BENCHMARK_MD = Path(os.environ.get("BENCHMARK_MD", "BENCHMARK3000.md"))

# ── Rule → Attack Vector mapping ─────────────────────────────────────

RULE_TO_VECTORS = {
    # Memory
    'AW-MEM-001': ['AW-ATK-MEM-001'],
    'AW-MEM-002': ['AW-ATK-MEM-002'],
    'AW-MEM-003': ['AW-ATK-MEM-003'],
    'AW-MEM-004': ['AW-ATK-MEM-004'],
    'AW-MEM-005': ['AW-ATK-INJ-001'],
    # Tool
    'AW-TOOL-001': ['AW-ATK-AGT-001'],
    'AW-TOOL-002': ['AW-ATK-AGT-001'],
    'AW-TOOL-003': ['AW-ATK-AGT-001'],
    'AW-TOOL-004': [],
    'AW-TOOL-005': [],
    # Secrets
    'AW-SEC-001': ['AW-ATK-CFG-004'],
    'AW-SEC-002': [],
    'AW-SEC-003': [],
    # RAG
    'AW-RAG-001': ['AW-ATK-INJ-001'],
    'AW-RAG-002': ['AW-ATK-POI-005'],
    'AW-RAG-003': [],
    'AW-RAG-004': ['AW-ATK-CFG-003'],
    # MCP
    'AW-MCP-001': ['AW-ATK-CFG-003'],
    'AW-MCP-002': ['AW-ATK-CFG-004'],
    'AW-MCP-003': ['AW-ATK-AGT-001'],
    # Serialization
    'AW-SER-001': [],
    'AW-SER-002': [],
    'AW-SER-003': [],
    # Agent
    'AW-AGT-001': ['AW-ATK-AGT-001'],
    'AW-AGT-002': ['AW-ATK-AGT-002'],
    'AW-AGT-003': ['AW-ATK-AGT-001'],
    'AW-AGT-004': ['AW-ATK-AGT-004'],
    # Config (already there)
    'AW-CFG-allow-reset': ['AW-ATK-CFG-001'],
    'AW-CFG-no-tls': ['AW-ATK-CFG-003'],
    'AW-CFG-hardcoded-secret': ['AW-ATK-CFG-004'],
    'AW-CFG-docker-no-auth': ['AW-ATK-CFG-003'],
    'AW-CFG-no-auth': ['AW-ATK-CFG-003'],
    'AW-CFG-debug-mode': ['AW-ATK-CFG-001'],
    'AW-CFG-exposed-port': ['AW-ATK-CFG-003'],
    'AW-CFG-no-password': ['AW-ATK-CFG-003'],
    'AW-CFG-chroma-ephemeral': [],
    'AW-CFG-faiss-no-wrapper': [],
    'AW-CFG-auth-disabled': ['AW-ATK-CFG-003'],
    'AW-CFG-anonymous-access': ['AW-ATK-CFG-003'],
}

ALL_VECTORS = {
    'AW-ATK-MEM-001': 'Cross-Tenant Retrieval (No Filter)',
    'AW-ATK-MEM-002': 'Weak Tenant Isolation (Static Filter)',
    'AW-ATK-MEM-003': 'Namespace/Collection Confusion',
    'AW-ATK-MEM-004': 'Partition Bypass via Direct API',
    'AW-ATK-POI-001': 'PoisonedRAG',
    'AW-ATK-POI-002': 'CorruptRAG',
    'AW-ATK-POI-003': 'MINJA',
    'AW-ATK-POI-004': 'Persistent Memory Poisoning',
    'AW-ATK-POI-005': 'Document Loader Exploitation',
    'AW-ATK-POI-006': 'Training Data Backdoor',
    'AW-ATK-EMB-001': 'Vector Collision Attack',
    'AW-ATK-EMB-002': 'Semantic Cache Poisoning',
    'AW-ATK-EMB-003': 'Embedding Inversion',
    'AW-ATK-EMB-004': 'Adversarial Multi-Modal Embedding',
    'AW-ATK-EMB-005': 'Vector Drift',
    'AW-ATK-INJ-001': 'Stored Prompt Injection',
    'AW-ATK-INJ-002': 'Cross-Session Context Hijacking',
    'AW-ATK-INJ-003': 'EchoLeak',
    'AW-ATK-EXF-001': 'Membership Inference',
    'AW-ATK-EXF-002': 'Embedding Exfiltration via API',
    'AW-ATK-EXF-003': 'Timing Side-Channel',
    'AW-ATK-CFG-001': 'Unsafe Reset Enabled',
    'AW-ATK-CFG-002': 'No Encryption at Rest',
    'AW-ATK-CFG-003': 'No TLS / No Auth / Exposed Ports',
    'AW-ATK-CFG-004': 'Hardcoded API Keys',
    'AW-ATK-CFG-005': 'Missing RBAC',
    'AW-ATK-CFG-006': 'No Row-Level Security',
    'AW-ATK-DOS-001': 'Embedding Flood',
    'AW-ATK-DOS-002': 'Query Amplification',
    'AW-ATK-DOS-003': 'Collection Deletion via Admin',
    'AW-ATK-AGT-001': 'Tool Poisoning / Unsafe Tool Access',
    'AW-ATK-AGT-002': 'Delegation Chain Escalation',
    'AW-ATK-AGT-003': 'Memory-Mediated Identity Hijacking',
    'AW-ATK-AGT-004': 'Cross-Agent Memory Contamination',
    'AW-ATK-AGT-005': 'Conversation History Replay',
}

DETECTABLE_VECTORS = {
    'AW-ATK-MEM-001', 'AW-ATK-MEM-002', 'AW-ATK-MEM-003', 'AW-ATK-MEM-004',
    'AW-ATK-INJ-001',
    'AW-ATK-CFG-001', 'AW-ATK-CFG-003', 'AW-ATK-CFG-004',
    'AW-ATK-AGT-001',
}

RULE_DESCS = {
    'AW-MEM-001': 'No tenant isolation in vector store',
    'AW-MEM-002': 'Shared collection without retrieval filter',
    'AW-MEM-003': 'Memory backend has no access control',
    'AW-MEM-004': 'Injection patterns in retrieval path',
    'AW-MEM-005': 'No sanitization on retrieved memory',
    'AW-TOOL-001': 'Destructive tool without approval gate',
    'AW-TOOL-002': 'Tool accepts arbitrary code execution',
    'AW-TOOL-003': 'High-risk tool lacks scope check',
    'AW-TOOL-004': 'Tool has no description',
    'AW-TOOL-005': 'Agent has >15 tools',
    'AW-SEC-001': 'Hardcoded API key/secret in agent config',
    'AW-SEC-002': 'Env var injected into prompt template',
    'AW-SEC-003': 'Agent context logged at DEBUG level',
    'AW-RAG-001': 'Retrieved context without delimiters',
    'AW-RAG-002': 'Ingestion from untrusted source',
    'AW-RAG-003': 'Unencrypted local vector store',
    'AW-RAG-004': 'Vector store exposed without auth',
    'AW-MCP-001': 'MCP server without authentication',
    'AW-MCP-002': 'Static token in MCP config',
    'AW-MCP-003': 'MCP tool with shell/filesystem access',
    'AW-SER-001': 'Unsafe deserialization',
    'AW-SER-002': 'Unpinned agent framework dependency',
    'AW-SER-003': 'Dynamic import with variable argument',
    'AW-AGT-001': 'Sub-agent inherits full parent tool set',
    'AW-AGT-002': 'Agent-to-agent communication without auth',
    'AW-AGT-003': 'Agent has read+write+delete without approval',
    'AW-AGT-004': 'LLM output stored to memory without validation',
}

NOT_DETECTED_REASONS = {
    'AW-ATK-POI-001': 'Requires runtime: inject docs, measure ranking',
    'AW-ATK-POI-002': 'Requires runtime: single-doc injection',
    'AW-ATK-POI-003': 'Requires runtime: query-only memory injection',
    'AW-ATK-POI-004': 'Requires runtime: time-delayed session analysis',
    'AW-ATK-POI-005': 'Requires binary analysis: PDF/DOCX hidden content',
    'AW-ATK-POI-006': 'Requires tracking memory→fine-tuning pipeline',
    'AW-ATK-EMB-001': 'Requires embedding model invocation',
    'AW-ATK-EMB-002': 'Requires semantic cache identification',
    'AW-ATK-EMB-003': 'Requires embedding model + inversion validation',
    'AW-ATK-EMB-004': 'Requires multi-modal model analysis',
    'AW-ATK-EMB-005': 'Requires embedding lifecycle tracking',
    'AW-ATK-INJ-002': 'Requires session identity tracking',
    'AW-ATK-INJ-003': 'Requires action execution tracing',
    'AW-ATK-EXF-001': 'Requires runtime: membership inference',
    'AW-ATK-EXF-002': 'Requires runtime: embedding extraction',
    'AW-ATK-EXF-003': 'Requires runtime: timing measurement',
    'AW-ATK-CFG-002': 'Requires vector DB config schema inspection',
    'AW-ATK-CFG-005': 'Requires vector DB RBAC/ACL audit',
    'AW-ATK-CFG-006': 'Requires PostgreSQL RLS policy inspection',
    'AW-ATK-DOS-001': 'Requires rate-limit config audit',
    'AW-ATK-DOS-002': 'Requires parameter bounds checking',
    'AW-ATK-DOS-003': 'Requires admin endpoint auth audit',
    'AW-ATK-AGT-002': 'Requires multi-agent delegation graph',
    'AW-ATK-AGT-003': 'Requires agent identity redefinition detection',
    'AW-ATK-AGT-004': 'Requires multi-agent shared memory provenance',
    'AW-ATK-AGT-005': 'Requires session management analysis',
}

# ── Category definitions for report grouping ─────────────────────────

CATEGORIES = [
    ("tier1-langchain",    "Tier 1 — LangChain Ecosystem (>2k stars)"),
    ("llamaindex",         "Tier 2 — LlamaIndex Ecosystem"),
    ("multi-agent",        "Tier 3 — Multi-Agent Frameworks"),
    ("rag-app",            "Tier 4 — RAG Applications"),
    ("vector-store",       "Tier 5 — Vector Store Ecosystems"),
    ("memory-knowledge",   "Tier 6 — Memory & Knowledge Systems"),
    ("chatbot-assistant",  "Tier 7 — Chatbot / Assistant Frameworks"),
    ("code-dev-agent",     "Tier 8 — Code / Dev Agents"),
    ("production-platform","Tier 9 — Production Agent Platforms"),
    ("tier2-small",        "Tier 10 — Small / Niche Projects"),
]

# ── Load all results ─────────────────────────────────────────────────

# Read the REPO_META from environment (passed as JSON)
import subprocess
repo_meta_raw = os.environ.get("REPO_META_JSON", "{}")
try:
    REPO_META = json.loads(repo_meta_raw)
except Exception:
    REPO_META = {}

# Build project list from result files + metadata
projects = {}
for json_file in sorted(RESULTS_DIR.glob("*.json")):
    key = json_file.stem
    try:
        data = json.loads(json_file.read_text())
    except Exception:
        data = None
    meta = REPO_META.get(key, f"{key}|?|unknown")
    parts = meta.split("|")
    display = parts[0] if len(parts) > 0 else key
    stars = parts[1] if len(parts) > 1 else "?"
    category = parts[2] if len(parts) > 2 else "unknown"
    projects[key] = {
        "display": display,
        "stars": stars,
        "category": category,
        "data": data,
    }

# Also add entries for registered repos without results (not cloned / not scanned)
for key, meta_str in REPO_META.items():
    if key not in projects:
        parts = meta_str.split("|")
        projects[key] = {
            "display": parts[0] if len(parts) > 0 else key,
            "stars": parts[1] if len(parts) > 1 else "?",
            "category": parts[2] if len(parts) > 2 else "unknown",
            "data": None,
        }

# Respect registration order
repo_order_raw = os.environ.get("REPO_ORDER", "")
REPO_ORDER = [x for x in repo_order_raw.split(",") if x] if repo_order_raw else sorted(projects.keys())


def extract_vectors(findings):
    vectors = {}
    for f in findings:
        rule_id = f.get('rule_id', '')
        for vec_id in RULE_TO_VECTORS.get(rule_id, []):
            if vec_id not in vectors:
                vectors[vec_id] = []
            vectors[vec_id].append({
                'rule_id': rule_id,
                'file': f.get('file'),
                'line': f.get('line'),
                'severity': f.get('severity', '?'),
                'title': f.get('title', ''),
            })
    return vectors


# ── Build report ─────────────────────────────────────────────────────

lines = []
w = lines.append

w("# AgentWall Benchmark 3000")
w("")
w(f"**Date:** {date.today().isoformat()}")
w(f"**Version:** {os.popen('agentwall version 2>/dev/null').read().strip() or 'dev'}")
w("**Layers enabled:** L0–L6 (default static analysis) + V5 engine")
w(f"**Projects:** {len(REPO_ORDER)}")
w("**Reproduce:** `./scripts/benchmark3000.sh`")
w("")
w("---")
w("")

# ── Per-category tables ──────────────────────────────────────────────

grand_findings = 0
grand_crit = 0
grand_high = 0
grand_files = 0
grand_scanned = 0
grand_with_findings = 0
all_vectors_found = {}
all_rules = defaultdict(int)

category_stats = []  # (label, findings, crit, high, files, scanned, with_findings)

section_num = 1
for cat_key, cat_label in CATEGORIES:
    cat_projects = [k for k in REPO_ORDER if projects.get(k, {}).get("category") == cat_key]
    if not cat_projects:
        continue

    w(f"## {section_num}. {cat_label}")
    w("")
    w("| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |")
    w("|---|---|---|---|---|---|---|---|---|---|")

    t_findings = 0; t_crit = 0; t_high = 0; t_files = 0; t_with = 0; t_scanned = 0

    for idx, key in enumerate(cat_projects, 1):
        proj = projects[key]
        display = proj["display"]
        stars = proj["stars"]
        data = proj["data"]

        if data is None:
            w(f"| {idx} | {display} | {stars} | - | - | - | - | - | - | not scanned |")
            continue

        t_scanned += 1
        findings = data.get("findings", [])
        files = data.get("scanned_files", 0)
        t_files += files

        sev = defaultdict(int)
        rules = defaultdict(int)
        for finding in findings:
            s = finding.get("severity", "?").lower()
            sev[s] += 1
            r = finding.get("rule_id", "?")
            rules[r] += 1
            all_rules[r] += 1

        crit = sev["critical"]; high = sev["high"]
        med = sev["medium"]; low = sev["low"] + sev["info"]
        total = len(findings)
        t_findings += total; t_crit += crit; t_high += high
        if total > 0:
            t_with += 1

        # Extract vectors
        proj_vectors = extract_vectors(findings)
        for vec_id, evidence in proj_vectors.items():
            if vec_id not in all_vectors_found:
                all_vectors_found[vec_id] = []
            for e in evidence:
                e["project"] = display
            all_vectors_found[vec_id].extend(evidence)

        top = sorted(rules.items(), key=lambda x: -x[1])[:3]
        rule_str = ", ".join(f"{r}({c})" for r, c in top) if top else "—"
        w(f"| {idx} | {display} | {stars} | {files} | {total} | {crit} | {high} | {med} | {low} | {rule_str} |")

    w("")
    w(f"**Totals: {t_findings} findings ({t_crit} CRITICAL, {t_high} HIGH) across {t_files} files. {t_with}/{len(cat_projects)} have findings.**")
    w("")
    w("---")
    w("")

    grand_findings += t_findings
    grand_crit += t_crit
    grand_high += t_high
    grand_files += t_files
    grand_scanned += t_scanned
    grand_with_findings += t_with
    category_stats.append((cat_label, t_findings, t_crit, t_high, t_files, t_scanned, t_with, len(cat_projects)))
    section_num += 1

# ── Grand summary ────────────────────────────────────────────────────

w(f"## {section_num}. Grand Summary")
w("")
w("| Metric | Value |")
w("|---|---|")
w(f"| Total projects | {len(REPO_ORDER)} |")
w(f"| Projects scanned | {grand_scanned} |")
w(f"| Projects with findings | {grand_with_findings} ({grand_with_findings*100//max(grand_scanned,1)}%) |")
w(f"| Total files scanned | {grand_files:,} |")
w(f"| Total findings | {grand_findings} |")
w(f"| CRITICAL | {grand_crit} |")
w(f"| HIGH | {grand_high} |")
fpf = f"{grand_findings / max(grand_files,1):.3f}" if grand_files else "0"
w(f"| Findings per file | {fpf} |")
w("")

w("### Category Comparison")
w("")
w("| Category | Projects | Scanned | With Findings | Findings | CRIT | HIGH | Files |")
w("|---|---|---|---|---|---|---|---|")
for label, f, c, h, fi, sc, wf, total in category_stats:
    short = label.split("—")[-1].strip() if "—" in label else label
    w(f"| {short} | {total} | {sc} | {wf} | {f} | {c} | {h} | {fi:,} |")
w("")
w("---")
w("")
section_num += 1

# ── Rule distribution ────────────────────────────────────────────────

w(f"## {section_num}. Rule Distribution")
w("")

if all_rules:
    w("| Rule | Count | % | Description |")
    w("|---|---|---|---|")
    for rule_id, count in sorted(all_rules.items(), key=lambda x: -x[1]):
        pct = f"{count / grand_findings * 100:.0f}%" if grand_findings else "0%"
        desc = RULE_DESCS.get(rule_id, rule_id)
        w(f"| {rule_id} | {count} | {pct} | {desc} |")
else:
    w("No findings to report.")

w("")
w("---")
w("")
section_num += 1

# ── FP Estimation ───────────────────────────────────────────────────
w(f"## {section_num}. False Positive Estimation")
w("")
w("Based on manual triage of 98 findings against real source code (2026-03-20).")
w("")

# Measured FP rates from triage (hardcoded from empirical measurement)
FP_RATES = {
    'AW-MEM-001': (0, 13, 'Skip library code, require multi-tenant evidence'),
    'AW-SEC-003': (14, 30, 'Require content reference, not metadata access'),
    'AW-SER-003': (16, 30, 'Suppress dict-lookup imports, variable indirection'),
    'AW-CFG-hardcoded-secret': (4, 16, 'Skip templates, placeholders, non-secret keys'),
    'AW-MEM-005': (2, 9, 'Require retrieval-to-sink path'),
}

w("| Rule | Count | Sampled | TP | FP | FP Rate | Est. FP in Benchmark | Mitigation |")
w("|---|---|---|---|---|---|---|---|")

total_est_tp = 0
total_est_fp = 0

for rule_id, count in sorted(all_rules.items(), key=lambda x: -x[1]):
    if rule_id in FP_RATES:
        tp, sampled, mitigation = FP_RATES[rule_id]
        fp = sampled - tp
        fp_rate = fp / sampled if sampled > 0 else 0
        est_fp = int(count * fp_rate)
        est_tp = count - est_fp
        total_est_fp += est_fp
        total_est_tp += est_tp
        w(f"| {rule_id} | {count} | {sampled} | {tp} | {fp} | {fp_rate:.0%} | ~{est_fp} | {mitigation} |")
    else:
        # Rules not triaged — assume 15% FP (conservative default)
        est_fp = int(count * 0.15)
        est_tp = count - est_fp
        total_est_fp += est_fp
        total_est_tp += est_tp
        desc = RULE_DESCS.get(rule_id, rule_id)
        w(f"| {rule_id} | {count} | — | — | — | ~15% (est.) | ~{est_fp} | Not triaged |")

w("")
w(f"**Estimated totals:** {grand_findings} findings → ~{total_est_tp} true positives, ~{total_est_fp} false positives ({total_est_fp * 100 // max(grand_findings, 1)}% est. FP rate)")
w("")
w("*FP rates for triaged rules are based on manual verification of real source code.")
w("Untriaged rules use 15% conservative estimate. Actual FP rate may vary.*")
w("")
w("---")
w("")
section_num += 1

# ── Attack vector coverage ───────────────────────────────────────────

detected_count = len(DETECTABLE_VECTORS)
total_vectors = len(ALL_VECTORS)
w(f"## {section_num}. Attack Vector Coverage ({detected_count} / {total_vectors} Detectable)")
w("")

atk_categories = {
    'MEM': ('Memory Isolation', 4),
    'POI': ('Data Poisoning', 6),
    'EMB': ('Embedding Attacks', 5),
    'INJ': ('Prompt Injection', 3),
    'EXF': ('Exfiltration', 3),
    'CFG': ('Configuration', 6),
    'DOS': ('Denial of Service', 3),
    'AGT': ('Agentic Attacks', 5),
}

w("| Category | Detected | Total | Coverage |")
w("|---|---|---|---|")
for cat, (cat_name, cat_total) in atk_categories.items():
    detected = sum(1 for v in DETECTABLE_VECTORS if f"-{cat}-" in v)
    pct = f"{detected / cat_total * 100:.0f}%"
    w(f"| **{cat}** — {cat_name} | {detected} | {cat_total} | {pct} |")

w("")

# Vectors confirmed
w("### Attack Vectors Confirmed in Real-World Projects")
w("")

if all_vectors_found:
    w("| Attack Vector | Description | Projects Affected | Hits | Example Evidence |")
    w("|---|---|---|---|---|")

    for vec_id in sorted(all_vectors_found.keys()):
        evidence_list = all_vectors_found[vec_id]
        desc = ALL_VECTORS.get(vec_id, vec_id)
        projects_hit = sorted(set(e["project"] for e in evidence_list))
        total_hits = len(evidence_list)

        example = None
        for sev_pref in ["critical", "high", "medium", "low"]:
            for e in evidence_list:
                if e["severity"] == sev_pref and e.get("file"):
                    example = e
                    break
            if example:
                break
        if not example and evidence_list:
            example = evidence_list[0]

        proj_str = ", ".join(projects_hit[:10])
        if len(projects_hit) > 10:
            proj_str += f" (+{len(projects_hit) - 10} more)"

        if example and example.get("file"):
            fname = Path(example["file"]).name
            evidence_str = f'`{fname}:{example.get("line", "?")}` ({example["rule_id"]})'
        else:
            evidence_str = f'({example["rule_id"]})' if example else "—"

        w(f"| **{vec_id}** | {desc} | {proj_str} | {total_hits} | {evidence_str} |")
    w("")
else:
    w("No scan results available yet. Run `./scripts/benchmark3000.sh` first.")
    w("")

# Vectors not detected
not_detected = [v for v in sorted(ALL_VECTORS.keys()) if v not in DETECTABLE_VECTORS]
w(f"### Vectors Not Detected ({len(not_detected)} / {total_vectors})")
w("")
w("| Vector | Description | Reason |")
w("|---|---|---|")
for vec_id in not_detected:
    desc = ALL_VECTORS[vec_id]
    reason = NOT_DETECTED_REASONS.get(vec_id, "Out of scope for static analysis")
    w(f"| {vec_id} | {desc} | {reason} |")

w("")
w("---")
w("")
section_num += 1

# ── Heatmap ──────────────────────────────────────────────────────────

w(f"## {section_num}. Attack Vector Heatmap (Per Project)")
w("")

detected_vec_ids = sorted(DETECTABLE_VECTORS)
short_labels = [v.replace("AW-ATK-", "") for v in detected_vec_ids]
header = "| Project | " + " | ".join(short_labels) + " | Total |"
sep = "| --- | " + " | ".join(["---"] * len(detected_vec_ids)) + " | --- |"
w(header)
w(sep)

for key in REPO_ORDER:
    proj = projects.get(key)
    if not proj:
        continue
    display = proj["display"]
    data = proj["data"]

    if data is None:
        cells = " | ".join(["—"] * len(detected_vec_ids))
        w(f"| {display} | {cells} | — |")
        continue

    findings = data.get("findings", [])
    proj_vectors = extract_vectors(findings)
    row_total = 0
    cells = []
    for vec_id in detected_vec_ids:
        hits = proj_vectors.get(vec_id, [])
        count = len(hits)
        row_total += count
        cells.append(f"**{count}**" if count > 0 else "·")

    w(f'| {display} | {" | ".join(cells)} | {row_total} |')

w("")
w("*Legend: number = findings count, · = not detected, — = not scanned*")
w("")
w("---")
w("")
section_num += 1

# ── How to reproduce ─────────────────────────────────────────────────

w(f"## {section_num}. How to Reproduce")
w("")
w("```bash")
w('pip install -e ".[dev]"')
w("./scripts/benchmark3000.sh")
w("```")
w("")
w("### Environment Variables")
w("")
w("| Variable | Default | Description |")
w("|---|---|---|")
w("| `MAX_PARALLEL` | 4 | Parallel git clone jobs |")
w("| `SCAN_TIMEOUT` | 300 | Per-project scan timeout (seconds) |")

BENCHMARK_MD.write_text("\n".join(lines) + "\n", encoding="utf-8")
print(f"  Written to: {BENCHMARK_MD}")
print(f"  Total projects: {len(REPO_ORDER)}")
print(f"  Total findings: {grand_findings}")
print(f"  Attack vectors confirmed: {len(all_vectors_found)}/{detected_count}")
PYEOF

# ── Write log summary ───────────────────────────────────────────────

{
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "Run Summary — $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "═══════════════════════════════════════════════════════"
  echo "BENCHMARK.md: $BENCHMARK_MD"
  echo "JSON reports: $RESULTS_DIR/"
  echo "Log: $RUN_LOG"
  python3 -c "
import json
from pathlib import Path
results_dir = Path('$RESULTS_DIR')
total_f = 0; total_files = 0; scanned = 0; with_findings = 0
for p in sorted(results_dir.glob('*.json')):
    try:
        d = json.loads(p.read_text())
        findings = d.get('findings', [])
        total_f += len(findings)
        total_files += d.get('scanned_files', 0)
        scanned += 1
        if findings: with_findings += 1
    except Exception:
        pass
print(f'Projects scanned: {scanned}')
print(f'Projects with findings: {with_findings}')
print(f'Total files: {total_files}')
print(f'Total findings: {total_f}')
" 2>/dev/null
} >> "$RUN_LOG"

echo ""
echo "=== Benchmark 3000 complete ==="
echo "JSON reports: $RESULTS_DIR/"
echo "Report: $BENCHMARK_MD"
echo "Log: $RUN_LOG"
