#!/usr/bin/env bash
# AgentWall Benchmark — scan top 20 real-world LangChain projects
# Usage: ./scripts/benchmark.sh [targets_dir] [results_dir]
#
# Clones projects (if not already present), runs agentwall scan on each,
# maps findings to attack vectors, and generates BENCHMARK.md.

set -euo pipefail

TARGETS_DIR="${1:-/tmp/agentwall-targets}"
RESULTS_DIR="${2:-/tmp/agentwall-results}"
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
BENCHMARK_MD="$PROJECT_ROOT/BENCHMARK.md"
LOG_DIR="$PROJECT_ROOT/logs"
RUN_TIMESTAMP="$(date '+%Y%m%d_%H%M%S')"
RUN_LOG="$LOG_DIR/benchmark_${RUN_TIMESTAMP}.log"

mkdir -p "$TARGETS_DIR" "$RESULTS_DIR" "$LOG_DIR"

# Start run log
{
  echo "═══════════════════════════════════════════════════════"
  echo "AgentWall Benchmark Run — $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "═══════════════════════════════════════════════════════"
  echo "Targets: $TARGETS_DIR"
  echo "Results: $RESULTS_DIR"
  echo "AgentWall version: $(agentwall version 2>/dev/null || echo 'unknown')"
  echo ""
} > "$RUN_LOG"

# ── Tier 1: Top 20 by stars (LangChain ecosystem) ────────────────────────

# Ordered list to preserve display order
REPO_NAMES=(
  langchain-chatchat
  private-gpt
  quivr
  localgpt
  docsgpt
  gpt-researcher
  onyx
  db-gpt
  chat-langchain
  rasagpt
  langflow
  flowise
  open-interpreter
  chainlit
  embedchain
  llm-app
  haystack
  superagent
  agentgpt
  auto-gpt-web
  # Tier 2: Small repos (<500 stars)
  memory-agent
  rag-research-agent
  langchain-chatbot
  chat-with-websites
  cohere-qdrant-retrieval
  rag-chatbot-langchain
  langchain-rag-chroma
  chat-with-pdf
  langchain-multi-agent
  objectbox-rag
)

declare -A REPOS=(
  # Tier 1
  [langchain-chatchat]="https://github.com/chatchat-space/Langchain-Chatchat.git"
  [private-gpt]="https://github.com/zylon-ai/private-gpt.git"
  [quivr]="https://github.com/QuivrHQ/quivr.git"
  [localgpt]="https://github.com/PromtEngineer/localGPT.git"
  [docsgpt]="https://github.com/arc53/DocsGPT.git"
  [gpt-researcher]="https://github.com/assafelovic/gpt-researcher.git"
  [onyx]="https://github.com/onyx-dot-app/onyx.git"
  [db-gpt]="https://github.com/eosphoros-ai/DB-GPT.git"
  [chat-langchain]="https://github.com/langchain-ai/chat-langchain.git"
  [rasagpt]="https://github.com/paulpierre/RasaGPT.git"
  [langflow]="https://github.com/langflow-ai/langflow.git"
  [flowise]="https://github.com/FlowiseAI/Flowise.git"
  [open-interpreter]="https://github.com/OpenInterpreter/open-interpreter.git"
  [chainlit]="https://github.com/Chainlit/chainlit.git"
  [embedchain]="https://github.com/mem0ai/mem0.git"
  [llm-app]="https://github.com/pathwaycom/llm-app.git"
  [haystack]="https://github.com/deepset-ai/haystack.git"
  [superagent]="https://github.com/superagent-ai/superagent.git"
  [agentgpt]="https://github.com/reworkd/AgentGPT.git"
  [auto-gpt-web]="https://github.com/Significant-Gravitas/AutoGPT.git"
  # Tier 2
  [memory-agent]="https://github.com/langchain-ai/memory-agent.git"
  [rag-research-agent]="https://github.com/langchain-ai/rag-research-agent-template.git"
  [langchain-chatbot]="https://github.com/shashankdeshpande/langchain-chatbot.git"
  [chat-with-websites]="https://github.com/alejandro-ao/chat-with-websites.git"
  [cohere-qdrant-retrieval]="https://github.com/menloparklab/langchain-cohere-qdrant-doc-retrieval.git"
  [rag-chatbot-langchain]="https://github.com/AlaGrine/RAG_chatabot_with_Langchain.git"
  [langchain-rag-chroma]="https://github.com/romilandc/langchain-RAG.git"
  [chat-with-pdf]="https://github.com/ashutoshvct/chat-with-pdf.git"
  [langchain-multi-agent]="https://github.com/Hegazy360/langchain-multi-agent.git"
  [objectbox-rag]="https://github.com/NebeyouMusie/End-to-End-RAG-Project-using-ObjectBox-and-LangChain.git"
)

# Projects that need --framework langchain (auto-detect fails)
declare -A FORCE_FRAMEWORK=(
  [localgpt]="langchain"
  [private-gpt]="langchain"
  [embedchain]="langchain"
  [llm-app]="langchain"
  [superagent]="langchain"
  # Tier 2
  [chat-with-pdf]="langchain"
  [objectbox-rag]="langchain"
  [cohere-qdrant-retrieval]="langchain"
  [langchain-rag-chroma]="langchain"
  [rag-chatbot-langchain]="langchain"
)

# ── Clone ─────────────────────────────────────────────────────────────────

echo "=== Cloning projects ==="
for name in "${REPO_NAMES[@]}"; do
  dir="$TARGETS_DIR/$name"
  if [ -d "$dir" ]; then
    echo "  $name: already cloned"
  else
    echo "  $name: cloning..."
    git clone --depth 1 "${REPOS[$name]}" "$dir" 2>/dev/null || echo "  $name: clone failed"
  fi
done

# ── Scan ──────────────────────────────────────────────────────────────────

echo ""
echo "=== Running AgentWall scans ==="
for name in "${REPO_NAMES[@]}"; do
  dir="$TARGETS_DIR/$name"
  out="$RESULTS_DIR/$name.json"

  if [ ! -d "$dir" ]; then
    echo "  $name: skipped (not cloned)"
    continue
  fi

  echo -n "  $name: scanning..."

  fw_flag=""
  if [[ -v "FORCE_FRAMEWORK[$name]" ]]; then
    fw_flag="--framework ${FORCE_FRAMEWORK[$name]}"
  fi

  # shellcheck disable=SC2086
  scan_start="$(date +%s)"
  if agentwall scan "$dir" $fw_flag --fail-on none --confidence medium --output "$out" >/dev/null 2>&1; then
    scan_exit=0
    echo " done"
  else
    scan_exit=$?
    echo " done (exit $scan_exit)"
  fi
  scan_end="$(date +%s)"
  scan_dur=$((scan_end - scan_start))

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
conf = {}
for f in findings:
    c = f.get('confidence', '?')
    conf[c] = conf.get(c, 0) + 1
if conf:
    print(f'  Confidence: {dict(sorted(conf.items()))}')
print()
for f in findings:
    loc = f.get('file', '?')
    line = f.get('line', '?')
    rule = f.get('rule_id', '?')
    sev = f.get('severity', '?')
    conf = f.get('confidence', '?')
    title = f.get('title', '')
    desc = f.get('description', '')
    fix = f.get('fix_suggestion') or f.get('fix', '')
    print(f'  [{sev.upper():8s}] [{conf:6s}] {rule}')
    print(f'    {title}')
    print(f'    {loc}:{line}')
    if desc and desc != title:
        print(f'    {desc}')
    if fix:
        print(f'    Fix: {fix}')
    print()
" 2>/dev/null || echo "  (could not parse result)"
    else
      echo "No output file produced"
    fi
  } >> "$RUN_LOG"
done

# ── Generate BENCHMARK.md ────────────────────────────────────────────────

echo ""
echo "=== Generating BENCHMARK.md ==="

python3 -c "
import json, sys
from pathlib import Path
from datetime import date

RESULTS_DIR = Path('$RESULTS_DIR')
BENCHMARK_MD = Path('$BENCHMARK_MD')

RULE_TO_VECTORS = {
    'AW-MEM-001': ['AW-ATK-MEM-001'],
    'AW-MEM-002': ['AW-ATK-MEM-002'],
    'AW-MEM-003': ['AW-ATK-MEM-003'],
    'AW-MEM-004': ['AW-ATK-MEM-004'],
    'AW-MEM-005': ['AW-ATK-INJ-001'],
    'AW-TOOL-001': ['AW-ATK-AGT-001'],
    'AW-TOOL-002': ['AW-ATK-AGT-001'],
    'AW-TOOL-003': ['AW-ATK-AGT-001'],
    'AW-TOOL-004': [],
    'AW-TOOL-005': [],
    'AW-CFG-allow-reset': ['AW-ATK-CFG-001'],
    'AW-CFG-no-tls': ['AW-ATK-CFG-003'],
    'AW-CFG-hardcoded-secret': ['AW-ATK-CFG-004'],
    'AW-CFG-docker-no-auth': ['AW-ATK-CFG-003'],
    'AW-CFG-no-auth': ['AW-ATK-CFG-003'],
    'AW-CFG-debug-mode': ['AW-ATK-CFG-001'],
    'AW-CFG-exposed-port': ['AW-ATK-CFG-003'],
    'AW-CFG-no-password': ['AW-ATK-CFG-003'],
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

PROJECTS = {
    'langchain-chatchat': ('Langchain-Chatchat', '~37k'),
    'private-gpt': ('PrivateGPT', '~54k'),
    'quivr': ('Quivr', '~36k'),
    'localgpt': ('LocalGPT', '~22k'),
    'docsgpt': ('DocsGPT', '~15k'),
    'gpt-researcher': ('GPT-Researcher', '~17k'),
    'onyx': ('Onyx/Danswer', '~12k'),
    'db-gpt': ('DB-GPT', '~17k'),
    'chat-langchain': ('Chat-LangChain', '~6k'),
    'rasagpt': ('RasaGPT', '~2.4k'),
    'langflow': ('Langflow', '~48k'),
    'flowise': ('Flowise', '~35k'),
    'open-interpreter': ('Open Interpreter', '~58k'),
    'chainlit': ('Chainlit', '~8k'),
    'embedchain': ('Mem0/Embedchain', '~25k'),
    'llm-app': ('LLM App (Pathway)', '~4k'),
    'haystack': ('Haystack', '~18k'),
    'superagent': ('SuperAgent', '~5k'),
    'agentgpt': ('AgentGPT', '~32k'),
    'auto-gpt-web': ('AutoGPT', '~172k'),
    # Tier 2
    'memory-agent': ('memory-agent', '416'),
    'rag-research-agent': ('rag-research-agent-template', '295'),
    'langchain-chatbot': ('langchain-chatbot', '273'),
    'chat-with-websites': ('chat-with-websites', '260'),
    'cohere-qdrant-retrieval': ('cohere-qdrant-doc-retrieval', '152'),
    'rag-chatbot-langchain': ('RAG-chatbot-langchain', '133'),
    'langchain-rag-chroma': ('langchain-RAG-chroma', '8'),
    'chat-with-pdf': ('chat-with-pdf', '2'),
    'langchain-multi-agent': ('langchain-multi-agent', '10'),
    'objectbox-rag': ('objectbox-rag', '10'),
}

TIER1_ORDER = [
    'langchain-chatchat', 'private-gpt', 'quivr', 'localgpt', 'docsgpt',
    'gpt-researcher', 'onyx', 'db-gpt', 'chat-langchain', 'rasagpt',
    'langflow', 'flowise', 'open-interpreter', 'chainlit', 'embedchain',
    'llm-app', 'haystack', 'superagent', 'agentgpt', 'auto-gpt-web',
]

TIER2_ORDER = [
    'memory-agent', 'rag-research-agent', 'langchain-chatbot',
    'chat-with-websites', 'cohere-qdrant-retrieval', 'rag-chatbot-langchain',
    'langchain-rag-chroma', 'chat-with-pdf', 'langchain-multi-agent',
    'objectbox-rag',
]

PROJECT_ORDER = TIER1_ORDER + TIER2_ORDER

def extract_vectors(findings):
    vectors = {}
    for f in findings:
        rule_id = f.get('rule_id', '')
        mapped = RULE_TO_VECTORS.get(rule_id, [])
        for vec_id in mapped:
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

lines = []
w = lines.append

w('# AgentWall Benchmark Report')
w('')
w(f'**Date:** {date.today().isoformat()}')
w('**Version:** 0.1.0 (Phase 1 complete)')
w('**Layers enabled:** L0\u2013L6 (default static analysis)')
w('**Reproduce:** \`./scripts/benchmark.sh\`')
w('')
w('---')
w('')

# Helper to emit a tier table
def emit_tier_table(tier_order, tier_label):
    w(f'| # | Project | Stars | Files | Findings | CRIT | HIGH | MED | LOW | Top Rules |')
    w(f'|---|---|---|---|---|---|---|---|---|---|')
    t_findings = 0; t_crit = 0; t_high = 0; t_files = 0; t_with = 0
    for idx, key in enumerate(tier_order, 1):
        name, stars = PROJECTS[key]
        f = RESULTS_DIR / f'{key}.json'
        if not f.exists():
            w(f'| {idx} | {name} | {stars} | - | - | - | - | - | - | not scanned |')
            continue
        try:
            data = json.loads(f.read_text())
        except Exception:
            w(f'| {idx} | {name} | {stars} | - | - | - | - | - | - | parse error |')
            continue
        findings = data.get('findings', [])
        files = data.get('scanned_files', 0)
        t_files += files
        sev = {}; rules = {}
        for finding in findings:
            s = finding.get('severity', '?').lower()
            sev[s] = sev.get(s, 0) + 1
            r = finding.get('rule_id', '?')
            rules[r] = rules.get(r, 0) + 1
        crit = sev.get('critical', 0); high = sev.get('high', 0)
        med = sev.get('medium', 0); low = sev.get('low', 0) + sev.get('info', 0)
        total = len(findings)
        t_findings += total; t_crit += crit; t_high += high
        if total > 0: t_with += 1
        top = sorted(rules.items(), key=lambda x: -x[1])[:3]
        rule_str = ', '.join(f'{r}({c})' for r, c in top) if top else '\u2014'
        w(f'| {idx} | {name} | {stars} | {files} | {total} | {crit} | {high} | {med} | {low} | {rule_str} |')
    w('')
    w(f'**Totals: {t_findings} findings ({t_crit} CRITICAL, {t_high} HIGH) across {t_files} files. {t_with}/{len(tier_order)} have findings.**')
    return t_findings, t_crit, t_high, t_files, t_with

# Section 1: Tier 1 — Established projects
w('## 1. Tier 1 — Established Projects (>2k stars)')
w('')
t1_findings, t1_crit, t1_high, t1_files, t1_with = emit_tier_table(TIER1_ORDER, 'Tier 1')
w('')
w('---')
w('')

# Section 2: Tier 2 — Small projects
w('## 2. Tier 2 — Small Projects (<500 stars)')
w('')
t2_findings, t2_crit, t2_high, t2_files, t2_with = emit_tier_table(TIER2_ORDER, 'Tier 2')
w('')

# Comparison table
t1_scanned = sum(1 for k in TIER1_ORDER if (RESULTS_DIR / f'{k}.json').exists())
t2_scanned = len(TIER2_ORDER)
w('### Tier Comparison')
w('')
w('| Metric | Tier 1 (>2k stars) | Tier 2 (<500 stars) |')
w('|---|---|---|')
w(f'| Projects with findings | {t1_with}/{t1_scanned} ({t1_with*100//max(t1_scanned,1)}%) | {t2_with}/{t2_scanned} ({t2_with*100//max(t2_scanned,1)}%) |')
fpf1 = f'{t1_findings / max(t1_files,1):.3f}' if t1_files else '0'
fpf2 = f'{t2_findings / max(t2_files,1):.3f}' if t2_files else '0'
w(f'| Findings per file | {t1_findings} / {t1_files} = **{fpf1}** | {t2_findings} / {t2_files} = **{fpf2}** |')
cpf1 = f'{t1_crit*100//max(t1_findings,1)}%' if t1_findings else '0%'
cpf2 = f'{t2_crit*100//max(t2_findings,1)}%' if t2_findings else '0%'
w(f'| CRITICAL rate | {t1_crit}/{t1_findings} = **{cpf1}** | {t2_crit}/{t2_findings} = **{cpf2}** |')
w('')
w('---')
w('')

# Collect attack vectors from all projects
total_findings = t1_findings + t2_findings
total_crit = t1_crit + t2_crit
total_high = t1_high + t2_high
total_files = t1_files + t2_files
projects_with_findings = t1_with + t2_with
all_vectors_found = {}

for key in PROJECT_ORDER:
    f = RESULTS_DIR / f'{key}.json'
    if not f.exists(): continue
    try:
        data = json.loads(f.read_text())
    except Exception:
        continue
    findings = data.get('findings', [])
    proj_vectors = extract_vectors(findings)
    name, _ = PROJECTS[key]
    for vec_id, evidence in proj_vectors.items():
        if vec_id not in all_vectors_found:
            all_vectors_found[vec_id] = []
        for e in evidence:
            e['project'] = name
        all_vectors_found[vec_id].extend(evidence)

# Section 3: Rule distribution
w('## 3. Rule Distribution')
w('')

all_rules = {}
for key in PROJECT_ORDER:
    f = RESULTS_DIR / f'{key}.json'
    if not f.exists():
        continue
    try:
        data = json.loads(f.read_text())
    except Exception:
        continue
    for finding in data.get('findings', []):
        r = finding.get('rule_id', '?')
        all_rules[r] = all_rules.get(r, 0) + 1

if all_rules:
    w('| Rule | Count | % | Description |')
    w('|---|---|---|---|')
    rule_descs = {
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
    }
    for rule_id, count in sorted(all_rules.items(), key=lambda x: -x[1]):
        pct = f'{count / total_findings * 100:.0f}%' if total_findings else '0%'
        desc = rule_descs.get(rule_id, rule_id)
        w(f'| {rule_id} | {count} | {pct} | {desc} |')

w('')
w('---')
w('')

# Section 4: Attack vector coverage
w('## 4. Attack Vector Coverage (10 / 32 Detectable)')
w('')

categories = {
    'MEM': ('Memory Isolation', 4),
    'POI': ('Data Poisoning', 6),
    'EMB': ('Embedding Attacks', 5),
    'INJ': ('Prompt Injection', 3),
    'EXF': ('Exfiltration', 3),
    'CFG': ('Configuration', 6),
    'DOS': ('Denial of Service', 3),
    'AGT': ('Agentic Attacks', 5),
}

w('| Category | Detected | Total | Coverage |')
w('|---|---|---|---|')
for cat, (cat_name, cat_total) in categories.items():
    detected = sum(1 for v in DETECTABLE_VECTORS if f'-{cat}-' in v)
    pct = f'{detected / cat_total * 100:.0f}%'
    w(f'| **{cat}** \u2014 {cat_name} | {detected} | {cat_total} | {pct} |')

w('')

# Section 4: Vectors found in real projects
w('### Attack Vectors Confirmed in Real-World Projects')
w('')

if all_vectors_found:
    w('| Attack Vector | Description | Projects Affected | Hits | Example Evidence |')
    w('|---|---|---|---|---|')

    for vec_id in sorted(all_vectors_found.keys()):
        evidence_list = all_vectors_found[vec_id]
        desc = ALL_VECTORS.get(vec_id, vec_id)
        projects_hit = sorted(set(e['project'] for e in evidence_list))
        total_hits = len(evidence_list)

        example = None
        for sev_pref in ['critical', 'high', 'medium', 'low']:
            for e in evidence_list:
                if e['severity'] == sev_pref and e.get('file'):
                    example = e
                    break
            if example:
                break
        if not example and evidence_list:
            example = evidence_list[0]

        proj_str = ', '.join(projects_hit)
        if example and example.get('file'):
            from pathlib import Path as P
            fname = P(example['file']).name
            evidence_str = f'\`{fname}:{example.get(\"line\", \"?\")}\` ({example[\"rule_id\"]})'
        else:
            evidence_str = f'({example[\"rule_id\"]})' if example else '\u2014'

        w(f'| **{vec_id}** | {desc} | {proj_str} | {total_hits} | {evidence_str} |')
    w('')
else:
    w('No scan results available yet. Run \`./scripts/benchmark.sh\` first.')
    w('')

# Section 5: Vectors not detected
w('### Vectors Not Detected (22 / 32)')
w('')
w('| Vector | Description | Reason |')
w('|---|---|---|')

not_detected_reasons = {
    'AW-ATK-POI-001': 'Requires runtime: inject docs, measure ranking',
    'AW-ATK-POI-002': 'Requires runtime: single-doc injection',
    'AW-ATK-POI-003': 'Requires runtime: query-only memory injection',
    'AW-ATK-POI-004': 'Requires runtime: time-delayed session analysis',
    'AW-ATK-POI-005': 'Requires binary analysis: PDF/DOCX hidden content',
    'AW-ATK-POI-006': 'Requires tracking memory\u2192fine-tuning pipeline',
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

for vec_id in sorted(ALL_VECTORS.keys()):
    if vec_id not in DETECTABLE_VECTORS:
        desc = ALL_VECTORS[vec_id]
        reason = not_detected_reasons.get(vec_id, 'Out of scope for static analysis')
        w(f'| {vec_id} | {desc} | {reason} |')

w('')
w('---')
w('')

# Section 5: Heatmap
w('## 5. Attack Vector Heatmap (Per Project)')
w('')

detected_vec_ids = sorted(DETECTABLE_VECTORS)
short_labels = [v.replace('AW-ATK-', '') for v in detected_vec_ids]
header = '| Project | ' + ' | '.join(short_labels) + ' | Total |'
sep = '|---|' + '|'.join(['---'] * len(detected_vec_ids)) + '|---|'
w(header)
w(sep)

for key in PROJECT_ORDER:
    name, _ = PROJECTS[key]
    f = RESULTS_DIR / f'{key}.json'

    if not f.exists():
        cells = ' | '.join(['\u2014'] * len(detected_vec_ids))
        w(f'| {name} | {cells} | \u2014 |')
        continue

    try:
        data = json.loads(f.read_text())
    except Exception:
        cells = ' | '.join(['\u2014'] * len(detected_vec_ids))
        w(f'| {name} | {cells} | \u2014 |')
        continue

    findings = data.get('findings', [])
    proj_vectors = extract_vectors(findings)
    row_total = 0
    cells = []
    for vec_id in detected_vec_ids:
        hits = proj_vectors.get(vec_id, [])
        count = len(hits)
        row_total += count
        if count > 0:
            cells.append(f'**{count}**')
        else:
            cells.append('\u00b7')

    w(f'| {name} | {\" | \".join(cells)} | {row_total} |')

w('')
w('*Legend: number = findings count, \u00b7 = not detected, \u2014 = not scanned*')
w('')
w('---')
w('')

# Section 6: How to reproduce
w('## 6. How to Reproduce')
w('')
w('\`\`\`bash')
w('pip install -e \".[dev]\"')
w('./scripts/benchmark.sh')
w('\`\`\`')

BENCHMARK_MD.write_text('\n'.join(lines) + '\n', encoding='utf-8')
print(f'  Written to: {BENCHMARK_MD}')
print(f'  Total findings: {total_findings}')
print(f'  Attack vectors confirmed in real projects: {len(all_vectors_found)}/{len(DETECTABLE_VECTORS)}')
"

# ── Write log summary ──────────────────────────────────────────────────

{
  echo ""
  echo "═══════════════════════════════════════════════════════"
  echo "Run Summary — $(date '+%Y-%m-%d %H:%M:%S %Z')"
  echo "═══════════════════════════════════════════════════════"
  echo "BENCHMARK.md: $BENCHMARK_MD"
  echo "JSON reports: $RESULTS_DIR/"
  echo "Log: $RUN_LOG"
  # Quick totals from JSON results
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
echo "=== Benchmark complete ==="
echo "JSON reports: $RESULTS_DIR/"
echo "Report: $BENCHMARK_MD"
echo "Log: $RUN_LOG"
