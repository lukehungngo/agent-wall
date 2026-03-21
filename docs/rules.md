# AgentWall Rule Reference

Auto-generated from `src/agentwall/rules.py`.

## Memory Rules (AW-MEM-*)

### AW-MEM-001: No tenant isolation in vector store
- **Severity:** CRITICAL
- **Category:** memory
- **Description:** Vector store queries are executed without any user/tenant filter. A similarity search returns the globally closest vectors — including other users' data.
- **Fix:** Add a metadata filter on every retrieval call: similarity_search(query, filter={'user_id': user_id})

### AW-MEM-002: Shared collection without metadata filter on retrieval
- **Severity:** HIGH
- **Category:** memory
- **Description:** Documents are written with user-scoped metadata (e.g. user_id) but retrieved without a matching filter. The write-time metadata provides false security.
- **Fix:** Ensure every retrieval call includes the same metadata filter used at write time.

### AW-MEM-003: Memory backend has no access control configuration
- **Severity:** HIGH
- **Category:** memory
- **Description:** The configured memory backend has no observable access control setup. Without explicit isolation, all agents share the same memory namespace.
- **Fix:** Configure per-user collections or namespaces, or add metadata-based filtering.

### AW-MEM-004: Known injection patterns in memory retrieval path
- **Severity:** HIGH
- **Category:** memory
- **Description:** The memory retrieval path uses unsanitized external input. This is a vector for memory poisoning attacks (MINJA, MemoryGraft patterns).
- **Fix:** Sanitize all content before storing it to memory. Validate retrieved content before injecting into context.

### AW-MEM-005: No sanitization on retrieved memory before context injection
- **Severity:** MEDIUM
- **Category:** memory
- **Description:** Retrieved memory content is injected directly into the agent context without sanitization. Poisoned memories can influence agent behavior across sessions.
- **Fix:** Pass retrieved memories through a sanitization step before adding to context.

## Tool Permission Rules (AW-TOOL-*)

### AW-TOOL-001: Destructive tool accessible without approval gate
- **Severity:** HIGH
- **Category:** tool
- **Description:** A tool classified as destructive (deletes data, modifies files, sends messages) is registered without a human-in-the-loop approval gate.
- **Fix:** Wrap destructive tools with an approval gate (e.g. HumanApprovalCallbackHandler).

### AW-TOOL-002: Tool accepts arbitrary code/SQL/shell execution
- **Severity:** MEDIUM
- **Category:** tool
- **Description:** A tool can execute arbitrary code, SQL queries, or shell commands. Without input validation this enables prompt-injection-to-RCE escalation.
- **Fix:** Restrict tool inputs with an allowlist schema. Avoid eval/exec patterns.

### AW-TOOL-003: High-risk tool lacks user-scope access check
- **Severity:** MEDIUM
- **Category:** tool
- **Description:** A high-risk tool (file access, database query, API call) does not verify that the requesting user has permission to perform the requested action.
- **Fix:** Add a user-scope check at the start of the tool function.

### AW-TOOL-004: Tool has no description
- **Severity:** LOW
- **Category:** tool
- **Description:** A registered tool has no description. This blocks risk classification and degrades the LLM's ability to select tools correctly.
- **Fix:** Add a docstring or description= argument to every tool.

### AW-TOOL-005: Agent has >15 tools (exceeds recommended limit)
- **Severity:** INFO
- **Category:** tool
- **Description:** The agent has more than 15 registered tools. Large tool sets increase token usage and reduce tool-selection accuracy.
- **Fix:** Split the agent into specialized sub-agents with focused tool sets.

## Secrets Rules (AW-SEC-*)

### AW-SEC-001: Hardcoded API key/secret in agent config
- **Severity:** HIGH
- **Category:** secrets
- **Description:** A string literal matching known API key patterns (sk-, AKIA, ghp_, xoxb-) was found in agent or tool configuration code.
- **Fix:** Move secrets to environment variables or a secrets manager.

### AW-SEC-002: Env var injected into prompt template
- **Severity:** MEDIUM
- **Category:** secrets
- **Description:** An environment variable value flows into a prompt template. If the env var contains sensitive data, it will be sent to the LLM.
- **Fix:** Redact sensitive env vars before injecting into prompts.

### AW-SEC-003: Agent context logged at DEBUG level
- **Severity:** MEDIUM
- **Category:** secrets
- **Description:** Agent memory, chat history, or conversation context is passed to a logging or print call. This may expose sensitive user data in logs.
- **Fix:** Redact or summarize context before logging. Never log full conversation state.

## RAG Rules (AW-RAG-*)

### AW-RAG-001: Retrieved context injected into prompt without delimiters
- **Severity:** HIGH
- **Category:** rag
- **Description:** Retrieved documents are concatenated directly into a prompt without structural delimiters (XML tags, fenced blocks). This increases indirect prompt injection risk.
- **Fix:** Wrap retrieved content in explicit delimiters: `<context>...</context>` or similar.

### AW-RAG-002: Ingestion from untrusted source without validation
- **Severity:** HIGH
- **Category:** rag
- **Description:** Documents from an external source (HTTP, file upload, web scraper) are ingested into the vector store without content validation or sanitization.
- **Fix:** Validate and sanitize document content before calling add_documents/add_texts.

### AW-RAG-003: Unencrypted local vector store persistence
- **Severity:** MEDIUM
- **Category:** rag
- **Description:** A local vector store (FAISS, Chroma) persists data to disk without encryption. Stored embeddings and documents are readable by any process with file access.
- **Fix:** Encrypt the persistence directory or use a vector store with built-in encryption.

### AW-RAG-004: Vector store exposed on network without auth
- **Severity:** HIGH
- **Category:** rag
- **Description:** A vector store client connects to a remote server without authentication parameters. The store may be accessible to anyone on the network.
- **Fix:** Add api_key, auth_credentials, or equivalent auth parameters to the client.

## MCP Rules (AW-MCP-*)

### AW-MCP-001: MCP server over HTTP without authentication
- **Severity:** HIGH
- **Category:** mcp
- **Description:** An MCP server is exposed over HTTP/SSE without authentication middleware. Any client on the network can invoke its tools.
- **Fix:** Add authentication middleware to the MCP server handler chain.

### AW-MCP-002: Static long-lived token in MCP config
- **Severity:** HIGH
- **Category:** mcp
- **Description:** A hardcoded token or API key was found in MCP server/client initialization. Static credentials cannot be rotated without redeployment.
- **Fix:** Load MCP credentials from environment variables or a secrets manager.

### AW-MCP-003: MCP tool with shell/filesystem access
- **Severity:** MEDIUM
- **Category:** mcp
- **Description:** An MCP tool handler contains subprocess, os.system, or open() calls with variable arguments. This enables arbitrary command/file execution via the tool.
- **Fix:** Restrict tool inputs with an allowlist. Avoid shell=True and variable file paths.

## Serialization Rules (AW-SER-*)

### AW-SER-001: Unsafe deserialization of agent state
- **Severity:** HIGH
- **Category:** serialization
- **Description:** Unsafe deserialization (pickle.load, yaml.unsafe_load, torch.load) is used in an agent or memory code path. This enables remote code execution if the serialized data is attacker-controlled.
- **Fix:** Use safe alternatives: json, yaml.safe_load, torch.load(weights_only=True).

### AW-SER-002: Unpinned agent framework dependency
- **Severity:** MEDIUM
- **Category:** serialization
- **Description:** An agent framework library is listed as a dependency without a version pin. Unpinned dependencies can introduce breaking changes or vulnerabilities silently.
- **Fix:** Pin agent framework dependencies to a specific version or bounded range.

### AW-SER-003: Dynamic import of external tool/plugin
- **Severity:** MEDIUM
- **Category:** serialization
- **Description:** importlib.import_module() or __import__() is called with a variable argument in a tool registration path. This enables loading arbitrary code as a tool.
- **Fix:** Use a static tool registry with explicit imports. Avoid dynamic plugin loading.

## Agent Architecture Rules (AW-AGT-*)

### AW-AGT-001: Sub-agent inherits full parent tool set
- **Severity:** HIGH
- **Category:** agent
- **Description:** A sub-agent receives the full tool set of its parent agent without filtering. This violates the principle of least privilege.
- **Fix:** Filter the tool list to only tools the sub-agent needs.

### AW-AGT-002: Agent-to-agent communication without authentication
- **Severity:** MEDIUM
- **Category:** agent
- **Description:** An agent delegation call passes no authentication-related parameters. The receiving agent cannot verify the caller's identity.
- **Fix:** Pass auth tokens or session credentials in agent delegation calls.

### AW-AGT-003: Agent has read+write+delete on same resource without separate approval
- **Severity:** MEDIUM
- **Category:** agent
- **Description:** An agent has tools for reading, writing, and deleting the same resource type but the destructive tools lack a separate approval gate.
- **Fix:** Add a separate approval gate for destructive tools on shared resources.

### AW-AGT-004: LLM output stored to memory without validation
- **Severity:** HIGH
- **Category:** agent
- **Description:** LLM output is stored directly into agent memory or a vector store without validation. This enables memory poisoning (MemoryGraft) attacks.
- **Fix:** Validate or sanitize LLM output before persisting to memory.

## Configuration Rules (AW-CFG-*)

*These rules are emitted by the L4 ConfigAuditor from infrastructure config files (docker-compose.yml, .env, etc.).*

### AW-CFG-hardcoded-secret: Hardcoded secret in configuration
- **Severity:** HIGH
- **Category:** config
- **Description:** A password, API key, or secret is hardcoded in a configuration file (docker-compose.yml, .env, etc.) rather than using environment variable references.
- **Fix:** Use environment variable references (`${SECRET}`) instead of hardcoded values. Store secrets in a secrets manager.

### AW-CFG-docker-no-auth: Docker service without authentication
- **Severity:** HIGH
- **Category:** config
- **Description:** A vector database or service container is configured without authentication (no password, no API key, no auth token).
- **Fix:** Enable authentication on all database and service containers. Use environment variables for credentials.

### AW-CFG-auth-disabled: Authentication explicitly disabled
- **Severity:** HIGH
- **Category:** config
- **Description:** Authentication is explicitly disabled in a service configuration (e.g., `auth_enabled: false`, `ANONYMOUS_ACCESS=true`).
- **Fix:** Enable authentication. Remove or set auth flags to true/enabled.

### AW-CFG-debug-mode: Debug mode enabled in production config
- **Severity:** MEDIUM
- **Category:** config
- **Description:** Debug mode is enabled in a configuration file, which may expose sensitive information in error messages or logs.
- **Fix:** Disable debug mode in production configurations.

### AW-CFG-no-tls: Service without TLS/SSL encryption
- **Severity:** MEDIUM
- **Category:** config
- **Description:** A service is configured without TLS/SSL encryption, exposing data in transit.
- **Fix:** Enable TLS/SSL for all services handling sensitive data.

### AW-CFG-no-password: Empty or missing service password
- **Severity:** MEDIUM
- **Category:** config
- **Description:** A service password is empty, unset, or set to a default value.
- **Fix:** Set a strong, unique password for each service.
