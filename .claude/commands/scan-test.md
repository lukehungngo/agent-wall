# /scan-test

Run AgentWall against all test fixtures and show findings summary.

```bash
echo "=== Unsafe fixture ===" && agentwall scan tests/fixtures/langchain_unsafe/ --output /tmp/aw_unsafe.json
echo "=== Safe fixture ===" && agentwall scan tests/fixtures/langchain_safe/ --fail-on critical
echo "=== Basic fixture ===" && agentwall scan tests/fixtures/langchain_basic/
```

Expected:
- `langchain_unsafe/` → exit 1, findings at HIGH or CRITICAL
- `langchain_safe/`   → exit 0, zero findings above MEDIUM
- `langchain_basic/`  → exit 0 or 1 depending on config
