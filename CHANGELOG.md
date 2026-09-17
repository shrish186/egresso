# Changelog

## 0.1.0 (unreleased)
- Secret-exfiltration enforcement with data-flow analysis (source → sink), catching
  base64/hex/env-var/DNS/staging evasions, not just literal secret strings.
- Destructive-command detection (rm -rf, force-push, DROP TABLE, kubectl delete, etc.).
- Unified policy engine: allow / warn / ask / block, with custom regex rules.
- Claude Code PreToolUse hook (`agentwall init` / `doctor`).
- Generic MCP proxy (`agentwall proxy -- <server>`) for any MCP client.
- Audit log (`.agentwall/audit.jsonl`) with `agentwall log` / `report`.
- Library API for embedding in custom agent loops.
