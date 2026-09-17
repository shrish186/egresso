// Public library API — import agentwall directly to inspect actions in your own
// agent framework (LangGraph, custom loops, MCP servers, etc.).
export { scan, entropy, redact, type SecretHit, type ScanOptions } from "./detect/secrets.js";
export { loadKnownSecrets } from "./detect/env.js";
export {
  inspectShellCommand,
  inspectHttpRequest,
  inspectToolCall,
  type Decision,
  type PolicyConfig,
} from "./enforce/action.js";
export { loadConfig, logDecision, type AgentwallConfig } from "./config.js";
export { analyzeDestructive, type DestructiveFinding } from "./enforce/destructive.js";
export {
  evaluateCommand,
  evaluateToolCall,
  type PolicyDecision,
  type EngineConfig,
  type CustomRule,
  type Verdict,
} from "./policy.js";
