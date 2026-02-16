#!/usr/bin/env node

import fs from "fs";
import path from "path";
import os from "os";

// --- Types ---

interface RuleEntry {
  rule: string;
  reason?: string;
  flags?: string;
}

interface ParsedRule {
  toolRe: RegExp;
  contentRe: RegExp;
  reason?: string;
}

interface RegexPermissionsConfig {
  deny?: (string | RuleEntry)[];
  ask?: (string | RuleEntry)[];
  allow?: (string | RuleEntry)[];
}

interface PreparedRules {
  deny: ParsedRule[];
  ask: ParsedRule[];
  allow: ParsedRule[];
}

interface HookInput {
  tool_name: string;
  tool_input: Record<string, string>;
  cwd?: string;
}

interface HookOutput {
  hookSpecificOutput: {
    hookEventName: string;
    permissionDecision: string;
    permissionDecisionReason?: string;
  };
}

interface EvalResult {
  decision: "deny" | "ask" | "allow";
  reason?: string;
}

// --- Logging ---

const DEBUG = process.env.REGEX_PERMISSIONS_DEBUG === "1";
function warn(msg: string): void { process.stderr.write(`[regex-permissions] ${msg}\n`); }
function debug(msg: string): void { if (DEBUG) warn(msg); }

// --- Helpers ---

// ReDoS heuristic: reject groups containing a single quantified token followed by
// a group quantifier. Catches (a+)+, (.+)*, (\d+)+, (\s*)+ etc. but allows
// complex groups like (-H\s+\S+\s+)* that have structural anchoring.
function isSafeRegex(pattern: string): boolean {
  return !/\((\.|\\.|[^)\\])[+*]\)[+*{]/.test(pattern);
}

const regexCache = new Map<string, RegExp>();

function toRegex(pattern: string, flags?: string): RegExp | null {
  const key = `${flags || ""}:${pattern}`;
  if (regexCache.has(key)) return regexCache.get(key)!;
  try {
    if (!isSafeRegex(pattern)) {
      warn(`Skipping unsafe regex (possible ReDoS): ${pattern}`);
      return null;
    }
    const re = new RegExp(pattern, flags || "");
    regexCache.set(key, re);
    return re;
  } catch {
    return null; // invalid regex — fail open
  }
}

// Auto-detect the primary content field for each tool type
function getPrimaryContent(toolName: string, toolInput: Record<string, string> | undefined): string | undefined {
  if (!toolInput) return undefined;
  if (toolName === "Bash") return toolInput.command;
  if (toolName === "Edit" || toolName === "Write" || toolName === "Read")
    return toolInput.file_path;
  if (toolName === "WebFetch") return toolInput.url;
  if (toolName === "Grep") return toolInput.pattern;
  if (toolName === "Glob") return toolInput.pattern;
  if (toolName === "WebSearch") return toolInput.query;
  // MCP tools or unknown — try common fields
  return toolInput.command || toolInput.file_path || toolInput.url || toolInput.pattern;
}

// Parse a rule entry — supports both formats:
//   String:  "Bash(^git\\s+push)"
//   Object:  { "rule": "Bash(^git\\s+push)", "reason": "...", "flags": "i" }
// Returns null for malformed entries.
function parseRule(entry: string | RuleEntry): ParsedRule | null {
  const raw = typeof entry === "string" ? entry : entry?.rule;
  if (!raw) return null;

  const match = raw.match(/^([^(]+)\((.+)\)$/s);
  if (!match) return null;

  let flags = typeof entry === "object" ? entry.flags : undefined;

  // Strip "g" flag — it causes stateful matching via lastIndex
  if (flags && flags.includes("g")) {
    warn(`Stripping "g" flag from rule (causes stateful matching): ${raw}`);
    flags = flags.replace(/g/g, "") || undefined;
  }

  // Anchor tool regex to prevent substring matches (e.g. "Edit" matching "NotebookEdit")
  const toolRe = toRegex(`^(?:${match[1]})$`);
  const contentRe = toRegex(match[2], flags);

  if (!toolRe || !contentRe) {
    warn(`Skipping invalid rule: ${raw}`);
    return null;
  }

  return {
    toolRe,
    contentRe,
    reason: typeof entry === "object" ? entry.reason : undefined,
  };
}

// --- Config loading ---

function loadConfig(filePath: string): RegexPermissionsConfig | null {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return parsed.regexPermissions || null;
  } catch {
    return null; // missing or malformed — fail open
  }
}

function mergeConfigs(a: RegexPermissionsConfig | null, b: RegexPermissionsConfig | null): RegexPermissionsConfig {
  if (!a) return b || { deny: [], ask: [], allow: [] };
  if (!b) return a;
  return {
    deny: (a.deny || []).concat(b.deny || []),
    ask: (a.ask || []).concat(b.ask || []),
    allow: (a.allow || []).concat(b.allow || []),
  };
}

// Pre-parse all rules once after config load
function prepareRules(config: RegexPermissionsConfig): PreparedRules {
  const safeArray = (key: keyof RegexPermissionsConfig): (string | RuleEntry)[] => {
    const val = config[key];
    if (val == null) return [];
    if (!Array.isArray(val)) {
      warn(`"${key}" must be an array, got ${typeof val} — skipping`);
      return [];
    }
    return val;
  };
  const parsed: PreparedRules = {
    deny: safeArray("deny").map(parseRule).filter((r): r is ParsedRule => r !== null),
    ask: safeArray("ask").map(parseRule).filter((r): r is ParsedRule => r !== null),
    allow: safeArray("allow").map(parseRule).filter((r): r is ParsedRule => r !== null),
  };
  debug(`Loaded ${parsed.deny.length} deny, ${parsed.ask.length} ask, ${parsed.allow.length} allow rules`);
  return parsed;
}

// --- Evaluation ---

function ruleMatches(parsed: ParsedRule, toolName: string, content: string | undefined): boolean {
  if (!parsed.toolRe.test(toolName)) return false;
  if (content == null) return false;
  return parsed.contentRe.test(content);
}

// For deny/ask: match if the full content or ANY individual line matches
function matchesAnyLine(parsed: ParsedRule, toolName: string, content: string | undefined, lines: string[] | null): boolean {
  if (ruleMatches(parsed, toolName, content)) return true;
  if (lines) {
    for (const line of lines) {
      if (ruleMatches(parsed, toolName, line)) return true;
    }
  }
  return false;
}

function evaluate(rules: PreparedRules, toolName: string, toolInput: Record<string, string>): EvalResult | null {
  const content = getPrimaryContent(toolName, toolInput);

  // Split multiline content for per-line checking
  const lines = (content && content.includes("\n"))
    ? content.split("\n").map(l => l.trim()).filter(Boolean)
    : null;

  // Deny first — any matching line triggers deny
  for (const parsed of rules.deny) {
    if (matchesAnyLine(parsed, toolName, content, lines)) {
      return {
        decision: "deny",
        reason: parsed.reason || "Blocked by regex-permissions deny rule",
      };
    }
  }

  // Then ask — any matching line triggers ask
  for (const parsed of rules.ask) {
    if (matchesAnyLine(parsed, toolName, content, lines)) {
      return {
        decision: "ask",
        reason: parsed.reason || "Flagged by regex-permissions ask rule",
      };
    }
  }

  // Then allow — for multiline, every non-empty line must match an allow rule
  if (lines) {
    for (const line of lines) {
      const lineAllowed = rules.allow.some(p => ruleMatches(p, toolName, line));
      if (!lineAllowed) return null; // passthrough — not all lines covered
    }
    return { decision: "allow" };
  }

  for (const parsed of rules.allow) {
    if (ruleMatches(parsed, toolName, content)) {
      return { decision: "allow" };
    }
  }

  // No match — passthrough to native permissions
  return null;
}

// --- Main ---

async function main(): Promise<void> {
  let input: HookInput;
  try {
    const chunks: Buffer[] = [];
    for await (const chunk of process.stdin) chunks.push(Buffer.from(chunk));
    input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    return;
  }

  const { tool_name, tool_input, cwd } = input;
  if (!tool_name) {
    return;
  }

  // Load project-level config
  const projectConfigPath = cwd
    ? path.join(cwd, ".claude", "settings.local.json")
    : null;
  const projectConfig = projectConfigPath
    ? loadConfig(projectConfigPath)
    : null;

  // Load global config
  const globalConfigPath = path.join(
    os.homedir(),
    ".claude",
    "settings.local.json"
  );
  const globalConfig = loadConfig(globalConfigPath);

  const merged = mergeConfigs(projectConfig, globalConfig);
  const rules = prepareRules(merged);

  if (
    !rules.deny.length &&
    !rules.ask.length &&
    !rules.allow.length
  ) {
    return;
  }

  const result = evaluate(rules, tool_name, tool_input);

  if (!result) {
    return;
  }

  const output: HookOutput = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: result.decision,
    },
  };
  if (result.reason) output.hookSpecificOutput.permissionDecisionReason = result.reason;
  process.stdout.write(JSON.stringify(output) + "\n");
}

main().catch(() => {});
