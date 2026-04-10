import fs from "fs";
import path from "path";
import os from "os";
import { HookInput, HookOutput } from "./types";

// --- Types ---

interface RuleEntry {
  rule: string;
  reason?: string;
  flags?: string;
}

interface ParsedRule {
  toolRe: RegExp;
  contentRe: RegExp | null; // null = tool-name-only rule, matches any content
  reason?: string;
  source: string; // original rule string for debug output
}

interface RegexPermissionsConfig {
  requireReason?: boolean;
  guardNativePermissions?: boolean | "auto";
  suggestOnPassthrough?: boolean;
  deny?: (string | RuleEntry)[];
  ask?: (string | RuleEntry)[];
  allow?: (string | RuleEntry)[];
}

interface PreparedRules {
  deny: ParsedRule[];
  ask: ParsedRule[];
  allow: ParsedRule[];
}

// --- Logging ---

const DEBUG = process.env.REGEX_PERMISSIONS_DEBUG === "1";
function debug(msg: string): void {
  if (DEBUG) process.stderr.write(`[regex-permissions] ${msg}\n`);
}

// --- Helpers ---

// ReDoS heuristic: reject (x+)+, (.+)*, (\d+)+ etc.
function isSafeRegex(pattern: string): boolean {
  return !/\((\.|\\.|[^)\\])[+*]\)[+*{]/.test(pattern);
}

function toRegex(pattern: string, flags?: string): RegExp | null {
  try {
    if (!isSafeRegex(pattern)) {
      debug(`Skipping unsafe regex (possible ReDoS): ${pattern}`);
      return null;
    }
    return new RegExp(pattern, flags || "");
  } catch {
    debug(`Skipping invalid regex: ${pattern}`);
    return null;
  }
}

function str(val: unknown): string | undefined {
  return typeof val === "string" ? val : undefined;
}

function getPrimaryContent(
  toolName: string,
  toolInput: Record<string, unknown> | undefined,
): string | undefined {
  if (!toolInput) return undefined;
  if (toolName === "Bash") return str(toolInput.command);
  if (toolName === "Edit" || toolName === "Write" || toolName === "Read")
    return str(toolInput.file_path);
  if (toolName === "WebFetch") return str(toolInput.url);
  if (toolName === "Grep" || toolName === "Glob") return str(toolInput.pattern);
  if (toolName === "WebSearch") return str(toolInput.query);
  return str(toolInput.command) || str(toolInput.file_path) || str(toolInput.url) || str(toolInput.pattern) || str(toolInput.query);
}

// --- Rule parsing ---

function parseRule(entry: string | RuleEntry): ParsedRule | null {
  const raw = typeof entry === "string" ? entry : entry?.rule;
  if (!raw) return null;

  const match = raw.match(/^([^(]+)\((.+)\)$/s);

  if (!match) {
    // Tool-name-only rule (no parentheses) — matches any content
    const toolRe = toRegex(`^(?:${raw})$`);
    if (!toolRe) return null;
    return {
      toolRe,
      contentRe: null,
      reason: typeof entry === "object" ? entry.reason : undefined,
      source: raw,
    };
  }

  const flags = typeof entry === "object" ? entry.flags : undefined;
  const toolRe = toRegex(`^(?:${match[1]})$`);
  const contentRe = toRegex(match[2], flags);

  if (!toolRe || !contentRe) return null;

  return {
    toolRe,
    contentRe,
    reason: typeof entry === "object" ? entry.reason : undefined,
    source: raw,
  };
}

// --- Config loading ---

const jsonCache = new Map<string, Record<string, unknown> | null>();

function readJsonFile(filePath: string): Record<string, unknown> | null {
  if (jsonCache.has(filePath)) return jsonCache.get(filePath)!;
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const json = JSON.parse(raw);
    jsonCache.set(filePath, json);
    return json;
  } catch {
    jsonCache.set(filePath, null);
    return null;
  }
}

function loadConfig(filePath: string): RegexPermissionsConfig | null {
  const json = readJsonFile(filePath);
  const config = (json?.regexPermissions as RegexPermissionsConfig) || null;
  if (config) validateConfig(config, filePath);
  return config;
}

const KNOWN_CONFIG_KEYS = new Set(["requireReason", "guardNativePermissions", "suggestOnPassthrough", "deny", "ask", "allow"]);

function validateConfig(config: RegexPermissionsConfig, filePath: string): void {
  for (const key of Object.keys(config)) {
    if (!KNOWN_CONFIG_KEYS.has(key)) {
      let suggestion = "";
      for (const known of KNOWN_CONFIG_KEYS) {
        if (known.toLowerCase().startsWith(key.toLowerCase().slice(0, 4))) {
          suggestion = ` (did you mean "${known}"?)`;
          break;
        }
      }
      process.stderr.write(`[regex-permissions] Unknown config key "${key}" in ${filePath}${suggestion}\n`);
    }
  }
}

function mergeConfigs(
  a: RegexPermissionsConfig | null,
  b: RegexPermissionsConfig | null,
): RegexPermissionsConfig {
  if (!a) return b || {};
  if (!b) return a;
  return {
    requireReason: a.requireReason || b.requireReason,
    guardNativePermissions:
      a.guardNativePermissions === "auto" || b.guardNativePermissions === "auto"
        ? "auto"
        : a.guardNativePermissions || b.guardNativePermissions,
    suggestOnPassthrough: a.suggestOnPassthrough || b.suggestOnPassthrough,
    deny: (a.deny || []).concat(b.deny || []),
    ask: (a.ask || []).concat(b.ask || []),
    allow: (a.allow || []).concat(b.allow || []),
  };
}

function prepareRules(config: RegexPermissionsConfig): PreparedRules {
  const requireReason = config.requireReason === true;
  const toArray = (key: "deny" | "ask" | "allow") => {
    const val = config[key];
    return Array.isArray(val) ? val : [];
  };
  const parse = (entries: (string | RuleEntry)[]) =>
    entries.map(parseRule).filter((r): r is ParsedRule => {
      if (r === null) return false;
      if (requireReason && !r.reason) {
        debug(`Skipping rule without reason (requireReason is enabled): ${r.source}`);
        return false;
      }
      return true;
    });
  return {
    deny: parse(toArray("deny")),
    ask: parse(toArray("ask")),
    allow: parse(toArray("allow")),
  };
}

// --- Evaluation ---

function ruleMatches(
  rule: ParsedRule,
  toolName: string,
  content: string | undefined,
): boolean {
  if (!rule.toolRe.test(toolName)) return false;
  if (rule.contentRe === null) return true; // tool-name-only: match any content
  if (content == null) return false;
  return rule.contentRe.test(content);
}

function matchesAnyLine(
  rule: ParsedRule,
  toolName: string,
  content: string | undefined,
  lines: string[] | null,
): boolean {
  if (ruleMatches(rule, toolName, content)) return true;
  if (!lines) return false;
  return lines.some((line) => ruleMatches(rule, toolName, line));
}

function evaluate(
  rules: PreparedRules,
  toolName: string,
  content: string | undefined,
): { decision: "deny" | "ask" | "allow"; reason?: string } | null {
  const contentPreview = content ? JSON.stringify(content.length > 80 ? content.slice(0, 80) + "…" : content) : "(no content)";
  const lines = content?.includes("\n")
    ? content.split("\n").map((l) => l.trim()).filter(Boolean)
    : null;

  for (const rule of rules.deny) {
    if (matchesAnyLine(rule, toolName, content, lines)) {
      debug(`DENY ${toolName} ${contentPreview} → ${rule.source}${rule.reason ? ` (${rule.reason})` : ""}`);
      return { decision: "deny", reason: rule.reason || "Blocked by regex-permissions deny rule" };
    }
  }

  for (const rule of rules.ask) {
    if (matchesAnyLine(rule, toolName, content, lines)) {
      debug(`ASK ${toolName} ${contentPreview} → ${rule.source}${rule.reason ? ` (${rule.reason})` : ""}`);
      return { decision: "ask", reason: rule.reason || "Flagged by regex-permissions ask rule" };
    }
  }

  for (const rule of rules.allow) {
    if (ruleMatches(rule, toolName, content)) {
      debug(`ALLOW ${toolName} ${contentPreview} → ${rule.source}`);
      return { decision: "allow" };
    }
  }

  debug(`PASS ${toolName} ${contentPreview} → no match`);
  return null;
}

// --- Regex suggestion ---

const BASH_WRAPPERS = /^(env|nohup|time|nice|ionice|timeout|sudo)$/;

function escapeRegex(s: string): string {
  return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
}

function generateRegexSuggestion(toolName: string, content: string | undefined): string {
  if (!content) return toolName;

  if (toolName === "Bash") {
    const firstLine = content.includes("\n") ? content.split("\n")[0].trim() : content;
    const tokens = firstLine.split(/\s+/).filter(Boolean);
    if (tokens.length === 0) return `Bash(.*)`;

    // Skip wrapper commands (env, nohup, time, sudo, etc.) and env var assignments (FOO=bar)
    let cmdIdx = 0;
    while (cmdIdx < tokens.length - 1 && (BASH_WRAPPERS.test(tokens[cmdIdx]) || /^\w+=/.test(tokens[cmdIdx]))) {
      cmdIdx++;
    }

    const cmd = tokens[cmdIdx];
    const subcmd = tokens[cmdIdx + 1];

    // Include subcommand if it looks like one (starts with letter, not a path, not a filename, not an assignment)
    if (subcmd && /^[a-zA-Z]/.test(subcmd) && !/[/.=]/.test(subcmd)) {
      return `Bash(^${escapeRegex(cmd)}\\s+${escapeRegex(subcmd)}\\b)`;
    }
    return `Bash(^${escapeRegex(cmd)}\\b)`;
  }

  if (toolName === "Edit" || toolName === "Write" || toolName === "Read") {
    const extMatch = content.match(/\.(\w+)$/);
    if (extMatch) {
      return `${toolName}(\\.${extMatch[1]}$)`;
    }
    return `${toolName}(.*)`;
  }

  if (toolName === "WebFetch") {
    const urlMatch = content.match(/^https?:\/\/([^/]+)/);
    if (urlMatch) {
      const domain = escapeRegex(urlMatch[1]);
      return `${toolName}(^https?://${domain}(/|$))`;
    }
    return `${toolName}(.*)`;
  }

  if (toolName === "Grep" || toolName === "Glob" || toolName === "WebSearch") {
    return `${toolName}(.*)`;
  }

  return toolName;
}

// --- Native permissions guard ---

const MANAGED_TOOL_RE = /^(Bash|Edit|Write|Read|WebFetch|Grep|Glob|WebSearch)\((.+)\)$/;

function suggestRegex(native: string): string {
  const m = native.match(/^([\w|]+)\((.+)\)$/);
  if (!m) return native;
  const [, tool, rawPattern] = m;

  // Handle WebFetch domain: prefix → URL regex
  const domainMatch = rawPattern.match(/^domain:(.+)$/);
  if (domainMatch) {
    const domain = escapeRegex(domainMatch[1]);
    return `${tool}(^https?://${domain}(/|$))`;
  }

  let core = rawPattern.replace(/[:*]+$/, "").trimEnd();
  const segments = core.split(/\*+/);
  core = segments
    .map((s) => escapeRegex(s))
    .join(".*");
  core = core.replace(/(\.\*)+/g, ".*");
  core = core.replace(/ +/g, "\\s+");

  const isBash = /\bBash\b/.test(tool);
  const needsBoundary = isBash && /\w$/.test(core);
  return needsBoundary ? `${tool}(^${core}\\b)` : `${tool}(^${core})`;
}

function guardNativePermissions(filePath: string, autoAdd: boolean): RuleEntry[] {
  const json = readJsonFile(filePath);
  if (!json) return [];

  const perms = json.permissions as Record<string, unknown> | undefined;
  if (!perms) return [];

  const allowEntries = perms.allow;
  if (!Array.isArray(allowEntries)) return [];

  let changed = false;
  const removed: Array<{ entry: string; suggestion: string }> = [];
  const kept: unknown[] = [];

  for (const entry of allowEntries) {
    const rule = typeof entry === "string" ? entry : (entry as Record<string, unknown>)?.rule;
    if (typeof rule === "string" && MANAGED_TOOL_RE.test(rule)) {
      removed.push({ entry: rule, suggestion: suggestRegex(rule) });
      changed = true;
    } else {
      kept.push(entry);
    }
  }

  if (!changed) return [];

  if (kept.length > 0) {
    perms.allow = kept;
  } else {
    delete perms.allow;
  }
  if (Object.keys(perms).length === 0) {
    delete json.permissions;
  }

  const addedRules: RuleEntry[] = [];

  if (autoAdd) {
    if (!json.regexPermissions) json.regexPermissions = {};
    const rp = json.regexPermissions as RegexPermissionsConfig;
    if (!rp.allow) rp.allow = [];
    for (const { suggestion } of removed) {
      const ruleEntry: RuleEntry = { rule: suggestion, reason: "Auto-converted from native permissions" };
      addedRules.push(ruleEntry);
      (rp.allow as RuleEntry[]).push(ruleEntry);
    }
  }

  // Invalidate cache before writing
  jsonCache.delete(filePath);
  fs.writeFileSync(filePath, JSON.stringify(json, null, 2) + "\n");

  for (const { entry, suggestion } of removed) {
    if (autoAdd) {
      debug(`Converted native allow: ${entry} → { "rule": ${JSON.stringify(suggestion)} }`);
    } else {
      debug(`Removed native allow: ${entry} → Add to regexPermissions.allow: { "rule": ${JSON.stringify(suggestion)}, "reason": "..." }`);
    }
  }

  return addedRules;
}

// Convert a single just-approved native rule matching this tool use
function guardApprovedRule(filePath: string, toolName: string, content: string | undefined): void {
  // Re-read from disk (Claude Code may have just written to it)
  let json: Record<string, unknown>;
  try {
    json = JSON.parse(fs.readFileSync(filePath, "utf8"));
  } catch {
    return;
  }

  const perms = json.permissions as Record<string, unknown> | undefined;
  if (!perms) return;

  const allowEntries = perms.allow;
  if (!Array.isArray(allowEntries)) return;

  // Find the native entry that matches this tool use
  let matchIdx = -1;
  let matchRule = "";
  for (let i = 0; i < allowEntries.length; i++) {
    const entry = allowEntries[i];
    const rule = typeof entry === "string" ? entry : (entry as Record<string, unknown>)?.rule;
    if (typeof rule !== "string") continue;

    // Must be a managed tool pattern: Tool(...)
    const m = rule.match(MANAGED_TOOL_RE);
    if (!m) continue;
    const [, entryTool, entryPattern] = m;

    if (entryTool !== toolName) continue;

    // Check if this native rule matches the current content
    // Native rules are either exact or prefix (:*)
    const prefix = entryPattern.replace(/:\*$/, "");
    if (content && (content === prefix || content.startsWith(prefix + " "))) {
      matchIdx = i;
      matchRule = rule;
      break;
    }
  }

  if (matchIdx === -1) return;

  const suggestion = suggestRegex(matchRule);

  // Remove from permissions.allow
  allowEntries.splice(matchIdx, 1);
  if (allowEntries.length === 0) delete perms.allow;
  if (Object.keys(perms).length === 0) delete json.permissions;

  // Add to regexPermissions.allow
  if (!json.regexPermissions) json.regexPermissions = {};
  const rp = json.regexPermissions as RegexPermissionsConfig;
  if (!rp.allow) rp.allow = [];
  (rp.allow as RuleEntry[]).push({ rule: suggestion, reason: "Auto-converted from native permissions" });

  fs.writeFileSync(filePath, JSON.stringify(json, null, 2) + "\n");
  debug(`PostToolUse: converted ${matchRule} → ${suggestion}`);
}

// --- Main ---

const mode = process.argv[2] || "pre";

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
  if (!tool_name) return;

  if (mode === "post") {
    if (!cwd) return;
    return handlePostToolUse(tool_name, tool_input, cwd);
  }

  return handlePreToolUse(tool_name, tool_input, cwd);
}

function handlePostToolUse(toolName: string, toolInput: Record<string, unknown>, cwd: string): void {
  // Check merged config for guardNativePermissions (same sources as PreToolUse)
  const projectConfig = mergeConfigs(
    loadConfig(path.join(cwd, ".claude", "settings.json")),
    loadConfig(path.join(cwd, ".claude", "settings.local.json")),
  );
  const globalHome = path.join(os.homedir(), ".claude");
  const globalConfig = mergeConfigs(
    loadConfig(path.join(globalHome, "settings.json")),
    loadConfig(path.join(globalHome, "settings.local.json")),
  );
  const merged = mergeConfigs(projectConfig, globalConfig);

  // Convert just-approved native rule when suggestOnPassthrough or guardNativePermissions is enabled
  if (!merged.suggestOnPassthrough && !merged.guardNativePermissions) return;

  // Always write to project settings.local.json
  const settingsPath = path.join(cwd, ".claude", "settings.local.json");
  const content = getPrimaryContent(toolName, toolInput);
  guardApprovedRule(settingsPath, toolName, content);
}

function handlePreToolUse(toolName: string, toolInput: Record<string, unknown>, cwd: string | undefined): void {
  const projectConfig = cwd
    ? mergeConfigs(
        loadConfig(path.join(cwd, ".claude", "settings.json")),
        loadConfig(path.join(cwd, ".claude", "settings.local.json")),
      )
    : null;

  const globalHome = path.join(os.homedir(), ".claude");
  const globalConfig = mergeConfigs(
    loadConfig(path.join(globalHome, "settings.json")),
    loadConfig(path.join(globalHome, "settings.local.json")),
  );

  const merged = mergeConfigs(projectConfig, globalConfig);

  // Bulk guard: clean up any leftover native entries (PreToolUse)
  if (merged.guardNativePermissions && cwd) {
    const autoAdd = merged.guardNativePermissions === "auto";
    const added = guardNativePermissions(
      path.join(cwd, ".claude", "settings.local.json"),
      autoAdd,
    );
    if (added.length > 0) {
      merged.allow = (merged.allow || []).concat(added);
    }
  }

  const rules = prepareRules(merged);

  if (!rules.deny.length && !rules.ask.length && !rules.allow.length && !merged.suggestOnPassthrough) return;

  debug(`Loaded ${rules.deny.length} deny, ${rules.ask.length} ask, ${rules.allow.length} allow rules`);

  const content = getPrimaryContent(toolName, toolInput);
  const result = evaluate(rules, toolName, content);

  if (!result) {
    if (merged.suggestOnPassthrough) {
      const suggestion = generateRegexSuggestion(toolName, content);
      debug(`SUGGEST ${toolName} → ${suggestion}`);
      const output: HookOutput = {
        hookSpecificOutput: {
          hookEventName: "PreToolUse",
          permissionDecision: "ask",
          permissionDecisionReason: `No matching regex rule. Suggested: ${JSON.stringify(suggestion)}`,
        },
      };
      process.stdout.write(JSON.stringify(output) + "\n");
    }
    return;
  }

  const output: HookOutput = {
    hookSpecificOutput: {
      hookEventName: "PreToolUse",
      permissionDecision: result.decision,
    },
  };
  if (result.reason) output.hookSpecificOutput!.permissionDecisionReason = result.reason;
  process.stdout.write(JSON.stringify(output) + "\n");
}

main().catch(() => {});
