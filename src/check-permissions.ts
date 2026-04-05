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
  contentRe: RegExp;
  reason?: string;
}

interface RegexPermissionsConfig {
  requireReason?: boolean;
  guardNativePermissions?: boolean;
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
  if (!match) return null;

  const flags = typeof entry === "object" ? entry.flags : undefined;
  const toolRe = toRegex(`^(?:${match[1]})$`);
  const contentRe = toRegex(match[2], flags);

  if (!toolRe || !contentRe) return null;

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
    return JSON.parse(raw).regexPermissions || null;
  } catch {
    return null;
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
    guardNativePermissions: a.guardNativePermissions || b.guardNativePermissions,
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
        debug(`Skipping rule without reason (requireReason is enabled): ${r.toolRe.source} / ${r.contentRe.source}`);
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
  toolInput: Record<string, unknown>,
): { decision: "deny" | "ask" | "allow"; reason?: string } | null {
  const content = getPrimaryContent(toolName, toolInput);
  const lines = content?.includes("\n")
    ? content.split("\n").map((l) => l.trim()).filter(Boolean)
    : null;

  for (const rule of rules.deny) {
    if (matchesAnyLine(rule, toolName, content, lines))
      return { decision: "deny", reason: rule.reason || "Blocked by regex-permissions deny rule" };
  }

  for (const rule of rules.ask) {
    if (matchesAnyLine(rule, toolName, content, lines))
      return { decision: "ask", reason: rule.reason || "Flagged by regex-permissions ask rule" };
  }

  for (const rule of rules.allow) {
    if (ruleMatches(rule, toolName, content))
      return { decision: "allow" };
  }

  return null;
}

// --- Native permissions guard ---

const MANAGED_TOOL_RE = /^(Bash|Edit|Write|Read|WebFetch|Grep|Glob|WebSearch)\(.+\)$/;

function suggestRegex(native: string): string {
  const m = native.match(/^([\w|]+)\((.+)\)$/);
  if (!m) return native;
  const [, tool, rawPattern] = m;

  let core = rawPattern.replace(/[:*]+$/, "").trimEnd();
  const segments = core.split(/\*+/);
  core = segments
    .map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
    .join(".*");
  core = core.replace(/(\.\*)+/g, ".*");
  core = core.replace(/ +/g, "\\s+");

  const isBash = /\bBash\b/.test(tool);
  const needsBoundary = isBash && /\w$/.test(core);
  return needsBoundary ? `${tool}(^${core}\\b)` : `${tool}(^${core})`;
}

function guardNativePermissions(filePath: string): void {
  let raw: string;
  try {
    raw = fs.readFileSync(filePath, "utf8");
  } catch {
    return;
  }

  let json: Record<string, unknown>;
  try {
    json = JSON.parse(raw);
  } catch {
    return;
  }

  const perms = json.permissions as Record<string, unknown> | undefined;
  if (!perms) return;

  let changed = false;
  const removed: Array<{ level: string; entry: string; suggestion: string }> = [];

  for (const level of ["allow", "deny", "ask"]) {
    const entries = perms[level];
    if (!Array.isArray(entries)) continue;

    const kept: unknown[] = [];
    for (const entry of entries) {
      if (typeof entry === "string" && MANAGED_TOOL_RE.test(entry)) {
        removed.push({ level, entry, suggestion: suggestRegex(entry) });
        changed = true;
      } else {
        kept.push(entry);
      }
    }
    perms[level] = kept;
  }

  if (!changed) return;

  for (const level of ["allow", "deny", "ask"]) {
    if (Array.isArray(perms[level]) && (perms[level] as unknown[]).length === 0) {
      delete perms[level];
    }
  }
  if (Object.keys(perms).length === 0) {
    delete json.permissions;
  }

  fs.writeFileSync(filePath, JSON.stringify(json, null, 2) + "\n");

  for (const { level, entry, suggestion } of removed) {
    process.stderr.write(
      `[regex-permissions] Removed native ${level}: ${entry}\n` +
      `  → Add to regexPermissions.${level}: { "rule": ${JSON.stringify(suggestion)}, "reason": "..." }\n`,
    );
  }
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
  if (!tool_name) return;

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

  if (merged.guardNativePermissions && cwd) {
    guardNativePermissions(path.join(cwd, ".claude", "settings.json"));
    guardNativePermissions(path.join(cwd, ".claude", "settings.local.json"));
  }

  const rules = prepareRules(merged);

  if (!rules.deny.length && !rules.ask.length && !rules.allow.length) return;

  debug(`Loaded ${rules.deny.length} deny, ${rules.ask.length} ask, ${rules.allow.length} allow rules`);

  const result = evaluate(rules, tool_name, tool_input);
  if (!result) return;

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
