#!/usr/bin/env node

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

function getPrimaryContent(
  toolName: string,
  toolInput: Record<string, string> | undefined,
): string | undefined {
  if (!toolInput) return undefined;
  if (toolName === "Bash") return toolInput.command;
  if (toolName === "Edit" || toolName === "Write" || toolName === "Read")
    return toolInput.file_path;
  if (toolName === "WebFetch") return toolInput.url;
  if (toolName === "Grep" || toolName === "Glob") return toolInput.pattern;
  if (toolName === "WebSearch") return toolInput.query;
  return toolInput.command || toolInput.file_path || toolInput.url || toolInput.pattern;
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
    deny: (a.deny || []).concat(b.deny || []),
    ask: (a.ask || []).concat(b.ask || []),
    allow: (a.allow || []).concat(b.allow || []),
  };
}

function prepareRules(config: RegexPermissionsConfig): PreparedRules {
  const toArray = (key: keyof RegexPermissionsConfig) => {
    const val = config[key];
    return Array.isArray(val) ? val : [];
  };
  return {
    deny: toArray("deny").map(parseRule).filter((r): r is ParsedRule => r !== null),
    ask: toArray("ask").map(parseRule).filter((r): r is ParsedRule => r !== null),
    allow: toArray("allow").map(parseRule).filter((r): r is ParsedRule => r !== null),
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

function evaluate(
  rules: PreparedRules,
  toolName: string,
  toolInput: Record<string, string>,
): { decision: "deny" | "ask" | "allow"; reason?: string } | null {
  const content = getPrimaryContent(toolName, toolInput);

  for (const rule of rules.deny) {
    if (ruleMatches(rule, toolName, content))
      return { decision: "deny", reason: rule.reason || "Blocked by regex-permissions deny rule" };
  }

  for (const rule of rules.ask) {
    if (ruleMatches(rule, toolName, content))
      return { decision: "ask", reason: rule.reason || "Flagged by regex-permissions ask rule" };
  }

  for (const rule of rules.allow) {
    if (ruleMatches(rule, toolName, content))
      return { decision: "allow" };
  }

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
