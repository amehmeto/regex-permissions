#!/usr/bin/env node
"use strict";

const fs = require("fs");
const path = require("path");
const os = require("os");

// --- Helpers ---

const regexCache = new Map();

function toRegex(pattern, flags) {
  const key = `${flags || ""}:${pattern}`;
  if (regexCache.has(key)) return regexCache.get(key);
  try {
    const re = new RegExp(pattern, flags || "");
    regexCache.set(key, re);
    return re;
  } catch {
    return null; // invalid regex — fail open
  }
}

// Auto-detect the primary content field for each tool type
function getPrimaryContent(toolName, toolInput) {
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
function parseRule(entry) {
  const raw = typeof entry === "string" ? entry : entry?.rule;
  if (!raw) return null;

  const match = raw.match(/^([^(]+)\((.+)\)$/s);
  if (!match) return null;

  return {
    tool: match[1],
    pattern: match[2],
    reason: typeof entry === "object" ? entry.reason : undefined,
    flags: typeof entry === "object" ? entry.flags : undefined,
  };
}

// --- Config loading ---

function loadConfig(filePath) {
  try {
    const raw = fs.readFileSync(filePath, "utf8");
    const parsed = JSON.parse(raw);
    return parsed.regexPermissions || null;
  } catch {
    return null; // missing or malformed — fail open
  }
}

function mergeConfigs(a, b) {
  if (!a) return b || { deny: [], ask: [], allow: [] };
  if (!b) return a;
  return {
    deny: (a.deny || []).concat(b.deny || []),
    ask: (a.ask || []).concat(b.ask || []),
    allow: (a.allow || []).concat(b.allow || []),
  };
}

// --- Evaluation ---

function ruleMatches(parsed, toolName, content) {
  if (!parsed) return false;

  // Check tool name
  const toolRe = toRegex(parsed.tool, parsed.flags);
  if (!toolRe || !toolRe.test(toolName)) return false;

  // Check primary content pattern
  if (content == null) return false;
  const contentRe = toRegex(parsed.pattern, parsed.flags);
  return contentRe ? contentRe.test(content) : true; // invalid regex → fail open
}

function evaluate(rules, toolName, toolInput) {
  const content = getPrimaryContent(toolName, toolInput);

  // Deny first
  for (const entry of rules.deny || []) {
    const parsed = parseRule(entry);
    if (ruleMatches(parsed, toolName, content)) {
      return {
        decision: "deny",
        reason: parsed.reason || "Blocked by regex-permissions deny rule",
      };
    }
  }

  // Then ask
  for (const entry of rules.ask || []) {
    const parsed = parseRule(entry);
    if (ruleMatches(parsed, toolName, content)) {
      return {
        decision: "ask",
        reason: parsed.reason || "Flagged by regex-permissions ask rule",
      };
    }
  }

  // Then allow
  for (const entry of rules.allow || []) {
    const parsed = parseRule(entry);
    if (ruleMatches(parsed, toolName, content)) {
      return { decision: "allow" };
    }
  }

  // No match — passthrough to native permissions
  return null;
}

// --- Main ---

async function main() {
  let input;
  try {
    const chunks = [];
    for await (const chunk of process.stdin) chunks.push(chunk);
    input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
  } catch {
    process.stdout.write("{}\n");
    return;
  }

  const { tool_name, tool_input, cwd } = input;
  if (!tool_name) {
    process.stdout.write("{}\n");
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

  if (
    !merged.deny?.length &&
    !merged.ask?.length &&
    !merged.allow?.length
  ) {
    process.stdout.write("{}\n");
    return;
  }

  const result = evaluate(merged, tool_name, tool_input);

  if (!result) {
    process.stdout.write("{}\n");
    return;
  }

  const output = { hookSpecificOutput: { permissionDecision: result.decision } };
  if (result.reason) output.hookSpecificOutput.reason = result.reason;
  process.stdout.write(JSON.stringify(output) + "\n");
}

main();
