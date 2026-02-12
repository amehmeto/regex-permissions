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

function matches(rule, field, value) {
  if (!rule[field]) return true; // field not specified — matches everything
  if (value == null) return false; // rule requires field but input lacks it
  const re = toRegex(rule[field], rule.flags);
  return re ? re.test(value) : true; // invalid regex → fail open
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

function evaluate(rules, toolName, toolInput) {
  const command = getPrimaryContent(toolName, toolInput);
  const filePath = toolInput?.file_path;
  const url = toolInput?.url;

  function ruleMatches(rule) {
    return (
      matches(rule, "tool", toolName) &&
      matches(rule, "command", command) &&
      matches(rule, "path", filePath) &&
      matches(rule, "url", url)
    );
  }

  // Deny first
  for (const rule of rules.deny || []) {
    if (ruleMatches(rule)) {
      return {
        decision: "deny",
        reason: rule.reason || "Blocked by regex-permissions deny rule",
      };
    }
  }

  // Then ask
  for (const rule of rules.ask || []) {
    if (ruleMatches(rule)) {
      return {
        decision: "ask",
        reason: rule.reason || "Flagged by regex-permissions ask rule",
      };
    }
  }

  // Then allow
  for (const rule of rules.allow || []) {
    if (ruleMatches(rule)) {
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
    // Can't parse input — fail open
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

  // If no regex permissions configured anywhere, passthrough
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
    // No match — passthrough
    process.stdout.write("{}\n");
    return;
  }

  if (result.decision === "deny") {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          permissionDecision: "deny",
          reason: result.reason,
        },
      }) + "\n"
    );
    return;
  }

  if (result.decision === "ask") {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          permissionDecision: "ask",
          reason: result.reason,
        },
      }) + "\n"
    );
    return;
  }

  if (result.decision === "allow") {
    process.stdout.write(
      JSON.stringify({
        hookSpecificOutput: {
          permissionDecision: "allow",
        },
      }) + "\n"
    );
    return;
  }

  // Fallback — should not reach here
  process.stdout.write("{}\n");
}

main();
