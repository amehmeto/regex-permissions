#!/usr/bin/env node
"use strict";

const { execFileSync } = require("child_process");
const fs = require("fs");
const path = require("path");
const os = require("os");

const SCRIPT = path.join(__dirname, "scripts", "check-permissions.js");
const TMP = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-test-"));
const CONFIG_DIR = path.join(TMP, ".claude");

fs.mkdirSync(CONFIG_DIR, { recursive: true });
fs.writeFileSync(
  path.join(CONFIG_DIR, "settings.local.json"),
  JSON.stringify({
    regexPermissions: {
      deny: [
        { rule: "Bash(^git\\s+push\\s+.*--force\\b(?!-))", reason: "No force push" },
        { rule: "Edit|Write(\\.env$)", reason: "No .env edits" },
      ],
      ask: [
        { rule: "Bash([;|&`$#])", reason: "Shell metacharacters" },
        { rule: "Bash(^git\\s+push)", reason: "Confirm push" },
      ],
      allow: [
        "Bash(^\\S+\\s+--help$)",
        "Bash(^git\\s+(status|log|diff))",
        "Bash(^aws\\s+\\S+\\s+(get|list|describe)-)",
        "Glob|Grep(.*)",
        "WebSearch(.*)",
        { rule: "WebFetch(example\\.com)", flags: "i" },
      ],
    },
  })
);

function run(input) {
  const result = execFileSync("node", [SCRIPT], {
    input: JSON.stringify(input),
    encoding: "utf8",
    timeout: 5000,
  });
  return JSON.parse(result.trim());
}

function decision(result) {
  return result?.hookSpecificOutput?.permissionDecision || "passthrough";
}

let passed = 0;
let failed = 0;
let skipped = 0;

function test(name, input, expected) {
  const result = run({ ...input, cwd: TMP });
  const got = decision(result);
  if (got === expected) {
    passed++;
    console.log(`  pass  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} — expected ${expected}, got ${got}`);
  }
}

console.log("regex-permissions tests\n");

// --- Deny ---
test("deny: git push --force",
  { tool_name: "Bash", tool_input: { command: "git push --force origin main" } },
  "deny");
test("ask: git push --force-with-lease is not denied, falls to ask",
  { tool_name: "Bash", tool_input: { command: "git push --force-with-lease" } },
  "ask");
test("deny: Edit .env",
  { tool_name: "Edit", tool_input: { file_path: "/project/.env" } },
  "deny");
test("deny: Write .env (tool regex Edit|Write)",
  { tool_name: "Write", tool_input: { file_path: "/project/.env" } },
  "deny");

// --- Ask ---
test("ask: pipe metacharacter",
  { tool_name: "Bash", tool_input: { command: "echo foo | bar" } },
  "ask");
test("ask: semicolon metacharacter",
  { tool_name: "Bash", tool_input: { command: "echo a; echo b" } },
  "ask");
test("ask: ampersand metacharacter",
  { tool_name: "Bash", tool_input: { command: "cmd1 && cmd2" } },
  "ask");

// --- Allow ---
test("allow: --help",
  { tool_name: "Bash", tool_input: { command: "jq --help" } },
  "allow");
test("allow: git status",
  { tool_name: "Bash", tool_input: { command: "git status" } },
  "allow");
test("allow: git log with args",
  { tool_name: "Bash", tool_input: { command: "git log --oneline" } },
  "allow");
test("allow: aws describe",
  { tool_name: "Bash", tool_input: { command: "aws ec2 describe-instances" } },
  "allow");
test("allow: aws list",
  { tool_name: "Bash", tool_input: { command: "aws s3 list-buckets" } },
  "allow");
test("allow: Glob tool",
  { tool_name: "Glob", tool_input: { pattern: "**/*.ts" } },
  "allow");
test("allow: Grep tool",
  { tool_name: "Grep", tool_input: { pattern: "TODO" } },
  "allow");
test("allow: WebSearch tool",
  { tool_name: "WebSearch", tool_input: { query: "node docs" } },
  "allow");
test("allow: WebFetch with flags (case-insensitive)",
  { tool_name: "WebFetch", tool_input: { url: "https://EXAMPLE.COM/page" } },
  "allow");

// --- Flags isolation: tool name stays case-sensitive ---
test("passthrough: tool name is case-sensitive even with flags",
  { tool_name: "webfetch", tool_input: { url: "https://example.com" } },
  "passthrough");

// --- Passthrough ---
test("passthrough: unknown command",
  { tool_name: "Bash", tool_input: { command: "some-unknown-thing" } },
  "passthrough");
test("passthrough: Read tool (no matching rule)",
  { tool_name: "Read", tool_input: { file_path: "/project/src/index.ts" } },
  "passthrough");

// --- Error resilience ---
// Use a temp dir with an empty settings file (no regexPermissions key)
const TMP2 = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-empty-"));
fs.mkdirSync(path.join(TMP2, ".claude"), { recursive: true });
fs.writeFileSync(path.join(TMP2, ".claude", "settings.local.json"), "{}");
{
  const result = run({ tool_name: "Bash", tool_input: { command: "git push --force" }, cwd: TMP2 });
  const got = decision(result);
  // May not be passthrough if global ~/.claude/settings.local.json has regexPermissions
  const globalHasConfig = (() => {
    try {
      const g = JSON.parse(fs.readFileSync(path.join(os.homedir(), ".claude", "settings.local.json"), "utf8"));
      return !!g.regexPermissions;
    } catch { return false; }
  })();
  if (globalHasConfig) {
    skipped++;
    console.log(`  skip  passthrough: no project config (global config exists)`);
  } else if (got === "passthrough") {
    passed++;
    console.log(`  pass  passthrough: no project config`);
  } else {
    failed++;
    console.log(`  FAIL  passthrough: no project config — expected passthrough, got ${got}`);
  }
}
fs.rmSync(TMP2, { recursive: true, force: true });

// --- Invalid regex is skipped (fail open) ---
const TMP3 = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-bad-"));
fs.mkdirSync(path.join(TMP3, ".claude"), { recursive: true });
fs.writeFileSync(
  path.join(TMP3, ".claude", "settings.local.json"),
  JSON.stringify({
    regexPermissions: {
      deny: [{ rule: "Bash(+)" }],
    },
  })
);
{
  const result = run({ tool_name: "Bash", tool_input: { command: "anything" }, cwd: TMP3 });
  const got = decision(result);
  if (got === "passthrough") {
    passed++;
    console.log("  pass  passthrough: invalid content regex is skipped");
  } else {
    failed++;
    console.log(`  FAIL  passthrough: invalid content regex — expected passthrough, got ${got}`);
  }
}
fs.rmSync(TMP3, { recursive: true, force: true });

const total = passed + failed + skipped;
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped (${total} total)\n`);

// Cleanup
fs.rmSync(TMP, { recursive: true, force: true });

process.exit(failed > 0 ? 1 : 0);
