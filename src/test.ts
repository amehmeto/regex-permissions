#!/usr/bin/env node

import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";

interface ToolInput {
  command?: string;
  file_path?: string;
  url?: string;
  pattern?: string;
  query?: string;
}

interface TestInput {
  tool_name: string;
  tool_input: ToolInput;
  cwd?: string;
}

interface HookSpecificOutput {
  permissionDecision?: string;
}

interface HookOutput {
  hookSpecificOutput?: HookSpecificOutput;
}

const SCRIPT = path.join(__dirname, "check-permissions.js");
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
        { rule: "Bash(^sudo)", reason: "No sudo" },
      ],
      ask: [
        { rule: "Bash([;|&`$#\\n])", reason: "Shell metacharacters" },
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

function run(input: TestInput): HookOutput {
  const result = execFileSync("node", [SCRIPT], {
    input: JSON.stringify(input),
    encoding: "utf8",
    timeout: 5000,
  });
  const trimmed = result.trim();
  return trimmed ? JSON.parse(trimmed) : {};
}

function decision(result: HookOutput): string {
  return result?.hookSpecificOutput?.permissionDecision || "passthrough";
}

let passed = 0;
let failed = 0;
let skipped = 0;

function test(name: string, input: Omit<TestInput, "cwd">, expected: string): void {
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

// --- Tool name anchoring: prevent substring matches ---
test("passthrough: NotebookEdit does not match Edit|Write rule",
  { tool_name: "NotebookEdit", tool_input: { file_path: "/project/.env" } },
  "passthrough");
test("passthrough: BashExecutor does not match Bash rules",
  { tool_name: "BashExecutor", tool_input: { command: "git push --force" } },
  "passthrough");
test("passthrough: MyGlob does not match Glob|Grep rule",
  { tool_name: "MyGlob", tool_input: { pattern: "*.ts" } },
  "passthrough");

// --- Multiline command handling ---
test("deny: multiline with sudo on line 2 is denied",
  { tool_name: "Bash", tool_input: { command: "git status\nsudo rm -rf /" } },
  "deny");
test("deny: multiline with denied command on line 3",
  { tool_name: "Bash", tool_input: { command: "ls\necho hello\nsudo apt install" } },
  "deny");
test("ask: multiline triggers metacharacter ask via newline",
  { tool_name: "Bash", tool_input: { command: "echo hello\necho world" } },
  "ask");

// Test per-line allow logic with a config that doesn't have \n in ask
const TMP_ML = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-ml-"));
fs.mkdirSync(path.join(TMP_ML, ".claude"), { recursive: true });
fs.writeFileSync(
  path.join(TMP_ML, ".claude", "settings.local.json"),
  JSON.stringify({
    regexPermissions: {
      deny: [{ rule: "Bash(^sudo)", reason: "No sudo" }],
      allow: ["Bash(^git\\s+(status|log|diff))"],
    },
  })
);
{
  const mlRun = (cmd: string): string => {
    const r = run({ tool_name: "Bash", tool_input: { command: cmd }, cwd: TMP_ML });
    return decision(r);
  };
  const tests: [string, string, string][] = [
    ["deny: multiline per-line deny (no \\n ask)", "git status\nsudo rm -rf /", "deny"],
    ["allow: multiline all lines allowed", "git status\ngit log", "allow"],
    ["passthrough: multiline one line not covered", "git status\nsome-random-cmd", "passthrough"],
  ];
  for (const [name, cmd, expected] of tests) {
    const got = mlRun(cmd);
    if (got === expected) {
      passed++;
      console.log(`  pass  ${name}`);
    } else {
      failed++;
      console.log(`  FAIL  ${name} — expected ${expected}, got ${got}`);
    }
  }
}
fs.rmSync(TMP_ML, { recursive: true, force: true });

// --- Error resilience ---
// Use a temp dir with an empty settings file (no regexPermissions key)
const TMP2 = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-empty-"));
fs.mkdirSync(path.join(TMP2, ".claude"), { recursive: true });
fs.writeFileSync(path.join(TMP2, ".claude", "settings.local.json"), "{}");
{
  const result = run({ tool_name: "Bash", tool_input: { command: "git push --force" }, cwd: TMP2 });
  const got = decision(result);
  // May not be passthrough if global ~/.claude/settings.local.json has regexPermissions
  const globalHasConfig = ((): boolean => {
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

// --- ReDoS protection ---
const TMP4 = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-redos-"));
fs.mkdirSync(path.join(TMP4, ".claude"), { recursive: true });
fs.writeFileSync(
  path.join(TMP4, ".claude", "settings.local.json"),
  JSON.stringify({
    regexPermissions: {
      deny: [{ rule: "Bash((a+)+$)" }],
    },
  })
);
{
  const result = run({ tool_name: "Bash", tool_input: { command: "aaaaaaaaaaaa" }, cwd: TMP4 });
  const got = decision(result);
  if (got === "passthrough") {
    passed++;
    console.log("  pass  passthrough: ReDoS pattern is rejected");
  } else {
    failed++;
    console.log(`  FAIL  passthrough: ReDoS pattern — expected passthrough, got ${got}`);
  }
}
fs.rmSync(TMP4, { recursive: true, force: true });

// --- Config validation: non-array deny ---
const TMP5 = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-badcfg-"));
fs.mkdirSync(path.join(TMP5, ".claude"), { recursive: true });
fs.writeFileSync(
  path.join(TMP5, ".claude", "settings.local.json"),
  JSON.stringify({
    regexPermissions: {
      deny: "not-an-array",
      allow: [{ rule: "Bash(^ls)" }],
    },
  })
);
{
  const result = run({ tool_name: "Bash", tool_input: { command: "ls -la" }, cwd: TMP5 });
  const got = decision(result);
  if (got === "allow") {
    passed++;
    console.log("  pass  allow: non-array deny is skipped, allow still works");
  } else {
    failed++;
    console.log(`  FAIL  allow: non-array deny — expected allow, got ${got}`);
  }
}
fs.rmSync(TMP5, { recursive: true, force: true });

// --- g flag stripping ---
const TMP6 = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-gflag-"));
fs.mkdirSync(path.join(TMP6, ".claude"), { recursive: true });
fs.writeFileSync(
  path.join(TMP6, ".claude", "settings.local.json"),
  JSON.stringify({
    regexPermissions: {
      allow: [{ rule: "WebFetch(example\\.com)", flags: "gi" }],
    },
  })
);
{
  // Call twice — with "g" flag, second call would fail due to lastIndex state.
  // Since "g" is stripped, both calls should return allow.
  const r1 = run({ tool_name: "WebFetch", tool_input: { url: "https://EXAMPLE.COM/1" }, cwd: TMP6 });
  const r2 = run({ tool_name: "WebFetch", tool_input: { url: "https://EXAMPLE.COM/2" }, cwd: TMP6 });
  const got1 = decision(r1);
  const got2 = decision(r2);
  if (got1 === "allow" && got2 === "allow") {
    passed++;
    console.log("  pass  allow: g flag stripped, case-insensitive still works");
  } else {
    failed++;
    console.log(`  FAIL  allow: g flag — expected allow+allow, got ${got1}+${got2}`);
  }
}
fs.rmSync(TMP6, { recursive: true, force: true });

const total = passed + failed + skipped;
console.log(`\n${passed} passed, ${failed} failed, ${skipped} skipped (${total} total)\n`);

// Cleanup
fs.rmSync(TMP, { recursive: true, force: true });

process.exit(failed > 0 ? 1 : 0);
