import { execFileSync } from "child_process";
import fs from "fs";
import path from "path";
import os from "os";
import { HookInput, HookOutput } from "./types";

const SCRIPT = path.join(__dirname, "check-permissions.js");

function makeTmpWithConfig(config: object): string {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "regex-perm-"));
  fs.mkdirSync(path.join(tmp, ".claude"), { recursive: true });
  fs.writeFileSync(
    path.join(tmp, ".claude", "settings.local.json"),
    JSON.stringify(config),
  );
  return tmp;
}

function run(input: HookInput): HookOutput {
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

function test(name: string, input: Omit<HookInput, "cwd">, expected: string, cwd: string): void {
  const got = decision(run({ ...input, cwd }));
  if (got === expected) {
    passed++;
    console.log(`  pass  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name} — expected ${expected}, got ${got}`);
  }
}

// --- Main test config ---

const TMP = makeTmpWithConfig({
  regexPermissions: {
    deny: [
      { rule: "Bash(^git\\s+push\\s+.*--force\\b(?!-))", reason: "No force push" },
      { rule: "Edit|Write(\\.env$)", reason: "No .env edits" },
      { rule: "Bash(^sudo)", reason: "No sudo" },
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
});

console.log("regex-permissions tests\n");

// --- Deny ---
test("deny: git push --force",
  { tool_name: "Bash", tool_input: { command: "git push --force origin main" } },
  "deny", TMP);
test("ask: git push --force-with-lease (negative lookahead avoids deny, falls to ask)",
  { tool_name: "Bash", tool_input: { command: "git push --force-with-lease" } },
  "ask", TMP);
test("deny: Edit .env",
  { tool_name: "Edit", tool_input: { file_path: "/project/.env" } },
  "deny", TMP);
test("deny: Write .env (tool regex Edit|Write)",
  { tool_name: "Write", tool_input: { file_path: "/project/.env" } },
  "deny", TMP);
test("deny: sudo",
  { tool_name: "Bash", tool_input: { command: "sudo rm -rf /" } },
  "deny", TMP);

// --- Ask ---
test("ask: pipe metacharacter",
  { tool_name: "Bash", tool_input: { command: "echo foo | bar" } },
  "ask", TMP);
test("ask: semicolon metacharacter",
  { tool_name: "Bash", tool_input: { command: "echo a; echo b" } },
  "ask", TMP);
test("ask: ampersand metacharacter",
  { tool_name: "Bash", tool_input: { command: "cmd1 && cmd2" } },
  "ask", TMP);

// --- Allow ---
test("allow: --help",
  { tool_name: "Bash", tool_input: { command: "jq --help" } },
  "allow", TMP);
test("allow: git status",
  { tool_name: "Bash", tool_input: { command: "git status" } },
  "allow", TMP);
test("allow: git log with args",
  { tool_name: "Bash", tool_input: { command: "git log --oneline" } },
  "allow", TMP);
test("allow: aws describe",
  { tool_name: "Bash", tool_input: { command: "aws ec2 describe-instances" } },
  "allow", TMP);
test("allow: aws list",
  { tool_name: "Bash", tool_input: { command: "aws s3 list-buckets" } },
  "allow", TMP);
test("allow: Glob tool",
  { tool_name: "Glob", tool_input: { pattern: "**/*.ts" } },
  "allow", TMP);
test("allow: Grep tool",
  { tool_name: "Grep", tool_input: { pattern: "TODO" } },
  "allow", TMP);
test("allow: WebSearch tool",
  { tool_name: "WebSearch", tool_input: { query: "node docs" } },
  "allow", TMP);
test("allow: WebFetch with flags (case-insensitive)",
  { tool_name: "WebFetch", tool_input: { url: "https://EXAMPLE.COM/page" } },
  "allow", TMP);

// --- Tool name anchoring ---
test("passthrough: tool name is case-sensitive",
  { tool_name: "webfetch", tool_input: { url: "https://example.com" } },
  "passthrough", TMP);
test("passthrough: NotebookEdit does not match Edit|Write",
  { tool_name: "NotebookEdit", tool_input: { file_path: "/project/.env" } },
  "passthrough", TMP);
test("passthrough: BashExecutor does not match Bash",
  { tool_name: "BashExecutor", tool_input: { command: "git push --force" } },
  "passthrough", TMP);

// --- Passthrough ---
test("passthrough: unknown command",
  { tool_name: "Bash", tool_input: { command: "some-unknown-thing" } },
  "passthrough", TMP);
test("passthrough: Read tool (no matching rule)",
  { tool_name: "Read", tool_input: { file_path: "/project/src/index.ts" } },
  "passthrough", TMP);

// --- Multiline ---
test("deny: multiline with sudo on line 2",
  { tool_name: "Bash", tool_input: { command: "git status\nsudo rm -rf /" } },
  "deny", TMP);
test("ask: multiline with metacharacter on line 2",
  { tool_name: "Bash", tool_input: { command: "echo hello\necho a | b" } },
  "ask", TMP);

// --- Unknown tool fallback ---
test("passthrough: unknown tool with command field",
  { tool_name: "CustomTool", tool_input: { command: "git status" } },
  "passthrough", TMP);

// --- Multiline trimming ---
test("deny: multiline with indented sudo (trimmed)",
  { tool_name: "Bash", tool_input: { command: "echo hello\n  sudo rm -rf /" } },
  "deny", TMP);

fs.rmSync(TMP, { recursive: true, force: true });

// --- Empty config → passthrough ---
{
  const tmp = makeTmpWithConfig({});
  test("passthrough: no regexPermissions key",
    { tool_name: "Bash", tool_input: { command: "git push --force" } },
    "passthrough", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Invalid regex → fail open ---
{
  const tmp = makeTmpWithConfig({ regexPermissions: { deny: ["Bash(+)"] } });
  test("passthrough: invalid regex is skipped",
    { tool_name: "Bash", tool_input: { command: "anything" } },
    "passthrough", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- ReDoS protection ---
{
  const tmp = makeTmpWithConfig({ regexPermissions: { deny: ["Bash((a+)+$)"] } });
  test("passthrough: ReDoS pattern is rejected",
    { tool_name: "Bash", tool_input: { command: "aaaaaaaaaaaa" } },
    "passthrough", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Non-array field → skip gracefully ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: { deny: "not-an-array", allow: ["Bash(^ls)"] },
  });
  test("allow: non-array deny is skipped, allow still works",
    { tool_name: "Bash", tool_input: { command: "ls -la" } },
    "allow", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Unknown tool with query fallback ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: { allow: ["CustomSearch(node docs)"] },
  });
  test("allow: unknown tool falls back to query field",
    { tool_name: "CustomSearch", tool_input: { query: "node docs" } },
    "allow", tmp);
  test("passthrough: unknown tool with no matching fallback field",
    { tool_name: "CustomSearch", tool_input: { other: "node docs" } },
    "passthrough", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Native rules in permissions key are ignored ---
{
  const tmp = makeTmpWithConfig({
    permissions: { allow: ["Bash(npm test:*)"] },
    regexPermissions: { allow: ["Bash(^git\\s+status)"] },
  });
  test("passthrough: native permissions key is ignored by plugin",
    { tool_name: "Bash", tool_input: { command: "npm test" } },
    "passthrough", tmp);
  test("allow: regexPermissions key is used",
    { tool_name: "Bash", tool_input: { command: "git status" } },
    "allow", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- requireReason: rules without reason are skipped ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      requireReason: true,
      deny: [
        { rule: "Bash(^sudo)", reason: "No sudo" },
        "Bash(^rm)",
      ],
      allow: [
        "Bash(^git\\s+status)",
        { rule: "Bash(^echo)", reason: "Allow echo" },
      ],
    },
  });
  test("deny: rule with reason is kept when requireReason is enabled",
    { tool_name: "Bash", tool_input: { command: "sudo rm -rf /" } },
    "deny", tmp);
  test("passthrough: deny string rule (no reason) is skipped when requireReason is enabled",
    { tool_name: "Bash", tool_input: { command: "rm file.txt" } },
    "passthrough", tmp);
  test("passthrough: allow string rule (no reason) is skipped when requireReason is enabled",
    { tool_name: "Bash", tool_input: { command: "git status" } },
    "passthrough", tmp);
  test("allow: allow object rule with reason is kept when requireReason is enabled",
    { tool_name: "Bash", tool_input: { command: "echo hello" } },
    "allow", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- requireReason: false (default) keeps all rules ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      allow: ["Bash(^ls)"],
    },
  });
  test("allow: string rule works when requireReason is not set",
    { tool_name: "Bash", tool_input: { command: "ls -la" } },
    "allow", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions ---
{
  // Removes managed tool entries, keeps Skill/MCP/bare entries
  const tmp = makeTmpWithConfig({
    permissions: {
      allow: [
        "Bash(git fetch:*)",
        "Bash(npm run lint:*)",
        "Edit",
        "Read",
        "Write",
        "Skill(commit-push)",
        "mcp__github__get_me",
      ],
      deny: [
        "Bash(git push --force:*)",
        "BashOutput(*)",
        "mcp__github__merge_pull_request",
      ],
    },
    regexPermissions: {
      guardNativePermissions: true,
      allow: ["Bash(^git\\s+status)"],
    },
  });

  // Trigger the hook so the guard runs
  run({ tool_name: "Bash", tool_input: { command: "git status" }, cwd: tmp });

  // Read the file back and check what was kept/removed
  const after = JSON.parse(
    fs.readFileSync(path.join(tmp, ".claude", "settings.local.json"), "utf8"),
  );
  const allowKept = after.permissions?.allow || [];
  const denyKept = after.permissions?.deny || [];

  function assert(condition: boolean, name: string): void {
    if (condition) {
      passed++;
      console.log(`  pass  ${name}`);
    } else {
      failed++;
      console.log(`  FAIL  ${name}`);
    }
  }

  // Managed tool entries with patterns should be removed
  assert(!allowKept.includes("Bash(git fetch:*)"), "guard: Bash(git fetch:*) removed from allow");
  assert(!allowKept.includes("Bash(npm run lint:*)"), "guard: Bash(npm run lint:*) removed from allow");
  assert(!denyKept.includes("Bash(git push --force:*)"), "guard: Bash(git push --force:*) removed from deny");

  // Bare tool names (no parens) should be kept
  assert(allowKept.includes("Edit"), "guard: bare Edit kept");
  assert(allowKept.includes("Read"), "guard: bare Read kept");
  assert(allowKept.includes("Write"), "guard: bare Write kept");

  // Skill/MCP entries should be kept
  assert(allowKept.includes("Skill(commit-push)"), "guard: Skill entry kept");
  assert(allowKept.includes("mcp__github__get_me"), "guard: MCP allow entry kept");
  assert(denyKept.includes("BashOutput(*)"), "guard: BashOutput deny kept");
  assert(denyKept.includes("mcp__github__merge_pull_request"), "guard: MCP deny entry kept");

  // regexPermissions should be untouched
  assert(!!after.regexPermissions, "guard: regexPermissions preserved");

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions: disabled by default ---
{
  const tmp = makeTmpWithConfig({
    permissions: { allow: ["Bash(git fetch:*)"] },
    regexPermissions: { allow: ["Bash(^git\\s+status)"] },
  });

  run({ tool_name: "Bash", tool_input: { command: "git status" }, cwd: tmp });

  const after = JSON.parse(
    fs.readFileSync(path.join(tmp, ".claude", "settings.local.json"), "utf8"),
  );

  function assert2(condition: boolean, name: string): void {
    if (condition) {
      passed++;
      console.log(`  pass  ${name}`);
    } else {
      failed++;
      console.log(`  FAIL  ${name}`);
    }
  }

  assert2(
    after.permissions?.allow?.includes("Bash(git fetch:*)"),
    "guard: native entries kept when guardNativePermissions is not set",
  );

  fs.rmSync(tmp, { recursive: true, force: true });
}

const total = passed + failed;
console.log(`\n${passed} passed, ${failed} failed (${total} total)\n`);
process.exit(failed > 0 ? 1 : 0);
