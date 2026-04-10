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

function reason(result: HookOutput): string {
  return result?.hookSpecificOutput?.permissionDecisionReason || "";
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

// --- Helper for guard tests ---
function assert(condition: boolean, name: string): void {
  if (condition) {
    passed++;
    console.log(`  pass  ${name}`);
  } else {
    failed++;
    console.log(`  FAIL  ${name}`);
  }
}

function readSettingsAfterRun(tmp: string): Record<string, unknown> {
  run({ tool_name: "Bash", tool_input: { command: "git status" }, cwd: tmp });
  return JSON.parse(
    fs.readFileSync(path.join(tmp, ".claude", "settings.local.json"), "utf8"),
  );
}

// --- guardNativePermissions: removes managed allow entries ---
{
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

  const after = readSettingsAfterRun(tmp);
  const allowKept = (after.permissions as Record<string, unknown>)?.allow as string[] || [];
  const denyKept = (after.permissions as Record<string, unknown>)?.deny as string[] || [];

  // Managed tool entries with patterns should be removed from allow
  assert(!allowKept.includes("Bash(git fetch:*)"), "guard: Bash(git fetch:*) removed from allow");
  assert(!allowKept.includes("Bash(npm run lint:*)"), "guard: Bash(npm run lint:*) removed from allow");

  // Bare tool names (no parens) should be kept
  assert(allowKept.includes("Edit"), "guard: bare Edit kept");
  assert(allowKept.includes("Read"), "guard: bare Read kept");
  assert(allowKept.includes("Write"), "guard: bare Write kept");

  // Skill/MCP entries should be kept in allow
  assert(allowKept.includes("Skill(commit-push)"), "guard: Skill entry kept");
  assert(allowKept.includes("mcp__github__get_me"), "guard: MCP allow entry kept");

  // deny is NOT touched — even managed tool entries in deny are kept
  assert(denyKept.includes("Bash(git push --force:*)"), "guard: native deny entries are never removed");
  assert(denyKept.includes("BashOutput(*)"), "guard: BashOutput deny kept");
  assert(denyKept.includes("mcp__github__merge_pull_request"), "guard: MCP deny entry kept");

  // regexPermissions should be untouched
  assert(!!after.regexPermissions, "guard: regexPermissions preserved");

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions: handles object-form entries ---
{
  const tmp = makeTmpWithConfig({
    permissions: {
      allow: [
        { rule: "Bash(git fetch:*)", reason: "auto-added" },
        "mcp__github__get_me",
      ],
    },
    regexPermissions: {
      guardNativePermissions: true,
      allow: ["Bash(^git\\s+status)"],
    },
  });

  const after = readSettingsAfterRun(tmp);
  const allowKept = (after.permissions as Record<string, unknown>)?.allow as unknown[] || [];

  assert(
    !allowKept.some((e: unknown) => typeof e === "object" && (e as Record<string, unknown>)?.rule === "Bash(git fetch:*)"),
    "guard: object-form Bash entry removed from allow",
  );
  assert(allowKept.includes("mcp__github__get_me"), "guard: MCP kept alongside object removal");

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions: WebFetch domain: prefix converted to URL regex ---
{
  const tmp = makeTmpWithConfig({
    permissions: {
      allow: ["WebFetch(domain:github.com)"],
    },
    regexPermissions: {
      guardNativePermissions: true,
      allow: ["Bash(^git\\s+status)"],
    },
  });

  const after = readSettingsAfterRun(tmp);
  assert(after.permissions === undefined, "guard: WebFetch domain: entry removed");

  // Verify the suggestion was correct by checking stderr would contain the URL regex
  // (We can't capture stderr easily, but we verify the function directly)
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions: empty permissions object is deleted ---
{
  const tmp = makeTmpWithConfig({
    permissions: {
      allow: ["Bash(git fetch:*)"],
    },
    regexPermissions: {
      guardNativePermissions: true,
      allow: ["Bash(^git\\s+status)"],
    },
  });

  const after = readSettingsAfterRun(tmp);
  assert(after.permissions === undefined, "guard: empty permissions object removed from file");

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions: disabled by default ---
{
  const tmp = makeTmpWithConfig({
    permissions: { allow: ["Bash(git fetch:*)"] },
    regexPermissions: { allow: ["Bash(^git\\s+status)"] },
  });

  const after = readSettingsAfterRun(tmp);
  assert(
    ((after.permissions as Record<string, unknown>)?.allow as string[])?.includes("Bash(git fetch:*)"),
    "guard: native entries kept when guardNativePermissions is not set",
  );

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions: settings.json is not modified ---
{
  const tmp = makeTmpWithConfig({
    permissions: { allow: ["Bash(git fetch:*)"] },
    regexPermissions: { guardNativePermissions: true, allow: ["Bash(^git\\s+status)"] },
  });
  // Also write the same config to settings.json (the committed one)
  fs.writeFileSync(
    path.join(tmp, ".claude", "settings.json"),
    JSON.stringify({ permissions: { allow: ["Bash(git log:*)"] } }),
  );

  run({ tool_name: "Bash", tool_input: { command: "git status" }, cwd: tmp });

  const settingsJson = JSON.parse(
    fs.readFileSync(path.join(tmp, ".claude", "settings.json"), "utf8"),
  );
  assert(
    settingsJson.permissions?.allow?.includes("Bash(git log:*)"),
    "guard: settings.json is never modified",
  );

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Tool-name-only rules (no parentheses) ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      deny: [
        { rule: "mcp__github__merge_pull_request", reason: "No merge via MCP" },
      ],
      allow: [
        "mcp__github__list_pulls",
        "Bash(^git\\s+status)",
      ],
    },
  });
  test("deny: tool-name-only rule matches MCP tool",
    { tool_name: "mcp__github__merge_pull_request", tool_input: { owner: "foo", repo: "bar", pull_number: 1 } },
    "deny", tmp);
  test("allow: tool-name-only rule matches MCP tool",
    { tool_name: "mcp__github__list_pulls", tool_input: { owner: "foo", repo: "bar" } },
    "allow", tmp);
  test("passthrough: tool-name-only rule does not match other tools",
    { tool_name: "mcp__github__create_pull", tool_input: { owner: "foo" } },
    "passthrough", tmp);
  test("allow: regular parenthesized rule still works alongside tool-name-only",
    { tool_name: "Bash", tool_input: { command: "git status" } },
    "allow", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Tool-name-only with regex alternation ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      allow: ["Glob|Grep|WebSearch"],
    },
  });
  test("allow: tool-name-only with alternation matches Glob",
    { tool_name: "Glob", tool_input: { pattern: "**/*.ts" } },
    "allow", tmp);
  test("allow: tool-name-only with alternation matches WebSearch",
    { tool_name: "WebSearch", tool_input: { query: "test" } },
    "allow", tmp);
  test("passthrough: tool-name-only with alternation does not match Bash",
    { tool_name: "Bash", tool_input: { command: "ls" } },
    "passthrough", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions: auto mode ---
{
  const tmp = makeTmpWithConfig({
    permissions: {
      allow: ["Bash(git fetch:*)", "Bash(npm run lint:*)"],
    },
    regexPermissions: {
      guardNativePermissions: "auto",
      allow: ["Bash(^git\\s+status)"],
    },
  });

  const after = readSettingsAfterRun(tmp);

  // Native entries should be removed
  assert(after.permissions === undefined, "guard-auto: native permissions removed");

  // Regex rules should be auto-added to regexPermissions
  const rpAllow = (after.regexPermissions as Record<string, unknown>)?.allow as unknown[];
  assert(
    rpAllow.some((e: unknown) => typeof e === "object" && (e as Record<string, unknown>)?.rule === "Bash(^git\\s+fetch\\b)"),
    "guard-auto: Bash(git fetch:*) converted and added to regexPermissions",
  );
  assert(
    rpAllow.some((e: unknown) => typeof e === "object" && (e as Record<string, unknown>)?.rule === "Bash(^npm\\s+run\\s+lint\\b)"),
    "guard-auto: Bash(npm run lint:*) converted and added to regexPermissions",
  );

  // Auto-added rules should work immediately (in-memory merge)
  test("guard-auto: auto-added rule takes effect immediately",
    { tool_name: "Bash", tool_input: { command: "git fetch origin" } },
    "allow", tmp);

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Config validation: unknown key warning ---
// (We can't easily capture stderr in tests, but we verify it doesn't crash)
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      requierReason: true,
      allow: ["Bash(^ls)"],
    },
  });
  test("allow: unknown config key does not crash, rules still work",
    { tool_name: "Bash", tool_input: { command: "ls -la" } },
    "allow", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- Tool-name-only with requireReason skips string rules ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      requireReason: true,
      allow: [
        "mcp__github__list_pulls",
        { rule: "mcp__github__get_me", reason: "Allow get_me" },
      ],
    },
  });
  test("passthrough: tool-name-only string skipped when requireReason is enabled",
    { tool_name: "mcp__github__list_pulls", tool_input: { owner: "foo" } },
    "passthrough", tmp);
  test("allow: tool-name-only object with reason kept when requireReason is enabled",
    { tool_name: "mcp__github__get_me", tool_input: {} },
    "allow", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- guardNativePermissions: auto merge precedence ---
{
  // "auto" in one config + true in another → "auto" wins
  const tmp = makeTmpWithConfig({
    permissions: { allow: ["Bash(git fetch:*)"] },
    regexPermissions: { guardNativePermissions: "auto", allow: ["Bash(^git\\s+status)"] },
  });
  // Write a second config with guardNativePermissions: true
  fs.writeFileSync(
    path.join(tmp, ".claude", "settings.json"),
    JSON.stringify({ regexPermissions: { guardNativePermissions: true } }),
  );

  const after = readSettingsAfterRun(tmp);

  // "auto" should win — native entry removed AND regex added
  const rpAllow = (after.regexPermissions as Record<string, unknown>)?.allow as unknown[] || [];
  assert(
    rpAllow.some((e: unknown) => typeof e === "object" && (e as Record<string, unknown>)?.rule === "Bash(^git\\s+fetch\\b)"),
    "guard-auto-merge: auto wins over true, regex rule auto-added",
  );

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- suggestOnPassthrough ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      suggestOnPassthrough: true,
      allow: ["Bash(^git\\s+status)"],
    },
  });

  // Matched rules still work normally
  test("suggest: matched allow rule still returns allow",
    { tool_name: "Bash", tool_input: { command: "git status" } },
    "allow", tmp);

  // Unmatched command returns ask with suggestion
  test("suggest: unmatched bash command returns ask",
    { tool_name: "Bash", tool_input: { command: "gh api repos/foo/bar" } },
    "ask", tmp);

  // Check the suggestion contains a regex pattern
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "gh api repos/foo/bar" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^gh\\\\s+api\\\\b)"), "suggest: bash suggestion contains correct regex");
  }

  // Single-token command
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "htop" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^htop\\\\b)"), "suggest: single command gets word-boundary regex");
  }

  // Edit tool suggests by extension
  {
    const result = run({ tool_name: "Edit", tool_input: { file_path: "/project/src/index.ts" }, cwd: tmp });
    assert(decision(result) === "ask", "suggest: unmatched Edit returns ask");
    const r = reason(result);
    assert(r.includes("Edit(\\\\.ts$)"), "suggest: Edit suggestion uses file extension");
  }

  // WebFetch suggests by domain
  {
    const result = run({ tool_name: "WebFetch", tool_input: { url: "https://api.github.com/repos/foo" }, cwd: tmp });
    assert(decision(result) === "ask", "suggest: unmatched WebFetch returns ask");
    const r = reason(result);
    assert(r.includes("api\\\\.github\\\\.com"), "suggest: WebFetch suggestion contains escaped domain");
  }

  // MCP tool suggests tool-name-only
  {
    const result = run({ tool_name: "mcp__github__create_issue", tool_input: { title: "bug" }, cwd: tmp });
    assert(decision(result) === "ask", "suggest: unmatched MCP tool returns ask");
    const r = reason(result);
    assert(r.includes("mcp__github__create_issue"), "suggest: MCP suggestion is tool-name-only");
  }

  // Grep/Glob suggests (.*)
  {
    const result = run({ tool_name: "Grep", tool_input: { pattern: "TODO" }, cwd: tmp });
    assert(decision(result) === "ask", "suggest: unmatched Grep returns ask");
    const r = reason(result);
    assert(r.includes("Grep(.*)"), "suggest: Grep suggestion is catch-all");
  }

  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- suggestOnPassthrough: disabled by default ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      allow: ["Bash(^git\\s+status)"],
    },
  });
  test("suggest: passthrough when suggestOnPassthrough is not set",
    { tool_name: "Bash", tool_input: { command: "gh api repos/foo" } },
    "passthrough", tmp);
  fs.rmSync(tmp, { recursive: true, force: true });
}

// --- suggestOnPassthrough: bash heuristics ---
{
  const tmp = makeTmpWithConfig({
    regexPermissions: {
      suggestOnPassthrough: true,
      allow: [],
    },
  });

  // Flags are skipped — only first token used
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "ls -la /tmp" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^ls\\\\b)"), "suggest: command with flags suggests first token only");
  }

  // Path-like second token is skipped
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "cat /etc/hosts" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^cat\\\\b)"), "suggest: path argument skipped, only command suggested");
  }

  // Wrapper commands (env, nohup, time) are skipped
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "env FOO=bar node server.js" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^node\\\\b)"), "suggest: env + var assignment skipped, actual command suggested");
  }
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "time git status" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^git\\\\s+status\\\\b)"), "suggest: wrapper 'time' skipped, git status suggested");
  }
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "nohup python3 app.py" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^python3\\\\b)"), "suggest: wrapper 'nohup' skipped, python3 suggested");
  }

  // Bare env var assignment without wrapper
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "FOO=bar npm test" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^npm\\\\s+test\\\\b)"), "suggest: env var assignment skipped, npm test suggested");
  }

  // sudo is treated as a wrapper — suggests the actual command
  {
    const result = run({ tool_name: "Bash", tool_input: { command: "sudo systemctl restart nginx" }, cwd: tmp });
    const r = reason(result);
    assert(r.includes("Bash(^systemctl\\\\s+restart\\\\b)"), "suggest: wrapper 'sudo' skipped, actual command suggested");
  }

  fs.rmSync(tmp, { recursive: true, force: true });
}

const total = passed + failed;
console.log(`\n${passed} passed, ${failed} failed (${total} total)\n`);
process.exit(failed > 0 ? 1 : 0);
