# regex-permissions

A Claude Code plugin that lets you write permission rules using regex instead of wildcards.

## Installation

**Install permanently** — inside Claude Code, run:

```
/plugin marketplace add amehmeto/regex-permissions
/plugin install regex-permissions@amehmeto-regex-permissions
```

**Or try it for a single session:**

```bash
git clone https://github.com/amehmeto/regex-permissions.git
claude --plugin-dir ./regex-permissions
```

Then add your rules under the `regexPermissions` key in `.claude/settings.json` or `.claude/settings.local.json` (project or global). See [Configuration](#configuration) below.

## Updating the Plugin

- **`--plugin-dir`** loads directly from the source directory — no cache, changes apply on restart
- **Marketplace installed** (`@local-plugins`) uses a cache in `~/.claude/plugins/cache/` — run `/reload-plugins` inside Claude Code to pick up updates without restarting
- If `/reload-plugins` doesn't pick up changes, clear the cache manually: `rm -rf ~/.claude/plugins/cache/local-plugins/regex-permissions` and restart

## Configuration

Add your regex rules under the `regexPermissions` key in your settings file. This key is separate from Claude Code's native `permissions` key — both can coexist without conflict. All four config files are loaded and merged additively.

```json
{
  "regexPermissions": {
    "suggestOnPassthrough": true,
    "guardNativePermissions": "auto",
    "deny": [
      { "rule": "Bash(^git\\s+push\\s+.*--force\\b(?!-))", "reason": "No force push" }
    ],
    "ask": [
      { "rule": "Bash([;|&`$#])", "reason": "Shell metacharacters detected" }
    ],
    "allow": [
      "Bash(^\\S+\\s+--help$)",
      "Bash(^git\\s+(status|log|diff|show|branch))",
      "Glob|Grep(.*)"
    ]
  }
}
```

See `regex-permissions.example.json` for a full annotated config.

## Rule Syntax

Rules use the `Tool(pattern)` format — the tool name and content pattern are both regexes:

```
Tool name regex ──┐    ┌── Content regex
                  Bash(^git\\s+status)
```

**String form** — for most rules:
```json
"Bash(^git\\s+push)"
```

**Object form** — when you need `reason` or `flags`:
```json
{ "rule": "Bash(^git\\s+push)", "reason": "Confirm before pushing", "flags": "i" }
```

**Tool-name-only form** — omit parentheses to match any content. Useful for MCP and Skill tools where the plugin cannot inspect input fields:
```json
{
  "deny": [
    { "rule": "mcp__github__merge_pull_request", "reason": "No merge via MCP" }
  ],
  "allow": [
    "mcp__github__list_pulls",
    "Glob|Grep|WebSearch"
  ]
}
```

The `flags` field applies to the content regex only (tool names are always case-sensitive).

## Tool Matching

The tool name portion is an **anchored regex** — it must match the full tool name (`^(?:...)$`). `Bash` matches only `Bash`, not `BashExecutor` or `MyBash`. Use alternation for multiple tools:

```json
"Edit|Write|Read(\\.(ts|js|py)$)"
```

The content pattern matches against the tool's primary field:

| Tool       | Pattern matches  |
|------------|------------------|
| Bash       | `command`        |
| Edit/Write/Read | `file_path` |
| WebFetch   | `url`            |
| Grep/Glob  | `pattern`        |
| WebSearch  | `query`          |
| Other tools  | First of: `command`, `file_path`, `url`, `pattern`, `query` |

## Requiring Reasons

Enable `requireReason` to enforce that every rule includes a `reason` field. Rules without one (including all string-form rules) are silently skipped, falling through to native permissions.

```json
{
  "regexPermissions": {
    "requireReason": true,
    "deny": [
      { "rule": "Bash(^sudo)", "reason": "No sudo" }
    ],
    "allow": [
      { "rule": "Bash(^git\\s+status)", "reason": "Read-only git" }
    ]
  }
}
```

This is opt-in — when `requireReason` is not set or `false`, string rules and object rules without `reason` work normally. Skipped rules are visible with `REGEX_PERMISSIONS_DEBUG=1`.

If any of the four config files sets `requireReason: true`, it applies to all merged rules.

## Suggesting Rules on Passthrough

Enable `suggestOnPassthrough` to get regex suggestions whenever a tool use doesn't match any rule. Instead of silently passing through to native permissions, the plugin returns `ask` with a suggested regex to add:

```json
{
  "regexPermissions": {
    "suggestOnPassthrough": true,
    "allow": ["Bash(^git\\s+status)"]
  }
}
```

When you run `docker compose up` (no matching rule), the approval prompt includes:
```
No matching regex rule. Suggested: "Bash(^docker\s+compose\b)"
```

Suggestions are context-aware:
- **Bash**: extracts the command and subcommand, skips wrappers (`sudo`, `env`, `nohup`, `time`) and env var assignments (`FOO=bar`)
- **Edit/Write/Read**: suggests a file extension pattern like `Edit(\.tsx$)`
- **WebFetch**: suggests a domain-based pattern like `WebFetch(^https?://docs\.github\.com(/|$))`
- **MCP/unknown tools**: suggests a tool-name-only rule

## Guarding Native Permissions

When Claude Code's "don't ask again" prompt is accepted, it writes a native wildcard rule (e.g. `Bash(cowsay:*)`) to `permissions.allow` in `settings.local.json`. Enable `guardNativePermissions` to intercept these and convert them to regex:

**Suggest mode** — removes the native entry and logs the suggested regex:
```json
{ "guardNativePermissions": true }
```

**Auto mode** (recommended) — removes the native entry AND adds the converted regex to `regexPermissions.allow` automatically:
```json
{ "guardNativePermissions": "auto" }
```

With auto mode, the full flow is seamless:

1. You run an unknown command → plugin suggests a regex and prompts for approval
2. You approve → Claude Code adds a native rule to `permissions.allow`
3. **Immediately** on the same tool use, the PostToolUse hook detects the native rule, removes it, and adds the regex equivalent to `regexPermissions.allow`

No manual migration needed — approved rules land in the right place automatically.

Only `allow` entries with patterns are removed — the guard does not touch `deny` or `ask` entries (which are intentional safety rules, not auto-added). Bare tool names like `"Edit"` and non-managed entries (Skill, MCP, BashOutput) are always kept. The guard only modifies `settings.local.json`, never the committed `settings.json` or global config.

## Evaluation Order

1. **Deny** — first matching deny rule blocks the action
2. **Ask** — first matching ask rule prompts the user
3. **Allow** — first matching allow rule auto-approves
4. **Passthrough** — no match = native Claude Code permissions handle it

Deny always wins. A deny rule cannot be overridden by an ask or allow rule.

For multiline commands, deny and ask rules check each line individually — `^sudo` will catch `sudo` embedded on any line. Each line is trimmed and empty lines are skipped, so `^sudo` also catches indented lines like `  sudo`. Allow rules match against the full command string only.

## Examples

Allow any command's `--help` flag with a single rule:
```json
"Bash(^\\S+\\s+--help$)"
```

Prompt for approval when shell metacharacters are detected:
```json
{ "rule": "Bash([;|&`$#])", "reason": "Shell metacharacters detected" }
```

Allow all AWS read-only operations across every service:
```json
"Bash(^aws\\s+\\S+\\s+(get|list|describe)-)"
```

Collapse many similar rules into one — **before** (native wildcards):
```json
{
  "permissions": {
    "allow": [
      "Bash(git status)",
      "Bash(git log *)",
      "Bash(git diff *)",
      "Bash(gh pr view *)",
      "Bash(gh pr list *)",
      "Bash(gh issue view *)"
    ]
  }
}
```

**After** (regex):
```json
{
  "regexPermissions": {
    "allow": [
      "Bash(^git\\s+(status|log|diff|show|branch|tag))",
      "Bash(^gh\\s+(pr|issue)\\s+(view|list|status))"
    ]
  }
}
```

## Error Handling

The plugin **fails open** — if anything goes wrong, native permissions take over:

- Missing config → passthrough
- Invalid JSON → passthrough
- Invalid regex → that rule is skipped
- Unsafe regex (ReDoS) → that rule is skipped
- Non-array config value → skipped
- Unknown config key → warning to stderr, rules still work
- Script crash → 5-second timeout, passthrough

## Debugging

Set the environment variable to see which rule matched each decision:

```bash
REGEX_PERMISSIONS_DEBUG=1 claude
```

Example debug output:
```
[regex-permissions] Loaded 3 deny, 2 ask, 5 allow rules
[regex-permissions] DENY Bash "git push --force" → Bash(^git\s+push\s+.*--force) (No force push)
[regex-permissions] ALLOW Bash "git status" → Bash(^git\s+(status|log|diff))
[regex-permissions] SUGGEST Bash → Bash(^docker\s+compose\b)
[regex-permissions] PASS Bash "some-unknown-cmd" → no match
[regex-permissions] PostToolUse: converted Bash(cowsay:*) → Bash(^cowsay\b)
```

Debug also warns about unknown config keys (possible typos):
```
[regex-permissions] Unknown config key: "requierReason" (did you mean "requireReason"?)
```

Test rules directly without Claude Code:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force"},"cwd":"."}' \
  | REGEX_PERMISSIONS_DEBUG=1 node dist/check-permissions.js
```

## Regex Tips

**Anchor patterns** with `^` to prevent partial matches:
```
^git\s+push    matches "git push" at start
git\s+push     also matches "digit push"
```

**Escape in JSON** — backslashes must be doubled: `\\s`, `\\b`, `\\.`

**Alternation** for multiple options: `^git\\s+(status|log|diff)`

**Word boundaries** to prevent partial matches: `^npm\\s+test\\b`

**Avoid nested quantifiers** (ReDoS risk) — patterns like `(a+)+` are automatically rejected.
