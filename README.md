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

## Configuration

Add your regex rules under the `regexPermissions` key in your settings file. This key is separate from Claude Code's native `permissions` key — both can coexist without conflict. All four config files are loaded and merged additively.

```json
{
  "regexPermissions": {
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
- Script crash → 5-second timeout, passthrough

## Debugging

Set the environment variable to see rule loading and skipped rules:

```bash
REGEX_PERMISSIONS_DEBUG=1 claude
```

Test rules directly without Claude Code:

```bash
echo '{"tool_name":"Bash","tool_input":{"command":"git push --force"},"cwd":"."}' \
  | node dist/check-permissions.js
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
