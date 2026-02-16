# regex-permissions

A Claude Code plugin that lets you write permission rules using regex instead of wildcards.

Requires **Node.js >= 18**.

## Installation

```bash
claude --plugin-dir ~/regex-permissions
```

Or add to your project's `.claude/plugins.json`:

```json
{
  "plugins": ["~/regex-permissions"]
}
```

Then add your rules to `.claude/settings.local.json` (project-level) or `~/.claude/settings.local.json` (global). See [Configuration](#configuration) below.

## Configuration

Add a `regexPermissions` key to your settings file. Both project-level and global configs are loaded and merged additively.

```json
{
  "regexPermissions": {
    "deny": [
      { "rule": "Bash(^git\\s+push\\s+.*--force\\b(?!-))", "reason": "No force push" }
    ],
    "ask": [
      { "rule": "Bash([;|&`$#\\n])", "reason": "Shell metacharacters detected" }
    ],
    "allow": [
      "Bash(^\\S+\\s+--help$)",
      "Bash(^git\\s+(status|log|diff|show|branch))",
      "Glob|Grep(.*)"
    ]
  }
}
```

See `regex-permissions.example.json` for a full annotated config with rules for git, GitHub CLI, AWS, Docker, package managers, and more.

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

The `flags` field applies to the content regex only (tool names are always case-sensitive). The `g` flag is automatically stripped to prevent stateful matching bugs.

## Tool Matching

The tool name portion is an **exact match** — `Bash` matches only `Bash`, not `BashExecutor` or `MyBash`. Use alternation for multiple tools:

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
| MCP tools  | First of: `command`, `file_path`, `url`, `pattern` |

## Evaluation Order

1. **Deny** — first matching deny rule blocks the action
2. **Ask** — first matching ask rule prompts the user
3. **Allow** — first matching allow rule auto-approves
4. **Passthrough** — no match = native Claude Code permissions handle it

Deny always wins. A deny rule cannot be overridden by an ask or allow rule.

## Multiline Protection

Commands containing newlines are evaluated per-line:

- **Deny/Ask**: if *any* line matches a deny or ask rule, that decision applies to the whole command
- **Allow**: *every* line must independently match an allow rule, otherwise the command falls through to native permissions

This prevents bypass attacks like embedding `sudo rm -rf /` on line 2 of an otherwise-allowed command.

## Examples

Allow any command's `--help` flag with a single rule:
```json
"Bash(^\\S+\\s+--help$)"
```

Prompt for approval when shell chaining, piping, or newlines are detected:
```json
{ "rule": "Bash([;|&`$#\\n])", "reason": "Shell metacharacters detected" }
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

- Missing `regexPermissions` key → passthrough
- Invalid JSON → passthrough
- Invalid regex → that rule is skipped (warning on stderr)
- Unsafe regex (ReDoS) → that rule is skipped (warning on stderr)
- Non-array config value → skipped (warning on stderr)
- Script crash → 5-second timeout, passthrough

## Debugging

Set the environment variable to see which rules are loaded:

```bash
REGEX_PERMISSIONS_DEBUG=1 claude --plugin-dir ~/regex-permissions
```

Warnings (invalid rules, unsafe regexes, bad config) are always printed to stderr regardless of debug mode.

You can also test rules directly without Claude Code:

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

**Avoid nested quantifiers** (ReDoS risk) — patterns like `(a+)+` are automatically rejected. Prefer `\\S+` over `.*` where possible.
