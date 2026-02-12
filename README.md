# regex-permissions

A Claude Code plugin that replaces hundreds of literal allow/deny/ask permission rules with compact regex patterns. Collapse 327 rules into ~41.

## Installation

```bash
# Clone or copy to any directory
git clone <repo-url> ~/regex-permissions

# Use with Claude Code
claude --plugin-dir ~/regex-permissions
```

Or add to your project's `.claude/plugins.json`:

```json
{
  "plugins": ["~/regex-permissions"]
}
```

## Configuration

Add a `regexPermissions` key to your existing `.claude/settings.local.json` (project-level) or `~/.claude/settings.local.json` (global). Both are loaded and merged additively.

```json
{
  "regexPermissions": {
    "deny": [
      { "rule": "Bash(^git\\s+push\\s+.*--force)", "reason": "No force push" }
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

### Rule Syntax

Rules use the same `Tool(pattern)` format as native Claude Code permissions, but with regex instead of wildcards:

```
Native:   Bash(git status)        ← wildcard
Plugin:   Bash(^git\\s+status)    ← regex
```

**String form** — for most rules:
```json
"Bash(^git\\s+push)"
```

**Object form** — when you need `reason` or `flags`:
```json
{ "rule": "Bash(^git\\s+push)", "reason": "Confirm before pushing", "flags": "i" }
```

### Tool Matching

The tool name (before the parentheses) is itself a regex, so `Edit|Write` matches both tools:

```json
"Edit|Write|Read(\\.(ts|js|py)$)"
```

The pattern inside parentheses matches against the tool's primary content:

| Tool       | Pattern matches  |
|------------|------------------|
| Bash       | `command`        |
| Edit/Write/Read | `file_path` |
| WebFetch   | `url`            |
| Grep/Glob  | `pattern`        |
| WebSearch  | `query`          |
| MCP tools  | First of: `command`, `file_path`, `url`, `pattern` |

### Evaluation Order

1. **Deny** — first matching deny rule blocks the action
2. **Ask** — first matching ask rule prompts the user
3. **Allow** — first matching allow rule auto-approves
4. **Passthrough** — no match = native Claude Code permissions handle it

## Community Patterns

Patterns from [GitHub issue #13154](https://github.com/anthropics/claude-code/issues/13154):

### Universal `--help` (RyanSaxe)

```json
"Bash(^\\S+\\s+--help$)"
```

### Shell metacharacter detection (RyanSaxe)

```json
{ "rule": "Bash([;|&`$#])", "reason": "Shell metacharacters detected" }
```

### AWS CLI read-only (blimmer)

```json
"Bash(^aws\\s+\\S+\\s+(get|list|describe)-)"
```

### Git with `-C` flag (kojiromike)

```json
"Bash(^git\\s+(-C\\s+\\S+\\s+)?grep\\s)"
```

## Migration Guide

**Before** (327 literal rules):

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

**After** (~41 regex rules):

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

See `regex-permissions.example.json` for a complete annotated example.

## Error Handling

The plugin **fails open** — if anything goes wrong, native permissions take over:

- Missing `regexPermissions` key → passthrough
- Invalid JSON → passthrough
- Invalid regex → that rule is skipped
- Script crash → 5-second timeout, passthrough

## Regex Tips

**Anchor patterns** with `^` to prevent partial matches:
```
^git\s+push    ✓  matches "git push" at start
git\s+push     ✗  also matches "digit push"
```

**Escape in JSON** — backslashes are doubled: `\\s`, `\\b`, `\\.`

**Alternation** for multiple options: `^git\\s+(status|log|diff)`

**Word boundaries** to prevent partial matches: `^npm\\s+test\\b`

**Avoid nested quantifiers** (ReDoS risk): prefer `\\S+` over `.*` where possible.

## License

MIT
