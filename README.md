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
  "permissions": {
    "...": "your existing native rules still work alongside"
  },
  "regexPermissions": {
    "deny": [
      {
        "tool": "Bash",
        "command": "^git\\s+push\\s+.*--force",
        "reason": "No force push"
      }
    ],
    "ask": [
      {
        "tool": "Bash",
        "command": "[;|&`$#]",
        "reason": "Shell metacharacters detected"
      }
    ],
    "allow": [
      {
        "tool": "Bash",
        "command": "^\\S+\\s+--help$",
        "reason": "Any command --help is safe"
      }
    ]
  }
}
```

## Rule Fields

All fields are optional. When multiple fields are present, they are AND-combined (all must match).

| Field     | Matches against                              | Example                        |
|-----------|----------------------------------------------|--------------------------------|
| `tool`    | Tool name                                    | `"Bash"`, `"Edit\|Write"`, `"^mcp__github__"` |
| `command` | Primary content (auto-detected per tool)     | `"^git\\s+push"`              |
| `path`    | `file_path` (Edit/Write/Read)                | `"\\.env$"`                   |
| `url`     | `url` (WebFetch)                             | `"docs\\.expo\\.dev"`         |
| `flags`   | Regex flags                                  | `"i"` (case-insensitive)      |
| `reason`  | Human-readable explanation (shown on deny/ask) | `"No force push"`           |

**Primary content auto-detection by tool:**

| Tool       | Primary field     |
|------------|-------------------|
| Bash       | `command`         |
| Edit/Write/Read | `file_path`  |
| WebFetch   | `url`             |
| Grep/Glob  | `pattern`         |
| WebSearch  | `query`           |
| Other/MCP  | First of: `command`, `file_path`, `url`, `pattern` |

## Evaluation Order

1. **Deny** — first matching deny rule blocks the action
2. **Ask** — first matching ask rule prompts the user for approval
3. **Allow** — first matching allow rule auto-approves
4. **Passthrough** — no match = native Claude Code permissions handle it

## Community Patterns

These patterns address common requests from [GitHub issue #13154](https://github.com/anthropics/claude-code/issues/13154):

### Universal `--help` (RyanSaxe)

Allow any command's `--help` flag with a single rule:

```json
{ "tool": "Bash", "command": "^\\S+\\s+--help$" }
```

### Shell metacharacter detection (RyanSaxe)

Prompt for approval when shell chaining, piping, or subshells are detected:

```json
{ "tool": "Bash", "command": "[;|&`$#]", "reason": "Shell metacharacters detected" }
```

### AWS CLI read-only operations (blimmer)

Allow all AWS `get`/`list`/`describe` across hundreds of services:

```json
{ "tool": "Bash", "command": "^aws\\s+\\S+\\s+(get|list|describe)-" }
```

### Optional flag groups for git (kojiromike)

Match `git -C <path> grep` without also matching `git push --force origin grep`:

```json
{ "tool": "Bash", "command": "^git\\s+(-C\\s+\\S+\\s+)?grep\\s" }
```

## Migration Guide

**Before** (327 literal rules in `settings.local.json`):

```json
{
  "permissions": {
    "allow": [
      "Bash(git status)",
      "Bash(git log)",
      "Bash(git diff)",
      "Bash(git branch)",
      "Bash(gh pr view*)",
      "Bash(gh pr list*)",
      "Bash(gh issue view*)",
      "Bash(gh issue list*)",
      "Bash(npm test*)",
      "Bash(npm run lint*)",
      "..."
    ]
  }
}
```

**After** (~41 regex rules):

```json
{
  "regexPermissions": {
    "allow": [
      { "tool": "Bash", "command": "^git\\s+(status|log|diff|show|branch|tag)" },
      { "tool": "Bash", "command": "^gh\\s+(pr|issue)\\s+(view|list|status)" },
      { "tool": "Bash", "command": "^npm\\s+(test|run)\\s+" }
    ]
  }
}
```

See `regex-permissions.example.json` for a complete annotated migration.

## Error Handling

The plugin is designed to **fail open** — if anything goes wrong, it passes through to native permissions:

- Missing `regexPermissions` key → passthrough
- Invalid JSON in settings → passthrough
- Invalid regex pattern → that rule is skipped (treated as non-matching)
- Unreadable config file → passthrough
- Script crash → Claude Code's 5-second timeout kicks in, passthrough

## Regex Tips

### Anchoring

Always anchor patterns with `^` to prevent partial matches:

```
^git\s+push           ✓  matches "git push" at start
git\s+push            ✗  also matches "digit push" or "sedigit push"
```

### Escaping

In JSON, backslashes must be doubled: `\\s`, `\\b`, `\\.`

### Alternation

Use `(a|b|c)` for multiple options:

```
^git\s+(status|log|diff|show)
```

### Word boundaries

Use `\b` to prevent partial word matches:

```
^npm\s+test\b         ✓  matches "npm test" but not "npm testing"
```

### ReDoS Warning

Avoid nested quantifiers that can cause catastrophic backtracking:

```
(a+)+b                ✗  exponential time on non-matching input
(a|b)*c               ✓  linear time alternation
```

Keep patterns simple and avoid `.*` when a more specific pattern like `\\S+` or `[^\\s]+` will do.

## How It Works

This plugin registers a `PreToolUse` hook that intercepts every tool call Claude Code makes. The hook script (`scripts/check-permissions.js`):

1. Reads the tool call JSON from stdin
2. Loads `regexPermissions` from project and global `settings.local.json`
3. Evaluates rules in deny → ask → allow order
4. Outputs a permission decision JSON to stdout

The hook runs in under 5ms for typical configs. A 5-second timeout in `hooks.json` serves as a backstop against pathological regex patterns.

## License

MIT
