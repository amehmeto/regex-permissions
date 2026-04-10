"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const fs_1 = __importDefault(require("fs"));
const path_1 = __importDefault(require("path"));
const os_1 = __importDefault(require("os"));
// --- Logging ---
const DEBUG = process.env.REGEX_PERMISSIONS_DEBUG === "1";
function debug(msg) {
    if (DEBUG)
        process.stderr.write(`[regex-permissions] ${msg}\n`);
}
// --- Helpers ---
// ReDoS heuristic: reject (x+)+, (.+)*, (\d+)+ etc.
function isSafeRegex(pattern) {
    return !/\((\.|\\.|[^)\\])[+*]\)[+*{]/.test(pattern);
}
function toRegex(pattern, flags) {
    try {
        if (!isSafeRegex(pattern)) {
            debug(`Skipping unsafe regex (possible ReDoS): ${pattern}`);
            return null;
        }
        return new RegExp(pattern, flags || "");
    }
    catch {
        debug(`Skipping invalid regex: ${pattern}`);
        return null;
    }
}
function str(val) {
    return typeof val === "string" ? val : undefined;
}
function getPrimaryContent(toolName, toolInput) {
    if (!toolInput)
        return undefined;
    if (toolName === "Bash")
        return str(toolInput.command);
    if (toolName === "Edit" || toolName === "Write" || toolName === "Read")
        return str(toolInput.file_path);
    if (toolName === "WebFetch")
        return str(toolInput.url);
    if (toolName === "Grep" || toolName === "Glob")
        return str(toolInput.pattern);
    if (toolName === "WebSearch")
        return str(toolInput.query);
    return str(toolInput.command) || str(toolInput.file_path) || str(toolInput.url) || str(toolInput.pattern) || str(toolInput.query);
}
// --- Rule parsing ---
function parseRule(entry) {
    const raw = typeof entry === "string" ? entry : entry?.rule;
    if (!raw)
        return null;
    const match = raw.match(/^([^(]+)\((.+)\)$/s);
    if (!match) {
        // Tool-name-only rule (no parentheses) — matches any content
        const toolRe = toRegex(`^(?:${raw})$`);
        if (!toolRe)
            return null;
        return {
            toolRe,
            contentRe: null,
            reason: typeof entry === "object" ? entry.reason : undefined,
            source: raw,
        };
    }
    const flags = typeof entry === "object" ? entry.flags : undefined;
    const toolRe = toRegex(`^(?:${match[1]})$`);
    const contentRe = toRegex(match[2], flags);
    if (!toolRe || !contentRe)
        return null;
    return {
        toolRe,
        contentRe,
        reason: typeof entry === "object" ? entry.reason : undefined,
        source: raw,
    };
}
// --- Config loading ---
const jsonCache = new Map();
function readJsonFile(filePath) {
    if (jsonCache.has(filePath))
        return jsonCache.get(filePath);
    try {
        const raw = fs_1.default.readFileSync(filePath, "utf8");
        const json = JSON.parse(raw);
        jsonCache.set(filePath, json);
        return json;
    }
    catch {
        jsonCache.set(filePath, null);
        return null;
    }
}
function loadConfig(filePath) {
    const json = readJsonFile(filePath);
    const config = json?.regexPermissions || null;
    if (config)
        validateConfig(config, filePath);
    return config;
}
const KNOWN_CONFIG_KEYS = new Set(["requireReason", "guardNativePermissions", "suggestOnPassthrough", "deny", "ask", "allow"]);
function validateConfig(config, filePath) {
    for (const key of Object.keys(config)) {
        if (!KNOWN_CONFIG_KEYS.has(key)) {
            let suggestion = "";
            for (const known of KNOWN_CONFIG_KEYS) {
                if (known.toLowerCase().startsWith(key.toLowerCase().slice(0, 4))) {
                    suggestion = ` (did you mean "${known}"?)`;
                    break;
                }
            }
            process.stderr.write(`[regex-permissions] Unknown config key "${key}" in ${filePath}${suggestion}\n`);
        }
    }
}
function mergeConfigs(a, b) {
    if (!a)
        return b || {};
    if (!b)
        return a;
    return {
        requireReason: a.requireReason || b.requireReason,
        guardNativePermissions: a.guardNativePermissions === "auto" || b.guardNativePermissions === "auto"
            ? "auto"
            : a.guardNativePermissions || b.guardNativePermissions,
        suggestOnPassthrough: a.suggestOnPassthrough || b.suggestOnPassthrough,
        deny: (a.deny || []).concat(b.deny || []),
        ask: (a.ask || []).concat(b.ask || []),
        allow: (a.allow || []).concat(b.allow || []),
    };
}
function prepareRules(config) {
    const requireReason = config.requireReason === true;
    const toArray = (key) => {
        const val = config[key];
        return Array.isArray(val) ? val : [];
    };
    const parse = (entries) => entries.map(parseRule).filter((r) => {
        if (r === null)
            return false;
        if (requireReason && !r.reason) {
            debug(`Skipping rule without reason (requireReason is enabled): ${r.source}`);
            return false;
        }
        return true;
    });
    return {
        deny: parse(toArray("deny")),
        ask: parse(toArray("ask")),
        allow: parse(toArray("allow")),
    };
}
// --- Evaluation ---
function ruleMatches(rule, toolName, content) {
    if (!rule.toolRe.test(toolName))
        return false;
    if (rule.contentRe === null)
        return true; // tool-name-only: match any content
    if (content == null)
        return false;
    return rule.contentRe.test(content);
}
function matchesAnyLine(rule, toolName, content, lines) {
    if (ruleMatches(rule, toolName, content))
        return true;
    if (!lines)
        return false;
    return lines.some((line) => ruleMatches(rule, toolName, line));
}
function evaluate(rules, toolName, content) {
    const contentPreview = content ? JSON.stringify(content.length > 80 ? content.slice(0, 80) + "…" : content) : "(no content)";
    const lines = content?.includes("\n")
        ? content.split("\n").map((l) => l.trim()).filter(Boolean)
        : null;
    for (const rule of rules.deny) {
        if (matchesAnyLine(rule, toolName, content, lines)) {
            debug(`DENY ${toolName} ${contentPreview} → ${rule.source}${rule.reason ? ` (${rule.reason})` : ""}`);
            return { decision: "deny", reason: rule.reason || "Blocked by regex-permissions deny rule" };
        }
    }
    for (const rule of rules.ask) {
        if (matchesAnyLine(rule, toolName, content, lines)) {
            debug(`ASK ${toolName} ${contentPreview} → ${rule.source}${rule.reason ? ` (${rule.reason})` : ""}`);
            return { decision: "ask", reason: rule.reason || "Flagged by regex-permissions ask rule" };
        }
    }
    for (const rule of rules.allow) {
        if (ruleMatches(rule, toolName, content)) {
            debug(`ALLOW ${toolName} ${contentPreview} → ${rule.source}`);
            return { decision: "allow" };
        }
    }
    debug(`PASS ${toolName} ${contentPreview} → no match`);
    return null;
}
// --- Regex suggestion ---
function escapeRegex(s) {
    return s.replace(/[.+?^${}()|[\]\\]/g, "\\$&");
}
function generateRegexSuggestion(toolName, content) {
    if (!content)
        return toolName;
    if (toolName === "Bash") {
        const firstLine = content.includes("\n") ? content.split("\n")[0].trim() : content;
        const tokens = firstLine.split(/\s+/).filter(Boolean);
        if (tokens.length === 0)
            return `Bash(.*)`;
        // Skip wrapper commands (env, nohup, time, etc.) and env var assignments (FOO=bar)
        let cmdIdx = 0;
        const WRAPPERS = /^(env|nohup|time|nice|ionice|timeout)$/;
        while (cmdIdx < tokens.length - 1 && (WRAPPERS.test(tokens[cmdIdx]) || /^\w+=/.test(tokens[cmdIdx]))) {
            cmdIdx++;
        }
        const cmd = tokens[cmdIdx];
        const subcmd = tokens[cmdIdx + 1];
        // Include subcommand if it looks like one (starts with letter, not a path, not a filename, not an assignment)
        if (subcmd && /^[a-zA-Z]/.test(subcmd) && !/[/.=]/.test(subcmd)) {
            return `Bash(^${escapeRegex(cmd)}\\s+${escapeRegex(subcmd)}\\b)`;
        }
        return `Bash(^${escapeRegex(cmd)}\\b)`;
    }
    if (toolName === "Edit" || toolName === "Write" || toolName === "Read") {
        const extMatch = content.match(/\.(\w+)$/);
        if (extMatch) {
            return `${toolName}(\\.${extMatch[1]}$)`;
        }
        return `${toolName}(.*)`;
    }
    if (toolName === "WebFetch") {
        const urlMatch = content.match(/^https?:\/\/([^/]+)/);
        if (urlMatch) {
            const domain = escapeRegex(urlMatch[1]);
            return `${toolName}(^https?://${domain}(/|$))`;
        }
        return `${toolName}(.*)`;
    }
    if (toolName === "Grep" || toolName === "Glob" || toolName === "WebSearch") {
        return `${toolName}(.*)`;
    }
    return toolName;
}
// --- Native permissions guard ---
const MANAGED_TOOL_RE = /^(Bash|Edit|Write|Read|WebFetch|Grep|Glob|WebSearch)\(.+\)$/;
function suggestRegex(native) {
    const m = native.match(/^([\w|]+)\((.+)\)$/);
    if (!m)
        return native;
    const [, tool, rawPattern] = m;
    // Handle WebFetch domain: prefix → URL regex
    const domainMatch = rawPattern.match(/^domain:(.+)$/);
    if (domainMatch) {
        const domain = escapeRegex(domainMatch[1]);
        return `${tool}(^https?://${domain}(/|$))`;
    }
    let core = rawPattern.replace(/[:*]+$/, "").trimEnd();
    const segments = core.split(/\*+/);
    core = segments
        .map((s) => escapeRegex(s))
        .join(".*");
    core = core.replace(/(\.\*)+/g, ".*");
    core = core.replace(/ +/g, "\\s+");
    const isBash = /\bBash\b/.test(tool);
    const needsBoundary = isBash && /\w$/.test(core);
    return needsBoundary ? `${tool}(^${core}\\b)` : `${tool}(^${core})`;
}
function guardNativePermissions(filePath, autoAdd) {
    const json = readJsonFile(filePath);
    if (!json)
        return [];
    const perms = json.permissions;
    if (!perms)
        return [];
    const allowEntries = perms.allow;
    if (!Array.isArray(allowEntries))
        return [];
    let changed = false;
    const removed = [];
    const kept = [];
    for (const entry of allowEntries) {
        const rule = typeof entry === "string" ? entry : entry?.rule;
        if (typeof rule === "string" && MANAGED_TOOL_RE.test(rule)) {
            removed.push({ entry: rule, suggestion: suggestRegex(rule) });
            changed = true;
        }
        else {
            kept.push(entry);
        }
    }
    if (!changed)
        return [];
    if (kept.length > 0) {
        perms.allow = kept;
    }
    else {
        delete perms.allow;
    }
    if (Object.keys(perms).length === 0) {
        delete json.permissions;
    }
    const addedRules = [];
    if (autoAdd) {
        if (!json.regexPermissions)
            json.regexPermissions = {};
        const rp = json.regexPermissions;
        if (!rp.allow)
            rp.allow = [];
        for (const { suggestion } of removed) {
            const ruleEntry = { rule: suggestion, reason: "Auto-converted from native permissions" };
            addedRules.push(ruleEntry);
            rp.allow.push(ruleEntry);
        }
    }
    // Invalidate cache before writing
    jsonCache.delete(filePath);
    fs_1.default.writeFileSync(filePath, JSON.stringify(json, null, 2) + "\n");
    for (const { entry, suggestion } of removed) {
        if (autoAdd) {
            process.stderr.write(`[regex-permissions] Converted native allow: ${entry} → { "rule": ${JSON.stringify(suggestion)} }\n`);
        }
        else {
            process.stderr.write(`[regex-permissions] Removed native allow: ${entry}\n` +
                `  → Add to regexPermissions.allow: { "rule": ${JSON.stringify(suggestion)}, "reason": "..." }\n`);
        }
    }
    return addedRules;
}
// --- Main ---
async function main() {
    let input;
    try {
        const chunks = [];
        for await (const chunk of process.stdin)
            chunks.push(Buffer.from(chunk));
        input = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    }
    catch {
        return;
    }
    const { tool_name, tool_input, cwd } = input;
    if (!tool_name)
        return;
    const projectConfig = cwd
        ? mergeConfigs(loadConfig(path_1.default.join(cwd, ".claude", "settings.json")), loadConfig(path_1.default.join(cwd, ".claude", "settings.local.json")))
        : null;
    const globalHome = path_1.default.join(os_1.default.homedir(), ".claude");
    const globalConfig = mergeConfigs(loadConfig(path_1.default.join(globalHome, "settings.json")), loadConfig(path_1.default.join(globalHome, "settings.local.json")));
    const merged = mergeConfigs(projectConfig, globalConfig);
    if (merged.guardNativePermissions && cwd) {
        const autoAdd = merged.guardNativePermissions === "auto";
        const added = guardNativePermissions(path_1.default.join(cwd, ".claude", "settings.local.json"), autoAdd);
        if (added.length > 0) {
            merged.allow = (merged.allow || []).concat(added);
        }
    }
    const rules = prepareRules(merged);
    if (!rules.deny.length && !rules.ask.length && !rules.allow.length && !merged.suggestOnPassthrough)
        return;
    debug(`Loaded ${rules.deny.length} deny, ${rules.ask.length} ask, ${rules.allow.length} allow rules`);
    const content = getPrimaryContent(tool_name, tool_input);
    const result = evaluate(rules, tool_name, content);
    if (!result) {
        if (merged.suggestOnPassthrough) {
            const suggestion = generateRegexSuggestion(tool_name, content);
            debug(`SUGGEST ${tool_name} → ${suggestion}`);
            const output = {
                hookSpecificOutput: {
                    hookEventName: "PreToolUse",
                    permissionDecision: "ask",
                    permissionDecisionReason: `No matching regex rule. Suggested: ${JSON.stringify(suggestion)}`,
                },
            };
            process.stdout.write(JSON.stringify(output) + "\n");
        }
        return;
    }
    const output = {
        hookSpecificOutput: {
            hookEventName: "PreToolUse",
            permissionDecision: result.decision,
        },
    };
    if (result.reason)
        output.hookSpecificOutput.permissionDecisionReason = result.reason;
    process.stdout.write(JSON.stringify(output) + "\n");
}
main().catch(() => { });
