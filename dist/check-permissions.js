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
    if (!match)
        return null;
    const flags = typeof entry === "object" ? entry.flags : undefined;
    const toolRe = toRegex(`^(?:${match[1]})$`);
    const contentRe = toRegex(match[2], flags);
    if (!toolRe || !contentRe)
        return null;
    return {
        toolRe,
        contentRe,
        reason: typeof entry === "object" ? entry.reason : undefined,
    };
}
// --- Config loading ---
function loadConfig(filePath) {
    try {
        const raw = fs_1.default.readFileSync(filePath, "utf8");
        return JSON.parse(raw).regexPermissions || null;
    }
    catch {
        return null;
    }
}
function mergeConfigs(a, b) {
    if (!a)
        return b || {};
    if (!b)
        return a;
    return {
        requireReason: a.requireReason || b.requireReason,
        guardNativePermissions: a.guardNativePermissions || b.guardNativePermissions,
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
            debug(`Skipping rule without reason (requireReason is enabled): ${r.toolRe.source} / ${r.contentRe.source}`);
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
function evaluate(rules, toolName, toolInput) {
    const content = getPrimaryContent(toolName, toolInput);
    const lines = content?.includes("\n")
        ? content.split("\n").map((l) => l.trim()).filter(Boolean)
        : null;
    for (const rule of rules.deny) {
        if (matchesAnyLine(rule, toolName, content, lines))
            return { decision: "deny", reason: rule.reason || "Blocked by regex-permissions deny rule" };
    }
    for (const rule of rules.ask) {
        if (matchesAnyLine(rule, toolName, content, lines))
            return { decision: "ask", reason: rule.reason || "Flagged by regex-permissions ask rule" };
    }
    for (const rule of rules.allow) {
        if (ruleMatches(rule, toolName, content))
            return { decision: "allow" };
    }
    return null;
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
        const domain = domainMatch[1].replace(/[.+?^${}()|[\]\\]/g, "\\$&");
        return `${tool}(^https?://${domain}(/|$))`;
    }
    let core = rawPattern.replace(/[:*]+$/, "").trimEnd();
    const segments = core.split(/\*+/);
    core = segments
        .map((s) => s.replace(/[.+?^${}()|[\]\\]/g, "\\$&"))
        .join(".*");
    core = core.replace(/(\.\*)+/g, ".*");
    core = core.replace(/ +/g, "\\s+");
    const isBash = /\bBash\b/.test(tool);
    const needsBoundary = isBash && /\w$/.test(core);
    return needsBoundary ? `${tool}(^${core}\\b)` : `${tool}(^${core})`;
}
function guardNativePermissions(filePath) {
    let raw;
    try {
        raw = fs_1.default.readFileSync(filePath, "utf8");
    }
    catch {
        return;
    }
    let json;
    try {
        json = JSON.parse(raw);
    }
    catch {
        return;
    }
    const perms = json.permissions;
    if (!perms)
        return;
    const allowEntries = perms.allow;
    if (!Array.isArray(allowEntries))
        return;
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
        return;
    if (kept.length > 0) {
        perms.allow = kept;
    }
    else {
        delete perms.allow;
    }
    if (Object.keys(perms).length === 0) {
        delete json.permissions;
    }
    fs_1.default.writeFileSync(filePath, JSON.stringify(json, null, 2) + "\n");
    for (const { entry, suggestion } of removed) {
        process.stderr.write(`[regex-permissions] Removed native allow: ${entry}\n` +
            `  → Add to regexPermissions.allow: { "rule": ${JSON.stringify(suggestion)}, "reason": "..." }\n`);
    }
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
        guardNativePermissions(path_1.default.join(cwd, ".claude", "settings.local.json"));
    }
    const rules = prepareRules(merged);
    if (!rules.deny.length && !rules.ask.length && !rules.allow.length)
        return;
    debug(`Loaded ${rules.deny.length} deny, ${rules.ask.length} ask, ${rules.allow.length} allow rules`);
    const result = evaluate(rules, tool_name, tool_input);
    if (!result)
        return;
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
