export interface HookSpecificOutput {
  hookEventName?: string;
  permissionDecision?: string;
  permissionDecisionReason?: string;
}

export interface HookOutput {
  hookSpecificOutput?: HookSpecificOutput;
}

export interface HookInput {
  tool_name: string;
  tool_input: Record<string, string>;
  cwd?: string;
}
