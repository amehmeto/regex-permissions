---
description: Fetch PR review comments and fix them all in one pass.
---

Fix all pending review comments on PR #$ARGUMENTS.

## Steps

1. **Fetch PR review comments**:
   ```bash
   gh api repos/{owner}/{repo}/pulls/$ARGUMENTS/comments --jq '.[] | select(.in_reply_to_id == null) | {id, path, line, body, diff_hunk}'
   ```
   Also fetch top-level PR comments:
   ```bash
   gh pr view $ARGUMENTS --comments --json comments
   ```

2. **Ensure you are on the correct branch** for this PR:
   ```bash
   gh pr view $ARGUMENTS --json headRefName --jq '.headRefName'
   ```
   Check out the branch if not already on it.

3. **Parse each review comment** to extract:
   - The file path and line number it's attached to
   - The comment body (the feedback / requested change)

4. **Create a todo plan** with one todo item per review comment, including the file, line reference, and what was asked for.

5. **Fix ALL review comments**, one by one, following the todo plan:
   - Apply the minimal change that addresses each comment — do NOT over-engineer
   - Do NOT modify files that weren't mentioned in review comments unless lint/test fixes require it

6. **Reply to each review comment** on the PR:
   - Always prefix replies with `Claude's answer:` so they're distinguishable
   - For each comment you fixed: reply with a concise summary of what you changed
   - For questions from the reviewer: reply with a direct answer
   - Reply in-thread:
     ```bash
     gh api repos/{owner}/{repo}/pulls/$ARGUMENTS/comments -f body="Claude's answer: <reply>" -f in_reply_to=COMMENT_ID
     ```

7. **After all fixes are applied:**
   - Run `npm run build` and fix any compilation errors
   - Run `npm test` and fix any test failures
   - Stage all changed files and use `/commit-push`

8. **After push, summarize on the PR:**
   ```bash
   gh pr comment $ARGUMENTS --body "Review feedback addressed: [summary of all changes made, one bullet per comment addressed]"
   ```

## Constraints

- Do NOT modify files that weren't mentioned in review comments unless build/test requires it
- Do NOT over-engineer fixes — apply the minimal change that addresses each comment
- If a comment is ambiguous, make the most reasonable interpretation and note it in the PR summary comment
