---
description: Commit all changes and push to remote.
---

Commit and push workflow:

1. **Stage all changes**:
   - Run `git add -A` to stage everything

2. **Create a conventional commit**:
   - Analyze all staged changes
   - Use HEREDOC format for the commit message:
   ```
   git commit -m "$(cat <<'EOF'
   <type>(<scope>): <description>

   Co-Authored-By: Claude Opus 4.6 <noreply@anthropic.com>
   EOF
   )"
   ```

3. **Push**:
   - Run `git push` to push changes
   - If no upstream is set, use `git push -u origin <branch-name>`

4. **Create or update PR**:
   - After pushing, check if a PR already exists for the current branch: `gh pr view --json url 2>/dev/null`
   - If no PR exists, create one with `gh pr create`
   - If PR exists, update the description with `gh pr edit <number> --body` to reflect all changes made
   - Use a descriptive title and summary of changes in the body

5. **Output the PR URL** so the user can review it.

Execute the commit and push now.
