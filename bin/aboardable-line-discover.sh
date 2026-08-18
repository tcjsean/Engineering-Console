#!/bin/zsh
# Aboardable Engineering Console -- environment discovery probe.
#
# Always inspects wherever it's running. "Remote" discovery is purely about
# how this script is invoked: console-api runs it directly for a local
# target, or pipes it over `ssh user@host 'bash -s'` for a remote one --
# there is only one probe implementation either way. Read-only: never
# installs anything, never starts a tmux session, never writes to
# controller.db (it doesn't even know that file exists).
set -uo pipefail

TIMEOUT_BIN="timeout"
SCAN_TIMEOUT=8
MAX_REPOS=12

hostname_val=$(hostname 2>/dev/null || echo "")
whoami_val=$(whoami 2>/dev/null || echo "")

repo_paths=()
while IFS= read -r gitdir; do
    [[ -n "$gitdir" ]] || continue
    repo_paths+=("${gitdir%/.git}")
done < <("$TIMEOUT_BIN" "$SCAN_TIMEOUT" find /home -maxdepth 5 -name .git -type d 2>/dev/null | sort -u | head -n "$MAX_REPOS")

repos_json="[]"
if (( ${#repo_paths[@]} > 0 )); then
    parts=()
    for p in "${repo_paths[@]}"; do
        owner=$(stat -c '%U' "$p" 2>/dev/null || echo "")
        remote=$(git -C "$p" remote get-url origin 2>/dev/null || echo "")
        branch=$(git -C "$p" branch --show-current 2>/dev/null || echo "")
        default_branch=$(git -C "$p" symbolic-ref refs/remotes/origin/HEAD 2>/dev/null | sed 's@^refs/remotes/origin/@@' || echo "")
        parts+=("$(jq -n --arg path "$p" --arg owner "$owner" --arg remote "$remote" --arg branch "$branch" --arg default_branch "$default_branch" \
            '{path:$path,owner:$owner,remote:$remote,branch:$branch,default_branch:$default_branch}')")
    done
    repos_json=$(printf '%s\n' "${parts[@]}" | jq -s '.')
fi

claude_path=$(command -v claude 2>/dev/null || echo "")
claude_version=""
[[ -n "$claude_path" ]] && claude_version=$("$TIMEOUT_BIN" 5 claude --version 2>/dev/null | head -1 || echo "")

codex_path=$(command -v codex 2>/dev/null || echo "")
codex_version=""
[[ -n "$codex_path" ]] && codex_version=$("$TIMEOUT_BIN" 5 codex --version 2>/dev/null | head -1 || echo "")

tmux_path=$(command -v tmux 2>/dev/null || echo "")
tmux_version=""
tmux_sessions_json="[]"
if [[ -n "$tmux_path" ]]; then
    tmux_version=$(tmux -V 2>/dev/null || echo "")
    tmux_sessions_json=$(tmux ls -F '#{session_name}' 2>/dev/null | jq -R -s 'split("\n") | map(select(length>0))')
fi

jq -n \
    --arg hostname "$hostname_val" \
    --arg whoami "$whoami_val" \
    --argjson repos "$repos_json" \
    --argjson claude_installed "$([[ -n "$claude_path" ]] && echo true || echo false)" \
    --arg claude_version "$claude_version" \
    --argjson codex_installed "$([[ -n "$codex_path" ]] && echo true || echo false)" \
    --arg codex_version "$codex_version" \
    --argjson tmux_installed "$([[ -n "$tmux_path" ]] && echo true || echo false)" \
    --arg tmux_version "$tmux_version" \
    --argjson tmux_sessions "$tmux_sessions_json" \
    '{ok:true,hostname:$hostname,whoami:$whoami,repos:$repos,
      claude:{installed:$claude_installed,version:$claude_version},
      codex:{installed:$codex_installed,version:$codex_version},
      tmux:{installed:$tmux_installed,version:$tmux_version,sessions:$tmux_sessions}}'
