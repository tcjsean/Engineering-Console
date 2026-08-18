#!/bin/zsh
# Aboardable Engineering Console -- Production Line Onboarding CLI.
#
# validate|plan|apply|verify|rollback --line LINE_ID [--manifest FILE]
#
# Ingestion-registration only: this never invokes controller-worker.sh or
# any dispatch/review logic, and apply's own end-to-end test relies entirely
# on the already-running report-ingest-watch.sh service to prove ingestion
# -- it does not ingest anything itself. Idempotent: re-running apply on an
# already-correct line reports each phase as already-satisfied rather than
# duplicating state.
set -euo pipefail

ROOT="${ABOARDABLE_CONTROLLER_ROOT:-$HOME/.aboardable-tools/v2}"
STATE="$ROOT/controller-state.sh"
DB="$ROOT/controller.db"
LINES_DIR="$ROOT/lines"
SIGNATURE="ABRD7F9C2E41A6B88D3F05C7A91E4B6D2READY"

usage() {
    echo "Usage: $0 {validate|plan|apply|verify|rollback} --line LINE_ID [--manifest FILE]" >&2
    exit 64
}

valid_line_id() { [[ "$1" =~ '^[a-z][a-z0-9-]{2,39}$' ]]; }

json_escape() {
    printf '%s' "$1" | python3 -c 'import json,sys; print(json.dumps(sys.stdin.read()))' 2>/dev/null \
        || printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk 'BEGIN{printf "\""} {printf "%s\\n", $0} END{printf "\""}'
}

SUBCOMMAND="${1:-}"
[[ -n "$SUBCOMMAND" ]] || usage
shift || true

LINE_ID=""
MANIFEST_FILE=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --line) LINE_ID="$2"; shift 2 ;;
        --manifest) MANIFEST_FILE="$2"; shift 2 ;;
        *) echo "unknown argument: $1" >&2; exit 64 ;;
    esac
done
[[ -n "$LINE_ID" ]] || usage
valid_line_id "$LINE_ID" || { echo "invalid line id: $LINE_ID" >&2; exit 64; }

MANIFEST_PATH="$LINES_DIR/$LINE_ID/manifest.json"
[[ -n "$MANIFEST_FILE" ]] || MANIFEST_FILE="$MANIFEST_PATH"

# run_checks LINE_ID MANIFEST_FILE -- prints one JSON object per check to
# stdout (newline-delimited); the caller derives pass/fail from the
# "status" fields in that output (subshell command substitution means a
# plain shell counter here would not survive back to the caller).
emit_check() {
    local name="$1" result="$2" detail="$3"
    printf '{"name":%s,"status":%s,"detail":%s}\n' "$(json_escape "$name")" "$(json_escape "$result")" "$(json_escape "$detail")"
}

run_checks() {
    local line_id="$1" manifest_file="$2"

    if [[ ! -f "$manifest_file" ]]; then
        emit_check "manifest_readable" "fail" "manifest file not found: $manifest_file"
        return
    fi
    if ! jq empty "$manifest_file" >/dev/null 2>&1; then
        emit_check "manifest_readable" "fail" "manifest is not valid JSON"
        return
    fi
    emit_check "manifest_readable" "pass" "manifest is valid JSON"

    local manifest_line_id project_path worker_account report_source_path vps_hostname ssh_user git_remote default_branch line_type access_mode
    manifest_line_id=$(jq -r '.line_id // empty' "$manifest_file")
    project_path=$(jq -r '.project_path // empty' "$manifest_file")
    worker_account=$(jq -r '.worker_account // empty' "$manifest_file")
    report_source_path=$(jq -r '.report_source_path // empty' "$manifest_file")
    vps_hostname=$(jq -r '.vps_hostname // empty' "$manifest_file")
    ssh_user=$(jq -r '.ssh_user // empty' "$manifest_file")
    git_remote=$(jq -r '.git_remote // empty' "$manifest_file")
    default_branch=$(jq -r '.default_branch // empty' "$manifest_file")
    line_type=$(jq -r '.line_type // empty' "$manifest_file")
    access_mode=$(jq -r '.access_mode // empty' "$manifest_file")

    if [[ "$manifest_line_id" != "$line_id" ]]; then
        emit_check "line_id_matches" "fail" "manifest line_id '$manifest_line_id' does not match --line '$line_id'"
    else
        emit_check "line_id_matches" "pass" "manifest line_id matches"
    fi

    [[ -n "$line_type" ]] && emit_check "line_type_present" "pass" "line_type=$line_type" || emit_check "line_type_present" "fail" "line_type is required"
    [[ -n "$access_mode" ]] && emit_check "access_mode_present" "pass" "access_mode=$access_mode" || emit_check "access_mode_present" "fail" "access_mode is required"

    if [[ -z "$project_path" ]]; then
        emit_check "project_path" "fail" "project_path is required"
    elif [[ -n "$vps_hostname" ]]; then
        emit_check "project_path" "warn" "remote line (host=$vps_hostname) -- local path existence not checked in this milestone"
    elif [[ -d "$project_path" ]]; then
        emit_check "project_path" "pass" "$project_path exists"
    else
        emit_check "project_path" "fail" "$project_path does not exist"
    fi

    if [[ -z "$worker_account" ]]; then
        emit_check "worker_account" "fail" "worker_account is required"
    elif [[ -z "$vps_hostname" && -d "$project_path" ]]; then
        local owner
        owner=$(stat -c '%U' "$project_path" 2>/dev/null || echo "")
        if [[ "$owner" == "$worker_account" ]]; then
            emit_check "worker_account" "pass" "project_path is owned by $worker_account"
        else
            emit_check "worker_account" "warn" "project_path is owned by '${owner:-unknown}', not declared worker_account '$worker_account'"
        fi
    else
        emit_check "worker_account" "pass" "worker_account=$worker_account"
    fi

    if [[ -z "$report_source_path" ]]; then
        emit_check "report_source_path" "fail" "report_source_path is required"
    else
        emit_check "report_source_path" "pass" "report_source_path=$report_source_path"
    fi

    if [[ -n "$vps_hostname" ]]; then
        local ssh_target="$vps_hostname"
        [[ -n "$ssh_user" ]] && ssh_target="$ssh_user@$vps_hostname"
        if ssh -o BatchMode=yes -o ConnectTimeout=5 -o StrictHostKeyChecking=accept-new "$ssh_target" true >/dev/null 2>&1; then
            emit_check "ssh_reachable" "pass" "$ssh_target reachable"
        else
            emit_check "ssh_reachable" "warn" "$ssh_target not reachable via SSH (non-fatal -- ingestion for remote lines is not yet automated in this milestone)"
        fi
    fi

    if [[ -n "$vps_hostname" ]]; then
        : # git checks require a local clone; skipped for remote lines in this milestone
    elif [[ -d "$project_path/.git" ]]; then
        local actual_remote actual_branch
        actual_remote=$(git -C "$project_path" remote get-url origin 2>/dev/null || true)
        actual_branch=$(git -C "$project_path" branch --show-current 2>/dev/null || true)
        if [[ -n "$git_remote" && -n "$actual_remote" && "$git_remote" != "$actual_remote" ]]; then
            emit_check "git_remote" "warn" "manifest git_remote '$git_remote' differs from actual '$actual_remote'"
        else
            emit_check "git_remote" "pass" "git remote checked"
        fi
        if [[ -n "$default_branch" && -n "$actual_branch" && "$default_branch" != "$actual_branch" ]]; then
            emit_check "default_branch" "warn" "manifest default_branch '$default_branch' differs from current branch '$actual_branch'"
        fi
    else
        emit_check "git_repo" "warn" "project_path is not a git repository -- not every line is repo-backed"
    fi

    local existing_status
    existing_status=$(sqlite3 "$DB" "SELECT status FROM lines WHERE line_id='$(printf '%s' "$line_id" | sed "s/'/''/g")';" 2>/dev/null || true)
    if [[ -z "$existing_status" ]]; then
        emit_check "identity" "pass" "line id is new"
    else
        emit_check "identity" "pass" "line already registered (status=$existing_status) -- apply will be idempotent"
    fi

    # A line can be selected for an agent role whose CLI isn't installed
    # (declaring intent before install is legitimate for a setup wizard),
    # but nothing else surfaces that the line has no runnable engine at
    # all -- check freshly here, not from stale wizard-time detection.
    # Skipped for remote lines: this VPS installing claude/codex tells you
    # nothing about a different host.
    if [[ -z "$vps_hostname" ]]; then
        local agent_roles_csv
        agent_roles_csv=$(jq -r '(.agent_roles // []) | join(",")' "$manifest_file")
        if [[ -z "$agent_roles_csv" ]]; then
            emit_check "agent_availability" "warn" "no agent role selected -- this line has no configured engineer yet"
        else
            local role not_runnable=()
            for role in ${(s:,:)agent_roles_csv}; do
                case "$role" in
                    claude-*) command -v claude >/dev/null 2>&1 || not_runnable+=("$role"); ;;
                    codex-*) command -v codex >/dev/null 2>&1 || not_runnable+=("$role"); ;;
                esac
            done
            if (( ${#not_runnable[@]} > 0 )); then
                emit_check "agent_availability" "warn" "selected role(s) not runnable yet, tool not installed: ${(j:, :)not_runnable}"
            else
                emit_check "agent_availability" "pass" "all selected agent role(s) have their tool installed"
            fi
        fi
    fi
}

cmd_validate() {
    local results checks_json failed_count
    results=$(run_checks "$LINE_ID" "$MANIFEST_FILE")
    checks_json="[$(printf '%s' "$results" | paste -sd, -)]"
    failed_count=$(printf '%s' "$checks_json" | jq '[.[] | select(.status=="fail")] | length')
    printf '{"ok":%s,"line_id":%s,"checks":%s}\n' \
        "$([[ "$failed_count" -eq 0 ]] && echo true || echo false)" \
        "$(json_escape "$LINE_ID")" \
        "$checks_json"
    [[ "$failed_count" -eq 0 ]]
}

cmd_plan() {
    local validate_output ok existing
    validate_output=$(cmd_validate) || true
    ok=$(printf '%s' "$validate_output" | jq -r '.ok')
    existing=$(sqlite3 -json "$DB" "SELECT * FROM lines WHERE line_id='$(printf '%s' "$LINE_ID" | sed "s/'/''/g")';" 2>/dev/null || true)
    local action
    if [[ -z "$existing" || "$existing" == "[]" ]]; then action="create"; else action="update"; fi
    printf '{"validate":%s,"action":"%s","would_write":["%s","lines row","line_connections row"],"note":"dry-run only -- apply performs no writes until this plan step passes validate"}\n' \
        "$validate_output" "$action" "$MANIFEST_PATH"
    [[ "$ok" == "true" ]]
}

cmd_apply() {
    mkdir -p "$LINES_DIR/$LINE_ID"
    local validate_output ok
    validate_output=$(cmd_validate) || true
    ok=$(printf '%s' "$validate_output" | jq -r '.ok')
    if [[ "$ok" != "true" ]]; then
        printf '{"ok":false,"phase":"validate","validate":%s}\n' "$validate_output"
        return 1
    fi

    local backup="$DB.pre-apply-$LINE_ID-$(date +%Y%m%d%H%M%S).bak"
    cp "$DB" "$backup"

    if [[ "$MANIFEST_FILE" != "$MANIFEST_PATH" ]]; then
        jq --arg mp "$MANIFEST_PATH" '.manifest_path = $mp' "$MANIFEST_FILE" > "$MANIFEST_PATH.tmp"
        mv "$MANIFEST_PATH.tmp" "$MANIFEST_PATH"
    elif ! jq -e '.manifest_path' "$MANIFEST_PATH" >/dev/null 2>&1 || [[ "$(jq -r '.manifest_path' "$MANIFEST_PATH")" != "$MANIFEST_PATH" ]]; then
        jq --arg mp "$MANIFEST_PATH" '.manifest_path = $mp' "$MANIFEST_PATH" > "$MANIFEST_PATH.tmp"
        mv "$MANIFEST_PATH.tmp" "$MANIFEST_PATH"
    fi

    "$STATE" lines-upsert "$MANIFEST_PATH" >/dev/null

    local vps_hostname
    vps_hostname=$(jq -r '.vps_hostname // empty' "$MANIFEST_PATH")
    local ingestion_ready=false
    if [[ -z "$vps_hostname" ]]; then
        "$STATE" lines-connections-set "$LINE_ID" ingestion_enabled 1 >/dev/null

        local report_source_path project_path
        report_source_path=$(jq -r '.report_source_path' "$MANIFEST_PATH")
        project_path=$(jq -r '.project_path' "$MANIFEST_PATH")
        mkdir -p "$report_source_path"

        local run_id="$LINE_ID-onboard-$(date +%s)-$$"
        {
            echo "Onboarding self-test report for $LINE_ID"
            echo "RUN_ID=$run_id"
            echo "STATE=COMPLETE"
            echo "  Project:   $project_path"
        } > "$report_source_path/current.tmp"
        mv "$report_source_path/current.tmp" "$report_source_path/latest.txt"
        {
            echo "STATE=COMPLETE"
            echo "RUN_ID=$run_id"
            echo "SIGNATURE=$SIGNATURE"
        } > "$report_source_path/status"

        local waited=0 found
        while (( waited < 12 )); do
            found=$(sqlite3 "$DB" "SELECT count(*) FROM reports WHERE run_id='$run_id' AND line_id='$(printf '%s' "$LINE_ID" | sed "s/'/''/g")';" 2>/dev/null || echo 0)
            if [[ "$found" != "0" ]]; then ingestion_ready=true; break; fi
            sleep 1
            waited=$((waited + 1))
        done
    fi

    if [[ "$ingestion_ready" == "true" || -n "$vps_hostname" ]]; then
        "$STATE" lines-set-status "$LINE_ID" active >/dev/null
        printf '{"ok":true,"line_id":%s,"status":"active","ingestion_test":%s,"manifest":%s,"backup":%s}\n' \
            "$(json_escape "$LINE_ID")" "$([[ "$ingestion_ready" == "true" ]] && echo '"passed"' || echo '"skipped-remote-line"')" \
            "$(json_escape "$MANIFEST_PATH")" "$(json_escape "$backup")"
        return 0
    else
        printf '{"ok":false,"phase":"ingestion_test","line_id":%s,"detail":"synthetic report was not ingested within 12s -- check aboardable-engineering-console-report-stream.service","backup":%s}\n' \
            "$(json_escape "$LINE_ID")" "$(json_escape "$backup")"
        return 1
    fi
}

cmd_verify() {
    local row
    row=$(sqlite3 -json "$DB" "SELECT l.line_id,l.status,l.report_source_path,c.ingestion_enabled,c.last_ingested_at,c.last_run_id
        FROM lines l LEFT JOIN line_connections c ON c.line_id=l.line_id WHERE l.line_id='$(printf '%s' "$LINE_ID" | sed "s/'/''/g")';")
    if [[ "$row" == "[]" || -z "$row" ]]; then
        printf '{"ok":false,"detail":"line not registered"}\n'
        return 1
    fi
    printf '%s\n' "$row" | jq '.[0]'
}

cmd_rollback() {
    local current_status
    current_status=$(sqlite3 "$DB" "SELECT status FROM lines WHERE line_id='$(printf '%s' "$LINE_ID" | sed "s/'/''/g")';" 2>/dev/null || true)
    if [[ -z "$current_status" ]]; then
        printf '{"ok":true,"detail":"nothing to roll back -- line was never registered"}\n'
        return 0
    fi
    if [[ "$current_status" == "active" ]]; then
        printf '{"ok":false,"detail":"refusing to roll back an active line -- use retire (lines-set-status retired) instead"}\n'
        return 1
    fi
    sqlite3 "$DB" "
        BEGIN IMMEDIATE;
        DELETE FROM line_connections WHERE line_id='$(printf '%s' "$LINE_ID" | sed "s/'/''/g")';
        DELETE FROM lines WHERE line_id='$(printf '%s' "$LINE_ID" | sed "s/'/''/g")';
        INSERT INTO events(kind, line_id, detail) VALUES('line_rolled_back', '$(printf '%s' "$LINE_ID" | sed "s/'/''/g")', 'onboarding rolled back, status was $current_status');
        COMMIT;
    "
    rm -rf "$LINES_DIR/$LINE_ID"
    printf '{"ok":true,"detail":"rolled back","previous_status":%s}\n' "$(json_escape "$current_status")"
}

case "$SUBCOMMAND" in
    validate) cmd_validate ;;
    plan) cmd_plan ;;
    apply) cmd_apply ;;
    verify) cmd_verify ;;
    rollback) cmd_rollback ;;
    *) usage ;;
esac
