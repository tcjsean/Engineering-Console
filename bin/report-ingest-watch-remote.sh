#!/bin/zsh
# Aboardable Engineering Console -- REMOTE report ingestion watcher.
#
# The mirror image of report-ingest-watch.sh's local-file adapter: same
# registry-driven poll loop, same call into controller-state.sh ingest, but
# collecting the status/report pair over SSH for lines whose report source
# lives on a different Unix account (same VPS or a real remote host) rather
# than reading a local file directly. Runs as `engineering-console`, which
# already holds the SSH trust set up for discovery -- no new grant.
#
# Deliberately does NOT invoke controller-worker.sh or any dispatch/review
# logic, same restriction as the local watcher.
set -uo pipefail

ROOT="${ABOARDABLE_CONTROLLER_ROOT:-$HOME/.aboardable-tools/v2}"
STATE="$ROOT/controller-state.sh"
DB="$ROOT/controller.db"
LOG="$ROOT/logs/report-ingest-remote.log"

mkdir -p "$ROOT/logs"

rotate_log() {
    [[ -f "$LOG" ]] || return 0
    local size
    size=$(stat -c %s "$LOG" 2>/dev/null || echo 0)
    (( size < 1048576 )) && return 0
    rm -f "$LOG.1"
    mv "$LOG" "$LOG.1"
}

rotate_log
exec >>"$LOG" 2>&1
echo "$(date -u +%FT%TZ) remote report-ingest watcher started (ssh-poll, ingestion only, no dispatch)"

typeset -A last_digest

active_remote_lines() {
    sqlite3 -separator '|' "$DB" "
        SELECT l.line_id, l.report_source_path, l.project_path, l.vps_hostname, l.ssh_user, l.ssh_port
        FROM lines l JOIN line_connections c ON c.line_id = l.line_id
        WHERE l.status IN ('onboarding','active') AND c.ingestion_enabled = 1
          AND l.vps_hostname IS NOT NULL AND l.vps_hostname != '';
    " 2>/dev/null
}

while true; do
    while IFS='|' read -r line_id report_source_path project_path vps_hostname ssh_user ssh_port; do
        [[ -n "$line_id" ]] || continue
        [[ -n "$report_source_path" ]] || continue

        target="$vps_hostname"
        [[ -n "$ssh_user" ]] && target="$ssh_user@$vps_hostname"
        port_args=()
        [[ -n "$ssh_port" && "$ssh_port" != "22" ]] && port_args=(-p "$ssh_port")

        digest=$(ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new "${port_args[@]}" "$target" \
            "sha256sum '$report_source_path/status' 2>/dev/null" 2>/dev/null | awk '{print $1}')
        [[ -n "$digest" ]] || continue
        if [[ "$digest" == "${last_digest[$line_id]:-}" ]]; then
            continue
        fi
        last_digest[$line_id]="$digest"

        tmp_status=$(mktemp)
        tmp_report=$(mktemp)
        if ! ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new "${port_args[@]}" "$target" \
            "cat '$report_source_path/status'" >"$tmp_status" 2>/dev/null; then
            echo "$(date -u +%FT%TZ) [$line_id] failed to fetch status over ssh" >&2
            rm -f "$tmp_status" "$tmp_report"
            continue
        fi
        if ! ssh -o BatchMode=yes -o ConnectTimeout=6 -o StrictHostKeyChecking=accept-new "${port_args[@]}" "$target" \
            "cat '$report_source_path/latest.txt'" >"$tmp_report" 2>/dev/null; then
            echo "$(date -u +%FT%TZ) [$line_id] failed to fetch report body over ssh" >&2
            rm -f "$tmp_status" "$tmp_report"
            continue
        fi

        project=$(awk -F: '/^[[:space:]]*Project:/ {sub(/^[[:space:]]*/,"",$2); print $2; exit}' "$tmp_report")
        if [[ -n "$project_path" && -n "$project" && "$project" != "$project_path" ]]; then
            echo "$(date -u +%FT%TZ) [$line_id] ignored status change for unexpected project: $project" >&2
            rm -f "$tmp_status" "$tmp_report"
            continue
        fi

        run_id=$("$STATE" ingest "$tmp_status" "$tmp_report" "$line_id" || true)
        rm -f "$tmp_status" "$tmp_report"
        if [[ -n "$run_id" ]]; then
            echo "$(date -u +%FT%TZ) [$line_id] ingested $run_id (via ssh)"
        else
            echo "$(date -u +%FT%TZ) [$line_id] status change observed, no new run id (duplicate or rejected report)"
        fi
    done < <(active_remote_lines)
    sleep 5
done
