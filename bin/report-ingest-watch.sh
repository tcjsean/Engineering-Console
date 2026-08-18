#!/bin/zsh
# Aboardable Engineering Console -- worker report ingestion watcher.
#
# Rehomed from the retired aboardable-controller-stream.service, then
# generalized (Production Line Onboarding, first milestone) from a single
# hardcoded project to a registry-driven loop over the `lines` table in
# controller.db. Each active line with ingestion enabled gets its own
# local-file status/report poll, tracked independently. Still local-file
# only -- a remote (ssh-poll) adapter for lines on a different host is a
# later milestone, not this one.
#
# Deliberately does NOT invoke controller-worker.sh or any dispatch/review
# logic for any line: ingestion only, no autonomous controller authority.
set -euo pipefail

ROOT="${ABOARDABLE_CONTROLLER_ROOT:-$HOME/.aboardable-tools/v2}"
STATE="$ROOT/controller-state.sh"
DB="$ROOT/controller.db"
LOG="$ROOT/logs/report-ingest.log"

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
echo "$(date -u +%FT%TZ) report-ingest watcher started (registry-driven, ingestion only, no dispatch)"

typeset -A last_digest

active_lines() {
    sqlite3 -separator '|' "$DB" "
        SELECT l.line_id, l.report_source_path, l.project_path
        FROM lines l JOIN line_connections c ON c.line_id = l.line_id
        WHERE l.status IN ('onboarding', 'active') AND c.ingestion_enabled = 1
          AND (l.vps_hostname IS NULL OR l.vps_hostname = '');
    " 2>/dev/null
}

while true; do
    while IFS='|' read -r line_id report_source_path project_path; do
        [[ -n "$line_id" ]] || continue
        status_file="$report_source_path/status"
        report_file="$report_source_path/latest.txt"
        [[ -f "$status_file" ]] || continue

        digest=$(sha256sum "$status_file" 2>/dev/null | awk '{print $1}')
        [[ -n "$digest" ]] || continue
        if [[ "$digest" == "${last_digest[$line_id]:-}" ]]; then
            continue
        fi
        last_digest[$line_id]="$digest"

        [[ -f "$report_file" ]] || continue
        project=$(awk -F: '/^[[:space:]]*Project:/ {sub(/^[[:space:]]*/,"",$2); print $2; exit}' "$report_file")
        if [[ "$project" != "$project_path" ]]; then
            echo "$(date -u +%FT%TZ) [$line_id] ignored status change for unexpected project: ${project:-<none>}" >&2
            continue
        fi
        run_id=$("$STATE" ingest "$status_file" "$report_file" "$line_id" || true)
        if [[ -n "$run_id" ]]; then
            echo "$(date -u +%FT%TZ) [$line_id] ingested $run_id"
        else
            echo "$(date -u +%FT%TZ) [$line_id] status change observed, no new run id (duplicate or rejected report)"
        fi
    done < <(active_lines)
    sleep 2
done
