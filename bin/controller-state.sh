#!/bin/zsh

set -euo pipefail

ROOT="${ABOARDABLE_CONTROLLER_ROOT:-$HOME/.aboardable-tools/v2}"
DB="$ROOT/controller.db"
ARCHIVE="$ROOT/archive"
RUNTIME="$ROOT/runtime"
LOGS="$ROOT/logs"

mkdir -p "$ARCHIVE" "$RUNTIME" "$LOGS"

sql_quote() {
    printf '%s' "$1" | sed "s/'/''/g"
}

init_db() {
    sqlite3 "$DB" >/dev/null <<'SQL'
PRAGMA journal_mode=WAL;
PRAGMA busy_timeout=5000;
CREATE TABLE IF NOT EXISTS reports (
    run_id TEXT PRIMARY KEY,
    signature TEXT NOT NULL,
    source_path TEXT NOT NULL,
    archived_path TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN (
        'queued', 'reviewing', 'integrated', 'needs_sean', 'manual', 'blocked', 'failed'
    )),
    detected_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    started_at TEXT,
    finished_at TEXT,
    attempts INTEGER NOT NULL DEFAULT 0,
    summary TEXT,
    error TEXT
);
CREATE TABLE IF NOT EXISTS work_items (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    lane TEXT NOT NULL CHECK (lane IN ('ready', 'needs_sean', 'manual', 'deferred')),
    title TEXT NOT NULL,
    detail TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open', 'active', 'done', 'cancelled')),
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    UNIQUE(lane, title, status)
);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    kind TEXT NOT NULL,
    run_id TEXT,
    detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS ai_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('review','console')),
    subject TEXT NOT NULL,
    input_digest TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('active','complete','failed','stopped')),
    attempts INTEGER NOT NULL DEFAULT 0,
    input_bytes INTEGER NOT NULL DEFAULT 0,
    output_bytes INTEGER NOT NULL DEFAULT 0,
    started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    finished_at TEXT,
    stop_reason TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS claude_dispatches (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    dispatch_key TEXT NOT NULL UNIQUE,
    kind TEXT NOT NULL CHECK (kind IN ('work','correction')),
    work_item_id INTEGER,
    parent_run_id TEXT,
    instruction_digest TEXT NOT NULL UNIQUE,
    state TEXT NOT NULL CHECK (state IN ('delivered','stopped','failed')),
    detail TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE TABLE IF NOT EXISTS lines (
    line_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL,
    product_name TEXT NOT NULL,
    purpose TEXT NOT NULL DEFAULT '',
    line_type TEXT NOT NULL CHECK (line_type IN (
        'product', 'native', 'review', 'ops-tool', 'experiment', 'other'
    )),
    phase TEXT,
    status TEXT NOT NULL DEFAULT 'onboarding' CHECK (status IN (
        'onboarding', 'active', 'paused', 'retired', 'archived'
    )),
    access_mode TEXT NOT NULL CHECK (access_mode IN (
        'read-only', 'active-development', 'worker-only', 'reviewer-only'
    )),
    agent_roles TEXT NOT NULL DEFAULT '',
    claude_chat_visible INTEGER NOT NULL DEFAULT 0,
    vps_hostname TEXT,
    vps_ip TEXT,
    ssh_user TEXT,
    ssh_port INTEGER NOT NULL DEFAULT 22,
    project_path TEXT NOT NULL,
    git_remote TEXT,
    default_branch TEXT,
    branch_strategy TEXT,
    worker_account TEXT NOT NULL,
    report_source_path TEXT NOT NULL,
    report_format_version TEXT NOT NULL DEFAULT 'v1',
    manifest_path TEXT NOT NULL,
    manifest_version INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
    retired_at TEXT
);
CREATE TABLE IF NOT EXISTS line_connections (
    line_id TEXT PRIMARY KEY REFERENCES lines(line_id),
    claude_installed INTEGER,
    claude_version TEXT,
    claude_checked_at TEXT,
    codex_installed INTEGER,
    codex_version TEXT,
    codex_checked_at TEXT,
    tmux_session_name TEXT,
    tmux_last_seen_at TEXT,
    tmux_installed INTEGER,
    tmux_version TEXT,
    ingestion_enabled INTEGER NOT NULL DEFAULT 0,
    last_ingested_at TEXT,
    last_run_id TEXT,
    ssh_key_configured INTEGER NOT NULL DEFAULT 0,
    ssh_key_fingerprint TEXT,
    ssh_key_configured_at TEXT,
    last_connectivity_test_at TEXT,
    last_connectivity_result TEXT,
    current_health_state TEXT NOT NULL DEFAULT 'unknown',
    updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
);
CREATE INDEX IF NOT EXISTS reports_state_idx ON reports(state, detected_at);
CREATE INDEX IF NOT EXISTS work_lane_idx ON work_items(lane, status, created_at);
CREATE INDEX IF NOT EXISTS ai_runs_state_idx ON ai_runs(state, started_at);
CREATE INDEX IF NOT EXISTS lines_status_idx ON lines(status);
SQL

    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('reports') WHERE name='report_digest';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE reports ADD COLUMN report_digest TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('reports') WHERE name='candidate_commit';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE reports ADD COLUMN candidate_commit TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('reports') WHERE name='line_id';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE reports ADD COLUMN line_id TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('events') WHERE name='line_id';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE events ADD COLUMN line_id TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='tmux_installed';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN tmux_installed INTEGER;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='tmux_version';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN tmux_version TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='dispatch_mode';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN dispatch_mode TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='dispatch_host';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN dispatch_host TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='dispatch_user';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN dispatch_user TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='dispatch_port';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN dispatch_port INTEGER;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='dispatch_key_path';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN dispatch_key_path TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='dispatch_report_key_path';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN dispatch_report_key_path TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='dispatch_tmux_session';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN dispatch_tmux_session TEXT;"
    fi
    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM pragma_table_info('line_connections') WHERE name='last_report_read_at';")" == "0" ]]; then
        sqlite3 "$DB" "ALTER TABLE line_connections ADD COLUMN last_report_read_at TEXT;"
    fi
    sqlite3 "$DB" "UPDATE reports SET line_id='aboardable-product' WHERE line_id IS NULL;"
    local reports_line_idx_exists
    reports_line_idx_exists="$(sqlite3 "$DB" "SELECT count(*) FROM sqlite_master WHERE type='index' AND name='reports_line_idx';")"
    if [[ "$reports_line_idx_exists" == "0" ]]; then
        sqlite3 "$DB" "CREATE INDEX reports_line_idx ON reports(line_id, detected_at);"
    fi

    seed_default_lines
}

seed_default_lines() {
    local branch remote
    branch=$(git -C /home/controller/projects/aboardable branch --show-current 2>/dev/null || true)
    remote=$(git -C /home/controller/projects/aboardable remote get-url origin 2>/dev/null || true)
    sqlite3 "$DB" "INSERT OR IGNORE INTO lines(
        line_id, display_name, product_name, purpose, line_type, phase, status,
        access_mode, agent_roles, claude_chat_visible, project_path, git_remote,
        default_branch, branch_strategy, worker_account, report_source_path,
        manifest_path
    ) VALUES(
        'aboardable-product', 'Aboardable Product', 'Aboardable',
        'The live Product engineering line -- Claude Code worker producing signed completion reports reviewed via the Engineering Console.',
        'product', NULL, 'active',
        'active-development', 'claude-worker', 0,
        '$(sql_quote "/home/controller/projects/aboardable")',
        '$(sql_quote "$remote")', '$(sql_quote "$branch")', 'trunk', 'controller',
        '$(sql_quote "/home/controller/.claude/reports")',
        '$(sql_quote "$ROOT/lines/aboardable-product/manifest.json")'
    );"
    sqlite3 "$DB" "INSERT OR IGNORE INTO line_connections(line_id, ingestion_enabled, current_health_state)
        VALUES('aboardable-product', 1, 'unknown');"
    sqlite3 "$DB" "UPDATE line_connections SET
            dispatch_mode='ssh-relay',
            dispatch_host='139.99.135.10',
            dispatch_user='ubuntu',
            dispatch_key_path='/var/lib/aboardable-mcp-poc/keys/worker_ed25519',
            dispatch_report_key_path='/var/lib/aboardable-mcp-poc/keys/report_read_ed25519'
        WHERE line_id='aboardable-product' AND dispatch_mode IS NULL;"
}

valid_run_id() {
    [[ "$1" =~ '^[A-Za-z0-9._-]+$' ]]
}

ingest_report() {
    local status_file="$1"
    local report_file="$2"
    local line_id="${3:-aboardable-product}"
    local expected_signature="ABRD7F9C2E41A6B88D3F05C7A91E4B6D2READY"
    local state run_id signature archive_path tmp_archive report_digest candidate_commit duplicate

    state=$(awk -F= '$1 == "STATE" { print $2; exit }' "$status_file")
    run_id=$(awk -F= '$1 == "RUN_ID" { print $2; exit }' "$status_file")
    signature=$(awk -F= '$1 == "SIGNATURE" { print $2; exit }' "$status_file")

    [[ "$state" == "COMPLETE" ]] || return 0
    [[ "$signature" == "$expected_signature" ]] || {
        sqlite3 "$DB" "INSERT INTO events(kind, line_id, detail) VALUES('rejected_report', '$(sql_quote "$line_id")', 'invalid signature');"
        return 65
    }
    valid_run_id "$run_id" || {
        sqlite3 "$DB" "INSERT INTO events(kind, line_id, detail) VALUES('rejected_report', '$(sql_quote "$line_id")', 'invalid run id');"
        return 65
    }
    grep -Fq "RUN_ID=$run_id" "$report_file" || {
        sqlite3 "$DB" "INSERT INTO events(kind, run_id, line_id, detail) VALUES('rejected_report', '$(sql_quote "$run_id")', '$(sql_quote "$line_id")', 'status/report run id mismatch');"
        return 65
    }

    report_digest=$(sha256sum "$report_file" | awk '{print $1}')
    candidate_commit=$(grep -Eio '(commit|commit_sha|commit hash)[ :=`]*[0-9a-f]{40}' "$report_file" | grep -Eo '[0-9a-f]{40}' | head -n 1 || true)

    if [[ "$(sqlite3 "$DB" "SELECT count(*) FROM reports WHERE run_id='$(sql_quote "$run_id")';")" != "0" ]]; then
        return 0
    fi

    duplicate=$(sqlite3 "$DB" "SELECT run_id FROM reports WHERE report_digest='$(sql_quote "$report_digest")' LIMIT 1;")
    if [[ -n "$duplicate" ]]; then
        sqlite3 "$DB" "INSERT INTO events(kind,run_id,line_id,detail) VALUES('redundant_report_stopped','$(sql_quote "$run_id")','$(sql_quote "$line_id")','same report content already recorded as $(sql_quote "$duplicate")');"
        return 0
    fi
    if [[ -n "$candidate_commit" ]]; then
        duplicate=$(sqlite3 "$DB" "SELECT run_id FROM reports WHERE candidate_commit='$(sql_quote "$candidate_commit")' AND state IN ('queued','reviewing','integrated') LIMIT 1;")
        if [[ -n "$duplicate" ]]; then
            sqlite3 "$DB" "INSERT INTO events(kind,run_id,line_id,detail) VALUES('redundant_report_stopped','$(sql_quote "$run_id")','$(sql_quote "$line_id")','candidate commit already handled by $(sql_quote "$duplicate")');"
            return 0
        fi
    fi

    archive_path="$ARCHIVE/$run_id.txt"
    tmp_archive="$archive_path.tmp.$$"
    cp "$report_file" "$tmp_archive"
    mv "$tmp_archive" "$archive_path"

    sqlite3 "$DB" <<SQL
BEGIN IMMEDIATE;
INSERT OR IGNORE INTO reports(run_id, signature, source_path, archived_path, state, report_digest, candidate_commit, line_id)
VALUES('$(sql_quote "$run_id")', '$(sql_quote "$signature")', '$(sql_quote "$report_file")', '$(sql_quote "$archive_path")', 'queued', '$(sql_quote "$report_digest")', '$(sql_quote "$candidate_commit")', '$(sql_quote "$line_id")');
INSERT INTO events(kind, run_id, line_id, detail)
SELECT 'report_queued', '$(sql_quote "$run_id")', '$(sql_quote "$line_id")', 'signed Claude completion report archived'
WHERE changes() > 0;
UPDATE line_connections SET last_ingested_at=CURRENT_TIMESTAMP, last_run_id='$(sql_quote "$run_id")', updated_at=CURRENT_TIMESTAMP
WHERE line_id='$(sql_quote "$line_id")';
COMMIT;
SQL
    printf '%s\n' "$run_id"
}

claim_next() {
    local run_id
    run_id=$(sqlite3 "$DB" "SELECT run_id FROM reports WHERE state='queued' ORDER BY detected_at LIMIT 1;")
    [[ -n "$run_id" ]] || return 0
    sqlite3 "$DB" <<SQL
BEGIN IMMEDIATE;
UPDATE reports
SET state='reviewing', started_at=CURRENT_TIMESTAMP, attempts=attempts+1, error=NULL
WHERE run_id='$(sql_quote "$run_id")' AND state='queued';
INSERT INTO events(kind, run_id, detail)
SELECT 'review_started', '$(sql_quote "$run_id")', 'controller worker claimed report'
WHERE changes() > 0;
COMMIT;
SQL
    printf '%s\n' "$run_id"
}

finish_report() {
    local run_id="$1"
    local state="$2"
    local summary="${3:-}"
    local error="${4:-}"
    [[ "$state" =~ '^(integrated|needs_sean|manual|blocked|failed)$' ]] || return 64
    sqlite3 "$DB" <<SQL
BEGIN IMMEDIATE;
UPDATE reports SET state='$(sql_quote "$state")', finished_at=CURRENT_TIMESTAMP,
    summary='$(sql_quote "$summary")', error='$(sql_quote "$error")'
WHERE run_id='$(sql_quote "$run_id")';
INSERT INTO events(kind, run_id, detail)
VALUES('review_finished', '$(sql_quote "$run_id")', '$(sql_quote "$state: $summary")');
COMMIT;
SQL
}

requeue_stale() {
    sqlite3 "$DB" <<'SQL'
BEGIN IMMEDIATE;
UPDATE reports
SET state='queued', started_at=NULL, error='recovered stale reviewing state'
WHERE state='reviewing' AND started_at < datetime('now', '-2 hours');
INSERT INTO events(kind, detail)
SELECT 'stale_reviews_requeued', printf('%d stale review(s) recovered', changes())
WHERE changes() > 0;
COMMIT;
SQL
}

retry_report() {
    local run_id="$1"
    valid_run_id "$run_id" || return 64
    local allowed
    allowed=$(sqlite3 "$DB" "SELECT count(*) FROM reports WHERE run_id='$(sql_quote "$run_id")' AND state IN ('failed','blocked') AND attempts < 3 AND (error LIKE 'Controller execution failed%' OR error LIKE '%capacity%');")
    if [[ "$allowed" == "0" && "${ABOARDABLE_FORCE_RETRY:-0}" != "1" ]]; then
        sqlite3 "$DB" "INSERT INTO events(kind,run_id,detail) VALUES('redundant_retry_stopped','$(sql_quote "$run_id")','unchanged completed review may not consume another AI run');"
        echo "Retry stopped: unchanged review input is not an infrastructure retry. Submit a new report or set ABOARDABLE_FORCE_RETRY=1 with explicit operator justification." >&2
        return 75
    fi
    sqlite3 "$DB" <<SQL
BEGIN IMMEDIATE;
UPDATE reports
SET state='queued', started_at=NULL, finished_at=NULL, summary=NULL, error=NULL
WHERE run_id='$(sql_quote "$run_id")' AND state IN ('failed','blocked');
INSERT INTO events(kind, run_id, detail)
SELECT 'report_retried', '$(sql_quote "$run_id")', 'operator requested retry'
WHERE changes() > 0;
COMMIT;
SQL
}

show_status() {
    printf 'Aboardable Engineering Controller v2\n\n'
    sqlite3 -header -column "$DB" <<'SQL'
SELECT state, count(*) AS reports FROM reports GROUP BY state ORDER BY state;
SELECT lane, count(*) AS open_items FROM work_items WHERE status IN ('open','active') GROUP BY lane ORDER BY lane;
SELECT run_id, state, detected_at, attempts, coalesce(summary, '') AS summary
FROM reports ORDER BY detected_at DESC LIMIT 8;
SELECT kind, state, count(*) AS runs, sum(input_bytes) AS input_bytes, sum(output_bytes) AS output_bytes
FROM ai_runs GROUP BY kind,state ORDER BY kind,state;
SQL
}

show_decisions() {
    sqlite3 -header -column "$DB" "SELECT id, title, detail, created_at FROM work_items WHERE lane='needs_sean' AND status='open' ORDER BY created_at;"
}

add_work() {
    local lane="$1"
    local title="$2"
    local detail="${3:-}"
    [[ "$lane" =~ '^(ready|needs_sean|manual|deferred)$' ]] || return 64
    sqlite3 "$DB" "INSERT OR IGNORE INTO work_items(lane,title,detail) VALUES('$(sql_quote "$lane")','$(sql_quote "$title")','$(sql_quote "$detail")');"
}

close_work() {
    local id="$1"
    [[ "$id" =~ '^[0-9]+$' ]] || return 64
    sqlite3 "$DB" <<SQL
BEGIN IMMEDIATE;
UPDATE work_items SET status='done', updated_at=CURRENT_TIMESTAMP
WHERE id=$id AND status IN ('open','active');
INSERT INTO events(kind, detail)
SELECT 'work_item_closed', 'work item $id completed'
WHERE changes() > 0;
COMMIT;
SQL
}

valid_line_id() {
    [[ "$1" =~ '^[a-z][a-z0-9-]{2,39}$' ]]
}

lines_list() {
    sqlite3 -json "$DB" "
        SELECT l.line_id, l.display_name, l.product_name, l.line_type, l.phase, l.status,
               l.access_mode, l.agent_roles, l.claude_chat_visible, l.project_path,
               l.vps_hostname, l.updated_at,
               c.ingestion_enabled, c.last_ingested_at, c.last_run_id, c.current_health_state
        FROM lines l LEFT JOIN line_connections c ON c.line_id = l.line_id
        ORDER BY (l.status != 'active'), l.display_name;"
}

lines_get() {
    local line_id="$1"
    valid_line_id "$line_id" || return 64
    sqlite3 -json "$DB" "
        SELECT l.*, c.claude_installed, c.claude_version, c.claude_checked_at,
               c.codex_installed, c.codex_version, c.codex_checked_at,
               c.tmux_session_name, c.tmux_last_seen_at, c.ingestion_enabled,
               c.last_ingested_at, c.last_run_id, c.ssh_key_configured,
               c.ssh_key_fingerprint, c.ssh_key_configured_at,
               c.last_connectivity_test_at, c.last_connectivity_result,
               c.current_health_state
        FROM lines l LEFT JOIN line_connections c ON c.line_id = l.line_id
        WHERE l.line_id = '$(sql_quote "$line_id")';"
}

# lines_upsert MANIFEST_JSON_PATH -- manifest fields drive the lines row;
# created_at is preserved across re-onboarding, everything else refreshes.
lines_upsert() {
    local manifest_file="$1"
    command -v jq >/dev/null 2>&1 || { echo "jq is required" >&2; return 69; }
    local line_id display_name product_name purpose line_type phase line_status
    local access_mode agent_roles claude_chat_visible vps_hostname vps_ip
    local ssh_user ssh_port project_path git_remote default_branch branch_strategy
    local worker_account report_source_path report_format_version manifest_path manifest_version

    line_id=$(jq -r '.line_id // empty' "$manifest_file")
    valid_line_id "$line_id" || { echo "invalid or missing line_id in manifest" >&2; return 64; }
    display_name=$(jq -r '.display_name // .line_id' "$manifest_file")
    product_name=$(jq -r '.product_name // ""' "$manifest_file")
    purpose=$(jq -r '.purpose // ""' "$manifest_file")
    line_type=$(jq -r '.line_type // "other"' "$manifest_file")
    phase=$(jq -r '.phase // empty' "$manifest_file")
    line_status=$(jq -r '.status // "onboarding"' "$manifest_file")
    access_mode=$(jq -r '.access_mode // "worker-only"' "$manifest_file")
    agent_roles=$(jq -r '(.agent_roles // []) | join(",")' "$manifest_file")
    claude_chat_visible=$(jq -r 'if (.claude_chat_visible // false) then 1 else 0 end' "$manifest_file")
    vps_hostname=$(jq -r '.vps_hostname // empty' "$manifest_file")
    vps_ip=$(jq -r '.vps_ip // empty' "$manifest_file")
    ssh_user=$(jq -r '.ssh_user // empty' "$manifest_file")
    ssh_port=$(jq -r '.ssh_port // 22' "$manifest_file")
    project_path=$(jq -r '.project_path // empty' "$manifest_file")
    git_remote=$(jq -r '.git_remote // empty' "$manifest_file")
    default_branch=$(jq -r '.default_branch // empty' "$manifest_file")
    branch_strategy=$(jq -r '.branch_strategy // empty' "$manifest_file")
    worker_account=$(jq -r '.worker_account // empty' "$manifest_file")
    report_source_path=$(jq -r '.report_source_path // empty' "$manifest_file")
    report_format_version=$(jq -r '.report_format_version // "v1"' "$manifest_file")
    manifest_path=$(jq -r '.manifest_path // empty' "$manifest_file")
    manifest_version=$(jq -r '.manifest_version // 1' "$manifest_file")

    [[ -n "$project_path" && -n "$worker_account" && -n "$report_source_path" ]] || {
        echo "manifest missing required field(s): project_path, worker_account, report_source_path" >&2
        return 64
    }

    sqlite3 "$DB" "
        INSERT INTO lines(line_id, display_name, product_name, purpose, line_type, phase, status,
            access_mode, agent_roles, claude_chat_visible, vps_hostname, vps_ip, ssh_user, ssh_port,
            project_path, git_remote, default_branch, branch_strategy, worker_account,
            report_source_path, report_format_version, manifest_path, manifest_version)
        VALUES('$(sql_quote "$line_id")', '$(sql_quote "$display_name")', '$(sql_quote "$product_name")',
            '$(sql_quote "$purpose")', '$(sql_quote "$line_type")', '$(sql_quote "$phase")',
            '$(sql_quote "$line_status")', '$(sql_quote "$access_mode")', '$(sql_quote "$agent_roles")',
            $claude_chat_visible, '$(sql_quote "$vps_hostname")', '$(sql_quote "$vps_ip")',
            '$(sql_quote "$ssh_user")', $ssh_port, '$(sql_quote "$project_path")',
            '$(sql_quote "$git_remote")', '$(sql_quote "$default_branch")', '$(sql_quote "$branch_strategy")',
            '$(sql_quote "$worker_account")', '$(sql_quote "$report_source_path")',
            '$(sql_quote "$report_format_version")', '$(sql_quote "$manifest_path")', $manifest_version)
        ON CONFLICT(line_id) DO UPDATE SET
            display_name=excluded.display_name, product_name=excluded.product_name,
            purpose=excluded.purpose, line_type=excluded.line_type, phase=excluded.phase,
            access_mode=excluded.access_mode, agent_roles=excluded.agent_roles,
            claude_chat_visible=excluded.claude_chat_visible, vps_hostname=excluded.vps_hostname,
            vps_ip=excluded.vps_ip, ssh_user=excluded.ssh_user, ssh_port=excluded.ssh_port,
            project_path=excluded.project_path, git_remote=excluded.git_remote,
            default_branch=excluded.default_branch, branch_strategy=excluded.branch_strategy,
            worker_account=excluded.worker_account, report_source_path=excluded.report_source_path,
            report_format_version=excluded.report_format_version, manifest_path=excluded.manifest_path,
            manifest_version=excluded.manifest_version, updated_at=CURRENT_TIMESTAMP;
        INSERT OR IGNORE INTO line_connections(line_id) VALUES('$(sql_quote "$line_id")');
        INSERT INTO events(kind, line_id, detail) VALUES('line_manifest_applied', '$(sql_quote "$line_id")', 'manifest written/refreshed');
    "
    printf '%s\n' "$line_id"
}

lines_set_status() {
    local line_id="$1" line_status="$2"
    valid_line_id "$line_id" || return 64
    [[ "$line_status" =~ '^(onboarding|active|paused|retired|archived)$' ]] || return 64
    sqlite3 "$DB" "
        UPDATE lines SET status='$(sql_quote "$line_status")', updated_at=CURRENT_TIMESTAMP,
            retired_at=CASE WHEN '$(sql_quote "$line_status")'='retired' THEN CURRENT_TIMESTAMP ELSE retired_at END
        WHERE line_id='$(sql_quote "$line_id")';
        INSERT INTO events(kind, line_id, detail)
        SELECT 'line_status_changed', '$(sql_quote "$line_id")', 'status set to $(sql_quote "$line_status")'
        WHERE changes() > 0;
    "
}

lines_connections_set() {
    local line_id="$1" field="$2" value="$3"
    valid_line_id "$line_id" || return 64
    [[ "$field" =~ '^(ingestion_enabled|current_health_state|last_connectivity_test_at|last_connectivity_result|claude_installed|claude_version|claude_checked_at|codex_installed|codex_version|codex_checked_at|tmux_session_name|tmux_last_seen_at|ssh_key_configured|ssh_key_fingerprint|ssh_key_configured_at|dispatch_mode|dispatch_host|dispatch_user|dispatch_port|dispatch_key_path|dispatch_report_key_path|dispatch_tmux_session|last_report_read_at)$' ]] || {
        echo "unknown line_connections field: $field" >&2
        return 64
    }
    sqlite3 "$DB" "UPDATE line_connections SET $field='$(sql_quote "$value")', updated_at=CURRENT_TIMESTAMP WHERE line_id='$(sql_quote "$line_id")';"
}

init_db

case "${1:-status}" in
    init) ;;
    ingest) ingest_report "$2" "$3" "${4:-aboardable-product}" ;;
    claim-next) claim_next ;;
    finish) finish_report "$2" "$3" "${4:-}" "${5:-}" ;;
    requeue-stale) requeue_stale ;;
    retry) retry_report "$2" ;;
    status) show_status ;;
    decisions) show_decisions ;;
    add-work) add_work "$2" "$3" "${4:-}" ;;
    close-work) close_work "$2" ;;
    lines-list) lines_list ;;
    lines-get) lines_get "$2" ;;
    lines-upsert) lines_upsert "$2" ;;
    lines-set-status) lines_set_status "$2" "$3" ;;
    lines-connections-set) lines_connections_set "$2" "$3" "$4" ;;
    *) echo "Usage: $0 {init|ingest STATUS REPORT [LINE_ID]|claim-next|finish RUN_ID STATE [SUMMARY] [ERROR]|requeue-stale|retry RUN_ID|status|decisions|add-work LANE TITLE [DETAIL]|close-work ID|lines-list|lines-get LINE_ID|lines-upsert MANIFEST_JSON|lines-set-status LINE_ID STATUS|lines-connections-set LINE_ID FIELD VALUE}" >&2; exit 64 ;;
esac
