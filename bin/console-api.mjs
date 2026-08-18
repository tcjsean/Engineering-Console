#!/usr/bin/env node

import { createServer } from "node:http";
import { spawn, spawnSync } from "node:child_process";
import { createHash, timingSafeEqual } from "node:crypto";
import { chmodSync, existsSync, mkdirSync, readFileSync, unlinkSync, writeFileSync } from "node:fs";
import { join } from "node:path";

const controllerRoot = process.env.ABOARDABLE_CONTROLLER_ROOT || "/home/controller/.aboardable-tools/v2";
const toolsRoot = "/home/controller/.aboardable-tools";
const repo = "/home/controller/projects/aboardable";
const database = join(controllerRoot, "controller.db");
const nativeDatabase = "/run/aboardable-native-controller/controller.db";
const controlPlaneSnapshotRoot = "/run/aboardable-control-plane-snapshots";
const secretPath = join(controllerRoot, "console-api.secret");
const telegramPath = join(controllerRoot, "telegram-notifications.json");
const port = Number(process.env.ABOARDABLE_CONSOLE_PORT || 8787);
const allowedPhases = new Set(["Phase 7", "Phase 8", "Phase 9", "Infrastructure"]);
const allowedProjects = new Set(["aboardable-product", "engineering-console"]);
const secret = readFileSync(secretPath, "utf8").trim();

if (!/^[a-f0-9]{64}$/.test(secret)) throw new Error("Invalid console API secret");

function telegramStatus() {
  if (!existsSync(telegramPath)) return { configured: false };
  const saved = JSON.parse(readFileSync(telegramPath, "utf8"));
  return { configured: true, username: saved.username || null, chatId: String(saved.chatId).slice(-4).padStart(String(saved.chatId).length, "•") };
}

async function configureTelegram(body) {
  const token = String(body?.token || "").trim();
  if (!/^\d{6,12}:[A-Za-z0-9_-]{25,}$/.test(token)) throw new Error("invalid Telegram bot token");
  const meResponse = await fetch(`https://api.telegram.org/bot${token}/getMe`);
  const me = await meResponse.json();
  if (!me.ok) throw new Error("Telegram rejected this bot token");
  const updatesResponse = await fetch(`https://api.telegram.org/bot${token}/getUpdates?limit=20`);
  const updates = await updatesResponse.json();
  const chats = (updates.result || []).map((item) => item.message?.chat || item.my_chat_member?.chat).filter(Boolean).reverse();
  const chat = chats.find((item) => item.type === "private");
  if (!chat?.id) throw new Error("Open the bot in Telegram, press Start, then try again");
  const saved = { token, chatId: chat.id, username: me.result.username, configuredAt: new Date().toISOString() };
  writeFileSync(telegramPath, JSON.stringify(saved), { mode: 0o600 }); chmodSync(telegramPath, 0o600);
  const test = await fetch(`https://api.telegram.org/bot${token}/sendMessage`, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ chat_id: chat.id, text: "✅ Aboardable Control Room notifications are connected." }) });
  if (!test.ok) throw new Error("Telegram setup saved, but the test notification failed");
  return telegramStatus();
}

function sqlText(value) {
  return `'${String(value).replaceAll("'", "''")}'`;
}

function sqlite(sql, json = true) {
  const args = json ? ["-json", database, sql] : [database, sql];
  const result = spawnSync("sqlite3", args, { encoding: "utf8", maxBuffer: 4 * 1024 * 1024 });
  if (result.status !== 0) throw new Error(result.stderr.trim() || "SQLite command failed");
  if (!json || !result.stdout.trim()) return [];
  return JSON.parse(result.stdout);
}

function nativeSqlite(sql) {
  const result = spawnSync("sqlite3", ["-json", `file:${nativeDatabase}?immutable=1`, sql], { encoding: "utf8", maxBuffer: 1024 * 1024 });
  if (result.status !== 0) throw new Error(result.stderr.trim() || "Native controller query failed");
  return result.stdout.trim() ? JSON.parse(result.stdout) : [];
}

// --- Production Line Onboarding -------------------------------------------
// The API and the standalone `aboardable-line-onboard` CLI share this one
// implementation: the API only ever spawns the CLI, it never duplicates its
// validate/apply/rollback logic. Reads (list/get) go straight to the DB via
// the existing sqlite() helper, matching this file's own style for every
// other table it already owns.
const lineOnboardCli = join(controllerRoot, "aboardable-line-onboard.sh");
const linesDir = join(controllerRoot, "lines");
const validLineId = /^[a-z][a-z0-9-]{2,39}$/;

function runLineOnboard(subcommand, lineId, extraArgs = []) {
  if (!validLineId.test(lineId)) throw new Error("invalid line id");
  const args = [subcommand, "--line", lineId, ...extraArgs];
  const result = spawnSync(lineOnboardCli, args, { encoding: "utf8", maxBuffer: 4 * 1024 * 1024, timeout: 20000 });
  const stdout = (result.stdout || "").trim();
  let parsed = null;
  if (stdout) {
    try { parsed = JSON.parse(stdout); } catch { /* fall through to raw text below */ }
  }
  if (result.status !== 0 && !parsed) {
    throw new Error((result.stderr || "").trim() || `${subcommand} failed`);
  }
  return parsed ?? { ok: result.status === 0, raw: stdout || (result.stderr || "").trim() };
}

const discoverCli = join(controllerRoot, "aboardable-line-discover.sh");

function runDiscover(body = {}) {
  const host = String(body.vps_hostname || "").trim();
  let result;
  if (!host) {
    result = spawnSync(discoverCli, [], { encoding: "utf8", maxBuffer: 2 * 1024 * 1024, timeout: 15000 });
  } else {
    const user = String(body.ssh_user || "").trim();
    if (!user) return { ok: false, error: "ssh_user is required for a remote host" };
    if (!/^[A-Za-z0-9._-]+$/.test(host) || !/^[A-Za-z0-9._-]+$/.test(user)) return { ok: false, error: "invalid host or user" };
    const port = String(Number(body.ssh_port) || 22);
    const scriptBody = readFileSync(discoverCli, "utf8");
    result = spawnSync("ssh", [
      "-o", "BatchMode=yes", "-o", "ConnectTimeout=8", "-o", "StrictHostKeyChecking=accept-new",
      "-p", port, `${user}@${host}`, "bash -s",
    ], { encoding: "utf8", maxBuffer: 2 * 1024 * 1024, timeout: 15000, input: scriptBody });
  }
  if (result.error || result.status !== 0) {
    return { ok: false, error: ((result.stderr || "").trim() || result.error?.message || "discovery failed") };
  }
  try { return JSON.parse(result.stdout); }
  catch { return { ok: false, error: "discovery returned invalid output" }; }
}

// Re-detection and manual configuration for an *existing* line. Discovery
// results from onboarding were only ever held in the wizard's transient
// state -- never persisted -- so a line whose environment wasn't detected
// at onboarding time (or whose detection has gone stale) had no way to
// refresh that, and there was no way to hand-set agent roles or a tmux
// session name at all after the fact. Both gaps fixed here.
function redetectLine(lineId) {
  if (!validLineId.test(lineId)) throw new Error("invalid line id");
  const rows = sqlite(`SELECT vps_hostname, ssh_user, ssh_port FROM lines WHERE line_id=${sqlText(lineId)};`);
  if (!rows.length) return { ok: false, error: "line not found" };
  const discovery = runDiscover({ vps_hostname: rows[0].vps_hostname, ssh_user: rows[0].ssh_user, ssh_port: rows[0].ssh_port });
  if (!discovery.ok) {
    sqlite(`UPDATE line_connections SET last_connectivity_test_at=CURRENT_TIMESTAMP, last_connectivity_result=${sqlText(discovery.error || "detection failed")}, updated_at=CURRENT_TIMESTAMP WHERE line_id=${sqlText(lineId)};`, false);
    return { ok: false, error: discovery.error || "detection failed" };
  }
  sqlite(`
    INSERT OR IGNORE INTO line_connections(line_id) VALUES(${sqlText(lineId)});
    UPDATE line_connections SET
      claude_installed=${discovery.claude?.installed ? 1 : 0}, claude_version=${sqlText(discovery.claude?.version || "")}, claude_checked_at=CURRENT_TIMESTAMP,
      codex_installed=${discovery.codex?.installed ? 1 : 0}, codex_version=${sqlText(discovery.codex?.version || "")}, codex_checked_at=CURRENT_TIMESTAMP,
      tmux_installed=${discovery.tmux?.installed ? 1 : 0}, tmux_version=${sqlText(discovery.tmux?.version || "")},
      last_connectivity_test_at=CURRENT_TIMESTAMP, last_connectivity_result='ok',
      updated_at=CURRENT_TIMESTAMP
    WHERE line_id=${sqlText(lineId)};
    INSERT INTO events(kind, line_id, detail) VALUES('line_redetected', ${sqlText(lineId)}, 'environment re-detected');
  `, false);
  return { ok: true, discovery };
}

function configureLine(lineId, body = {}) {
  if (!validLineId.test(lineId)) throw new Error("invalid line id");
  let changed = false;
  if (Array.isArray(body.agent_roles)) {
    sqlite(`UPDATE lines SET agent_roles=${sqlText(body.agent_roles.join(","))}, updated_at=CURRENT_TIMESTAMP WHERE line_id=${sqlText(lineId)};`, false);
    changed = true;
  }
  if (typeof body.report_source_path === "string" && body.report_source_path) {
    sqlite(`UPDATE lines SET report_source_path=${sqlText(body.report_source_path)}, updated_at=CURRENT_TIMESTAMP WHERE line_id=${sqlText(lineId)};`, false);
    changed = true;
  }
  if (typeof body.tmux_session_name === "string") {
    sqlite(`INSERT OR IGNORE INTO line_connections(line_id) VALUES(${sqlText(lineId)});
      UPDATE line_connections SET tmux_session_name=${sqlText(body.tmux_session_name)}, updated_at=CURRENT_TIMESTAMP WHERE line_id=${sqlText(lineId)};`, false);
    changed = true;
  }
  if (!changed) return { ok: false, error: "nothing to update" };
  sqlite(`INSERT INTO events(kind, line_id, detail) VALUES('line_configured', ${sqlText(lineId)}, 'manual configuration update');`, false);
  return { ok: true };
}

// Called after a successful read_worker_report tool call so the Approval
// Inbox's "New" badge for this line clears for every viewer immediately,
// not just in whichever single browser happens to click the panel. Not
// tied to a specific report's run_id -- read_worker_report always fetches
// whatever is currently live, so "now" is the correct read watermark:
// anything detected at or before this moment has been seen.
function markReportRead(lineId) {
  if (!validLineId.test(lineId)) throw new Error("invalid line id");
  sqlite(`INSERT OR IGNORE INTO line_connections(line_id) VALUES(${sqlText(lineId)});
    UPDATE line_connections SET last_report_read_at=CURRENT_TIMESTAMP, updated_at=CURRENT_TIMESTAMP WHERE line_id=${sqlText(lineId)};`, false);
  return { ok: true };
}

function listLines() {
  return sqlite(`
    SELECT l.line_id, l.display_name, l.product_name, l.line_type, l.phase, l.status,
           l.access_mode, l.agent_roles, l.claude_chat_visible, l.project_path,
           l.vps_hostname, l.updated_at,
           c.ingestion_enabled, c.last_ingested_at, c.last_run_id, c.current_health_state,
           c.last_report_read_at
    FROM lines l LEFT JOIN line_connections c ON c.line_id = l.line_id
    ORDER BY (l.status != 'active'), l.display_name;
  `);
}

function getLine(lineId) {
  if (!validLineId.test(lineId)) throw new Error("invalid line id");
  const rows = sqlite(`SELECT l.*, c.claude_installed, c.claude_version, c.claude_checked_at,
      c.codex_installed, c.codex_version, c.codex_checked_at, c.tmux_session_name,
      c.tmux_last_seen_at, c.tmux_installed, c.tmux_version, c.ingestion_enabled, c.last_ingested_at, c.last_run_id,
      c.ssh_key_configured, c.ssh_key_fingerprint, c.ssh_key_configured_at,
      c.last_connectivity_test_at, c.last_connectivity_result, c.current_health_state,
      c.dispatch_mode, c.dispatch_host, c.dispatch_user, c.dispatch_port,
      c.dispatch_key_path, c.dispatch_report_key_path, c.dispatch_tmux_session,
      c.last_report_read_at
    FROM lines l LEFT JOIN line_connections c ON c.line_id = l.line_id
    WHERE l.line_id = ${sqlText(lineId)};`);
  if (!rows.length) return null;
  const reports = sqlite(`SELECT run_id, state, detected_at, summary FROM reports WHERE line_id = ${sqlText(lineId)} ORDER BY detected_at DESC LIMIT 20;`);
  const events = sqlite(`SELECT kind, detail, created_at FROM events WHERE line_id = ${sqlText(lineId)} ORDER BY id DESC LIMIT 30;`);
  return { ...rows[0], reports, events };
}

function writeTempManifest(body) {
  if (!body || typeof body !== "object" || !validLineId.test(String(body.line_id || ""))) {
    throw new Error("manifest requires a valid line_id");
  }
  mkdirSync(linesDir, { recursive: true });
  const path = join(linesDir, `.tmp-${body.line_id}-${Date.now()}.json`);
  writeFileSync(path, JSON.stringify(body), { mode: 0o600 });
  return path;
}

function controlPlaneSnapshots() {
  return ["product", "native"].map((line) => {
    const path = join(controlPlaneSnapshotRoot, `${line}.json`);
    if (!existsSync(path)) return { lineId: line, verified: false, color: "red", state: "unknown", detail: "No verified sensor snapshot" };
    try {
      const snapshot = JSON.parse(readFileSync(path, "utf8"));
      const payload = snapshot.payload || {};
      const ageSeconds = Math.max(0, (Date.now() - Date.parse(payload.generated_at || 0)) / 1000);
      if (!snapshot.verified || payload.line_id !== line || ageSeconds > Number(payload.stale_after_seconds || 120)) {
        return { lineId: line, verified: false, color: "red", state: "unknown", detail: "Sensor snapshot is invalid or stale", ageSeconds };
      }
      return { lineId: line, verified: true, color: payload.color, state: payload.color,
        observedAt: payload.generated_at, staleAfterSeconds: payload.stale_after_seconds,
        nodes: payload.project?.nodes || [], handoffs: payload.handoffs || [], queues: payload.queues || [],
        workItems: payload.work_items || [], sourceDigest: snapshot.source_digest };
    } catch (error) {
      return { lineId: line, verified: false, color: "red", state: "unknown", detail: `Unreadable sensor snapshot: ${error.message}` };
    }
  });
}

function initialize() {
  sqlite(`
    PRAGMA busy_timeout=5000;
    CREATE TABLE IF NOT EXISTS lines (
      line_id TEXT PRIMARY KEY,
      display_name TEXT NOT NULL,
      product_name TEXT NOT NULL,
      purpose TEXT NOT NULL DEFAULT '',
      line_type TEXT NOT NULL,
      phase TEXT,
      status TEXT NOT NULL DEFAULT 'onboarding',
      access_mode TEXT NOT NULL,
      agent_roles TEXT NOT NULL DEFAULT '',
      claude_chat_visible INTEGER NOT NULL DEFAULT 0,
      vps_hostname TEXT, vps_ip TEXT, ssh_user TEXT, ssh_port INTEGER NOT NULL DEFAULT 22,
      project_path TEXT NOT NULL,
      git_remote TEXT, default_branch TEXT, branch_strategy TEXT,
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
      claude_installed INTEGER, claude_version TEXT, claude_checked_at TEXT,
      codex_installed INTEGER, codex_version TEXT, codex_checked_at TEXT,
      tmux_session_name TEXT, tmux_last_seen_at TEXT, tmux_installed INTEGER, tmux_version TEXT,
      ingestion_enabled INTEGER NOT NULL DEFAULT 0,
      last_ingested_at TEXT, last_run_id TEXT,
      ssh_key_configured INTEGER NOT NULL DEFAULT 0, ssh_key_fingerprint TEXT, ssh_key_configured_at TEXT,
      last_connectivity_test_at TEXT, last_connectivity_result TEXT,
      current_health_state TEXT NOT NULL DEFAULT 'unknown',
      dispatch_mode TEXT, dispatch_host TEXT, dispatch_user TEXT, dispatch_port INTEGER,
      dispatch_key_path TEXT, dispatch_report_key_path TEXT, dispatch_tmux_session TEXT,
      last_report_read_at TEXT,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS console_messages (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      phase TEXT NOT NULL,
      role TEXT NOT NULL CHECK(role IN ('user','assistant','system')),
      author TEXT NOT NULL DEFAULT '',
      body TEXT NOT NULL,
      state TEXT NOT NULL DEFAULT 'complete' CHECK(state IN ('queued','processing','complete','failed')),
      created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE INDEX IF NOT EXISTS idx_console_messages_phase_id ON console_messages(phase,id);
    CREATE TABLE IF NOT EXISTS console_phase_memory (
      phase TEXT PRIMARY KEY,
      summary TEXT NOT NULL DEFAULT '',
      updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS ai_runs (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      run_key TEXT NOT NULL UNIQUE,
      kind TEXT NOT NULL CHECK(kind IN ('review','console')),
      subject TEXT NOT NULL,
      input_digest TEXT NOT NULL,
      state TEXT NOT NULL CHECK(state IN ('active','complete','failed','stopped')),
      attempts INTEGER NOT NULL DEFAULT 0,
      input_bytes INTEGER NOT NULL DEFAULT 0,
      output_bytes INTEGER NOT NULL DEFAULT 0,
      started_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
      finished_at TEXT,
      stop_reason TEXT NOT NULL DEFAULT ''
    );
    UPDATE ai_runs SET state='stopped',finished_at=CURRENT_TIMESTAMP,stop_reason='stale process recovered at API start'
      WHERE state='active' AND started_at < datetime('now','-2 hours');
    UPDATE console_messages SET state='queued',updated_at=CURRENT_TIMESTAMP
      WHERE state='processing' AND updated_at < datetime('now','-2 hours');
  `, false);

  const existing = sqlite("SELECT count(*) AS count FROM console_messages;")[0]?.count ?? 0;
  if (Number(existing) === 0) {
    sqlite(`INSERT INTO console_messages(phase,role,author,body,state) VALUES(
      'Phase 7','system','controller',
      'Mobile control channel opened. Phase 7 remains active. Production route exclusion is under review; Stripe sandbox lifecycle evidence and branded magic-link email verification remain open. Phase 8 is locked until the Phase 7 exit audit passes.',
      'complete'
    );`, false);
  }
}

function authorized(request) {
  const header = request.headers.authorization || "";
  const supplied = header.startsWith("Bearer ") ? header.slice(7) : "";
  const a = Buffer.from(supplied);
  const b = Buffer.from(secret);
  return a.length === b.length && timingSafeEqual(a, b);
}

function sendJson(response, status, value) {
  const body = JSON.stringify(value);
  response.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(body),
    "cache-control": "no-store",
    "x-content-type-options": "nosniff",
  });
  response.end(body);
}

async function readJson(request) {
  const chunks = [];
  let size = 0;
  for await (const chunk of request) {
    size += chunk.length;
    if (size > 32 * 1024) throw new Error("request too large");
    chunks.push(chunk);
  }
  return JSON.parse(Buffer.concat(chunks).toString("utf8"));
}

function serviceState() {
  const line = controlPlaneSnapshots().find((item) => item.lineId === "product");
  const controller = line?.nodes?.find((node) => node.id === "product-controller");
  return line?.verified && controller && !controller.stale && !["failed", "offline", "unknown"].includes(controller.state) ? "Ready" : "Failed";
}

function claudeState(activeTitle) {
  const lines = controlPlaneSnapshots();
  const product = lines.find((item) => item.lineId === "product");
  const native = lines.find((item) => item.lineId === "native");
  const productWorker = product?.nodes?.find((node) => node.id === "product-worker");
  const nativeWorker = native?.nodes?.find((node) => node.id === "native-worker");
  const connected = (line, node) => Boolean(line?.verified && node && !node.stale && !["failed", "offline", "unknown"].includes(node.state));
  const productSession = connected(product, productWorker);
  const nativeSession = connected(native, nativeWorker);
  const productWorking = productWorker?.state === "working";
  const nativeWorking = nativeWorker?.state === "working";
  return {
    state: !productSession ? "Failed" : productWorking ? "Working" : productWorker?.state === "waiting" ? "Waiting" : "Ready",
    detail: !productSession ? "Product worker sensor is disconnected or unknown" : productWorking ? (activeTitle || "Working on the active Product task") : "Connected and ready",
    workerConnected: productSession || nativeSession,
    productSession,
    nativeSession,
    nativeState: nativeWorking ? "Working" : "Ready",
    nativeDetail: !nativeSession ? "Native worker sensor is disconnected or unknown" : nativeWorking ? "Working on the active Engineering Console milestone" : "Connected and ready",
  };
}

function detectedProjects(productClaude) {
  const projects = [{ id: "aboardable-product", label: "Aboardable Product", kind: "web", state: productClaude.productSession ? productClaude.state : "Failed" }];
  if (productClaude.nativeSession) projects.push({ id: "engineering-console", label: "Engineering Console", kind: "mobile", state: productClaude.nativeState || "Ready" });
  return projects;
}

function topology(reports, productClaude) {
  const sensorLines = controlPlaneSnapshots();
  const productSensor = sensorLines.find((item) => item.lineId === "product");
  const nativeSensor = sensorLines.find((item) => item.lineId === "native");
  const nativeReviewerSensor = nativeSensor?.nodes?.find((node) => node.id === "native-reviewer");
  const workerConnected = productClaude.workerConnected === true;
  const productSession = productClaude.productSession === true;
  const nativeSession = productClaude.nativeSession === true;
  const controllerNode = productSensor?.nodes?.find((node) => node.id === "product-controller");
  const retiredController = productSensor?.nodes?.find((node) => node.id === "product-claude-controller-retired");
  const uxAdvisory = productSensor?.nodes?.find((node) => node.id === "product-ux-qa-claude");
  const controllerHealthy = serviceState() === "Ready";
  // The API service has PrivateTmp, so it cannot see the controller's tmux
  // socket. Sense the dedicated Codex process by its isolated working root.
  const nativeCodexController = Boolean(nativeSensor?.verified);
  const nativeReviewerProcess = Boolean(nativeReviewerSensor && !nativeReviewerSensor.stale && nativeReviewerSensor.state === "working");
  const observedAt = new Date().toISOString();
  const productHandoff = reports.find((report) => ["queued", "reviewing", "manual", "needs_sean"].includes(report.state));
  const productWaiting = productHandoff?.state === "queued";
  const productReviewing = productHandoff?.state === "reviewing";
  const nativeReviewResult = spawnSync("sqlite3", ["-json", "file:/run/aboardable-native-controller/controller.db?immutable=1", "SELECT state,summary,updated_at FROM reviews ORDER BY id DESC LIMIT 1;"], {
    encoding: "utf8",
    timeout: 3000,
  });
  const nativeReviewRecord = nativeReviewResult.status === 0 && nativeReviewResult.stdout.trim() ? JSON.parse(nativeReviewResult.stdout)[0] : null;

  return {
    nodes: {
      controlRoom: { state: "healthy", detail: "Owner authenticated", source: "Sites session", observedAt },
      controller: { label: "Product Orchestrator — deterministic software", state: controllerNode?.state || "unknown", detail: controllerHealthy ? "Deterministic workflow service is advancing durable transitions" : "Deterministic workflow service is unavailable", source: controllerNode?.evidence_source || "signed control-plane snapshot", observedAt: controllerNode?.sensor_timestamp || productSensor?.observedAt },
      productController: {
        label: "Product Orchestrator — deterministic software",
        state: productSensor?.color === "amber" ? "active" : productSensor?.color === "blue" ? "waiting" : controllerHealthy ? "healthy" : "failed",
        detail: productSensor?.workItems?.find((item) => ["dispatched","working","report_received","reviewing","accepted","integrating","deploying"].includes(item.state))?.state || "Ready; no executable work improperly waiting",
        reviewer: null, source: "durable Product DB + signed receipts", observedAt: productSensor?.observedAt,
      },
      retiredProductClaudeController: { label: "Product controller — Claude", state: "retired", color: "grey", detail: "RETIRED / AUDIT — read-only archive; zero workflow authority", source: retiredController?.endpoint || "retirement ledger", observedAt: retiredController?.retired_at || productSensor?.observedAt },
      productUxQaAdvisory: { label: "Product UI/UX QA — Claude (advisory)", state: uxAdvisory?.state === "working" ? "active" : "on_demand", detail: "Non-blocking, on-demand UI/UX findings only; no ACCEPT/REJECT authority", source: uxAdvisory?.evidence_source || "registry", observedAt: uxAdvisory?.sensor_timestamp || null },
      nativeController: {
        state: !nativeCodexController ? "failed" : nativeReviewRecord?.state === "reviewing" ? "active" : nativeReviewRecord?.state === "rejected" ? "correction_required" : "healthy",
        detail: !nativeCodexController ? "Dedicated Native Codex controller session is not running" : nativeReviewRecord?.state === "reviewing" ? "Codex controller handed the submission to independent review" : nativeReviewRecord?.state === "rejected" ? "Codex controller received corrections from the reviewer" : "Dedicated Native Codex controller ready",
        reviewer: nativeReviewRecord?.state === "reviewing" ? "Native Codex reviewer" : null,
        source: "isolated Codex tmux session + native ledger",
        observedAt: nativeReviewRecord?.updated_at || observedAt,
      },
      worker: { state: workerConnected ? "healthy" : "failed", detail: workerConnected ? "Worker VPS reachable" : "Worker VPS unreachable", source: "SSH probe", observedAt },
      productClaude: { label: "Product worker — Claude Code", state: productSession ? (productClaude.state === "Working" ? "active" : productReviewing ? "waiting" : "standby") : "failed", detail: productSession ? (productReviewing ? "Implementation submitted; independent Codex review is active" : productClaude.detail) : "Product worker unavailable" },
      nativeClaude: { state: nativeSession ? (nativeReviewRecord?.state === "reviewing" ? "waiting" : "standby") : "failed", detail: nativeSession ? (nativeReviewRecord?.state === "reviewing" ? "Submission complete; reviewer is working" : "Native Claude session available") : "Native Claude session unavailable" },
      productReview: { label: "Product reviewer — Codex", state: productReviewing ? "active" : productWaiting ? "waiting" : "standby", detail: productReviewing ? `Reviewing ${productHandoff.run_id}` : productWaiting ? `Submission ${productHandoff.run_id} is waiting for review` : "Product Codex reviewer ready for the next submission", source: "product review ledger", observedAt: productHandoff?.detected_at || observedAt },
      nativeReview: { state: nativeReviewerProcess || nativeReviewRecord?.state === "reviewing" ? "active" : "standby", detail: nativeReviewerProcess ? "Native Codex reviewer process is running" : nativeReviewRecord?.state === "reviewing" ? "Native review recorded as in progress" : "Native Codex reviewer ready for the next submission", source: "isolated review process + native ledger", observedAt: nativeReviewRecord?.updated_at || observedAt },
    },
    links: {
      siteToController: controllerHealthy ? "healthy" : "failed",
      controllerToWorker: workerConnected ? "healthy" : "failed",
      workerToProduct: productSession ? (productClaude.state === "Working" ? "active" : "healthy") : "failed",
      workerToNative: nativeSession ? "healthy" : "failed",
      productToReview: productReviewing ? "active" : productWaiting ? "waiting" : "standby",
      nativeToReview: nativeReviewerProcess || nativeReviewRecord?.state === "reviewing" ? "active" : "standby",
    },
  };
}

function phaseSummary(phase, workItems) {
  const activeItems = workItems.filter((item) => item.status === "active");
  if (phase === "Phase 7") return { name: phase, state: "Complete", headline: "Phase 7 exit evidence is complete." };
  if (phase === "Infrastructure") return { name: phase, state: "Open", headline: "Engineering workflow reliability and efficiency." };
  if (activeItems.length === 0) return { name: phase, state: "Open · work in progress", headline: `No active ${phase} work item.` };
  return {
    name: phase,
    state: "Open · work in progress",
    headline: activeItems.map((item) => item.title).join(" · "),
    activeItems: activeItems.map((item) => ({ id: item.id, title: item.title })),
  };
}

function snapshot(phase, project = "aboardable-product") {
  const workItems = sqlite("SELECT id,lane,title,detail,status,updated_at FROM work_items WHERE status IN ('open','active') ORDER BY CASE status WHEN 'active' THEN 0 ELSE 1 END,id;");
  const reports = sqlite("SELECT run_id,state,detected_at,coalesce(summary,'') AS summary,coalesce(error,'') AS error FROM reports ORDER BY detected_at DESC LIMIT 8;");
  const messages = sqlite(`SELECT id,phase,role,body,state,created_at FROM console_messages WHERE phase=${sqlText(phase)} ORDER BY id DESC LIMIT 60;`).reverse();
  const aiRuns = sqlite("SELECT id,kind,subject,state,attempts,input_bytes,output_bytes,started_at,finished_at,stop_reason FROM ai_runs ORDER BY id DESC LIMIT 20;");
  const dispatches = sqlite("SELECT id,kind,work_item_id,parent_run_id,state,detail,created_at FROM claude_dispatches ORDER BY id DESC LIMIT 20;");
  const reviewing = reports.find((report) => report.state === "reviewing" || report.state === "queued");
  const active = workItems.find((item) => item.status === "active");
  const controllerService = serviceState();
  const productClaude = claudeState(active?.title);
  const productLine = controlPlaneSnapshots().find((item) => item.lineId === "product");
  const authoritativeItems = productLine?.workItems || [];
  const workflowActive = authoritativeItems.find((item) => ["dispatched","working","report_received","reviewing","accepted","integrating","deploying"].includes(item.state));
  const workflowNext = authoritativeItems.find((item) => ["queued","open"].includes(item.state));
  if (project === "engineering-console") {
    const nativeItems = nativeSqlite("SELECT id,title,acceptance AS detail,CASE WHEN status='blocked' THEN 'open' ELSE status END AS status,CASE WHEN status='blocked' THEN 'needs_sean' ELSE 'ready' END AS lane,updated_at FROM work_items WHERE status IN ('open','active','blocked') ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'blocked' THEN 1 ELSE 2 END,priority DESC,id;");
    const nativeReports = nativeSqlite("SELECT 'native-' || id AS run_id,state,updated_at AS detected_at,coalesce(summary,'') AS summary,'' AS error FROM reviews ORDER BY id DESC LIMIT 8;");
    const nativeActive = nativeItems.find((item) => item.status === "active");
    const nativeClaude = { state: productClaude.nativeState || "Ready", detail: productClaude.nativeState === "Working" ? (nativeActive?.title || productClaude.nativeDetail) : productClaude.nativeDetail };
    const latestNative = nativeReports[0];
    return {
      generatedAt: new Date().toISOString(), project: "engineering-console", projects: detectedProjects(productClaude),
      controller: { state: latestNative?.state === "reviewing" ? "Reviewing" : "Ready", detail: latestNative?.state === "reviewing" ? `Reviewing ${latestNative.run_id}` : "Watching the Engineering Console ledger" },
      claude: nativeClaude, topology: topology(reports, productClaude),
      phase: { name: "Engineering Console", state: "Open · work in progress", headline: nativeActive?.title || "No active Engineering Console task." },
      workItems: nativeItems, reports: nativeReports, aiRuns: [], dispatches: [],
      messages: sqlite("SELECT id,phase,role,body,state,created_at FROM console_messages WHERE phase='Infrastructure' ORDER BY id DESC LIMIT 60;").reverse(),
    };
  }
  const controller = reviewing
    ? { state: "Reviewing", detail: `Independent review of ${reviewing.run_id}` }
    : { state: controllerService, detail: controllerService === "Ready" ? "Watching reports and advancing authorised work" : "Controller service needs attention" };
  return {
    generatedAt: new Date().toISOString(), project: "aboardable-product", projects: detectedProjects(productClaude),
    controller,
    claude: productClaude,
    topology: topology(reports, productClaude),
    phase: phaseSummary(phase, workItems),
    workItems,
    reports,
    aiRuns,
    dispatches,
    messages,
    workflow: { phase: "Phase 9", activeItem: workflowActive || null, currentTransition: workflowActive?.state || "idle", lastEvidenceTimestamp: productLine?.observedAt || null, nextDependencyClearItem: workflowNext || null, automaticSuccessorDispatchArmed: Boolean(workflowActive || workflowNext), controllerAuthority: "deterministic software" },
  };
}

function acceptMessage(payload) {
  const phase = typeof payload.phase === "string" ? payload.phase.trim() : "";
  const message = typeof payload.message === "string" ? payload.message.trim() : "";
  const author = typeof payload.author === "string" ? payload.author.trim().slice(0, 200) : "Sean";
  if (!allowedPhases.has(phase) || !message || message.length > 8000) throw new Error("invalid message");
  const latest = sqlite("SELECT created_at FROM console_messages WHERE role='user' ORDER BY id DESC LIMIT 1;")[0];
  if (latest && Date.now() - new Date(`${latest.created_at}Z`).getTime() < 1500) throw new Error("please wait a moment");
  const duplicate = sqlite(`SELECT id,state FROM console_messages WHERE phase=${sqlText(phase)} AND role='user' AND body=${sqlText(message)} AND created_at > datetime('now','-24 hours') ORDER BY id DESC LIMIT 1;`)[0];
  if (duplicate) throw new Error(`duplicate message already ${duplicate.state} as #${duplicate.id}`);
  return sqlite(`INSERT INTO console_messages(phase,role,author,body,state)
    VALUES(${sqlText(phase)},'user',${sqlText(author)},${sqlText(message)},'queued')
    RETURNING id,phase,role,body,state,created_at;`)[0];
}

function runCodex(prompt, outputPath) {
  return new Promise((resolve) => {
    const args = [
      "exec",
      "-c", "model_reasoning_effort=\"high\"",
      "--cd", repo,
      "--sandbox", "read-only",
      "--ephemeral",
      "--output-last-message", outputPath,
      "-",
    ];
    const child = spawn("codex", args, { cwd: repo, stdio: ["pipe", "ignore", "pipe"] });
    let stderr = "";
    child.stderr.on("data", (chunk) => { stderr += chunk.toString(); });
    child.on("close", (code) => resolve({ code: code ?? 1, stderr }));
    child.stdin.end(prompt);
  });
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

let workerBusy = false;

function deterministicStatusAnswer() {
  const active = sqlite("SELECT id,title,status FROM work_items WHERE status='active' ORDER BY id LIMIT 1;")[0];
  const report = sqlite("SELECT run_id,state,detected_at FROM reports WHERE state IN ('queued','reviewing') ORDER BY detected_at LIMIT 1;")[0];
  const latest = sqlite("SELECT run_id,state,substr(coalesce(summary,''),1,240) AS summary FROM reports ORDER BY detected_at DESC LIMIT 1;")[0];
  if (report) return `Work item ${active?.id ?? "—"} (${active?.title ?? "no active item"}) is active. Claude has submitted report ${report.run_id}; the Codex controller is ${report.state}. No duplicate AI work will start until that review finishes.`;
  return `Work item ${active?.id ?? "—"} (${active?.title ?? "no active item"}) is ${active?.status ?? "not active"}. No report is queued or under review. Latest report: ${latest?.run_id ?? "none"} — ${latest?.state ?? "none"}. ${latest?.summary ?? ""}`.trim();
}

async function processNextMessage() {
  if (workerBusy) return;
  const next = sqlite("SELECT id,phase,author,body FROM console_messages WHERE role='user' AND state='queued' ORDER BY id LIMIT 1;")[0];
  if (!next) return;
  if (/^(status|status update|what(?:'s| is) (?:happening|the status)|is (?:claude|the workflow) (?:idle|stopped|working))\??$/i.test(next.body)) {
    workerBusy = true;
    sqlite(`UPDATE console_messages SET state='processing',updated_at=CURRENT_TIMESTAMP WHERE id=${Number(next.id)} AND state='queued';`, false);
    const answer = deterministicStatusAnswer();
    sqlite(`BEGIN IMMEDIATE; UPDATE console_messages SET state='complete',updated_at=CURRENT_TIMESTAMP WHERE id=${Number(next.id)}; INSERT INTO console_messages(phase,role,author,body,state) VALUES(${sqlText(next.phase)},'assistant','controller',${sqlText(answer)},'complete'); COMMIT;`, false);
    workerBusy = false;
    return;
  }
  const engineeringBusy = sqlite("SELECT count(*) AS count FROM reports WHERE state IN ('queued','reviewing');")[0]?.count ?? 0;
  const aiBusy = sqlite("SELECT count(*) AS count FROM ai_runs WHERE state='active';")[0]?.count ?? 0;
  if (Number(engineeringBusy) > 0 || Number(aiBusy) > 0) return;
  workerBusy = true;
  sqlite(`UPDATE console_messages SET state='processing',updated_at=CURRENT_TIMESTAMP WHERE id=${Number(next.id)} AND state='queued';`, false);


  const history = sqlite(`SELECT role,body,created_at FROM console_messages WHERE phase=${sqlText(next.phase)} AND id < ${Number(next.id)} ORDER BY id DESC LIMIT 24;`).reverse();
  const queue = sqlite("SELECT id,lane,title,detail,status FROM work_items WHERE status IN ('open','active') ORDER BY id;");
  const reports = sqlite("SELECT run_id,state,detected_at,coalesce(summary,'') AS summary,coalesce(error,'') AS error FROM reports ORDER BY detected_at DESC LIMIT 8;");
  const phaseMemory = sqlite(`SELECT summary,updated_at FROM console_phase_memory WHERE phase=${sqlText(next.phase)} LIMIT 1;`)[0] || null;
  const digest = createHash("sha256").update(`${next.phase}\0${next.body}\0${JSON.stringify(queue)}\0${JSON.stringify(reports)}`).digest("hex");
  const aiRunKey = `console:${Number(next.id)}:${digest}`;
  sqlite(`INSERT INTO ai_runs(run_key,kind,subject,input_digest,state,input_bytes) SELECT ${sqlText(aiRunKey)},'console',${sqlText(String(next.id))},${sqlText(digest)},'active',${Buffer.byteLength(next.body)} WHERE NOT EXISTS (SELECT 1 FROM ai_runs WHERE state='active');`, false);
  const claimed = sqlite(`SELECT count(*) AS count FROM ai_runs WHERE run_key=${sqlText(aiRunKey)} AND state='active';`)[0]?.count ?? 0;
  if (Number(claimed) !== 1) {
    sqlite(`UPDATE console_messages SET state='queued',updated_at=CURRENT_TIMESTAMP WHERE id=${Number(next.id)};`, false);
    workerBusy = false;
    return;
  }

  const prompt = `You are the read-only Aboardable engineering-console adviser. You answer through the owner-only console, using the durable queue and reports below.

Sean's current message (${next.phase}):
${next.body}

Recent conversation:
${history.map((item) => `${item.role.toUpperCase()}: ${item.body}`).join("\n\n") || "No earlier messages in this phase."}

Durable controller queue:
${JSON.stringify(queue, null, 2)}

Authoritative current controller reports (newest first):
${JSON.stringify(reports, null, 2)}

Durable phase memory:
${JSON.stringify(phaseMemory, null, 2)}

Read current repository authority and relevant files when needed. Give Sean a direct, concise answer. The report and queue data above are current authority: do not repeat stale claims, reopen completed decisions, or misstate review state. This console AI invocation is deliberately read-only: do not edit files, update the queue, run mutating commands, dispatch Claude, integrate, push, or claim an action occurred. Explain what should happen next or ask only for a genuinely necessary decision.

Current authority: Phase 7 is complete and Phase 8 is active. Never touch AXETEXA, Stripe live mode/settings, unrelated or hosted customer data, DNS, email-provider settings, credentials, production billing, or .claude/settings.local.json. The real received-email test resolved the former Supabase Auth branding blocker. The console conversation is durable; do not claim it mirrors an OpenAI desktop task verbatim.

Return only the user-facing response, with enough context to stand alone on mobile.`;

  const outputPath = join(controllerRoot, "runtime", `console-message-${Number(next.id)}.txt`);
  let result = { code: 1, stderr: "" };
  for (let attempt = 1; attempt <= 3; attempt += 1) {
    result = await runCodex(prompt, outputPath);
    if (result.code === 0) break;
    if (!result.stderr.includes("Selected model is at capacity") || attempt === 3) break;
    await delay(attempt * 10000);
  }

  if (result.code === 0) {
    const answer = readFileSync(outputPath, "utf8").trim() || "The controller completed the request without a written response.";
    sqlite(`BEGIN IMMEDIATE;
      UPDATE console_messages SET state='complete',updated_at=CURRENT_TIMESTAMP WHERE id=${Number(next.id)};
      INSERT INTO console_messages(phase,role,author,body,state) VALUES(${sqlText(next.phase)},'assistant','Codex',${sqlText(answer)},'complete');
      COMMIT;`, false);
    const outputBytes = Buffer.byteLength(answer);
    sqlite(`UPDATE ai_runs SET state='complete',attempts=1,output_bytes=${outputBytes},finished_at=CURRENT_TIMESTAMP WHERE run_key=${sqlText(aiRunKey)};`, false);
  } else {
    const safeError = result.stderr.includes("at capacity") ? "The review model is temporarily at capacity; retry this message shortly." : "The controller could not complete this message. Its engineering queue is still running.";
    sqlite(`BEGIN IMMEDIATE;
      UPDATE console_messages SET state='failed',updated_at=CURRENT_TIMESTAMP WHERE id=${Number(next.id)};
      INSERT INTO console_messages(phase,role,author,body,state) VALUES(${sqlText(next.phase)},'system','controller',${sqlText(safeError)},'failed');
      COMMIT;`, false);
    sqlite(`UPDATE ai_runs SET state='failed',attempts=1,finished_at=CURRENT_TIMESTAMP,stop_reason=${sqlText(safeError)} WHERE run_key=${sqlText(aiRunKey)};`, false);
  }
  workerBusy = false;
}

initialize();
setInterval(() => void processNextMessage(), 2000);

createServer(async (request, response) => {
  if (!authorized(request)) return sendJson(response, 401, { error: "unauthorized" });
  const url = new URL(request.url || "/", "https://controller.local");
  try {
    if (request.method === "GET" && url.pathname === "/v1/health") {
      return sendJson(response, 200, { ok: true, controller: serviceState() });
    }
    if (request.method === "GET" && url.pathname === "/v1/control-plane") {
      return sendJson(response, 200, { generatedAt: new Date().toISOString(), lines: controlPlaneSnapshots() });
    }
    if (request.method === "GET" && url.pathname === "/v1/snapshot") {
      const phase = url.searchParams.get("phase") || "Phase 7";
      const project = url.searchParams.get("project") || "aboardable-product";
      if (!allowedPhases.has(phase)) return sendJson(response, 400, { error: "invalid phase" });
      if (!allowedProjects.has(project)) return sendJson(response, 400, { error: "invalid project" });
      return sendJson(response, 200, snapshot(phase, project));
    }
    if (request.method === "POST" && url.pathname === "/v1/messages") {
      const message = acceptMessage(await readJson(request));
      void processNextMessage();
      return sendJson(response, 202, { accepted: true, message });
    }
    if (request.method === "GET" && url.pathname === "/v1/notifications/telegram") return sendJson(response, 200, telegramStatus());
    if (request.method === "POST" && url.pathname === "/v1/notifications/telegram") return sendJson(response, 200, await configureTelegram(await readJson(request)));

    if (request.method === "GET" && url.pathname === "/v1/lines") return sendJson(response, 200, { lines: listLines() });
    if (request.method === "POST" && url.pathname === "/v1/lines/discover") return sendJson(response, 200, runDiscover(await readJson(request)));

    const lineDetailMatch = url.pathname.match(/^\/v1\/lines\/([a-z][a-z0-9-]{2,39})$/);
    if (request.method === "GET" && lineDetailMatch) {
      const line = getLine(lineDetailMatch[1]);
      return line ? sendJson(response, 200, line) : sendJson(response, 404, { error: "line not found" });
    }

    if (request.method === "POST" && url.pathname === "/v1/lines/plan") {
      const body = await readJson(request);
      const manifestPath = writeTempManifest(body);
      try {
        return sendJson(response, 200, runLineOnboard("plan", body.line_id, ["--manifest", manifestPath]));
      } finally {
        try { unlinkSync(manifestPath); } catch { /* best effort cleanup */ }
      }
    }
    if (request.method === "POST" && url.pathname === "/v1/lines/apply") {
      const body = await readJson(request);
      const manifestPath = writeTempManifest(body);
      try {
        return sendJson(response, 200, runLineOnboard("apply", body.line_id, ["--manifest", manifestPath]));
      } finally {
        try { unlinkSync(manifestPath); } catch { /* best effort cleanup */ }
      }
    }

    const lineConfigureMatch = url.pathname.match(/^\/v1\/lines\/([a-z][a-z0-9-]{2,39})\/configure$/);
    if (request.method === "POST" && lineConfigureMatch) {
      return sendJson(response, 200, configureLine(lineConfigureMatch[1], await readJson(request)));
    }

    const lineActionMatch = url.pathname.match(/^\/v1\/lines\/([a-z][a-z0-9-]{2,39})\/(test|pause|resume|retire|rollback|redetect|mark-report-read)$/);
    if (request.method === "POST" && lineActionMatch) {
      const [, lineId, action] = lineActionMatch;
      if (action === "test") return sendJson(response, 200, runLineOnboard("verify", lineId));
      if (action === "rollback") return sendJson(response, 200, runLineOnboard("rollback", lineId));
      if (action === "redetect") return sendJson(response, 200, redetectLine(lineId));
      if (action === "mark-report-read") return sendJson(response, 200, markReportRead(lineId));
      if (action === "pause") {
        spawnSync(join(controllerRoot, "controller-state.sh"), ["lines-set-status", lineId, "paused"], { encoding: "utf8" });
        spawnSync(join(controllerRoot, "controller-state.sh"), ["lines-connections-set", lineId, "ingestion_enabled", "0"], { encoding: "utf8" });
        return sendJson(response, 200, { ok: true, line_id: lineId, status: "paused" });
      }
      if (action === "resume") {
        spawnSync(join(controllerRoot, "controller-state.sh"), ["lines-set-status", lineId, "active"], { encoding: "utf8" });
        spawnSync(join(controllerRoot, "controller-state.sh"), ["lines-connections-set", lineId, "ingestion_enabled", "1"], { encoding: "utf8" });
        return sendJson(response, 200, { ok: true, line_id: lineId, status: "active" });
      }
      if (action === "retire") {
        spawnSync(join(controllerRoot, "controller-state.sh"), ["lines-connections-set", lineId, "ingestion_enabled", "0"], { encoding: "utf8" });
        const result = spawnSync(join(controllerRoot, "controller-state.sh"), ["lines-set-status", lineId, "retired"], { encoding: "utf8" });
        return sendJson(response, result.status === 0 ? 200 : 500, { ok: result.status === 0, line_id: lineId, status: "retired" });
      }
    }

    return sendJson(response, 404, { error: "not found" });
  } catch (error) {
    const message = error instanceof Error ? error.message : "request failed";
    return sendJson(response, message === "please wait a moment" ? 429 : 400, { error: message });
  }
}).listen(port, "127.0.0.1", () => {
  console.log(`Aboardable console API listening on 127.0.0.1:${port}`);
});
