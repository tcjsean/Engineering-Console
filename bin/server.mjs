import http from "node:http";
import { createHash, randomBytes, randomUUID, scryptSync, timingSafeEqual } from "node:crypto";
import { appendFile, mkdir, readFile, readdir, rename, writeFile } from "node:fs/promises";
import path from "node:path";
import { spawn } from "node:child_process";

const HOST = "127.0.0.1";
const PORT = 8799;
const STORE = "/var/lib/aboardable-mcp-poc/drafts";
const MAX_BODY = 16 * 1024;
const MAX_TEXT = 4096;
const PUBLIC_ORIGIN = "https://vps-543c8f7f.vps.ovh.ca";
const MCP_PATH = "/mcp-poc-115afaf42c35ad9492a1ba29ee5606ff44bd4966aa5db11a";
const OAUTH_BASE = "/oauth-poc-115afaf42c35ad9492a1ba29ee5606ff44bd4966aa5db11a";
const APPROVE_BASE = "/owner-approve-115afaf42c35ad9492a1ba29ee5606ff44bd4966aa5db11a";
const SECURITY_BASE = "/owner-security-359cb82b7221816e373d2cf8e6faa5e895adbd13280b45b1";
const INBOX_BASE = "/owner-inbox-586157130be2b85964e02d07cd6d6adab87dc518cd075eed";
const MANIFEST_PATH = "/engineering-control.webmanifest";
const SERVICE_WORKER_PATH = "/engineering-control-sw.js";
const REPORT_NOTIFY_PATH = "/report-notify-1234ca8b8fd9c9b4efa7dfb093dabcf5cfe811c67c5a2b73";
const WORKER_STATUS_PATH = "/worker-status-45433af55990923336c456c82698a2fafe7a3963f0242f68";
const RESET_BASE = "/owner-reset-2e5b94afb91e7210479845f9aa4a1c0149566c2230aaac3a";
const RESET2_BASE = "/owner-reset2-00124087d5367e5c44cb0ef33d0db296aa72233a58d9611b";
const LINES_BASE = "/production-lines-8a8019d5536af744efb1dd3fe76822a78cff956e11b25eaa";
const CONSOLE_API_ORIGIN = "http://127.0.0.1:8787";
const CONSOLE_API_SECRET_PATH = "/var/lib/aboardable-mcp-poc/credentials/console-api.secret";
const OWNER_CODE = process.env.OWNER_APPROVAL_CODE || "";
const CREDENTIAL_PATH = "/var/lib/aboardable-mcp-poc/credentials/owner.json";
const OAUTH_STATE_PATH = "/var/lib/aboardable-mcp-poc/credentials/oauth-state.json";
const REPORT_EVENTS_PATH = "/var/lib/aboardable-mcp-poc/credentials/report-events.json";
const WORKER_STATUS_FILE = "/var/lib/aboardable-mcp-poc/credentials/worker-status.json";
const SEND_AUDIT_PATH = "/var/lib/aboardable-mcp-poc/credentials/send-audit.jsonl";
const RESET_CONSUMED_PATH = "/var/lib/aboardable-mcp-poc/credentials/pin-reset-consumed";
const RESET2_CONSUMED_PATH = "/var/lib/aboardable-mcp-poc/credentials/pin-reset2-consumed";
const INBOX_COOKIE_VALUE = "85d46e8131eb463e9b6c439cf99a4768a5a1a713fa5a463e0b120bb5fd31248d";
const RESOURCE = `${PUBLIC_ORIGIN}${MCP_PATH}`;
const ISSUER = `${PUBLIC_ORIGIN}${OAUTH_BASE}`;
const clients = new Map();
const codes = new Map();
const tokens = new Map();
const approvalFailures = new Map();
let loginFailures = { attempts: 0, blockedUntil: 0 };

async function persistOAuthState() {
  const state = {
    clients: [...clients.entries()],
    tokens: [...tokens.entries()].filter(([, value]) => value.expiresAt > Date.now()),
  };
  await writeFile(OAUTH_STATE_PATH, JSON.stringify(state), { mode: 0o600 });
}

async function loadOAuthState() {
  try {
    const state = JSON.parse(await readFile(OAUTH_STATE_PATH, "utf8"));
    for (const [key, value] of state.clients || []) clients.set(key, value);
    for (const [key, value] of state.tokens || []) if (value.expiresAt > Date.now()) tokens.set(key, value);
  } catch (err) {
    if (err?.code !== "ENOENT") throw err;
  }
}

// --- Per-line dispatch/status/report -----------------------------------
// Every send, status check, and report read resolves through a specific
// line's dispatch config (line_connections.dispatch_*) instead of one
// hardcoded global worker. `aboardable-product` is seeded with
// dispatch_mode='ssh-relay' and byte-identical host/key/known_hosts values
// to what used to be hardcoded here, so its behavior is unchanged -- just
// now data-driven. No mode ever falls back to another line's target; a
// line with no/unknown dispatch_mode is a hard error, never a default.
const SSH_RELAY_KNOWN_HOSTS = "/var/lib/aboardable-mcp-poc/keys/worker_known_hosts";

function shq(value) {
  return `'${String(value).replaceAll("'", "'\\''")}'`;
}

function sshTarget(line) {
  return `${line.dispatch_user}@${line.dispatch_host}`;
}

function sshPortArgs(line) {
  const port = Number(line.dispatch_port);
  return port && port !== 22 ? ["-p", String(port)] : [];
}

function dispatchToWorker(payload, line) {
  if (!line?.dispatch_mode) return Promise.reject(new Error(`Line "${line?.line_id || "(unknown)"}" has no dispatch configuration`));
  if (line.dispatch_mode === "ssh-relay") return sshRelayDispatch(payload, line);
  if (line.dispatch_mode === "tmux-ssh") return tmuxSshDispatch(payload, line);
  return Promise.reject(new Error(`Unsupported dispatch mode "${line.dispatch_mode}" for line "${line.line_id}"`));
}

function sshRelayDispatch(payload, line) {
  return new Promise((resolve, reject) => {
    if (!line.dispatch_key_path) return reject(new Error(`Line "${line.line_id}" has no dispatch_key_path configured for ssh-relay mode`));
    const child = spawn("/usr/bin/ssh", [
      "-T",
      "-i", line.dispatch_key_path,
      "-o", "IdentitiesOnly=yes",
      "-o", `UserKnownHostsFile=${SSH_RELAY_KNOWN_HOSTS}`,
      "-o", "BatchMode=yes",
      "-o", "ConnectTimeout=5",
      ...sshPortArgs(line),
      sshTarget(line),
    ], { stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 12_000);
    child.stderr.on("data", chunk => { stderr += chunk.toString(); });
    child.on("error", reject);
    child.on("close", code => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else {
        const err = new Error(stderr.trim() || `worker dispatch exited ${code}`);
        err.exitCode = code;
        reject(err);
      }
    });
    child.stdin.end(payload);
  });
}

// tmux set-buffer + paste-buffer (not `send-keys -l`) so arbitrary
// multi-line/quoted payloads reach the pane safely -- the payload travels
// over stdin ($(cat)) and never gets embedded in the remote command string.
function tmuxSshDispatch(payload, line) {
  return new Promise((resolve, reject) => {
    if (!line.dispatch_tmux_session) return reject(new Error(`Line "${line.line_id}" has no dispatch_tmux_session configured`));
    const session = shq(line.dispatch_tmux_session);
    const remoteCmd = `tmux set-buffer -b engineering-console -- "$(cat)" && tmux paste-buffer -b engineering-console -d -t ${session} && tmux send-keys -t ${session} Enter`;
    const child = spawn("/usr/bin/ssh", [
      "-T",
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=accept-new",
      "-o", "ConnectTimeout=5",
      ...sshPortArgs(line),
      sshTarget(line),
      remoteCmd,
    ], { stdio: ["pipe", "pipe", "pipe"] });
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 12_000);
    child.stderr.on("data", chunk => { stderr += chunk.toString(); });
    child.on("error", reject);
    child.on("close", code => {
      clearTimeout(timer);
      if (code === 0) resolve();
      else {
        const err = new Error(stderr.trim() || `tmux dispatch exited ${code}`);
        err.exitCode = code;
        reject(err);
      }
    });
    child.stdin.end(payload);
  });
}

function readWorkerReport(line) {
  if (!line?.dispatch_mode) return Promise.reject(new Error(`Line "${line?.line_id || "(unknown)"}" has no dispatch configuration`));
  if (line.dispatch_mode === "ssh-relay") return sshRelayReadReport(line);
  if (line.dispatch_mode === "tmux-ssh") return tmuxSshReadReport(line);
  return Promise.reject(new Error(`Unsupported dispatch mode "${line.dispatch_mode}" for line "${line.line_id}"`));
}

function sshRelayReadReport(line) {
  return new Promise((resolve, reject) => {
    if (!line.dispatch_report_key_path) return reject(new Error(`Line "${line.line_id}" has no dispatch_report_key_path configured`));
    const child = spawn("/usr/bin/ssh", [
      "-T",
      "-i", line.dispatch_report_key_path,
      "-o", "IdentitiesOnly=yes",
      "-o", `UserKnownHostsFile=${SSH_RELAY_KNOWN_HOSTS}`,
      "-o", "BatchMode=yes",
      "-o", "ConnectTimeout=5",
      ...sshPortArgs(line),
      sshTarget(line),
    ], { stdio: ["ignore", "pipe", "pipe"] });
    const chunks = [];
    let size = 0;
    let stderr = "";
    const timer = setTimeout(() => child.kill("SIGKILL"), 12_000);
    child.stdout.on("data", chunk => {
      size += chunk.length;
      if (size <= 128 * 1024) chunks.push(chunk);
      else child.kill("SIGKILL");
    });
    child.stderr.on("data", chunk => { stderr += chunk.toString(); });
    child.on("error", reject);
    child.on("close", code => {
      clearTimeout(timer);
      if (code === 0 && size <= 128 * 1024) resolve(Buffer.concat(chunks).toString("utf8"));
      else reject(new Error(stderr.trim() || `report read exited ${code}`));
    });
  });
}

function tmuxSshReadReport(line) {
  return new Promise((resolve, reject) => {
    if (!line.report_source_path) return reject(new Error("No report available yet for this line."));
    const remoteCmd = `cat ${shq(`${line.report_source_path}/latest.txt`)} 2>/dev/null`;
    const child = spawn("/usr/bin/ssh", [
      "-T",
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=accept-new",
      "-o", "ConnectTimeout=6",
      ...sshPortArgs(line),
      sshTarget(line),
      remoteCmd,
    ], { stdio: ["ignore", "pipe", "pipe"] });
    const chunks = [];
    let size = 0;
    const timer = setTimeout(() => child.kill("SIGKILL"), 10_000);
    child.stdout.on("data", chunk => {
      size += chunk.length;
      if (size <= 128 * 1024) chunks.push(chunk);
      else child.kill("SIGKILL");
    });
    child.on("error", () => reject(new Error("No report available yet for this line.")));
    child.on("close", code => {
      clearTimeout(timer);
      const text = Buffer.concat(chunks).toString("utf8");
      if (code === 0 && text.trim()) resolve(text);
      else reject(new Error("No report available yet for this line."));
    });
  });
}

function tmuxSessionExists(line) {
  return new Promise((resolve) => {
    if (!line.dispatch_tmux_session) return resolve(false);
    const child = spawn("/usr/bin/ssh", [
      "-T",
      "-o", "BatchMode=yes",
      "-o", "StrictHostKeyChecking=accept-new",
      "-o", "ConnectTimeout=5",
      ...sshPortArgs(line),
      sshTarget(line),
      `tmux has-session -t ${shq(line.dispatch_tmux_session)} 2>/dev/null`,
    ], { stdio: ["ignore", "ignore", "ignore"] });
    const timer = setTimeout(() => { child.kill("SIGKILL"); resolve(false); }, 8_000);
    child.on("error", () => { clearTimeout(timer); resolve(false); });
    child.on("close", code => { clearTimeout(timer); resolve(code === 0); });
  });
}

async function countPendingDraftsForLine(lineId) {
  let count = 0;
  for (const name of await readdir(STORE)) {
    if (!/^draft-[A-Za-z0-9-]+\.json$/.test(name)) continue;
    try {
      const record = JSON.parse(await readFile(path.join(STORE, name), "utf8"));
      if (record.line_id === lineId && (record.status === "PENDING_NOT_SENT" || record.status === "SEND_FAILED_RETRY_ALLOWED")) count += 1;
    } catch {}
  }
  return count;
}

// Aboardable (ssh-relay) keeps the exact status mechanism it always had --
// the same webhook-fed WORKER_STATUS_FILE and REPORT_EVENTS_PATH, only now
// reached by line_id instead of implicitly. ChairFly (tmux-ssh) gets a
// deliberately minimal, honest check -- does its tmux session exist -- not
// a full heartbeat system it has no infrastructure for.
async function getWorkerStatus(line) {
  const observedAt = new Date().toISOString();
  const pendingDrafts = await countPendingDraftsForLine(line.line_id);

  if (line.dispatch_mode === "ssh-relay") {
    let worker = { state: "unavailable", process: null, terminal_attached: false, last_heartbeat_at: null };
    try {
      const stored = JSON.parse(await readFile(WORKER_STATUS_FILE, "utf8"));
      const heartbeatTime = new Date(stored.received_at).getTime();
      const fresh = Number.isFinite(heartbeatTime) && Date.now() - heartbeatTime < 15_000;
      worker.last_heartbeat_at = stored.received_at || null;
      if (fresh) {
        worker.state = /^(ready|working)$/.test(stored.state) ? stored.state : "unavailable";
        worker.process = stored.process || null;
        worker.terminal_attached = Boolean(stored.attached);
      }
    } catch {}

    let lastReportUpdatedAt = null;
    let lastReportReceivedAt = null;
    try {
      const events = JSON.parse(await readFile(REPORT_EVENTS_PATH, "utf8"));
      if (Array.isArray(events) && events[0]) {
        lastReportUpdatedAt = events[0].updated_at || null;
        lastReportReceivedAt = events[0].received_at || null;
      }
    } catch {}

    return { worker, pending_drafts: pendingDrafts, last_report_updated_at: lastReportUpdatedAt, last_report_received_at: lastReportReceivedAt, observed_at: observedAt };
  }

  if (line.dispatch_mode === "tmux-ssh") {
    let worker = { state: "unavailable", process: null, terminal_attached: false, last_heartbeat_at: null };
    if (await tmuxSessionExists(line)) {
      worker = { state: "ready", process: line.dispatch_tmux_session, terminal_attached: true, last_heartbeat_at: observedAt };
    }
    return {
      worker,
      pending_drafts: pendingDrafts,
      last_report_updated_at: line.reports?.[0]?.detected_at || null,
      last_report_received_at: null,
      observed_at: observedAt,
    };
  }

  return { worker: { state: "unavailable", process: null, terminal_attached: false, last_heartbeat_at: null }, pending_drafts: pendingDrafts, last_report_updated_at: null, last_report_received_at: null, observed_at: observedAt };
}

// --- Production Line Onboarding: compact status strip on the Approval Inbox
// mcp-poc has no filesystem access to /home/controller (ProtectHome=true),
// so it never touches controller.db or the onboarding CLI directly -- it
// only calls console-api's already-Bearer-authed /v1/lines* JSON routes
// over localhost, using a read copy of that same secret kept in mcp-poc's
// own credentials directory. This never breaks the Approval Inbox: any
// failure here (console-api down, secret missing) renders nothing.
let cachedConsoleApiSecret = null;
async function consoleApiSecret() {
  if (!cachedConsoleApiSecret) cachedConsoleApiSecret = (await readFile(CONSOLE_API_SECRET_PATH, "utf8")).trim();
  return cachedConsoleApiSecret;
}

async function consoleApiFetch(pathname, options = {}) {
  const secret = await consoleApiSecret();
  const response = await fetch(`${CONSOLE_API_ORIGIN}${pathname}`, {
    ...options,
    headers: { authorization: `Bearer ${secret}`, "content-type": "application/json", ...(options.headers || {}) },
  });
  if (!response.ok) throw new Error(`console API ${pathname} returned ${response.status}`);
  return response.json();
}

// Every dispatch/status/report call resolves through this -- an unknown or
// non-active line_id is a hard error, never a default or guessed target.
async function resolveLine(lineId) {
  if (lineId === undefined || lineId === null || lineId === "") {
    throw new Error("line_id is required (added when per-line routing shipped -- this is not an outage). If this MCP connector was already connected before that change, its cached tool list is stale: disconnect and reconnect the connector (or start a new session) to pick up the new required line_id parameter, then retry.");
  }
  if (typeof lineId !== "string" || !/^[a-z][a-z0-9-]{2,39}$/.test(lineId)) {
    throw new Error(`"${lineId}" is not a valid line_id`);
  }
  let line;
  try {
    line = await consoleApiFetch(`/v1/lines/${encodeURIComponent(lineId)}`);
  } catch (err) {
    throw new Error(`Could not resolve line_id "${lineId}": ${err.message}`);
  }
  if (!line || !line.line_id) throw new Error(`Unknown production line: ${lineId}`);
  if (line.status !== "active") throw new Error(`Line "${lineId}" is not active (status: ${line.status})`);
  return line;
}

const LINE_STATUS_COLOR = { active: "#2f8f4e", onboarding: "#a87a1f", paused: "#8a8a86", retired: "#8a8a86", archived: "#8a8a86" };

function lineDotHtml(line) {
  const color = LINE_STATUS_COLOR[line.status] || "#8a8a86";
  const label = escapeHtml(line.display_name || line.line_id);
  const detailParts = [line.status, line.ingestion_enabled ? "ingestion on" : "ingestion off"];
  if (line.last_ingested_at) detailParts.push(`last report ${line.last_ingested_at}`);
  const detail = escapeHtml(detailParts.join(" · "));
  return `<button type="button" class="line-dot" data-line-detail="${detail}" aria-expanded="false"><span style="color:${color}">●</span> ${label}</button>`;
}

async function linesStripHtml() {
  try {
    const { lines } = await consoleApiFetch("/v1/lines");
    if (!Array.isArray(lines) || !lines.length) {
      return `<div id="lines-strip" class="lines-strip"><a class="lines-add" href="${LINES_BASE}">+ Add line</a></div>`;
    }
    const dots = lines.map(lineDotHtml).join("");
    return `<div id="lines-strip" class="lines-strip">${dots}<a class="lines-add" href="${LINES_BASE}">+ Add line</a><div id="lines-strip-detail" class="lines-strip-detail" hidden></div></div>`;
  } catch {
    return "";
  }
}

await mkdir(STORE, { recursive: true });
await loadOAuthState();

function send(res, status, body) {
  const data = body === undefined ? "" : JSON.stringify(body);
  res.writeHead(status, {
    "content-type": "application/json; charset=utf-8",
    "content-length": Buffer.byteLength(data),
    "cache-control": "no-store",
  });
  res.end(data);
}

function sendHtml(res, status, html, extraHeaders = {}) {
  html = html.replace('<div id="status-banner" class="status"', '<div id="status-banner" class="status" style="display:block;visibility:hidden;min-height:1.25em"');
  html = html.replace('banner.className="status visible "+type', 'banner.className="status visible "+type;banner.style.visibility="visible"');
  html = html.replace('const banner=document.getElementById("status-banner");function setBanner', 'const banner=document.getElementById("status-banner");function updateStatusLine(){const text=document.getElementById("draft-list")?.textContent||"";const worker=text.includes("Working")?"Worker working":text.includes("Ready")?"Worker idle":"Worker disconnected";const count=(text.match(/PENDING_NOT_SENT/g)||[]).length;const now=new Date().toLocaleString("en-SG",{timeZone:"Asia/Singapore",day:"2-digit",month:"short",year:"numeric",hour:"numeric",minute:"2-digit",second:"2-digit",hour12:true}).toUpperCase();banner.textContent=now+" SGT | "+worker+" | "+count+" pending draft"+(count===1?"":"s");banner.className="status visible "+(worker==="Worker disconnected"?"error":"success");banner.style.visibility="visible"}updateStatusLine();function setBanner');
  html = html.replace('setInterval(refreshInbox,3000);', 'setInterval(refreshInbox,3000);setInterval(updateStatusLine,1000);');
  html = html.replace('setInterval(refreshInbox,3000);setInterval(updateStatusLine,1000);', 'document.querySelectorAll(".draft-card").forEach(card=>{if(card.querySelector(".edit-draft"))return;const trigger=document.createElement("button");trigger.type="button";trigger.className="edit-draft";trigger.textContent="Edit";const actions=card.querySelector(".draft-actions");if(actions)actions.prepend(trigger);trigger.addEventListener("click",async()=>{const body=card.querySelector(".message-body")||card.querySelector(".message-preview");const form=card.querySelector(".send-form");const token=form?.querySelector("input[name=token]")?.value||"";const draftId=card.dataset.draftId||"";const edited=window.prompt("Edit this pending draft. It will not be sent until you press Send.",body?.textContent||"");if(edited===null||!edited.trim())return;trigger.disabled=true;try{const response=await fetch(inboxPath+"/edit/"+encodeURIComponent(draftId),{method:"POST",body:new URLSearchParams({token,text:edited}),credentials:"same-origin"});if(!response.ok)throw new Error("Draft was not changed");setBanner(shortDraftReference(draftId)+" updated.","success");await refreshInbox()}catch(error){setBanner(error.message,"error")}finally{trigger.disabled=false}})});setInterval(refreshInbox,3000);setInterval(updateStatusLine,1000);');
  html = html.replace('document.addEventListener("submit",async event=>', 'document.addEventListener("click",async event=>{const trigger=event.target.closest("[data-edit-draft]");if(!trigger)return;const card=trigger.closest(".draft-card");const form=card?.querySelector(".send-form");const body=card?.querySelector(".message-body")||card?.querySelector(".message-preview");const draftId=card?.dataset.draftId||"";const token=form?.querySelector("input[name=token]")?.value||"";const edited=window.prompt("Edit this pending draft. It will not be sent until you press Send.",body?.textContent||"");if(edited===null||!edited.trim())return;trigger.disabled=true;try{const response=await fetch(inboxPath+"/edit/"+encodeURIComponent(draftId),{method:"POST",body:new URLSearchParams({token,text:edited}),credentials:"same-origin"});if(!response.ok)throw new Error("Draft was not changed");setBanner(shortDraftReference(draftId)+" updated.","success");await refreshInbox()}catch(error){setBanner(error.message,"error")}finally{trigger.disabled=false}});document.addEventListener("submit",async event=>');
  html = html.replace('if(summary&&list&&history){document.getElementById("pending-summary").innerHTML=summary.innerHTML;', 'if(summary&&list&&history){const openDetails=document.querySelectorAll("details[open]").length;document.getElementById("pending-summary").innerHTML=summary.innerHTML;');
  html = html.replace('document.getElementById("recent-history").innerHTML=history.innerHTML;applyReportReadState()', 'document.getElementById("recent-history").innerHTML=history.innerHTML;document.querySelectorAll("details").forEach((item,index)=>{if(index<openDetails)item.open=true});applyReportReadState()');
  html = html.replace('const discarding=button.classList.contains("discard");submitting=true;', 'const discarding=button.classList.contains("discard");submitting=true;');
  html = html.replace('</style>', '.window-inactive::after{background:rgba(205,220,229,.38);backdrop-filter:none;color:#42515b}body{font-size:13px;min-width:0;overflow-x:hidden}header h1{font-size:clamp(22px,4vw,30px)}article{padding:12px;margin:10px 0;min-width:0}.draft-head>div:first-child{min-width:0}.draft-head h2,.draft-id,.history code{overflow-wrap:anywhere;word-break:break-word}pre{font-size:12px;padding:10px;max-width:100%;box-sizing:border-box;overflow-wrap:anywhere}.draft-actions{flex-shrink:1}.edit-bottom{margin-top:6px}.edit-draft{background:white;color:#245b78;border:1px solid #7aa8be;border-radius:7px}.status{padding:5px 9px!important;margin:4px 0!important;min-height:0!important}.history h2{font-size:16px}.history li{padding:9px;margin:6px 0;min-width:0}.unread-report{background:#f8e2df!important;border-color:#b94a3c!important;color:#6f1e17!important}.unread-report .new-badge{background:#b23b2c}.draft-card{border:1px solid #aaa!important;background:white;box-shadow:none}section:not(.history){background:transparent!important;border:0!important;border-radius:0!important;padding:0!important;margin:8px 0 12px!important}section:not(.history)>strong:first-child{display:none}#pending-summary{display:none!important}.history{background:transparent!important;border:0!important;border-radius:0!important;padding:0!important;margin:20px 0!important}</style>');
  res.writeHead(status, {
    "content-type": "text/html; charset=utf-8",
    "content-length": Buffer.byteLength(html),
    "cache-control": "no-store",
    "x-frame-options": "DENY",
    ...extraHeaders,
  });
  res.end(html);
}

function hasOwnerInboxCookie(req) {
  const cookies = String(req.headers.cookie || "").split(";").map(value => value.trim());
  const match = cookies.find(value => value.startsWith("owner_inbox="));
  return Boolean(match) && safeEqual(match.slice("owner_inbox=".length), INBOX_COOKIE_VALUE);
}

function hasOwnerInboxAuthorization(req) {
  return hasOwnerInboxCookie(req);
}

function ownerLoginHtml(error = "") {
  const errorHtml = error ? `<p class="error">${error}</p>` : "";
  return `<!doctype html><meta name="viewport" content="width=device-width"><title>Engineering Control Login</title><style>body{font:17px system-ui;max-width:440px;margin:0 auto;padding:28px 20px;color:#171711;background:#f7f7f4}main{background:white;border:1px solid #aaa;border-radius:14px;padding:24px;margin-top:4vh}h1{margin:0 0 10px}input,button{box-sizing:border-box;font:inherit;width:100%;padding:13px;margin-top:10px}input{font-size:22px;letter-spacing:.35em}button{background:#171711;color:white;border:0;border-radius:8px;font-weight:650}.error{background:#f7dfdc;color:#7b2118;padding:12px;border-radius:8px}</style><main><h1>Engineering Control</h1><p><strong>Approval Inbox</strong></p><p>Enter your private four-digit PIN once. This browser will remain signed in for 30 days.</p>${errorHtml}<form id="login-form" method="post" action="${INBOX_BASE}"><input type="hidden" name="intent" value="login"><label>Private owner PIN<input name="owner_code" type="password" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" required autocomplete="current-password"></label><button type="submit">Log in</button></form></main>`;
}

function opaque(bytes = 32) {
  return randomBytes(bytes).toString("base64url");
}

function bearer(req) {
  const value = req.headers.authorization || "";
  return value.startsWith("Bearer ") ? value.slice(7) : "";
}

function safeEqual(a, b) {
  const aa = Buffer.from(a || "");
  const bb = Buffer.from(b || "");
  return aa.length === bb.length && timingSafeEqual(aa, bb);
}

async function verifyOwnerCode(candidate) {
  try {
    const credential = JSON.parse(await readFile(CREDENTIAL_PATH, "utf8"));
    const derived = scryptSync(candidate, Buffer.from(credential.salt, "hex"), 32).toString("hex");
    return safeEqual(derived, credential.hash);
  } catch (err) {
    if (err?.code !== "ENOENT") return false;
    return Boolean(OWNER_CODE) && safeEqual(candidate, OWNER_CODE);
  }
}

async function readBody(req) {
  let size = 0;
  const chunks = [];
  for await (const chunk of req) {
    size += chunk.length;
    if (size > MAX_BODY) throw new Error("body too large");
    chunks.push(chunk);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function result(id, value) {
  return { jsonrpc: "2.0", id, result: value };
}

function error(id, code, message) {
  return { jsonrpc: "2.0", id: id ?? null, error: { code, message } };
}

function escapeHtml(value) {
  return String(value || "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
}

function draftSubject(text) {
  const lines = String(text || "")
    .split(/\n+/)
    .map(line => line.replace(/^\s*(?:[-*•]|\d+[.)])\s*/, "").replace(/\s+/g, " ").trim())
    .filter(Boolean);
  const action = lines.find(line => /^(?:add|build|change|commit|continue|create|delete|design|fix|implement|investigate|remove|replace|resolve|review|revert|update)\b/i);
  const chosen = action || lines[0] || "Worker request";
  return chosen.length > 76 ? `${chosen.slice(0, 73).trimEnd()}…` : chosen;
}

function draftReference(draftId) {
  const compact = String(draftId || "").replace(/[^A-Za-z0-9]/g, "");
  return `Draft ${compact.slice(-6).toUpperCase() || "------"}`;
}

async function handleRpc(rpc) {
  const { id, method, params } = rpc;

  if (method === "initialize") {
    return result(id, {
      protocolVersion: "2025-06-18",
      capabilities: { tools: { listChanged: true } },
      serverInfo: { name: "aboardable-draft-poc", version: "0.1.0" },
    });
  }

  if (method === "notifications/initialized" || method?.startsWith("notifications/")) {
    return null;
  }

  if (method === "ping") return result(id, {});

  if (method === "tools/list") {
    return result(id, {
      tools: [{
        name: "create_worker_draft",
        description: "POC only: save text as a pending draft for a specific production line. This NEVER executes or sends the text to a worker.",
        inputSchema: {
          type: "object",
          properties: {
            text: { type: "string", description: "Draft instructions, maximum 4096 characters." },
            line_id: { type: "string", description: "Target production line id (e.g. aboardable-product, chairfly-product). Required -- a draft is never sent to a default or guessed line." },
          },
          required: ["text", "line_id"],
          additionalProperties: false,
        },
      }, {
        name: "read_worker_report",
        description: "Read the target production line's latest report. Read-only: cannot type into the worker, run project commands, or modify files.",
        inputSchema: {
          type: "object",
          properties: {
            line_id: { type: "string", description: "Target production line id (e.g. aboardable-product, chairfly-product). Required." },
          },
          required: ["line_id"],
          additionalProperties: false,
        },
      }, {
        name: "get_worker_status",
        description: "Read a specific production line's worker status, terminal attachment state, pending-draft count, and latest report timestamp. Strictly read-only: cannot create, approve, send, delete, or modify drafts; cannot type into or control the worker.",
        inputSchema: {
          type: "object",
          properties: {
            line_id: { type: "string", description: "Target production line id (e.g. aboardable-product, chairfly-product). Required." },
          },
          required: ["line_id"],
          additionalProperties: false,
        },
      }],
    });
  }

  if (method === "tools/call") {
    if (params?.name === "get_worker_status") {
      try {
        const line = await resolveLine(params?.arguments?.line_id);
        const status = await getWorkerStatus(line);
        const stateLabel = status.worker.state === "ready" ? "Ready" : status.worker.state === "working" ? "Working" : "Unavailable";
        const text = [
          `Production line: ${line.display_name} (${line.line_id})`,
          `Product worker: ${stateLabel}`,
          `Process: ${status.worker.process || "none"}`,
          `Terminal attached: ${status.worker.terminal_attached ? "yes" : "no"}`,
          `Pending drafts: ${status.pending_drafts}`,
          `Last heartbeat: ${status.worker.last_heartbeat_at || "none"}`,
          `Last report update: ${status.last_report_updated_at || "none"}`,
        ].join("\n");
        return result(id, {
          content: [{ type: "text", text }],
          structuredContent: { ...status, line_id: line.line_id },
          isError: false,
        });
      } catch (err) {
        return result(id, {
          content: [{ type: "text", text: `Worker status could not be read: ${String(err.message || err).slice(0, 300)}` }],
          isError: true,
        });
      }
    }
    if (params?.name === "read_worker_report") {
      try {
        const line = await resolveLine(params?.arguments?.line_id);
        const report = await readWorkerReport(line);
        const sha256 = createHash("sha256").update(report).digest("hex");
        return result(id, {
          content: [{ type: "text", text: report }],
          structuredContent: { line_id: line.line_id, source: line.report_source_path ? `${line.report_source_path}/latest.txt` : "unknown", bytes: Buffer.byteLength(report), sha256 },
          isError: false,
        });
      } catch (err) {
        return result(id, {
          content: [{ type: "text", text: `The worker report could not be read: ${String(err.message || err).slice(0, 300)}` }],
          isError: true,
        });
      }
    }
    if (params?.name !== "create_worker_draft") {
      return error(id, -32602, "Unknown tool");
    }
    const text = params?.arguments?.text;
    if (typeof text !== "string" || text.length < 1 || text.length > MAX_TEXT) {
      return error(id, -32602, `text must contain 1-${MAX_TEXT} characters`);
    }
    let line;
    try {
      line = await resolveLine(params?.arguments?.line_id);
    } catch (err) {
      return error(id, -32602, String(err.message || err));
    }

    const draftId = `draft-${new Date().toISOString().replace(/[:.]/g, "-")}-${randomUUID()}`;
    const sha256 = createHash("sha256").update(text).digest("hex");
    const record = {
      draft_id: draftId,
      line_id: line.line_id,
      status: "PENDING_NOT_SENT",
      created_at: new Date().toISOString(),
      sha256,
      text,
      approval_token: opaque(24),
    };
    await writeFile(path.join(STORE, `${draftId}.json`), JSON.stringify(record, null, 2), { flag: "wx", mode: 0o600 });

    return result(id, {
      content: [{
        type: "text",
        text: `Draft saved but NOT sent or executed. Line: ${line.display_name} (${line.line_id}). Draft ID: ${draftId}. SHA-256: ${sha256}. The owner must personally open this approval page and enter the private owner code: ${PUBLIC_ORIGIN}${APPROVE_BASE}/${draftId}?token=${record.approval_token}`,
      }],
      structuredContent: { draft_id: draftId, line_id: line.line_id, status: "PENDING_NOT_SENT", sha256 },
      isError: false,
    });
  }

  return error(id, -32601, "Method not found");
}

const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, PUBLIC_ORIGIN);

  if (req.method === "POST" && url.pathname === REPORT_NOTIFY_PATH) {
    const form = new URLSearchParams(await readBody(req));
    const updatedAt = form.get("updated_at") || "";
    if (!/^\d{2} [A-Z][a-z]{2} \d{4}, \d{1,2}:\d{2}:\d{2} (AM|PM) SGT$/.test(updatedAt)) {
      return send(res, 400, { ok: false, error: "invalid timestamp" });
    }
    let events = [];
    try {
      events = JSON.parse(await readFile(REPORT_EVENTS_PATH, "utf8"));
      if (!Array.isArray(events)) events = [];
    } catch (err) {
      if (err?.code !== "ENOENT") return send(res, 500, { ok: false });
    }
    if (!events.some(event => event.updated_at === updatedAt)) {
      events.unshift({
        id: randomUUID(),
        message: `📄 Product worker report updated\nFile: ~/.claude-report.md\nUpdated: ${updatedAt}`,
        updated_at: updatedAt,
        received_at: new Date().toISOString(),
      });
      await writeFile(REPORT_EVENTS_PATH, JSON.stringify(events.slice(0, 20), null, 2), { mode: 0o600 });
    }
    return send(res, 200, { ok: true });
  }

  if (req.method === "GET" && url.pathname === MANIFEST_PATH) {
    return send(res, 200, { name: "Engineering Control", short_name: "Engineering Control", start_url: INBOX_BASE, display: "standalone", background_color: "#f7f7f4", theme_color: "#171711", icons: [] });
  }
  if (req.method === "GET" && url.pathname === SERVICE_WORKER_PATH) {
    res.writeHead(200, { "Content-Type": "application/javascript; charset=utf-8", "Service-Worker-Allowed": "/", "Cache-Control": "no-store" });
    return res.end("self.addEventListener('install',()=>self.skipWaiting()); self.addEventListener('activate',()=>self.clients.claim());");
  }

  if (req.method === "POST" && url.pathname === WORKER_STATUS_PATH) {
    const form = new URLSearchParams(await readBody(req));
    const state = form.get("state") || "";
    const processName = form.get("process") || "";
    const attached = form.get("attached") === "1";
    if (!/^(ready|working|unavailable)$/.test(state) || !/^[A-Za-z0-9._-]{0,40}$/.test(processName)) {
      return send(res, 400, { ok: false });
    }
    await writeFile(WORKER_STATUS_FILE, JSON.stringify({ state, process: processName, attached, received_at: new Date().toISOString() }, null, 2), { mode: 0o600 });
    return send(res, 200, { ok: true });
  }

  if ((req.method === "GET" || req.method === "POST") && url.pathname === RESET2_BASE) {
    try {
      await readFile(RESET2_CONSUMED_PATH, "utf8");
      return sendHtml(res, 410, "<h1>Corrected PIN reset already used</h1><p>This one-time page is permanently locked.</p>");
    } catch (err) {
      if (err?.code !== "ENOENT") return sendHtml(res, 500, "<h1>PIN reset unavailable</h1>");
    }
    if (req.method === "GET") {
      return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Corrected owner PIN reset</title><style>body{font:17px system-ui;max-width:600px;margin:8vh auto;padding:24px}input,button{font:inherit;padding:12px;margin:8px 0 18px;letter-spacing:.25em}button{display:block;background:#171711;color:white;border:0;border-radius:8px;letter-spacing:normal}</style><h1>Corrected owner PIN reset</h1><p>The digits are visible so browser password autofill cannot silently replace them.</p><form method="post"><label>New four-digit PIN<br><input name="new_code" type="text" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" required autocomplete="one-time-code" data-lpignore="true"></label><br><label>Confirm PIN<br><input name="confirm_code" type="text" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" required autocomplete="one-time-code" data-lpignore="true"></label><button type="submit">Set and verify PIN</button></form>`);
    }
    const form = new URLSearchParams(await readBody(req));
    const newCode = form.get("new_code") || "";
    if (!/^[0-9]{4}$/.test(newCode) || newCode !== (form.get("confirm_code") || "")) {
      return sendHtml(res, 400, "<h1>PINs did not match</h1><p>Use exactly four visible digits.</p>");
    }
    const salt = randomBytes(16);
    const hash = scryptSync(newCode, salt, 32).toString("hex");
    const tempPath = `${CREDENTIAL_PATH}.reset2`;
    try {
      await writeFile(tempPath, JSON.stringify({ version: 1, algorithm: "scrypt", salt: salt.toString("hex"), hash, created_at: new Date().toISOString(), reason: "corrected_visible_pin_reset" }, null, 2), { flag: "wx", mode: 0o600 });
      await rename(tempPath, CREDENTIAL_PATH);
      if (!(await verifyOwnerCode(newCode))) throw new Error("post-write verification failed");
      await writeFile(RESET2_CONSUMED_PATH, new Date().toISOString(), { flag: "wx", mode: 0o600 });
    } catch {
      return sendHtml(res, 500, "<h1>PIN verification failed</h1><p>The page did not confirm success. Ask Sean's assistant to inspect the credential state.</p>");
    }
    return sendHtml(res, 200, "<h1>PIN set and verified</h1><p>The server immediately verified the same four digits against the stored hash. This reset page is now locked.</p>");
  }

  if ((req.method === "GET" || req.method === "POST") && url.pathname === RESET_BASE) {
    try {
      await readFile(RESET_CONSUMED_PATH, "utf8");
      return sendHtml(res, 410, "<h1>PIN reset link already used</h1><p>This one-time page is permanently locked.</p>");
    } catch (err) {
      if (err?.code !== "ENOENT") return sendHtml(res, 500, "<h1>PIN reset unavailable</h1>");
    }
    if (req.method === "GET") {
      return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Reset owner PIN</title><style>body{font:17px system-ui;max-width:600px;margin:8vh auto;padding:24px}input,button{font:inherit;padding:12px;margin:8px 0 18px}button{display:block;background:#171711;color:white;border:0;border-radius:8px}</style><h1>One-time owner PIN reset</h1><p>Choose a new four-digit PIN. This link will permanently lock after submission.</p><form method="post"><label>New four-digit PIN<br><input name="new_code" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" required autocomplete="off"></label><br><label>Confirm PIN<br><input name="confirm_code" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" required autocomplete="off"></label><button type="submit">Reset private PIN</button></form>`);
    }
    const form = new URLSearchParams(await readBody(req));
    const newCode = form.get("new_code") || "";
    if (!/^[0-9]{4}$/.test(newCode) || newCode !== (form.get("confirm_code") || "")) {
      return sendHtml(res, 400, "<h1>PINs did not match</h1><p>Use exactly four digits.</p>");
    }
    const salt = randomBytes(16);
    const hash = scryptSync(newCode, salt, 32).toString("hex");
    const tempPath = `${CREDENTIAL_PATH}.reset`;
    try {
      await writeFile(RESET_CONSUMED_PATH, new Date().toISOString(), { flag: "wx", mode: 0o600 });
      await writeFile(tempPath, JSON.stringify({ version: 1, algorithm: "scrypt", salt: salt.toString("hex"), hash, created_at: new Date().toISOString(), reason: "owner_requested_reset" }, null, 2), { flag: "wx", mode: 0o600 });
      await rename(tempPath, CREDENTIAL_PATH);
    } catch {
      return sendHtml(res, 500, "<h1>PIN reset could not be saved</h1><p>Do not retry this page. Ask Sean's assistant to inspect the credential state.</p>");
    }
    return sendHtml(res, 200, "<h1>Private owner PIN reset</h1><p>Your new four-digit PIN is active. This reset page is now permanently locked.</p><p>You may close this page.</p>");
  }

  if (req.method === "POST" && url.pathname === `${INBOX_BASE}/logout`) {
    res.writeHead(303, {
      location: INBOX_BASE,
      "cache-control": "no-store",
      "set-cookie": "owner_inbox=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0",
    });
    res.end();
    return;
  }

  if (req.method === "POST" && url.pathname === INBOX_BASE) {
    const form = new URLSearchParams(await readBody(req));
    if (form.get("intent") !== "login") return sendHtml(res, 400, "<h1>Invalid request</h1>");
    if (loginFailures.blockedUntil > Date.now()) {
      return sendHtml(res, 429, ownerLoginHtml("Too many incorrect attempts. Login is locked for 30 minutes."));
    }
    if (!(await verifyOwnerCode(form.get("owner_code") || ""))) {
      const attempts = loginFailures.attempts + 1;
      loginFailures = attempts >= 5 ? { attempts, blockedUntil: Date.now() + 30 * 60_000 } : { attempts, blockedUntil: 0 };
      return sendHtml(res, 403, ownerLoginHtml("Incorrect PIN."));
    }
    loginFailures = { attempts: 0, blockedUntil: 0 };
    res.writeHead(303, {
      location: INBOX_BASE,
      "cache-control": "no-store",
      "set-cookie": `owner_inbox=${INBOX_COOKIE_VALUE}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=2592000`,
    });
    res.end();
    return;
  }

  if (req.method === "GET" && url.pathname === INBOX_BASE) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const allRecords = [];
    for (const name of await readdir(STORE)) {
      if (!/^draft-[A-Za-z0-9-]+\.json$/.test(name)) continue;
      try {
        const record = JSON.parse(await readFile(path.join(STORE, name), "utf8"));
        allRecords.push(record);
      } catch {}
    }
    let lineNameById = new Map();
    try {
      const { lines } = await consoleApiFetch("/v1/lines");
      for (const l of lines || []) lineNameById.set(l.line_id, l.display_name || l.line_id);
    } catch {}
    function lineLabelFor(record) {
      if (!record.line_id) return "";
      const name = lineNameById.get(record.line_id) || record.line_id;
      return escapeHtml(name.replace(/\bProduct\b/gi, "").replace(/\s+/g, " ").trim());
    }
    const records = allRecords.filter(record => record.status === "PENDING_NOT_SENT" || record.status === "SEND_FAILED_RETRY_ALLOWED");
    records.sort((a, b) => String(b.created_at).localeCompare(String(a.created_at)));
    let cards = records.map(record => {
      const subject = escapeHtml(draftSubject(record.text));
      const reference = escapeHtml(draftReference(record.draft_id));
      const cardLineLabel = lineLabelFor(record);
      const lineBadge = cardLineLabel ? `<span class="draft-line-badge">${cardLineLabel}</span>` : "";
      const preview = record.text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
      const shortPreview = String(record.text || "").slice(0, 220).trimEnd().replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
      const messageBody = String(record.text || "").length > 220
        ? `<details class="message-details"><summary><span class="message-preview">${shortPreview}…</span><span class="toggle-label"></span></summary><pre class="message-body">${preview}</pre></details>`
        : `<pre class="message-body">${preview}</pre>`;
      return `<div class="draft-row" data-draft-id="${record.draft_id}"><form class="swipe-delete" method="post" data-draft-id="${record.draft_id}"><input type="hidden" name="token" value="${record.approval_token}"><button formaction="${INBOX_BASE}/discard/${record.draft_id}" class="discard delete-action">Delete</button></form><article class="draft-card" data-draft-id="${record.draft_id}" ontouchstart="this.dataset.swipeX=event.touches[0].clientX" ontouchmove="const d=Math.max(0,Math.min(96,event.touches[0].clientX-Number(this.dataset.swipeX||0)));this.dataset.swipeD=d;this.style.transform='translateX('+d+'px)'" ontouchend="this.style.transform=Number(this.dataset.swipeD||0)>48?'translateX(96px)':'translateX(0)' "><div class="draft-head"><div><h2>${subject}</h2>${lineBadge}<code class="draft-id" title="${record.draft_id}">${reference}</code><p><strong>${record.status}</strong> · ${record.created_at}</p></div><div class="draft-actions"><form class="desktop-delete" method="post" data-draft-id="${record.draft_id}"><input type="hidden" name="token" value="${record.approval_token}"><button formaction="${INBOX_BASE}/discard/${record.draft_id}" class="discard">Delete</button></form><form class="send-form" method="post" data-draft-id="${record.draft_id}"><input type="hidden" name="token" value="${record.approval_token}"><button formaction="${APPROVE_BASE}/${record.draft_id}" class="send">Send</button></form></div></div>${messageBody}<p class="swipe-hint">Swipe right to reveal Delete</p></article></div>`;
    }).join("");
    if (cards) cards = `<style>.draft-row{position:relative;overflow:hidden;margin:12px 0;border-radius:10px}.draft-card{position:relative;z-index:1;margin:0;transition:transform .18s ease;touch-action:pan-y;background:white}.draft-head{display:flex;align-items:flex-start;justify-content:space-between;gap:12px}.draft-head h2{margin:0 0 5px;font-size:16px;line-height:1.25;word-break:normal}.draft-head .draft-line-badge{display:table;margin:0 0 6px auto}.draft-id{display:block;margin:0 0 5px;color:#777;font-size:10px;line-height:1.25;word-break:break-all}.draft-head p{margin:0}.draft-actions{display:flex;align-items:flex-start;gap:6px;flex:0 0 auto}.send-form,.desktop-delete{margin:0}.send-form .send,.desktop-delete .discard{margin:0}.message-body,.message-preview{display:block;box-sizing:border-box;width:100%;font:13px/1.4 ui-monospace,SFMono-Regular,Menlo,monospace;white-space:pre-wrap;background:#e2e3e5;padding:13px;border-radius:7px;color:#171711}.message-body{margin:12px 0 0}.message-details{margin-top:12px}.message-details summary{list-style:none;cursor:pointer}.message-details summary::-webkit-details-marker{display:none}.toggle-label{display:inline-block;margin-top:7px;color:#555;text-decoration:underline;font-weight:650}.toggle-label:after{content:'See more'}.message-details[open] .message-preview{display:none}.message-details[open] .toggle-label:after{content:'See less'}.message-details[open] .message-body{margin-top:7px}.swipe-delete{display:none;position:absolute;inset:0 auto 0 0;width:96px;margin:0;background:#9b2c22}.delete-action{width:100%;height:100%;margin:0;border:0;border-radius:0;background:#9b2c22;color:white;font-weight:700}.swipe-hint{display:none;margin:8px 0 0;color:#777;font-size:11px}@media(hover:none),(pointer:coarse){.swipe-delete{display:flex}.desktop-delete{display:none}.swipe-hint{display:block}}</style>${cards}`;
    let reportEvents = [];
    try {
      reportEvents = JSON.parse(await readFile(REPORT_EVENTS_PATH, "utf8"));
      if (!Array.isArray(reportEvents)) reportEvents = [];
    } catch (err) {
      if (err?.code !== "ENOENT") reportEvents = [];
    }
    const activity = [];
    for (const record of allRecords) {
      const recordId = escapeHtml(record.draft_id || "");
      const reference = escapeHtml(draftReference(record.draft_id));
      const subject = escapeHtml(draftSubject(record.text));
      const lineLabel = lineLabelFor(record);
      const lineBadgeSuffix = lineLabel ? ` · <span class="draft-line-badge">${lineLabel}</span>` : "";
      if (record.status === "SENT_TO_PRODUCT_WORKER" && record.sent_at) {
        const sentAt = new Date(record.sent_at).toLocaleString("en-SG", { timeZone: "Asia/Singapore", day: "2-digit", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
        const summary = String(record.text || "").replace(/\s+/g, " ").slice(0, 180).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
        activity.push({ at: record.sent_at, html: `<li class="sent-history"><strong>Sent</strong> · ${sentAt} SGT${lineBadgeSuffix}<br><code title="${recordId}">${reference}</code><p>${summary}${String(record.text || "").length > 180 ? "…" : ""}</p></li>` });
      } else if ((record.status === "PENDING_NOT_SENT" || record.status === "SEND_FAILED_RETRY_ALLOWED") && record.created_at) {
        const createdAt = new Date(record.created_at).toLocaleString("en-SG", { timeZone: "Asia/Singapore", day: "2-digit", month: "short", year: "numeric", hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true });
        activity.push({ at: record.created_at, html: `<li class="draft-created-history"><strong>Draft created</strong> · ${createdAt} SGT${lineBadgeSuffix}<br><code title="${recordId}">${reference}</code><p>${subject}</p></li>` });
      }
    }
    for (const event of reportEvents) {
      const message = String(event.message || "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
      const reportId = escapeHtml(event.id || "");
      const at = event.received_at || event.updated_at || "";
      activity.push({ at, html: `<li class="report-history" data-report-id="${reportId}" tabindex="0" title="Click to mark this report read"><div class="report-history-head"><strong>Report ready</strong><span class="new-badge">New</span></div><pre>${message}</pre></li>` });
    }
    activity.sort((a, b) => new Date(b.at).getTime() - new Date(a.at).getTime());
    const recentHistory = activity.slice(0, 15).map(item => item.html).join("");
    let workerStatus = { state: "unavailable", process: "", attached: false, received_at: "" };
    try {
      const storedStatus = JSON.parse(await readFile(WORKER_STATUS_FILE, "utf8"));
      const fresh = Date.now() - new Date(storedStatus.received_at).getTime() < 15_000;
      if (fresh) workerStatus = storedStatus;
    } catch {}
    const stateLabel = workerStatus.state === "ready" ? "Ready" : workerStatus.state === "working" ? "Working" : "Unavailable";
    const stateColor = workerStatus.state === "ready" ? "#b8bdc2" : workerStatus.state === "working" ? "#1f8a4c" : "#b23b2c";
    const checkedAt = workerStatus.received_at ? new Date(workerStatus.received_at).toLocaleString("en-SG", { timeZone: "Asia/Singapore", hour: "numeric", minute: "2-digit", second: "2-digit", hour12: true }) + " SGT" : "No heartbeat";
    const heartbeatAge = workerStatus.received_at ? Date.now() - new Date(workerStatus.received_at).getTime() : Infinity;
    const healthNotice = heartbeatAge > 15_000 ? `<div role="status" style="background:#fff2c7;color:#684b00;border:1px solid #d4ad49;border-radius:7px;padding:9px 10px;margin:0 0 11px"><strong>Connection check needed</strong><br>Worker heartbeat is stale. The page will keep checking automatically.</div>` : "";
    const latestReport = reportEvents[0]?.message ? String(reportEvents[0].message).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;") : "No report notification received yet.";
    const latestReportId = escapeHtml(reportEvents[0]?.id || "");
    const topologyHtml = `<section style="background:#fff;border:1px solid #bbb;border-radius:10px;padding:13px;margin:10px 0 14px"><strong style="display:block;margin-bottom:10px">Live worker topology</strong>${healthNotice}<div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap"><div><small>Controller inbox</small><br><strong><span style="color:#1f8a4c">●</span> Online</strong></div><span aria-hidden="true">→</span><div><small>Product worker</small><br><strong><span style="color:${stateColor}">●</span> ${stateLabel}</strong><br><small>${workerStatus.process || "No process"}${workerStatus.attached ? " · terminal attached" : ""} · ${checkedAt}</small></div></div><div class="latest-report-panel" data-report-id="${latestReportId}"><div class="report-history-head"><strong>Latest report</strong><span class="new-badge">New</span></div><pre style="margin:6px 0 0;background:transparent;padding:0">${latestReport}</pre></div></section>`;
    cards = topologyHtml + (cards || "<article><p>No pending drafts.</p></article>");
    cards = cards.replaceAll('<p class="swipe-hint">', '<div class="edit-bottom"><button type="button" class="edit-draft" data-edit-draft="1">Edit</button></div><p class="swipe-hint">');
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Engineering Control — Approval Inbox</title><style>body{font:14px system-ui;max-width:900px;margin:0 auto;padding:12px 18px 26px;color:#171711;background:#f7f7f4}header{display:flex;justify-content:space-between;align-items:center;gap:14px}header h1{margin:1px 0 6px;font-size:clamp(24px,5vw,34px)}.product-name{display:block;color:#687078;font-size:11px;font-weight:750;letter-spacing:.11em;text-transform:uppercase}.header-actions{display:flex;align-items:center;gap:10px}.header-actions form{margin:0}.link-button{border:0;background:none;padding:0;margin:0;text-decoration:underline;color:#171711}article{background:white;border:1px solid #aaa;border-radius:10px;padding:16px;margin:12px 0}h2{font-size:13px;word-break:break-all}pre{font-size:13px;line-height:1.4;white-space:pre-wrap;background:#f1f0eb;padding:13px;border-radius:7px}input,button{font:inherit;padding:9px 10px;margin:6px 7px 6px 0}button:disabled{opacity:.55}.send{background:#171711;color:white;border:0;border-radius:7px}.discard{background:white;color:#8a2f22;border:1px solid #8a2f22;border-radius:7px}a{color:#171711}.status{display:none;font-size:13px;padding:11px 13px;margin:10px 0;border-radius:8px;font-weight:650}.status.visible{display:block}.status.working{background:#fff2c7;color:#684b00}.status.success{background:#dff4e7;color:#174d2b}.status.error{background:#f7dfdc;color:#7b2118}.history{margin-top:20px}.history h2{font-size:18px}.history ul{list-style:none;padding:0}.history li{background:white;border:1px solid #ccc;border-radius:9px;padding:11px;margin:8px 0}.history li.sent-history{background:#e9e9e5;border-color:#d1d1cb;color:#686863}.draft-line-badge{display:inline-block;margin:0 6px 6px 0;padding:4px 12px;border-radius:999px;background:#e5eef2;color:#245b78;font-size:14px;font-weight:650}.history li.sent-history p{color:#777772}.history code{font-size:11px;word-break:break-all}.history p{font-size:13px;margin:6px 0 0;color:#555}.latest-report-panel{background:#e2e3e5;border:1px solid transparent;border-radius:7px;padding:10px;margin-top:11px;cursor:pointer}.report-history{cursor:pointer}.report-history-head{display:flex;align-items:center;justify-content:space-between;gap:10px}.new-badge{display:none;background:#245b78;color:white;border-radius:999px;padding:2px 7px;font-size:10px;text-transform:uppercase;letter-spacing:.05em}.unread-report{background:#e8f1f6!important;border-color:#79a9c1!important;color:#173f54!important}.unread-report .new-badge{display:inline-block}.window-inactive::after{content:'Click once to activate';position:fixed;inset:0;z-index:9999;display:flex;align-items:center;justify-content:center;background:rgba(242,242,242,.70);backdrop-filter:grayscale(1) blur(1px);color:#4b4b4b;font-size:16px;font-weight:700;pointer-events:none}.lines-strip{display:flex;flex-wrap:wrap;align-items:center;gap:4px 10px;padding:6px 2px 8px;margin:2px 0 6px;border-bottom:1px solid #ddd}.line-dot{font:inherit;font-size:12px;background:none;border:0;padding:2px 0;color:#3d3d38;cursor:pointer}.line-dot span{font-size:11px}.lines-add{margin-left:auto;font-size:12px;color:#171711;text-decoration:underline;white-space:nowrap}.lines-strip-detail{flex-basis:100%;font-size:11px;color:#5c655c;padding-top:2px}.lines-strip-detail[hidden]{display:none}@media(max-width:560px){header{align-items:flex-start}.header-actions{flex-direction:column;align-items:flex-end;gap:4px}}</style><header><div><span class="product-name">Engineering Control</span><h1>Approval Inbox</h1></div><div class="header-actions"><a href="${INBOX_BASE}">Refresh</a><form method="post" action="${INBOX_BASE}/logout"><button class="link-button" type="submit">Log out</button></form></div></header>${await linesStripHtml()}<div id="status-banner" class="status" role="status" aria-live="polite"></div><p id="pending-summary">${records.length} pending draft${records.length === 1 ? "" : "s"}.</p><main id="draft-list">${cards || "<article><p>No pending drafts.</p></article>"}</main><section class="history"><h2>Recent activity</h2><ul id="recent-history">${recentHistory || "<li>No recent sends.</li>"}</ul></section><script>function syncWindowFocus(){document.body.classList.toggle("window-inactive",!document.hasFocus())}window.addEventListener("focus",syncWindowFocus);window.addEventListener("blur",syncWindowFocus);document.addEventListener("visibilitychange",syncWindowFocus);syncWindowFocus();const reportReadKey="ownerInboxLastReadReport";function storedReportId(){try{return localStorage.getItem(reportReadKey)||""}catch{return ""}}function saveReportId(id){try{localStorage.setItem(reportReadKey,id)}catch{}}function applyReportReadState(){const latest=document.querySelector(".latest-report-panel[data-report-id]");const latestId=latest?.dataset.reportId||"";let lastRead=storedReportId();if(!lastRead&&latestId){saveReportId(latestId);lastRead=latestId}let beforeLast=true;for(const item of document.querySelectorAll(".report-history[data-report-id]")){const id=item.dataset.reportId||"";if(id===lastRead)beforeLast=false;item.classList.toggle("unread-report",Boolean(id)&&beforeLast)}if(latest)latest.classList.toggle("unread-report",Boolean(latestId)&&latestId!==lastRead)}function markReportRead(item){const id=item?.dataset.reportId||"";if(id){saveReportId(id);applyReportReadState()}}document.addEventListener("click",event=>{const item=event.target.closest(".report-history,.latest-report-panel");if(item)markReportRead(item)});document.addEventListener("click",event=>{const dot=event.target.closest(".line-dot");const panel=document.getElementById("lines-strip-detail");if(!panel)return;if(!dot){panel.hidden=true;return}const expanded=dot.getAttribute("aria-expanded")==="true";document.querySelectorAll(".line-dot[aria-expanded=true]").forEach(other=>other.setAttribute("aria-expanded","false"));if(expanded){panel.hidden=true;return}dot.setAttribute("aria-expanded","true");panel.textContent=dot.dataset.lineDetail||"";panel.hidden=false});document.addEventListener("keydown",event=>{if(event.key!=="Enter"&&event.key!==" ")return;const item=event.target.closest(".report-history");if(item){event.preventDefault();markReportRead(item)}});applyReportReadState();function shortDraftReference(id){const compact=String(id||"").replace(/[^A-Za-z0-9]/g,"");return "Draft "+(compact.slice(-6).toUpperCase()||"------")}const inboxPath=${JSON.stringify(INBOX_BASE)};let submitting=false;const banner=document.getElementById("status-banner");function setBanner(message,type){banner.textContent=message;banner.className="status visible "+type}async function refreshInbox(){if(submitting)return;try{const response=await fetch(inboxPath,{cache:"no-store",credentials:"same-origin"});if(response.status===401){location.reload();return}if(!response.ok)return;const html=await response.text();const doc=new DOMParser().parseFromString(html,"text/html");const summary=doc.getElementById("pending-summary");const list=doc.getElementById("draft-list");const history=doc.getElementById("recent-history");const linesStrip=doc.getElementById("lines-strip");if(linesStrip)document.getElementById("lines-strip")?.replaceWith(linesStrip);if(summary&&list&&history){document.getElementById("pending-summary").innerHTML=summary.innerHTML;document.getElementById("draft-list").innerHTML=list.innerHTML;document.getElementById("recent-history").innerHTML=history.innerHTML;applyReportReadState()}}catch{}}document.addEventListener("submit",async event=>{const form=event.target.closest("form[data-draft-id]");if(!form)return;event.preventDefault();const button=event.submitter;if(!button||submitting)return;const draftId=form.dataset.draftId;const draftRef=shortDraftReference(draftId);const discarding=button.classList.contains("discard");submitting=true;document.querySelectorAll("button").forEach(item=>item.disabled=true);setBanner((discarding?"Discarding ":"Sending ")+draftRef+"…","working");try{const response=await fetch(button.formAction,{method:"POST",body:new URLSearchParams(new FormData(form)),credentials:"same-origin",redirect:"follow"});if(!response.ok){const html=await response.text();const doc=new DOMParser().parseFromString(html,"text/html");const heading=doc.querySelector("h1")?.textContent||"Action failed";const detail=doc.querySelector("p")?.textContent||"Nothing changed.";throw new Error(heading+": "+detail)}setBanner(draftRef+(discarding?" discarded.":" sent."),"success")}catch(error){setBanner(error.message,"error")}finally{submitting=false;document.querySelectorAll("button").forEach(item=>item.disabled=false);await refreshInbox()}});setInterval(refreshInbox,3000);</script>`);
  }

  if (req.method === "POST" && url.pathname.startsWith(`${INBOX_BASE}/discard/`)) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml("Your session expired. Log in again."));
    const draftId = url.pathname.slice(`${INBOX_BASE}/discard/`.length);
    if (!/^draft-[A-Za-z0-9-]+$/.test(draftId)) return sendHtml(res, 404, "<h1>Draft not found</h1>");
    let record;
    try {
      record = JSON.parse(await readFile(path.join(STORE, `${draftId}.json`), "utf8"));
    } catch {
      return sendHtml(res, 404, "<h1>Draft not found</h1>");
    }
    await readBody(req);
    // A logged-in owner may discard legacy POC drafts that predate tokens.
    if (record.status !== "PENDING_NOT_SENT" && record.status !== "SEND_FAILED_RETRY_ALLOWED") {
      return sendHtml(res, 409, `<h1>Draft unchanged</h1><p>This draft is already ${record.status}.</p>`);
    }
    record.status = "DISCARDED_BY_OWNER";
    record.discarded_at = new Date().toISOString();
    await writeFile(path.join(STORE, `${draftId}.json`), JSON.stringify(record, null, 2), { mode: 0o600 });
    res.writeHead(303, { location: INBOX_BASE, "cache-control": "no-store" });
    res.end();
    return;
  }

  if (req.method === "POST" && url.pathname.startsWith(`${INBOX_BASE}/edit/`)) {
    if (!hasOwnerInboxCookie(req)) return send(res, 401, { ok: false, error: "session expired" });
    const draftId = url.pathname.slice(`${INBOX_BASE}/edit/`.length);
    if (!/^draft-[A-Za-z0-9-]+$/.test(draftId)) return send(res, 404, { ok: false, error: "draft not found" });
    let record;
    try { record = JSON.parse(await readFile(path.join(STORE, `${draftId}.json`), "utf8")); } catch { return send(res, 404, { ok: false, error: "draft not found" }); }
    const form = new URLSearchParams(await readBody(req));
    if (!safeEqual(form.get("token") || "", record.approval_token)) return send(res, 403, { ok: false, error: "invalid draft token" });
    if (record.status !== "PENDING_NOT_SENT" && record.status !== "SEND_FAILED_RETRY_ALLOWED") return send(res, 409, { ok: false, error: "only pending drafts can be edited" });
    const text = form.get("text") || "";
    if (!text.trim() || text.length > MAX_TEXT) return send(res, 400, { ok: false, error: "draft text must be 1-4096 characters" });
    record.text = text;
    record.edited_at = new Date().toISOString();
    await writeFile(path.join(STORE, `${draftId}.json`), JSON.stringify(record, null, 2), { mode: 0o600 });
    return send(res, 200, { ok: true, draft_id: draftId, status: record.status });
  }

  // --- Production Lines: onboarding, connections, health, retirement -----
  // Presentation only. All durable state and validation lives behind
  // console-api's /v1/lines* routes (called via consoleApiFetch above);
  // this file never writes to controller.db or runs shell commands.
  const linesPageStyle = `<style>body{font:14px system-ui;max-width:820px;margin:0 auto;padding:12px 18px 26px;color:#171711;background:#f7f7f4}h1{font-size:22px;margin:6px 0 4px}h2{font-size:15px;margin:20px 0 8px}a{color:#171711}table{width:100%;border-collapse:collapse;font-size:13px}th,td{text-align:left;padding:6px 8px;border-bottom:1px solid #ddd;vertical-align:top}th{font-size:11px;text-transform:uppercase;letter-spacing:.05em;color:#687078}tr.status-active td:first-child{border-left:3px solid #2f8f4e}tr.status-onboarding td:first-child{border-left:3px solid #a87a1f}tr.status-paused td:first-child,tr.status-retired td:first-child{border-left:3px solid #8a8a86}form.inline{display:inline}fieldset{border:1px solid #aaa;border-radius:10px;padding:14px 16px;margin:16px 0}legend{font-size:12px;text-transform:uppercase;letter-spacing:.05em;color:#687078;padding:0 6px}label{display:block;font-size:12px;color:#3d3d38;margin:10px 0 3px}label.radio{display:flex;align-items:center;gap:8px;font-size:14px;color:#171711;margin:8px 0}label.radio input{width:auto}input,select,textarea{font:inherit;width:100%;box-sizing:border-box;padding:8px;border:1px solid #aaa;border-radius:6px}textarea{min-height:52px}button{font:inherit;padding:8px 14px;margin:10px 6px 0 0;border-radius:7px;cursor:pointer}button.primary{background:#171711;color:white;border:0}button.secondary{background:white;border:1px solid #aaa}.link-button{border:0;background:none;padding:0;margin:0;text-decoration:underline;color:#171711;font:inherit;cursor:pointer}pre.checks{font-size:12px;background:#f1f0eb;padding:10px;border-radius:7px;white-space:pre-wrap}.chk-pass{color:#2f8f4e}.chk-warn{color:#a87a1f}.chk-fail{color:#a83d2a}.small{font-size:12px;color:#687078}.card{border:1px solid #ccc;border-radius:9px;padding:10px 12px;margin:8px 0;display:flex;justify-content:space-between;align-items:center;gap:10px}.card .state{font-size:12px;color:#687078}.card .state.ready{color:#2f8f4e}.card .state.missing{color:#a87a1f}.review-table{width:100%;font-size:14px;margin:10px 0}.review-table td{padding:6px 4px;border-bottom:1px solid #eee;vertical-align:top}.review-table td:first-child{color:#687078;font-size:11px;text-transform:uppercase;letter-spacing:.05em;width:110px}.banner-error{background:#f7dfdc;color:#7b2118;padding:10px 13px;border-radius:8px;margin:10px 0;font-size:13px}.step-eyebrow{font-size:11px;text-transform:uppercase;letter-spacing:.08em;color:#687078;margin:0 0 2px}</style>`;

  function checksHtml(checks) {
    if (!Array.isArray(checks)) return "";
    return checks.map(c => `<span class="chk-${c.status}">${c.status === "pass" ? "✓" : c.status === "warn" ? "!" : "✗"} ${escapeHtml(c.name)}</span> — ${escapeHtml(c.detail)}`).join("\n");
  }

  const ROLE_DEFAULTS = {
    main: { label: "Main development", access_mode: "active-development", agent_roles: ["claude-main-engineer"], line_type: "other" },
    worker: { label: "Worker", access_mode: "worker-only", agent_roles: ["claude-worker"], line_type: "other" },
    reviewer: { label: "Reviewer", access_mode: "reviewer-only", agent_roles: ["codex-reviewer"], line_type: "other" },
    experiment: { label: "Experiment / other", access_mode: "worker-only", agent_roles: [], line_type: "experiment" },
  };

  function slugify(name) {
    let s = String(name || "").toLowerCase().trim().replace(/[^a-z0-9]+/g, "-").replace(/^-+|-+$/g, "");
    if (!s) s = "line";
    if (!/^[a-z]/.test(s)) s = `l-${s}`;
    return s.slice(0, 40);
  }

  async function uniqueLineId(base) {
    let existing = new Set();
    try { const { lines } = await consoleApiFetch("/v1/lines"); existing = new Set(lines.map(l => l.line_id)); } catch {}
    if (!existing.has(base)) return base;
    let n = 2;
    while (existing.has(`${base}-${n}`.slice(0, 40))) n += 1;
    return `${base}-${n}`.slice(0, 40);
  }

  // escapeHtml() (shared elsewhere in this file for plain text content)
  // deliberately does not escape quotes -- the wizard state is JSON full of
  // them, embedded inside an HTML attribute, so it needs full attribute
  // escaping or the value truncates at the first embedded ".
  function encodeState(state) {
    return JSON.stringify(state).replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
  }
  function decodeState(form) { try { return JSON.parse(form.get("state") || "{}"); } catch { return {}; } }
  function stateField(state) { return `<input type="hidden" name="state" value="${encodeState(state)}">`; }
  function wizardChrome(step, title) { return `<p class="small"><a href="${LINES_BASE}">← Production Lines</a></p><p class="step-eyebrow">Add production line · Step ${step} of 6</p><h1>${escapeHtml(title)}</h1>`; }

  function buildManifest(state, form) {
    const val = (name, fallback) => { const v = form.get(name); return (v !== null && v !== undefined && v !== "") ? v : (fallback || ""); };
    const repo = (state.selected_repo_index !== undefined && state.selected_repo_index !== null && state.discovery?.repos?.[state.selected_repo_index]) || null;
    const worker_account = val("worker_account", repo?.owner || state.discovery?.whoami || "");
    const manifest = {
      line_id: state.line_id,
      display_name: val("display_name", state.display_name),
      product_name: val("product_name", state.display_name),
      purpose: val("purpose", `Onboarded via the discovery wizard as a ${ROLE_DEFAULTS[state.line_role]?.label || "worker"} line.`),
      line_type: val("line_type", state.line_type || "other"),
      access_mode: val("access_mode", state.access_mode || "worker-only"),
      agent_roles: (state.agent_roles || []),
      vps_hostname: val("vps_hostname", state.vps_hostname || ""),
      ssh_user: val("ssh_user", state.ssh_user || ""),
      ssh_port: val("ssh_port", state.ssh_port || ""),
      project_path: val("project_path", repo?.path || state.manual_project_path || ""),
      worker_account,
      report_source_path: val("report_source_path", worker_account ? `/home/${worker_account}/.claude/reports` : ""),
      git_remote: val("git_remote", repo?.remote || ""),
      default_branch: val("default_branch", repo?.branch || repo?.default_branch || ""),
    };
    for (const key of Object.keys(manifest)) { if (manifest[key] === "" || manifest[key] === undefined) delete manifest[key]; }
    return manifest;
  }

  function advancedFieldsHtml(manifest) {
    const get = (name) => escapeHtml(manifest[name] || "");
    const hostRow = manifest.vps_hostname ? `<label>SSH user<input name="ssh_user" value="${get("ssh_user")}"></label><label>SSH port<input name="ssh_port" value="${get("ssh_port")}"></label>` : "";
    return `<details><summary>Edit detected details / Advanced</summary><div style="padding-top:8px">
      <label>Product / project name<input name="product_name" value="${get("product_name")}"></label>
      <label>Purpose<textarea name="purpose">${get("purpose")}</textarea></label>
      <label>Line type<select name="line_type">${["product", "native", "review", "ops-tool", "experiment", "other"].map(t => `<option value="${t}" ${manifest.line_type === t ? "selected" : ""}>${t}</option>`).join("")}</select></label>
      <label>Access mode<select name="access_mode">${["active-development", "worker-only", "reviewer-only", "read-only"].map(t => `<option value="${t}" ${manifest.access_mode === t ? "selected" : ""}>${t}</option>`).join("")}</select></label>
      <label>Project path<input name="project_path" value="${get("project_path")}"></label>
      <label>Worker OS account<input name="worker_account" value="${get("worker_account")}"></label>
      <label>Report source path<input name="report_source_path" value="${get("report_source_path")}"></label>
      <label>Git remote<input name="git_remote" value="${get("git_remote")}"></label>
      <label>Default branch<input name="default_branch" value="${get("default_branch")}"></label>
      <label>VPS hostname (blank = this VPS)<input name="vps_hostname" value="${get("vps_hostname")}"></label>
      ${hostRow}
    </div></details>`;
  }

  function renderReview(state, manifest, extra = {}) {
    const detected = state.discovery && state.discovery.ok;
    const claudeRole = (state.agent_roles || []).some(r => r.startsWith("claude"));
    const codexRole = (state.agent_roles || []).some(r => r.startsWith("codex"));
    const hostLabel = manifest.vps_hostname ? `${escapeHtml(manifest.ssh_user || "")}@${escapeHtml(manifest.vps_hostname)}` : `${escapeHtml(state.discovery?.hostname || "this VPS")} · ${escapeHtml(manifest.worker_account || "")}`;
    const projectLabel = manifest.git_remote ? escapeHtml(manifest.git_remote) : (manifest.project_path ? "local path" : "not set");
    const rows = [
      ["Line", escapeHtml(manifest.display_name || state.line_id)],
      ["Host", hostLabel],
      ["Project", `${projectLabel}<br><code>${escapeHtml(manifest.project_path || "not set — add one below")}</code>`],
      ["Branch", escapeHtml(manifest.default_branch || "—")],
      ["Claude Code", claudeRole ? (detected && state.discovery.claude?.installed ? `Ready · v${escapeHtml(state.discovery.claude.version || "")}` : "Selected · not detected as installed") : "Not configured"],
      ["Codex", codexRole ? (detected && state.discovery.codex?.installed ? `Ready · v${escapeHtml(state.discovery.codex.version || "")}` : "Selected · not detected as installed") : "Not configured"],
      ["tmux", state.tmux_session_name ? (detected && state.discovery.tmux?.installed ? `Ready · session "${escapeHtml(state.tmux_session_name)}"` : "Selected · not detected as installed") : "Not configured"],
      ["Reporting", manifest.vps_hostname ? "Needs setup · remote ingestion not yet automated" : (manifest.report_source_path ? "Ready" : "Needs setup")],
    ];
    const editForm = (toStep) => `<form class="inline" method="post" action="${LINES_BASE}/new/${toStep}">${stateField(state)}<button class="link-button" type="submit">Edit</button></form>`;
    const table = rows.map(([label, value], i) => `<tr><td>${label}</td><td>${value} ${i <= 3 ? editForm("host") : editForm("agents")}</td></tr>`).join("");
    const planBlock = extra.plan ? `<pre class="checks">${checksHtml(extra.plan?.validate?.checks)}</pre>` : "";
    const errorBlock = extra.error ? `<div class="banner-error">${escapeHtml(extra.error)}</div>` : "";
    // Advanced fields carry the resolved manifest forward as their own
    // pre-filled `value=`, submitted with the form whether or not the
    // <details> is expanded -- no separate hidden duplicate needed (and a
    // duplicate would silently win over an edited value, since form.get()
    // returns the first field with a given name).
    return `${wizardChrome(5, "Review")}${errorBlock}<table class="review-table">${table}</table>${planBlock}
      <form method="post" action="${LINES_BASE}/new/dry-run">${stateField(state)}${advancedFieldsHtml(manifest)}
      <div style="margin-top:14px"><button class="secondary" type="submit" formaction="${LINES_BASE}/new/dry-run">Dry run</button><button class="primary" type="submit" formaction="${LINES_BASE}/new/onboard">Onboard line</button></div></form>`;
  }

  if (req.method === "GET" && url.pathname === LINES_BASE) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    let lines = [];
    try { ({ lines } = await consoleApiFetch("/v1/lines")); } catch {}
    const rows = lines.map(l => `<tr class="status-${escapeHtml(l.status)}"><td><a href="${LINES_BASE}/${escapeHtml(l.line_id)}">${escapeHtml(l.display_name)}</a></td><td>${escapeHtml(l.line_type)}</td><td>${escapeHtml(l.status)}</td><td>${l.ingestion_enabled ? "on" : "off"}</td><td>${escapeHtml(l.last_ingested_at || "—")}</td></tr>`).join("");
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Engineering Control — Production Lines</title>${linesPageStyle}<p class="small"><a href="${INBOX_BASE}">← Approval Inbox</a></p><h1>Production Lines</h1><table><thead><tr><th>Line</th><th>Type</th><th>Status</th><th>Ingest</th><th>Last report</th></tr></thead><tbody>${rows || '<tr><td colspan="5">No lines registered yet.</td></tr>'}</tbody></table><p><a href="${LINES_BASE}/new"><button class="primary" type="button">+ Add production line</button></a></p>`);
  }

  if (req.method === "GET" && url.pathname === `${LINES_BASE}/new`) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const roleOptions = Object.entries(ROLE_DEFAULTS).map(([key, r]) => `<label class="radio"><input type="radio" name="line_role" value="${key}" ${key === "worker" ? "checked" : ""}> ${escapeHtml(r.label)}</label>`).join("");
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Add production line</title>${linesPageStyle}${wizardChrome(1, "Identify the line")}
      <form method="post" action="${LINES_BASE}/new/host">
        <label>Display name<input name="display_name" id="dn" required autofocus placeholder="e.g. ChairFly Main"></label>
        <p class="small">Line ID: <code id="idpv">—</code> · <a href="#" id="editidlink">Edit</a></p>
        <div id="idwrap" style="display:none"><label>Line ID (advanced)<input name="line_id_override" id="idin" pattern="[a-z][a-z0-9-]{2,39}"></label></div>
        <fieldset><legend>Line role</legend>${roleOptions}</fieldset>
        <button class="primary" type="submit">Continue</button>
      </form>
      <script>
        var dn=document.getElementById('dn'),idpv=document.getElementById('idpv'),idin=document.getElementById('idin');
        function slug(s){return (String(s||'').toLowerCase().trim().replace(/[^a-z0-9]+/g,'-').replace(/^-+|-+$/g,'')||'line').slice(0,40)}
        dn.addEventListener('input',function(){idpv.textContent=slug(dn.value);if(idin)idin.value=slug(dn.value)});
        document.getElementById('editidlink').addEventListener('click',function(e){e.preventDefault();document.getElementById('idwrap').style.display='block'});
      </script>`);
  }

  if (req.method === "POST" && url.pathname === `${LINES_BASE}/new/host`) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const form = new URLSearchParams(await readBody(req));
    const display_name = form.get("display_name") || "";
    const line_role = ROLE_DEFAULTS[form.get("line_role")] ? form.get("line_role") : "worker";
    const role = ROLE_DEFAULTS[line_role];
    const base = slugify(form.get("line_id_override") || display_name);
    const line_id = await uniqueLineId(base);
    const state = { display_name, line_role, line_id, access_mode: role.access_mode, agent_roles: [...role.agent_roles], line_type: role.line_type };
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Add production line</title>${linesPageStyle}${wizardChrome(2, "Choose where it runs")}
      <form method="post" action="${LINES_BASE}/new/discover">${stateField(state)}
        <label class="radio"><input type="radio" name="host_mode" value="local" checked onclick="document.getElementById('remotefields').style.display='none'"> This VPS</label>
        <label class="radio"><input type="radio" name="host_mode" value="remote" onclick="document.getElementById('remotefields').style.display='block'"> Existing remote VPS</label>
        <label class="radio"><input type="radio" name="host_mode" value="later" onclick="document.getElementById('remotefields').style.display='none'"> Configure host later</label>
        <div id="remotefields" style="display:none;padding-top:6px">
          <label>Hostname or IP<input name="vps_hostname"></label>
          <label>SSH user<input name="ssh_user"></label>
          <label>SSH port (only if not 22)<input name="ssh_port"></label>
        </div>
        <button class="primary" type="submit">Detect environment</button>
      </form>`);
  }

  if (req.method === "POST" && url.pathname === `${LINES_BASE}/new/discover`) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const form = new URLSearchParams(await readBody(req));
    const state = decodeState(form);
    const hostMode = form.get("host_mode") || "local";
    state.host_mode = hostMode;
    if (hostMode === "remote") {
      state.vps_hostname = form.get("vps_hostname") || "";
      state.ssh_user = form.get("ssh_user") || "";
      state.ssh_port = form.get("ssh_port") || "";
    }
    if (hostMode === "later") {
      state.discovery = null;
      return sendHtml(res, 200, agentsStepHtml(state));
    }
    let discovery;
    try { discovery = await consoleApiFetch("/v1/lines/discover", { method: "POST", body: JSON.stringify(hostMode === "remote" ? { vps_hostname: state.vps_hostname, ssh_user: state.ssh_user, ssh_port: state.ssh_port } : {}) }); }
    catch (err) { discovery = { ok: false, error: err.message }; }
    state.discovery = discovery;
    if (!discovery.ok) {
      return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Add production line</title>${linesPageStyle}${wizardChrome(3, "Detection failed")}<div class="banner-error">${escapeHtml(discovery.error || "Could not connect.")}</div>
        <form class="inline" method="post" action="${LINES_BASE}/new/host">${stateField(state)}<button class="secondary" type="submit">← Try again</button></form>
        <form class="inline" method="post" action="${LINES_BASE}/new/agents">${stateField(state)}<button class="secondary" type="submit">Continue without detection</button></form>`);
    }
    const repos = discovery.repos || [];
    if (repos.length === 1) { state.selected_repo_index = 0; return sendHtml(res, 200, agentsStepHtml(state, `Found <code>${escapeHtml(repos[0].path)}</code> · ${escapeHtml(repos[0].remote || "no remote")} · ${escapeHtml(repos[0].branch || "no branch")}.`)); }
    if (repos.length === 0) {
      return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Add production line</title>${linesPageStyle}${wizardChrome(3, "No repository found automatically")}
        <form method="post" action="${LINES_BASE}/new/agents">${stateField(state)}
          <label>Project path<input name="manual_project_path" required></label>
          <button class="primary" type="submit">Continue</button>
        </form>`);
    }
    const chooserRows = repos.map((r, i) => `<label class="radio"><input type="radio" name="selected_repo_index" value="${i}" ${i === 0 ? "checked" : ""}> <code>${escapeHtml(r.path)}</code> · ${escapeHtml(r.remote || "no remote")} · ${escapeHtml(r.branch || "no branch")}</label>`).join("");
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Add production line</title>${linesPageStyle}${wizardChrome(3, "Choose the repository")}
      <form method="post" action="${LINES_BASE}/new/agents">${stateField(state)}${chooserRows}<button class="primary" type="submit">Continue</button></form>`);
  }

  function agentsStepHtml(state, note = "") {
    const d = state.discovery;
    const has = (r) => (state.agent_roles || []).includes(r);
    const toolCard = (name, tool, roles) => {
      const installed = d?.ok && tool?.installed;
      const stateLabel = installed ? `<span class="state ready">Installed · v${escapeHtml(tool.version || "")}</span>` : `<span class="state missing">Not installed</span>`;
      const toggles = roles.map(([role, label]) => `<label class="radio"><input type="checkbox" name="agent_roles" value="${role}" ${has(role) ? "checked" : ""}> ${escapeHtml(label)}</label>`).join("");
      return `<div class="card" style="flex-direction:column;align-items:stretch"><div style="display:flex;justify-content:space-between"><strong>${escapeHtml(name)}</strong>${stateLabel}</div>${toggles}</div>`;
    };
    const tmuxInstalled = d?.ok && d.tmux?.installed;
    const suggestedSession = state.line_id;
    return `<!doctype html><meta name="viewport" content="width=device-width"><title>Add production line</title>${linesPageStyle}${wizardChrome(4, "Agent configuration")}${note ? `<p class="small">${note}</p>` : ""}
      <form method="post" action="${LINES_BASE}/new/review">${stateField(state)}
        ${state.selected_repo_index !== undefined ? `<input type="hidden" name="selected_repo_index" value="${state.selected_repo_index}">` : ""}
        ${state.manual_project_path ? `<input type="hidden" name="manual_project_path" value="${escapeHtml(state.manual_project_path)}">` : ""}
        ${toolCard("Claude Code", d?.claude, [["claude-main-engineer", "Use as Main Engineer"], ["claude-worker", "Use as Worker"]])}
        ${toolCard("Codex", d?.codex, [["codex-worker", "Use as Worker"], ["codex-reviewer", "Use as Reviewer"]])}
        <div class="card" style="flex-direction:column;align-items:stretch"><div style="display:flex;justify-content:space-between"><strong>tmux</strong>${tmuxInstalled ? `<span class="state ready">Installed · v${escapeHtml(d.tmux.version || "")}</span>` : `<span class="state missing">Not installed</span>`}</div><label class="radio"><input type="checkbox" name="use_tmux" value="1" ${tmuxInstalled ? "checked" : ""}> Configure tmux · suggested session <code>${escapeHtml(suggestedSession)}</code></label></div>
        <div class="card" style="flex-direction:column;align-items:stretch"><div style="display:flex;justify-content:space-between"><strong>Report ingestion</strong><span class="state ${state.vps_hostname ? "missing" : "ready"}">${state.vps_hostname ? "Not automated for remote lines yet" : "Will be configured"}</span></div></div>
        <button class="primary" type="submit">Continue to review</button>
      </form>`;
  }

  if (req.method === "POST" && url.pathname === `${LINES_BASE}/new/agents`) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const form = new URLSearchParams(await readBody(req));
    const state = decodeState(form);
    if (form.get("selected_repo_index") !== null) state.selected_repo_index = Number(form.get("selected_repo_index"));
    if (form.get("manual_project_path")) state.manual_project_path = form.get("manual_project_path");
    return sendHtml(res, 200, agentsStepHtml(state));
  }

  if (req.method === "POST" && url.pathname === `${LINES_BASE}/new/review`) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const form = new URLSearchParams(await readBody(req));
    const state = decodeState(form);
    state.agent_roles = form.getAll("agent_roles");
    if (form.get("use_tmux") === "1") state.tmux_session_name = state.line_id; else delete state.tmux_session_name;
    const manifest = buildManifest(state, new URLSearchParams());
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Review — ${escapeHtml(manifest.display_name || "")}</title>${linesPageStyle}${renderReview(state, manifest)}`);
  }

  if (req.method === "POST" && url.pathname === `${LINES_BASE}/new/dry-run`) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const form = new URLSearchParams(await readBody(req));
    const state = decodeState(form);
    const manifest = buildManifest(state, form);
    let plan, error;
    try { plan = await consoleApiFetch("/v1/lines/plan", { method: "POST", body: JSON.stringify(manifest) }); }
    catch (err) { error = err.message; }
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Review — ${escapeHtml(manifest.display_name || "")}</title>${linesPageStyle}${renderReview(state, manifest, { plan, error })}`);
  }

  if (req.method === "POST" && url.pathname === `${LINES_BASE}/new/onboard`) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const form = new URLSearchParams(await readBody(req));
    const state = decodeState(form);
    const manifest = buildManifest(state, form);
    let outcome, error;
    try { outcome = await consoleApiFetch("/v1/lines/apply", { method: "POST", body: JSON.stringify(manifest) }); }
    catch (err) { error = err.message; }
    if (outcome?.ok) { res.writeHead(303, { location: INBOX_BASE, "cache-control": "no-store" }); return res.end(); }
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Onboarding failed</title>${linesPageStyle}${renderReview(state, manifest, { error: error || outcome?.detail || "Onboarding failed." })}`);
  }

  const lineDetailMatch = url.pathname.match(new RegExp(`^${LINES_BASE}\\/([a-z][a-z0-9-]{2,39})$`));
  if (req.method === "GET" && lineDetailMatch) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const lineId = lineDetailMatch[1];
    let line;
    try { line = await consoleApiFetch(`/v1/lines/${lineId}`); } catch { line = null; }
    if (!line) return sendHtml(res, 404, `<!doctype html>${linesPageStyle}<h1>Line not found</h1><p><a href="${LINES_BASE}">← Production Lines</a></p>`);
    const reportsHtml = (line.reports || []).map(r => `<li>${escapeHtml(r.state)} · ${escapeHtml(r.run_id)} · ${escapeHtml(r.detected_at)}</li>`).join("") || "<li>No reports yet.</li>";
    const eventsHtml = (line.events || []).map(e => `<li>${escapeHtml(e.created_at)} — ${escapeHtml(e.kind)}: ${escapeHtml(e.detail)}</li>`).join("") || "<li>No events yet.</li>";
    const actionForm = (action, label, cls = "secondary") => `<form class="inline" method="post" action="${LINES_BASE}/${lineId}/${action}"><button class="${cls}" type="submit">${label}</button></form>`;
    return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>${escapeHtml(line.display_name)} — Production Lines</title>${linesPageStyle}<p class="small"><a href="${LINES_BASE}">← Production Lines</a></p><h1>${escapeHtml(line.display_name)}</h1><p class="small">${escapeHtml(line.line_id)} · ${escapeHtml(line.line_type)} · status: <strong>${escapeHtml(line.status)}</strong></p>

<h2>Overview</h2><p>${escapeHtml(line.purpose || "—")}</p><p class="small">Product: ${escapeHtml(line.product_name)} · Phase: ${escapeHtml(line.phase || "—")} · Access: ${escapeHtml(line.access_mode)} · Claude Chat visible: ${line.claude_chat_visible ? "yes" : "no"}</p>

<h2>Connections</h2><p class="small">Project path: <code>${escapeHtml(line.project_path)}</code><br>Worker account: ${escapeHtml(line.worker_account)}${line.vps_hostname ? `<br>VPS: ${escapeHtml(line.ssh_user || "")}@${escapeHtml(line.vps_hostname)}` : "<br>Host: this VPS"}${line.git_remote ? `<br>Git remote: <code>${escapeHtml(line.git_remote)}</code>` : ""}${line.default_branch ? `<br>Default branch: ${escapeHtml(line.default_branch)}` : ""}</p>

<h2>Agents</h2><p class="small">Claude Code: ${line.claude_installed ? `detected · v${escapeHtml(line.claude_version || "")}` : "not detected"} · Codex: ${line.codex_installed ? `detected · v${escapeHtml(line.codex_version || "")}` : "not detected"} · tmux: ${line.tmux_installed ? `detected · v${escapeHtml(line.tmux_version || "")}` : "not detected"}</p>
<p class="small">Detected status only reflects the environment; it never blocks configuration below — set roles and a session name whether or not a tool was detected here.</p>
<form method="post" action="${LINES_BASE}/${lineId}/configure">
  ${[["claude-main-engineer", "Claude Code — Main Engineer"], ["claude-worker", "Claude Code — Worker"], ["codex-worker", "Codex — Worker"], ["codex-reviewer", "Codex — Reviewer"]].map(([role, label]) => `<label class="radio"><input type="checkbox" name="agent_roles" value="${role}" ${(line.agent_roles || "").split(",").includes(role) ? "checked" : ""}> ${escapeHtml(label)}</label>`).join("")}
  <label>tmux session name<input name="tmux_session_name" value="${escapeHtml(line.tmux_session_name || line.line_id)}"></label>
  <button class="primary" type="submit">Save configuration</button>
</form>

<h2>Reporting</h2><p class="small">Report source: <code>${escapeHtml(line.report_source_path)}</code><br>Ingestion: ${line.ingestion_enabled ? "enabled" : "disabled"} · Last report: ${escapeHtml(line.last_ingested_at || "—")} (${escapeHtml(line.last_run_id || "—")})</p><h2>Recent reports</h2><ul>${reportsHtml}</ul>

<h2>Health</h2><p class="small">Health state: ${escapeHtml(line.current_health_state || "unknown")} · Last connectivity test: ${escapeHtml(line.last_connectivity_test_at || "never")}${line.last_connectivity_result ? ` (${escapeHtml(line.last_connectivity_result)})` : ""}</p>${actionForm("test", "Test all")}${actionForm("redetect", "Re-detect environment")}

<h2>Operations</h2>${line.status === "active" ? actionForm("pause", "Pause line") : ""}${line.status === "paused" ? actionForm("resume", "Resume line") : ""}${line.status === "onboarding" ? actionForm("rollback", "Roll back", "secondary") : ""}

<h2>History</h2><ul>${eventsHtml}</ul>

<h2>Retirement</h2>${line.status === "retired" ? `<p class="small">Retired ${escapeHtml(line.retired_at || "")}. Report and event history is preserved.</p>` : actionForm("retire", "Retire line")}`);
  }

  if (req.method === "POST" && url.pathname.match(new RegExp(`^${LINES_BASE}\\/([a-z][a-z0-9-]{2,39})\\/configure$`))) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const lineId = url.pathname.match(new RegExp(`^${LINES_BASE}\\/([a-z][a-z0-9-]{2,39})\\/configure$`))[1];
    const form = new URLSearchParams(await readBody(req));
    const body = { agent_roles: form.getAll("agent_roles") };
    if (form.has("tmux_session_name")) body.tmux_session_name = form.get("tmux_session_name");
    try { await consoleApiFetch(`/v1/lines/${lineId}/configure`, { method: "POST", body: JSON.stringify(body) }); } catch {}
    res.writeHead(303, { location: `${LINES_BASE}/${lineId}`, "cache-control": "no-store" });
    return res.end();
  }

  const lineActionMatch = url.pathname.match(new RegExp(`^${LINES_BASE}\\/([a-z][a-z0-9-]{2,39})\\/(test|pause|resume|retire|rollback|redetect)$`));
  if (req.method === "POST" && lineActionMatch) {
    if (!hasOwnerInboxCookie(req)) return sendHtml(res, 401, ownerLoginHtml());
    const [, lineId, action] = lineActionMatch;
    try { await consoleApiFetch(`/v1/lines/${lineId}/${action}`, { method: "POST", body: "{}" }); } catch {}
    res.writeHead(303, { location: `${LINES_BASE}/${lineId}`, "cache-control": "no-store" });
    return res.end();
  }

  if ((req.method === "GET" || req.method === "POST") && url.pathname === `${SECURITY_BASE}/enroll`) {
    try {
      await readFile(CREDENTIAL_PATH, "utf8");
      return sendHtml(res, 409, "<h1>Private owner passphrase already enrolled</h1><p>This one-time page is now locked.</p>");
    } catch (err) {
      if (err?.code !== "ENOENT") return sendHtml(res, 500, "<h1>Enrollment unavailable</h1>");
    }

    if (req.method === "GET") {
      return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Enroll private owner PIN</title><style>body{font:17px system-ui;max-width:650px;margin:6vh auto;padding:24px;color:#171711}input,button{font:inherit;padding:12px;margin:7px 0 18px;width:min(420px,90%)}button{display:block;width:auto;background:#171711;color:white;border:0;border-radius:8px}.box{border:1px solid #aaa;padding:22px;border-radius:12px}</style><h1>Private owner PIN enrollment</h1><div class="box"><p>Choose a 4-digit PIN that you will never paste into Claude Chat or Codex. Five incorrect approval attempts lock that draft for 30 minutes.</p><form method="post"><label>Temporary code<br><input name="current_code" type="password" required autocomplete="off"></label><br><label>New 4-digit PIN<br><input name="new_code" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" required autocomplete="new-password"></label><br><label>Confirm new 4-digit PIN<br><input name="confirm_code" type="password" inputmode="numeric" pattern="[0-9]{4}" maxlength="4" required autocomplete="new-password"></label><button type="submit">Replace temporary code</button></form></div>`);
    }

    const form = new URLSearchParams(await readBody(req));
    const currentCode = form.get("current_code") || "";
    const newCode = form.get("new_code") || "";
    if (!(await verifyOwnerCode(currentCode))) return sendHtml(res, 403, "<h1>Enrollment denied</h1><p>The temporary code was incorrect.</p>");
    if (!/^[0-9]{4}$/.test(newCode) || newCode !== (form.get("confirm_code") || "")) {
      return sendHtml(res, 400, "<h1>PINs did not match</h1><p>Use exactly four digits.</p>");
    }
    const salt = randomBytes(16);
    const hash = scryptSync(newCode, salt, 32).toString("hex");
    try {
      await writeFile(CREDENTIAL_PATH, JSON.stringify({ version: 1, algorithm: "scrypt", salt: salt.toString("hex"), hash, created_at: new Date().toISOString() }, null, 2), { flag: "wx", mode: 0o600 });
    } catch (err) {
      if (err?.code === "EEXIST") return sendHtml(res, 409, "<h1>Private owner passphrase already enrolled</h1><p>This one-time page is now locked.</p>");
      return sendHtml(res, 500, "<h1>Enrollment could not be saved</h1><p>No credential was changed. Ask Sean's assistant to inspect storage permissions.</p>");
    }
    return sendHtml(res, 200, "<h1>Private owner PIN enrolled</h1><p>The temporary code no longer authorizes worker sends. Store your new PIN safely; it cannot be recovered from the server.</p><p>You may close this page.</p>");
  }

  if ((req.method === "GET" || req.method === "POST") && url.pathname.startsWith(`${APPROVE_BASE}/`)) {
    const draftId = url.pathname.slice(APPROVE_BASE.length + 1);
    if (!/^draft-[A-Za-z0-9-]+$/.test(draftId)) return sendHtml(res, 404, "<h1>Draft not found</h1>");
    let record;
    try {
      record = JSON.parse(await readFile(path.join(STORE, `${draftId}.json`), "utf8"));
    } catch {
      return sendHtml(res, 404, "<h1>Draft not found</h1>");
    }

    if (req.method === "GET") {
      const approvalToken = url.searchParams.get("token") || "";
      if (!safeEqual(approvalToken, record.approval_token)) return sendHtml(res, 403, "<h1>Invalid approval link</h1>");
      const preview = record.text.replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;");
      let lineLabelText = "No assigned line (predates per-line routing)";
      if (record.line_id) {
        try {
          const previewLine = await consoleApiFetch(`/v1/lines/${encodeURIComponent(record.line_id)}`);
          lineLabelText = previewLine?.display_name || record.line_id;
        } catch { lineLabelText = record.line_id; }
      }
      return sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Approve Product Worker Draft</title><style>body{font:17px system-ui;max-width:720px;margin:6vh auto;padding:24px;color:#171711}pre{white-space:pre-wrap;background:#f4f3ef;padding:18px;border:1px solid #aaa;border-radius:10px}input,button{font:inherit;padding:12px;margin-top:10px}input{width:min(320px,90%)}button{display:block;background:#171711;color:white;border:0;border-radius:8px}.warning{color:#8a2f22}</style><h1>Owner approval required</h1><p class="warning"><strong>Pressing Send will paste this instruction into the live ${escapeHtml(lineLabelText)} worker.</strong></p><p>Status: ${record.status} · Line: ${escapeHtml(lineLabelText)}</p><pre>${preview}</pre><form method="post"><input type="hidden" name="token" value="${record.approval_token}"><label>Private 4-digit owner PIN<br><input name="owner_code" type="text" inputmode="numeric" pattern="[0-9]{4}" minlength="4" maxlength="4" required autocomplete="one-time-code" data-lpignore="true"></label><button type="submit">Send to Product Worker</button></form>`);
    }

    const form = new URLSearchParams(await readBody(req));
    const failure = approvalFailures.get(draftId);
    if (failure?.blockedUntil > Date.now()) {
      return sendHtml(res, 429, "<h1>Approval temporarily locked</h1><p>Too many incorrect PIN attempts. Try again in 30 minutes.</p>");
    }
    if (!safeEqual(form.get("token") || "", record.approval_token) || (!hasOwnerInboxAuthorization(req, form) && !(await verifyOwnerCode(form.get("owner_code") || "")))) {
      const attempts = (failure?.attempts || 0) + 1;
      approvalFailures.set(draftId, attempts >= 5 ? { attempts, blockedUntil: Date.now() + 30 * 60_000 } : { attempts, blockedUntil: 0 });
      return sendHtml(res, 403, "<h1>Approval denied</h1><p>The private owner code was incorrect.</p>");
    }
    approvalFailures.delete(draftId);
    if (record.status !== "PENDING_NOT_SENT" && record.status !== "SEND_FAILED_RETRY_ALLOWED") {
      return sendHtml(res, 409, `<h1>Not sent again</h1><p>This draft is already ${record.status}.</p>`);
    }
    if (!record.line_id) {
      return sendHtml(res, 409, "<h1>Cannot send</h1><p>This draft predates per-line routing and has no assigned production line. Discard it instead — it cannot be sent to a guessed target.</p>");
    }
    let line;
    try {
      line = await consoleApiFetch(`/v1/lines/${encodeURIComponent(record.line_id)}`);
    } catch (err) {
      return sendHtml(res, 502, `<h1>Cannot send</h1><p>Could not resolve production line "${escapeHtml(record.line_id)}": ${escapeHtml(String(err.message || err))}</p>`);
    }
    if (!line || !line.line_id) {
      return sendHtml(res, 409, `<h1>Cannot send</h1><p>Production line "${escapeHtml(record.line_id)}" no longer exists.</p>`);
    }
    if (line.status !== "active") {
      return sendHtml(res, 409, `<h1>Cannot send</h1><p>Production line "${escapeHtml(line.display_name || line.line_id)}" is not active (status: ${escapeHtml(line.status)}).</p>`);
    }
    await appendFile(SEND_AUDIT_PATH, JSON.stringify({ at: new Date().toISOString(), draft_id: draftId, line_id: line.line_id, route: "owner-approval", remote: req.socket.remoteAddress || "", user_agent: String(req.headers["user-agent"] || "").slice(0, 240), via_inbox_session: hasOwnerInboxAuthorization(req, form) }) + "\n", { mode: 0o600 });

    // Deliver only the owner-reviewed instruction. Claude Code treats formal
    // bridge metadata as an unfamiliar authority claim and correctly pauses;
    // draft IDs and hashes remain in the controller's audit record instead.
    const payload = `${record.text}\n`;
    record.status = "SENDING";
    await writeFile(path.join(STORE, `${draftId}.json`), JSON.stringify(record, null, 2), { mode: 0o600 });
    try {
      await dispatchToWorker(payload, line);
      record.status = "SENT_TO_PRODUCT_WORKER";
      record.sent_at = new Date().toISOString();
      await writeFile(path.join(STORE, `${draftId}.json`), JSON.stringify(record, null, 2), { mode: 0o600 });
      res.writeHead(303, { location: INBOX_BASE, "cache-control": "no-store" });
      res.end();
      return;
    } catch (err) {
      record.status = "SEND_FAILED_RETRY_ALLOWED";
      record.send_error = String(err.message || err).slice(0, 500);
      await writeFile(path.join(STORE, `${draftId}.json`), JSON.stringify(record, null, 2), { mode: 0o600 });
      if (err.exitCode === 75) return sendHtml(res, 409, "<h1>Worker is currently working</h1><p>Nothing was sent, and you do not need to close or detach your terminal. Wait until Claude Code finishes and shows an empty prompt, then return to the private inbox and press Send again.</p>");
      if (err.exitCode === 78) return sendHtml(res, 503, "<h1>Sending is temporarily unavailable</h1><p>Nothing was sent. The live Product worker is currently a direct terminal session without a safe tmux input socket.</p>");
      return sendHtml(res, 502, "<h1>Send failed</h1><p>Nothing was sent. Ask Sean's assistant to inspect the connection.</p>");
    }
  }

  if (req.method === "GET" && url.pathname.startsWith("/.well-known/oauth-protected-resource")) {
    send(res, 200, {
      resource: RESOURCE,
      authorization_servers: [ISSUER],
      bearer_methods_supported: ["header"],
      scopes_supported: ["draft:create"],
    });
    return;
  }

  if (req.method === "GET" && (
    url.pathname === `${OAUTH_BASE}/.well-known/oauth-authorization-server` ||
    url.pathname === "/.well-known/oauth-authorization-server" ||
    url.pathname === `/.well-known/oauth-authorization-server${OAUTH_BASE}`
  )) {
    send(res, 200, {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/authorize`,
      token_endpoint: `${ISSUER}/token`,
      registration_endpoint: `${ISSUER}/register`,
      response_types_supported: ["code"],
      grant_types_supported: ["authorization_code"],
      token_endpoint_auth_methods_supported: ["none"],
      code_challenge_methods_supported: ["S256"],
      scopes_supported: ["draft:create"],
    });
    return;
  }

  if (req.method === "POST" && url.pathname === `${OAUTH_BASE}/register`) {
    try {
      const body = JSON.parse(await readBody(req));
      const redirectUris = Array.isArray(body.redirect_uris) ? body.redirect_uris.filter(x => typeof x === "string" && x.startsWith("https://")) : [];
      if (!redirectUris.length) return send(res, 400, { error: "invalid_redirect_uri" });
      const clientId = opaque(24);
      clients.set(clientId, { redirectUris, createdAt: Date.now() });
      await persistOAuthState();
      send(res, 201, {
        client_id: clientId,
        client_id_issued_at: Math.floor(Date.now() / 1000),
        redirect_uris: redirectUris,
        grant_types: ["authorization_code"],
        response_types: ["code"],
        token_endpoint_auth_method: "none",
      });
    } catch {
      send(res, 400, { error: "invalid_client_metadata" });
    }
    return;
  }

  if (req.method === "GET" && url.pathname === `${OAUTH_BASE}/authorize`) {
    const clientId = url.searchParams.get("client_id") || "";
    const redirectUri = url.searchParams.get("redirect_uri") || "";
    const client = clients.get(clientId);
    if (!client || !client.redirectUris.includes(redirectUri) || url.searchParams.get("response_type") !== "code") {
      return sendHtml(res, 400, "<h1>Invalid authorization request</h1>");
    }
    const fields = ["client_id", "redirect_uri", "state", "code_challenge", "code_challenge_method", "scope", "resource"]
      .map(name => `<input type="hidden" name="${name}" value="${(url.searchParams.get(name) || "").replaceAll("&", "&amp;").replaceAll('"', "&quot;")}">`).join("");
    sendHtml(res, 200, `<!doctype html><meta name="viewport" content="width=device-width"><title>Approve Aboardable Draft POC</title><style>body{font:18px system-ui;max-width:560px;margin:10vh auto;padding:24px;color:#171711}button{font:inherit;padding:12px 22px;background:#171711;color:white;border:0;border-radius:8px}code{word-break:break-all}.box{border:1px solid #aaa;padding:20px;border-radius:12px}</style><h1>Aboardable Draft POC</h1><div class="box"><p>Claude is requesting permission to <strong>save pending drafts only</strong>.</p><p>This connector cannot execute commands or contact the worker.</p><form method="post" action="${OAUTH_BASE}/authorize">${fields}<button type="submit">Allow draft creation</button></form></div>`);
    return;
  }

  if (req.method === "POST" && url.pathname === `${OAUTH_BASE}/authorize`) {
    const form = new URLSearchParams(await readBody(req));
    const clientId = form.get("client_id") || "";
    const redirectUri = form.get("redirect_uri") || "";
    const client = clients.get(clientId);
    if (!client || !client.redirectUris.includes(redirectUri)) return sendHtml(res, 400, "<h1>Invalid authorization request</h1>");
    const code = opaque(32);
    codes.set(code, { clientId, redirectUri, challenge: form.get("code_challenge") || "", createdAt: Date.now() });
    const target = new URL(redirectUri);
    target.searchParams.set("code", code);
    if (form.get("state")) target.searchParams.set("state", form.get("state"));
    res.writeHead(302, { location: target.toString(), "cache-control": "no-store" });
    res.end();
    return;
  }

  if (req.method === "POST" && url.pathname === `${OAUTH_BASE}/token`) {
    const form = new URLSearchParams(await readBody(req));
    const codeValue = form.get("code") || "";
    const record = codes.get(codeValue);
    if (!record || Date.now() - record.createdAt > 5 * 60_000 || form.get("client_id") !== record.clientId || form.get("redirect_uri") !== record.redirectUri) {
      return send(res, 400, { error: "invalid_grant" });
    }
    const expected = createHash("sha256").update(form.get("code_verifier") || "").digest("base64url");
    if (record.challenge && !safeEqual(expected, record.challenge)) return send(res, 400, { error: "invalid_grant" });
    codes.delete(codeValue);
    const accessToken = opaque(32);
    // No refresh_token grant is implemented, so the original 1-hour TTL
    // meant any MCP connector session open longer than an hour silently
    // lost tool access with no visible reauth prompt in some clients --
    // fine for one continuously-driven session, not for a long-running or
    // separate per-line review conversation. Matches the existing 30-day
    // precedent already used for the owner_inbox cookie in this file.
    const TOKEN_TTL_MS = 30 * 24 * 60 * 60 * 1000;
    tokens.set(accessToken, { expiresAt: Date.now() + TOKEN_TTL_MS });
    await persistOAuthState();
    send(res, 200, { access_token: accessToken, token_type: "Bearer", expires_in: TOKEN_TTL_MS / 1000, scope: "draft:create" });
    return;
  }

  if (url.pathname !== MCP_PATH) {
    send(res, 404, { error: "not_found" });
    return;
  }

  const token = tokens.get(bearer(req));
  if (!token || token.expiresAt < Date.now()) {
    res.writeHead(401, {
      "content-type": "application/json",
      "www-authenticate": `Bearer resource_metadata="${PUBLIC_ORIGIN}/.well-known/oauth-protected-resource${MCP_PATH}"`,
      "cache-control": "no-store",
    });
    res.end(JSON.stringify({ error: "unauthorized" }));
    return;
  }

  if (req.method === "GET") {
    res.writeHead(405, { allow: "POST", "content-type": "text/plain" });
    res.end("This MCP endpoint accepts POST requests only.\n");
    return;
  }
  if (req.method !== "POST") {
    res.writeHead(405, { allow: "POST" });
    res.end();
    return;
  }

  try {
    const body = JSON.parse(await readBody(req));
    const response = await handleRpc(body);
    if (response === null) {
      res.writeHead(202, { "cache-control": "no-store" });
      res.end();
    } else {
      send(res, 200, response);
    }
  } catch {
    send(res, 400, error(null, -32700, "Invalid JSON-RPC request"));
  }
});

server.listen(PORT, HOST, () => {
  console.log(`Draft-only MCP POC listening on http://${HOST}:${PORT}`);
});
