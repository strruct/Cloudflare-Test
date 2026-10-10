import { DatabaseSync } from "node:sqlite";
import { scryptSync, randomBytes, timingSafeEqual } from "crypto";
import fs from "fs";
import path from "path";
import { dataRoot, ensureDataDir } from "./config";

let db: DatabaseSync | null = null;

function dbFile() {
  const custom = (process.env.PANEL_USERS_DB ?? "").trim();
  if (custom) return custom;
  return path.join(dataRoot(), "users.db");
}

function open(): DatabaseSync {
  if (db) return db;
  const file = dbFile();
  try {
    ensureDataDir();
    fs.mkdirSync(path.dirname(file), { recursive: true });
    db = new DatabaseSync(file);
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "unknown";
    throw new Error(`users db not writable: ${file} (${code}); set PANEL_DATA_DIR to a writable path`);
  }
  db.exec("PRAGMA journal_mode = WAL");
  db.exec(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    pass_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL,
    last_login INTEGER
  )`);
  return db;
}

function nowSec() {
  return Math.floor(Date.now() / 1000);
}

function hashPass(password: string) {
  const salt = randomBytes(16).toString("hex");
  const hash = scryptSync(password, salt, 64).toString("hex");
  return `${salt}:${hash}`;
}

function checkPass(password: string, stored: string) {
  const [salt, hash] = stored.split(":");
  if (!salt || !hash) return false;
  const calc = scryptSync(password, salt, 64);
  const exp = Buffer.from(hash, "hex");
  return calc.length === exp.length && timingSafeEqual(calc, exp);
}

export type LocalUser = {
  id: number;
  username: string;
  isAdmin: boolean;
  tgId: number;
};

type Row = {
  id: number;
  username: string;
  pass_hash: string;
  is_admin: number;
  created_at: number;
  last_login: number | null;
};

function toUser(row: Row): LocalUser {
  return { id: row.id, username: row.username, isAdmin: !!row.is_admin, tgId: row.id };
}

export function createUser(username: string, password: string, isAdmin = false) {
  const d = open();
  const info = d
    .prepare("INSERT INTO users (username, pass_hash, is_admin, created_at) VALUES (?, ?, ?, ?)")
    .run(username.trim(), hashPass(password), isAdmin ? 1 : 0, nowSec());
  return Number(info.lastInsertRowid);
}

export function ensureSeed() {
  const d = open();
  const username = (process.env.PANEL_ADMIN_USER ?? "").trim() || "admin";
  const envPass = (process.env.PANEL_ADMIN_PASS ?? "").trim();
  const row = d.prepare("SELECT * FROM users WHERE username = ?").get(username) as
    | Row
    | undefined;
  if (!row) {
    const pass = envPass || randomBytes(9).toString("base64url");
    createUser(username, pass, true);
    if (!envPass) {
      console.log(`[users] seeded admin '${username}' password: ${pass}`);
    } else {
      console.log(`[users] seeded admin '${username}' from PANEL_ADMIN_PASS`);
    }
    return;
  }
  if (envPass && !checkPass(envPass, row.pass_hash)) {
    d.prepare("UPDATE users SET pass_hash = ?, is_admin = 1 WHERE id = ?").run(
      hashPass(envPass),
      row.id,
    );
    console.log(`[users] synced admin '${username}' to PANEL_ADMIN_PASS`);
  }
  if (!row.is_admin) {
    d.prepare("UPDATE users SET is_admin = 1 WHERE id = ?").run(row.id);
  }
}

export function verifyUser(username: string, password: string): LocalUser | null {
  ensureSeed();
  const d = open();
  const row = d
    .prepare("SELECT * FROM users WHERE username = ?")
    .get(username.trim()) as Row | undefined;
  if (!row) return null;
  if (!checkPass(password, row.pass_hash)) return null;
  d.prepare("UPDATE users SET last_login = ? WHERE id = ?").run(nowSec(), row.id);
  return toUser(row);
}

export function getLocalUser(id: number): LocalUser | null {
  const d = open();
  const row = d.prepare("SELECT * FROM users WHERE id = ?").get(id) as Row | undefined;
  return row ? toUser(row) : null;
}

export function listLocalUsers() {
  const d = open();
  const rows = d
    .prepare("SELECT id, username, is_admin, created_at, last_login FROM users ORDER BY id")
    .all() as Array<Omit<Row, "pass_hash">>;
  return rows.map((r) => ({
    id: r.id,
    username: r.username,
    isAdmin: !!r.is_admin,
    createdAt: r.created_at,
    lastLogin: r.last_login,
  }));
}

export function deleteLocalUser(id: number) {
  const d = open();
  const info = d.prepare("DELETE FROM users WHERE id = ?").run(id);
  return Number(info.changes) > 0;
}

export function setLocalAdmin(id: number, isAdmin: boolean) {
  const d = open();
  const info = d
    .prepare("UPDATE users SET is_admin = ? WHERE id = ?")
    .run(isAdmin ? 1 : 0, id);
  return Number(info.changes) > 0;
}

export function changePassword(id: number, newPassword: string) {
  const d = open();
  const info = d
    .prepare("UPDATE users SET pass_hash = ? WHERE id = ?")
    .run(hashPass(newPassword), id);
  return Number(info.changes) > 0;
}
