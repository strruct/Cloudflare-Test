import fs from "fs";
import path from "path";

const PROD_API = "http://haykocepkin51265.rf.gd";
const PROD_UI = "http://haykocepkin51265.rf.gd";

export function env(name: string, fallback = "") {
  return (process.env[name] ?? fallback).trim();
}

export function panelSecret() {
  const s = env("PANEL_SECRET");
  if (!s || s === "dev-panel-secret-change" || s.length < 24) {
    throw new Error("PANEL_SECRET required (min 24 chars, default forbidden)");
  }
  return s;
}

function loopback(url: string) {
  const u = url.toLowerCase();
  return (
    u.includes("localhost") ||
    u.includes("127.0.0.1") ||
    u.includes("[::1]") ||
    u.startsWith("http://")
  );
}

export function panelBase() {
  const base = env("PANEL_BASE_URL", PROD_API).replace(/\/$/, "");
  if (!base || loopback(base)) return PROD_API;
  return base;
}

export function panelBases() {
  const raw = env("PANEL_BASE_URLS", `${PROD_API},${PROD_UI}`);
  const out: string[] = [];
  const seen = new Set<string>();
  for (const part of raw.split(",")) {
    const b = part.trim().replace(/\/$/, "");
    if (!b || loopback(b) || seen.has(b)) continue;
    seen.add(b);
    out.push(b);
  }
  if (!out.length) return [PROD_API, PROD_UI];
  return out;
}

export function hubPort() {
  const n = Number(env("HUB_PORT", "3001"));
  return Number.isFinite(n) && n > 0 ? n : 3001;
}

export function hubPublicUrl() {
  const custom = env("HUB_URL", PROD_API).replace(/\/$/, "");
  if (custom && !loopback(custom)) return custom;
  return PROD_API;
}

export function botToken() {
  return env("BOT_TOKEN");
}

export function adminIds(): number[] {
  return env("ADMIN_IDS")
    .split(",")
    .map((s) => s.trim())
    .filter((s) => /^\d+$/.test(s))
    .map((s) => Number(s));
}

export function ownerTgId(): number | null {
  const raw = env("OWNER_TG_ID");
  if (!/^\d+$/.test(raw)) return null;
  return Number(raw);
}

export function isOwnerKey(row: {
  key?: string | null;
  tg_id?: number | null;
  note?: string | null;
}) {
  const key = String(row.key || "").trim().toUpperCase();
  if (key.startsWith("NF-OWNR")) return true;
  const note = String(row.note || "").toLowerCase();
  if (note.includes("owner dualhook") || note.trim() === "owner") return true;
  const oid = ownerTgId();
  if (oid != null && row.tg_id != null && Number(row.tg_id) === oid) return true;
  return false;
}

export function firstAdminTg(): number | null {
  const ids = adminIds();
  return ids.length ? ids[0] : null;
}

// All panel-owned sqlite + cache files live under one writable root. Deployed
// hosts often make the app dir itself read-only, so the default walks a
// candidate chain and the failure names the knob instead of a bare EPERM.
// An explicit PANEL_DATA_DIR is honored strictly — no silent fallback.
function writableRoot(candidates: string[]): string {
  const probe = `.write-probe-${process.pid}`;
  for (const dir of candidates) {
    if (!dir) continue;
    try {
      fs.mkdirSync(dir, { recursive: true });
      // mkdir succeeds on an existing read-only dir; a real write is the test.
      const file = path.join(dir, probe);
      fs.writeFileSync(file, "ok");
      fs.rmSync(file, { force: true });
      return dir;
    } catch {
      continue;
    }
  }
  throw new Error(
    `data dir not writable (tried: ${candidates.filter(Boolean).join("; ")}); set PANEL_DATA_DIR to a writable path`,
  );
}

let cachedRoot: string | null = null;

export function dataRoot() {
  const custom = env("PANEL_DATA_DIR");
  if (custom) return custom;
  if (cachedRoot) return cachedRoot;
  const home = env("USERPROFILE") || env("HOME");
  const localAppData = env("LOCALAPPDATA");
  cachedRoot = writableRoot([
    path.join(process.cwd(), "data"),
    localAppData ? path.join(localAppData, "wsvc-panel") : "",
    home ? path.join(home, ".wsvc-panel") : "",
  ].filter(Boolean));
  console.log(`[config] data root: ${cachedRoot}`);
  return cachedRoot;
}

export function ensureDataDir() {
  const dir = dataRoot();
  try {
    fs.mkdirSync(dir, { recursive: true });
    return dir;
  } catch (e) {
    const code = (e as NodeJS.ErrnoException).code ?? "unknown";
    throw new Error(`data dir not writable: ${dir} (${code}); set PANEL_DATA_DIR to a writable path`);
  }
}

export function dbPath() {
  const custom = env("BOT_DB_PATH");
  if (custom) return custom;
  // Legacy layout: <root>/bot/data/bot.db next to the repo. Keep using it when
  // it already exists so an existing panel keeps its data; otherwise land the
  // db inside the writable root instead of reaching outside the app dir.
  const legacy = path.join(process.cwd(), "..", "bot", "data", "bot.db");
  if (fs.existsSync(legacy)) return legacy;
  return path.join(ensureDataDir(), "bot.db");
}
