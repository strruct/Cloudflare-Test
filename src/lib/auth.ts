import { SignJWT, jwtVerify } from "jose";
import { cookies } from "next/headers";
import { adminIds, panelSecret } from "./config";
import { getLocalUser } from "./users";

const COOKIE = "wsvc_sess";

function key() {
  return new TextEncoder().encode(panelSecret());
}

export type Session =
  | { kind: "user"; tgId: number; key: string }
  | { kind: "admin"; tgId: number; key: string };

export function isAdminTg(tgId: number) {
  return adminIds().includes(tgId);
}

export async function setSession(session: Session) {
  const token = await new SignJWT(session as unknown as Record<string, unknown>)
    .setProtectedHeader({ alg: "HS256" })
    .setIssuedAt()
    .setExpirationTime("7d")
    .sign(key());
  const jar = await cookies();
  jar.set(COOKIE, token, {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    secure: process.env.NODE_ENV === "production",
  });
}

export async function clearSession() {
  const jar = await cookies();
  jar.set(COOKIE, "", {
    httpOnly: true,
    sameSite: "lax",
    path: "/",
    secure: process.env.NODE_ENV === "production",
    maxAge: 0,
  });
}

export async function getSession(): Promise<Session | null> {
  const jar = await cookies();
  const raw = jar.get(COOKIE)?.value;
  if (!raw) return null;
  try {
    const { payload } = await jwtVerify(raw, key());
    if (
      (payload.kind === "admin" || payload.kind === "user") &&
      typeof payload.tgId === "number" &&
      typeof payload.key === "string"
    ) {
      return { kind: payload.kind, tgId: payload.tgId, key: payload.key };
    }
    return null;
  } catch {
    return null;
  }
}

export function isAdminSession(sess: Session | null): sess is Session & { kind: "admin" } {
  if (sess?.kind !== "admin") return false;
  if (isAdminTg(sess.tgId)) return true;
  return getLocalUser(sess.tgId)?.isAdmin ?? false;
}

export async function requireSession(): Promise<Session | null> {
  const sess = await getSession();
  if (!sess) return null;
  const user = getLocalUser(sess.tgId);
  if (!user) {
    await clearSession();
    return null;
  }
  if (sess.kind === "admin" && !user.isAdmin && !isAdminTg(sess.tgId)) {
    await clearSession();
    return null;
  }
  return sess;
}

export async function requireAdmin(): Promise<Session | null> {
  const sess = await requireSession();
  if (!sess || !isAdminSession(sess)) return null;
  return sess;
}
