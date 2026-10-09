import { NextResponse } from "next/server";
import { requireSession, isAdminSession } from "@/lib/auth";
import { listAgents } from "@/lib/db";

export async function GET() {
  const sess = await requireSession();
  if (!sess) return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  try {
    const rows = await listAgents(isAdminSession(sess) ? undefined : sess.tgId, 300);
    return NextResponse.json({
      agents: rows.map((a) => ({
        hwid: a.hwid,
        name: a.name,
        os: a.os,
        ip: a.ip,
        lastSeen: a.last_seen,
        online: Boolean(a.online),
        meta: (() => {
          try {
            return JSON.parse(a.meta || "{}");
          } catch {
            return {};
          }
        })(),
      })),
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "db fail";
    return NextResponse.json({ error: msg.slice(0, 500), agents: [] }, { status: 503 });
  }
}
