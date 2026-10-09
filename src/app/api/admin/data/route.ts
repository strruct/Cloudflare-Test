import { NextResponse } from "next/server";
import { isAdminTg, requireAdmin } from "@/lib/auth";
import { isOwnerKey } from "@/lib/config";
import { listKeys, listUsers, maskWebhook, now } from "@/lib/db";

export async function GET() {
  const sess = await requireAdmin();
  if (!sess) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  try {
    const t = now();
    const keys = (await listKeys(500)).map((r) => {
      const tgId = r.tg_id != null ? Number(r.tg_id) : null;
      const owner = isOwnerKey(r);
      const protectedKey = owner || (tgId != null && isAdminTg(tgId));
      return {
        key: r.key,
        note: r.note,
        days: r.days,
        leftDays: Math.max(0, Math.floor((r.expires_at - t) / 86400)),
        status: r.revoked ? "REV" : r.expires_at <= t ? "EXP" : "OK",
        username: (r.username || "").trim() || null,
        tgId,
        protected: protectedKey,
        owner,
      };
    });
    const users = (await listUsers(200)).map((u) => ({
      tgId: u.tg_id,
      username: u.username,
      key: u.key,
      webhook: maskWebhook(u.webhook),
      ingest: Boolean(u.hook_id),
      updatedAt: u.updated_at,
    }));
    return NextResponse.json({
      keys,
      users,
      stats: {
        keys: keys.length,
        active: keys.filter((k) => k.status === "OK").length,
        revoked: keys.filter((k) => k.status === "REV").length,
        expired: keys.filter((k) => k.status === "EXP").length,
        users: users.length,
        hooked: users.filter((u) => u.ingest).length,
      },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "db fail";
    return NextResponse.json(
      { error: msg.slice(0, 500), keys: [], users: [], stats: { keys: 0, active: 0, revoked: 0, expired: 0, users: 0, hooked: 0 } },
      { status: 503 },
    );
  }
}
