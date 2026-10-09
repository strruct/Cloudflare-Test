import { NextResponse } from "next/server";
import { requireSession } from "@/lib/auth";
import { getLocalUser } from "@/lib/users";
import { getKey, getUser, maskWebhook, now } from "@/lib/db";

export async function GET() {
  const sess = await requireSession();
  if (!sess) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const local = getLocalUser(sess.tgId);
  if (!local) return NextResponse.json({ error: "user not found" }, { status: 404 });

  let key = "-";
  let webhookMask = "-";
  let hasWebhook = false;
  let daysLeft = 0;
  try {
    const user = await getUser(sess.tgId);
    if (user) {
      key = user.key || "-";
      webhookMask = maskWebhook(user.webhook);
      hasWebhook = Boolean(user.webhook);
      const row = user.key ? await getKey(user.key) : null;
      daysLeft = row ? Math.floor(Math.max(0, row.expires_at - now()) / 86400) : 0;
    }
  } catch {
    // bot DB is optional; local auth works without it
  }

  return NextResponse.json({
    user: {
      tgId: local.tgId,
      username: local.username,
      key,
      webhookMask,
      hasWebhook,
    },
    daysLeft,
    role: local.isAdmin ? "admin" : "user",
  });
}
