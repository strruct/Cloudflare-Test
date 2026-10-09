import { NextResponse } from "next/server";
import { requireSession } from "@/lib/auth";
import { setWebhook, validDiscordWebhook } from "@/lib/db";

export async function POST(req: Request) {
  const sess = await requireSession();
  if (!sess) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const body = await req.json().catch(() => ({}));
  const url = String(body.url ?? "").trim();
  if (!validDiscordWebhook(url)) {
    return NextResponse.json({ error: "invalid discord webhook" }, { status: 400 });
  }
  try {
    await setWebhook(sess.tgId, url);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "db fail";
    return NextResponse.json({ error: msg.slice(0, 500) }, { status: 503 });
  }
  return NextResponse.json({ ok: true });
}
