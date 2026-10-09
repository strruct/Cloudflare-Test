import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth";
import { ensureHook } from "@/lib/db";

export async function POST() {
  const sess = await requireAdmin();
  if (!sess) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  try {
    await ensureHook(sess.tgId, true);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "db fail";
    return NextResponse.json({ error: msg.slice(0, 500) }, { status: 503 });
  }
  return NextResponse.json({ ok: true });
}
