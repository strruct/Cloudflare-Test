import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/auth";
import { insertKey, makeKey } from "@/lib/db";

export async function POST(req: Request) {
  const sess = await requireAdmin();
  if (!sess) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  const body = await req.json().catch(() => ({}));
  const days = Number(body.days ?? 30);
  const note = String(body.note ?? "").trim();
  if (!Number.isFinite(days) || days < 1 || days > 3650) {
    return NextResponse.json({ error: "days 1-3650" }, { status: 400 });
  }
  const key = await makeKey().catch((e) => {
    const msg = e instanceof Error ? e.message : "db fail";
    return NextResponse.json({ error: msg.slice(0, 500) }, { status: 503 });
  });
  if (key instanceof NextResponse) return key;
  try {
    await insertKey(key, days, note);
  } catch (e) {
    const msg = e instanceof Error ? e.message : "db fail";
    return NextResponse.json({ error: msg.slice(0, 500) }, { status: 503 });
  }
  return NextResponse.json({ ok: true, key });
}
