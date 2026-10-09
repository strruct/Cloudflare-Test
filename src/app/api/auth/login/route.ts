import { NextResponse } from "next/server";
import { setSession } from "@/lib/auth";
import { verifyUser } from "@/lib/users";
import { rateOk } from "@/lib/rate";

export async function POST(req: Request) {
  try {
    const ip = req.headers.get("x-forwarded-for")?.split(",")[0]?.trim() || "unknown";
    if (!rateOk(`login:${ip}`, 8, 600_000)) {
      return NextResponse.json({ error: "too many attempts" }, { status: 429 });
    }
    const body = await req.json().catch(() => ({}));
    const username = String(body.username ?? "").trim();
    const password = String(body.password ?? "");
    if (!username || !password) {
      return NextResponse.json({ error: "username and password required" }, { status: 400 });
    }

    const user = verifyUser(username, password);
    if (!user) {
      return NextResponse.json({ error: "invalid username or password" }, { status: 401 });
    }

    await setSession({ kind: user.isAdmin ? "admin" : "user", tgId: user.tgId, key: "local" });
    return NextResponse.json({ ok: true, role: user.isAdmin ? "admin" : "user" });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "fail";
    return NextResponse.json({ error: msg.slice(0, 200) }, { status: 500 });
  }
}
