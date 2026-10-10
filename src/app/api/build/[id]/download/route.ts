import fs from "fs";
import path from "path";
import { NextResponse } from "next/server";
import { requireSession } from "@/lib/auth";
import { distRoots, getBuild } from "@/lib/db";

export async function GET(
  _req: Request,
  ctx: { params: Promise<{ id: string }> },
) {
  const sess = await requireSession();
  if (!sess) {
    return NextResponse.json({ error: "unauthorized" }, { status: 401 });
  }
  try {
    const { id } = await ctx.params;
    const build = await getBuild(Number(id));
    if (!build || Number(build.tg_id) !== sess.tgId) {
      return NextResponse.json({ error: "not found" }, { status: 404 });
    }
    if ((build.kind !== "jar" && build.kind !== "exe") || build.status !== "ok") {
      return NextResponse.json({ error: "not downloadable" }, { status: 400 });
    }
    if (!build.artifact) {
      return NextResponse.json({ error: "file missing" }, { status: 404 });
    }

    const candidate = path.resolve(build.artifact);
    const norm = candidate.replace(/\\/g, "/");
    const ok = distRoots().some((r) => {
      const prefix = r.replace(/\\/g, "/").replace(/\/+$/, "");
      return norm === prefix || norm.startsWith(prefix + "/");
    });
    if (!ok) {
      return NextResponse.json({ error: "not downloadable" }, { status: 400 });
    }
    if (!fs.existsSync(candidate)) {
      return NextResponse.json({ error: "file missing" }, { status: 404 });
    }

    const buf = fs.readFileSync(candidate);
    const isExe = build.kind === "exe";
    const defLabel = isExe ? "installer" : "zombiesurvival";
    const ext = isExe ? "exe" : "jar";
    const label = (build.label || defLabel).replace(/[^\w\- ]+/g, "").trim() || defLabel;
    const fname = `${label.replace(/\s+/g, "") || "build"}.${ext}`;
    return new NextResponse(buf, {
      status: 200,
      headers: {
        "Content-Type": isExe ? "application/octet-stream" : "application/java-archive",
        "Content-Disposition": `attachment; filename="${fname}"`,
        "Content-Length": String(buf.length),
      },
    });
  } catch (e) {
    const msg = e instanceof Error ? e.message : "db fail";
    return NextResponse.json({ error: msg.slice(0, 500) }, { status: 503 });
  }
}
