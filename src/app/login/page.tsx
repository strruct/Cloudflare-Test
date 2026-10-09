"use client";

import { useRef, useState } from "react";
import { motion } from "motion/react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { play } from "@/lib/sound";
import { Particles } from "@/components/ui/particles";
import { ShineBorder } from "@/components/ui/shine-border";

export default function LoginPage() {
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [err, setErr] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const lock = useRef(false);

  async function submit(e: React.FormEvent) {
    e.preventDefault();
    if (lock.current) return;
    lock.current = true;
    setBusy(true);
    setErr(null);
    try {
      const res = await fetch("/api/auth/login", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ username, password }),
      });
      const data = await res.json().catch(() => ({}));
      if (!res.ok) throw new Error(data.error || `fail ${res.status}`);
      play("ok");
      window.location.assign("/dash");
      return;
    } catch (ex) {
      play("err");
      setErr(ex instanceof Error ? ex.message : "fail");
    } finally {
      lock.current = false;
      setBusy(false);
    }
  }

  return (
    <main className="relative flex min-h-dvh items-center justify-center overflow-hidden px-4 py-8">
      <div className="pointer-events-none absolute inset-0 z-0">
        <div className="absolute inset-0 bg-[radial-gradient(ellipse_at_center,rgba(255,255,255,0.06),transparent_55%)]" />
        <Particles
          className="absolute inset-0"
          quantity={48}
          ease={80}
          staticity={50}
          size={0.4}
          color="#ffffff"
        />
      </div>

      <div className="relative z-10 w-full max-w-md page-enter">
        <div className="mb-8 text-center">
          <p className="text-[11px] font-medium uppercase tracking-[0.22em] text-zinc-500">spywarehook</p>
          <h1 className="mt-3 font-heading text-4xl font-semibold tracking-tight text-white">
            Sign in
          </h1>
          <p className="mt-2 text-sm leading-relaxed text-zinc-400">Username &amp; password</p>
        </div>

        <div className="relative overflow-hidden rounded-3xl border border-white/10 bg-card/80 p-6 shadow-[0_24px_80px_rgba(0,0,0,0.45)] backdrop-blur-xl">
          <ShineBorder
            borderWidth={1}
            duration={12}
            shineColor={["#ffffff33", "#a1a1aa55", "#ffffff22"]}
            className="rounded-3xl"
          />
          {err ? <p className="relative z-10 mb-4 text-center text-sm text-red-300">{err}</p> : null}
          <motion.form
            key="creds"
            initial={{ opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.2 }}
            onSubmit={submit}
            className="relative z-10 space-y-4"
          >
            <div className="space-y-2 text-center">
              <label className="block text-xs text-zinc-500">username</label>
              <Input
                value={username}
                onChange={(e) => setUsername(e.target.value)}
                placeholder="admin"
                required
                autoFocus
                autoComplete="username"
                className="text-center font-mono tracking-wide"
              />
            </div>
            <div className="space-y-2 text-center">
              <label className="block text-xs text-zinc-500">password</label>
              <Input
                type="password"
                value={password}
                onChange={(e) => setPassword(e.target.value)}
                placeholder="••••••••"
                required
                autoComplete="current-password"
                className="text-center font-mono tracking-wide"
              />
            </div>
            <Button type="submit" className="w-full" disabled={busy} sound={false}>
              {busy ? "signing in…" : "sign in"}
            </Button>
          </motion.form>
        </div>
      </div>
    </main>
  );
}
