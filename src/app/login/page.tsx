"use client";

import { FormEvent, useState } from "react";
import Link from "next/link";
import { createClient } from "@/lib/supabase/client";

export default function LoginPage() {
  const [mode, setMode] = useState<"signin" | "signup">("signin");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [message, setMessage] = useState("");
  const [busy, setBusy] = useState(false);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setMessage("");
    setBusy(true);
    try {
      const supabase = createClient();
      if (mode === "signup") {
        const { data, error } = await supabase.auth.signUp({
          email,
          password,
          options: { emailRedirectTo: `${window.location.origin}/auth/callback` }
        });
        if (error) throw error;
        if (data.session) {
          window.location.assign("/wallet?setup=recovery");
        } else {
          setMessage("Check your email for the confirmation link. After confirming, MANDATE will guide you through creating your one-time recovery code.");
        }
      } else {
        const { error } = await supabase.auth.signInWithPassword({ email, password });
        if (error) throw error;
        window.location.assign("/");
      }
    } catch (error) {
      setMessage(error instanceof Error ? error.message : "Authentication failed. Please try again.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="auth-shell">
      <section className="auth-card">
        <Link className="brand auth-brand" href="/"><span className="brand-mark">M</span><span>MANDATE<small>SECURITY LAYER</small></span></Link>
        <p className="eyebrow">PRIVATE WORKSPACE</p>
        <h1>{mode === "signin" ? "Welcome back." : "Create your workspace."}</h1>
        <p className="auth-copy">Your agents. Your rules. Your authorization boundary.</p>
        <form className="auth-form" onSubmit={submit}>
          <label htmlFor="email">Email address</label>
          <input id="email" type="email" autoComplete="email" required value={email} onChange={(e) => setEmail(e.target.value)} placeholder="you@example.com" />
          <label htmlFor="password">Password</label>
          <input id="password" type="password" autoComplete={mode === "signin" ? "current-password" : "new-password"} minLength={8} required value={password} onChange={(e) => setPassword(e.target.value)} placeholder="At least 8 characters" />
          <button className="inspect-button" type="submit" disabled={busy}>{busy ? "Please wait…" : mode === "signin" ? "Sign in" : "Create account"} <span>→</span></button>
        </form>
        {message && <p className="auth-message" role="status">{message}</p>}
        <p className="auth-switch">{mode === "signin" ? "New to MANDATE?" : "Already have an account?"} <button type="button" onClick={() => { setMode(mode === "signin" ? "signup" : "signin"); setMessage(""); }}>{mode === "signin" ? "Create an account" : "Sign in"}</button></p>
        <p className="auth-foot">Authentication is handled by MANDATE's separate Supabase project. No wallet or funds are connected.</p>
      </section>
    </main>
  );
}
