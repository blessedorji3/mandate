"use client";

import { useEffect, useState } from "react";
import { createClient } from "@/lib/supabase/client";

type ApiKey = { id: string; name: string; key_prefix: string; created_at: string; last_used_at: string | null; revoked_at: string | null };
const endpoint = "https://abyyyehfivahedvjrcwj.supabase.co/functions/v1/agent-inspect";

async function sha256(value: string) {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest)).map(byte => byte.toString(16).padStart(2, "0")).join("");
}

export function DeveloperPanel() {
  const [keys, setKeys] = useState<ApiKey[]>([]);
  const [name, setName] = useState("My first agent");
  const [newKey, setNewKey] = useState("");
  const [message, setMessage] = useState("Loading API keys…");
  const [busy, setBusy] = useState(false);

  async function refresh() {
    const supabase = createClient();
    const { data, error } = await supabase.from("api_keys")
      .select("id,name,key_prefix,created_at,last_used_at,revoked_at")
      .order("created_at", { ascending: false }).limit(20);
    if (error) throw error;
    setKeys((data ?? []) as ApiKey[]);
  }

  useEffect(() => { refresh().then(() => setMessage("Your API keys are private to your account.")).catch(() => setMessage("Could not load API keys. Please refresh.")); }, []);

  async function createKey() {
    if (!name.trim() || name.trim().length > 80) { setMessage("Give this key a name between 1 and 80 characters."); return; }
    setBusy(true); setMessage(""); setNewKey("");
    try {
      const supabase = createClient();
      const { data: { user }, error: authError } = await supabase.auth.getUser();
      if (authError || !user) throw new Error("Sign in before creating an API key.");
      const bytes = crypto.getRandomValues(new Uint8Array(32));
      const random = btoa(Array.from(bytes, b => String.fromCharCode(b)).join("")).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/g, "");
      const secret = "mnd_live_" + random;
      const hash = await sha256(secret);
      const { error } = await supabase.from("api_keys").insert({
        owner_id: user.id, name: name.trim(), key_prefix: secret.slice(0, 18), key_hash: hash
      });
      if (error) throw error;
      setNewKey(secret);
      await refresh();
      setMessage("API key created. Copy it now; MANDATE will not show it again.");
    } catch (e) { setMessage(e instanceof Error ? e.message : "Could not create API key."); }
    finally { setBusy(false); }
  }

  async function revoke(id: string) {
    setBusy(true); setMessage("");
    try {
      const supabase = createClient();
      const { error } = await supabase.from("api_keys").update({ revoked_at: new Date().toISOString() }).eq("id", id).is("revoked_at", null);
      if (error) throw error;
      await refresh();
      setMessage("API key revoked. Requests using it will now be rejected.");
      if (newKey) setNewKey("");
    } catch (e) { setMessage(e instanceof Error ? e.message : "Could not revoke API key."); }
    finally { setBusy(false); }
  }

  return <section className="panel developer-panel" id="developers">
    <div className="panel-heading"><div><span className="step">05</span><h3>Developer API</h3></div><span className="muted-tag">AGENT ACCESS</span></div>
    <p className="section-copy">Create private API keys for your agents. Each request is checked against your active security policy.</p>
    <div className="developer-create">
      <label>Key name<input value={name} onChange={e => setName(e.target.value)} maxLength={80} placeholder="e.g. Trading research agent"/></label>
      <button className="inspect-button" onClick={createKey} disabled={busy}>{busy ? "Working…" : "＋ Create API key"}</button>
    </div>
    {newKey && <div className="new-key-box"><strong>Copy your new key now</strong><p>This is the only time the full key will be shown. Store it in your agent's server-side environment variables, never in frontend code.</p><code>{newKey}</code><button className="outline-button" onClick={() => navigator.clipboard.writeText(newKey)}>Copy API key</button></div>}
    <div className="api-key-list">{keys.length === 0 ? <p className="empty-history">No API keys created yet.</p> : keys.map(key => <div className="api-key-row" key={key.id}><div className="api-key-info"><strong>{key.name}</strong><code>{key.key_prefix}••••••••</code><small>Created {new Date(key.created_at).toLocaleDateString()} · {key.last_used_at ? "Last used " + new Date(key.last_used_at).toLocaleString() : "Never used"}</small></div>{key.revoked_at ? <span className="key-revoked">REVOKED</span> : <button className="revoke-button" onClick={() => revoke(key.id)} disabled={busy}>Revoke</button>}</div>)}</div>
    <div className="api-endpoint"><span>INSPECTION ENDPOINT</span><code>{endpoint}</code></div>
    <details className="api-example"><summary>View integration example</summary><pre>{`const response = await fetch("${endpoint}", {
  method: "POST",
  headers: {
    "Authorization": "Bearer " + process.env.MANDATE_API_KEY,
    "Content-Type": "application/json"
  },
  body: JSON.stringify({
    proposal: {
      id: "proposal-001",
      agentId: "my-agent",
      actionType: "transfer",
      asset: "NEAR",
      amountAtomic: "200000000000000000000000",
      target: "alice.near"
    }
  })
});

const result = await response.json();
console.log(result.decision); // ALLOW, BLOCK or REQUIRE_APPROVAL`}</pre></details>
    <p className="secure-note">API keys are stored as SHA-256 hashes. The raw key is shown once, can be revoked, and never grants wallet signing or fund access.</p>
    <p className="developer-status" role="status">{message}</p>
  </section>;
}
