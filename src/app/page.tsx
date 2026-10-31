"use client";

import { useMemo, useState } from "react";
import { SignOutButton } from "@/app/sign-out-button";
import { PolicyPanel } from "@/app/policy-panel";

type Outcome = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
type Decision = { outcome: Outcome; reason: string; message: string; policyId: string; policyVersion: number; proposalId: string };

const scenarios = [
  { id: "safe", label: "Permitted transfer", detail: "Known recipient · within limit", amount: "0.2", target: "alice.near", type: "transfer" },
  { id: "limit", label: "Excessive transfer", detail: "Amount exceeds policy limit", amount: "2", target: "alice.near", type: "transfer" },
  { id: "recipient", label: "Unknown recipient", detail: "Destination is not approved", amount: "0.1", target: "mallory.near", type: "transfer" },
  { id: "approval", label: "Token approval", detail: "Sensitive allowance requires owner approval", amount: "0.1", target: "alice.near", type: "token_approval" },
  { id: "override", label: "Unsupported swap", detail: "Swap inspection is disabled until transaction details can be verified", amount: "0.1", target: "alice.near", type: "swap" }
] as const;

export default function Home() {
  const [selected, setSelected] = useState<string>("safe");
  const [result, setResult] = useState<Decision | null>(null);
  const [loading, setLoading] = useState(false);
  const [history, setHistory] = useState<Decision[]>([]);
  const scenario = useMemo(() => scenarios.find((item) => item.id === selected) ?? scenarios[0], [selected]);

  async function inspect() {
    setLoading(true);
    setResult(null);
    const proposal = {
      id: `demo-${scenario.id}-${Date.now()}`,
      agentId: "research-agent",
      actionType: scenario.type,
      asset: "NEAR",
      amountAtomic: scenario.amount === "2" ? "2000000000000000000000000" : "200000000000000000000000",
      target: scenario.target,
      ...(scenario.type === "token_approval" ? { approvalAmountAtomic: "200000000000000000000000" } : {})
    };
    try {
      const response = await fetch("/api/inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ proposal })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? "Inspection failed");
      setResult(data.decision);
      setHistory((items) => [data.decision, ...items].slice(0, 6));
    } catch (error) {
      setResult({
        outcome: "BLOCK",
        reason: "INSPECTION_UNAVAILABLE",
        message: error instanceof Error ? error.message : "Inspection unavailable. Fail closed.",
        policyId: "demo",
        policyVersion: 1,
        proposalId: "unavailable"
      });
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="shell">
      <aside className="sidebar">
        <a className="brand" href="#"><span className="brand-mark">M</span><span>MANDATE<small>SECURITY LAYER</small></span></a>
        <div className="workspace"><span className="avatar">D</span><span>Private workspace<small>Account protected</small></span><span className="chevron">⌄</span></div>
        <p className="nav-label">WORKSPACE</p>
        <a className="nav-item active" href="#overview"><span>◫</span> Overview</a>
        <a className="nav-item" href="#attack-lab"><span>⌘</span> Attack Lab <i>LIVE</i></a>
        <a className="nav-item" href="#activity"><span>↗</span> Decision history</a>
        <p className="nav-label second">CONFIGURATION</p>
        <a className="nav-item" href="#policy"><span>◈</span> Security policy</a>
        <a className="nav-item" href="#developers"><span>⌘</span> Developer API</a>
        <div className="sidebar-bottom"><div className="status-dot"></div><span>Policy engine online<small>Deterministic checks active</small></span></div>
      </aside>

      <section className="main-area" id="overview">
        <header className="topbar"><div className="crumb">Workspace <span>/</span> Overview</div><div className="top-actions"><SignOutButton /><span className="env-pill"><b></b> TEST ENVIRONMENT</span><button className="icon-button" aria-label="Notifications">♧</button><div className="user-avatar">B</div></div></header>
        <div className="content">
          <div className="welcome-row"><div><p className="eyebrow">SATURDAY, OCTOBER 31, 2026</p><h1>Your agents. <em>Your rules.</em></h1><p className="subheading">A clear view of what your AI agents can do — and what they can&apos;t.</p></div><button className="outline-button" onClick={() => { setResult(null); setHistory([]); }}>↻ Reset demo</button></div>

          <div className="metrics">
            <article className="metric-card"><div className="metric-top"><span>POLICY STATUS</span><span className="metric-icon green">◈</span></div><div className="metric-value"><span className="live-dot"></span> Active</div><p>Owner-managed policy</p></article>
            <article className="metric-card"><div className="metric-top"><span>AGENTS CONNECTED</span><span className="metric-icon">⌘</span></div><div className="metric-value">01 <small>agent</small></div><p>No wallet or agent connected</p></article>
            <article className="metric-card"><div className="metric-top"><span>ACTIONS INSPECTED</span><span className="metric-icon">⌁</span></div><div className="metric-value">{history.length.toString().padStart(2, "0")}</div><p>In this demo session</p></article>
            <article className="metric-card"><div className="metric-top"><span>SECURITY DECISIONS</span><span className="metric-icon">⬡</span></div><div className="metric-value">{history.filter((item) => item.outcome !== "ALLOW").length.toString().padStart(2, "0")} <small>blocked / approval</small></div><p>Denied or awaiting owner review</p></article>
          </div>

          <div className="section-heading" id="attack-lab"><div><p className="eyebrow">INTERACTIVE SIMULATION</p><h2>Security inspection</h2><p className="section-copy">Send an agent action through the real server-side policy engine.</p></div><span className="engine-badge"><span className="live-dot"></span> ENGINE READY</span></div>

          <div className="lab-grid">
            <section className="panel scenario-panel">
              <div className="panel-heading"><div><span className="step">01</span><h3>Choose an action</h3></div><span className="muted-tag">AGENT PROPOSAL</span></div>
              <div className="scenario-list">
                {scenarios.map((item) => <button key={item.id} className={selected === item.id ? "scenario selected" : "scenario"} onClick={() => { setSelected(item.id); setResult(null); }}><span className="scenario-radio">{selected === item.id ? "●" : ""}</span><span className="scenario-text"><strong>{item.label}</strong><small>{item.detail}</small></span><span className="scenario-arrow">↗</span></button>)}
              </div>
              <div className="proposal-preview"><div className="preview-title">PROPOSAL PREVIEW <span>JSON</span></div><pre>{JSON.stringify({ agent: "research-agent", action: scenario.type, asset: "NEAR", amount: scenario.amount, recipient: scenario.target }, null, 2)}</pre></div>
              <button className="inspect-button" onClick={inspect} disabled={loading}>{loading ? <><span className="spinner"></span> Inspecting action…</> : <>Inspect action <span>→</span></>}</button>
              <p className="secure-note"><span>◆</span> Inspection runs on the server. No wallet is connected and no funds move.</p>
            </section>

            <section className="panel decision-panel">
              <div className="panel-heading"><div><span className="step">02</span><h3>Authorization decision</h3></div><span className="muted-tag">POLICY ENGINE</span></div>
              {!result ? <div className="empty-decision"><div className="shield-art"><span>◇</span><i></i></div><h3>Awaiting inspection</h3><p>Choose an action and inspect it to see how MANDATE enforces the owner&apos;s policy.</p><div className="decision-legend"><span><i className="allow-dot"></i> Allow</span><span><i className="block-dot"></i> Block</span><span><i className="review-dot"></i> Needs approval</span></div></div> : <div className="result-wrap"><div className={`result-symbol ${result.outcome.toLowerCase()}`}>{result.outcome === "ALLOW" ? "✓" : result.outcome === "BLOCK" ? "×" : "!"}</div><div className={`result-outcome ${result.outcome.toLowerCase()}`}>{result.outcome.replace("_", " ")}</div><h3>{result.outcome === "ALLOW" ? "This action is permitted." : result.outcome === "BLOCK" ? "Action stopped by policy." : "Owner confirmation required."}</h3><p>{result.message}</p><div className="reason-card"><span>DECISION REASON</span><strong>{result.reason}</strong><small>Policy {result.policyId} · Version {result.policyVersion}</small></div><div className="decision-foot"><span>Proposal reference</span><code>{result.proposalId}</code></div></div>}
              <div className="engine-footer"><span className="live-dot"></span> Deterministic authorization · AI-independent</div>
            </section>
          </div>

          <section className="panel activity-panel" id="activity"><div className="panel-heading"><div><span className="step">03</span><h3>Recent decisions</h3></div><span className="muted-tag">THIS SESSION</span></div>{history.length === 0 ? <div className="empty-history">No decisions yet. Run your first inspection above.</div> : <div className="history-list">{history.map((item, index) => <div className="history-row" key={item.proposalId + index}><span className={`history-icon ${item.outcome.toLowerCase()}`}>{item.outcome === "ALLOW" ? "✓" : item.outcome === "BLOCK" ? "×" : "!"}</span><span className="history-main"><strong>{item.reason.replaceAll("_", " ").toLowerCase()}</strong><small>{item.proposalId}</small></span><span className={`history-status ${item.outcome.toLowerCase()}`}>{item.outcome.replace("_", " ")}</span></div>)}</div>}</section>

          <PolicyPanel />

          <footer className="footer"><span>MANDATE <b>·</b> Intelligence with boundaries.</span><span>Prototype v0.1 <b>·</b> Test environment only</span></footer>
        </div>
      </section>
    </main>
  );
}
