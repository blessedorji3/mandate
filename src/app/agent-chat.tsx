"use client";

import { FormEvent, useState } from "react";

type Outcome = "ALLOW" | "BLOCK" | "REQUIRE_APPROVAL";
type Decision = {
  outcome: Outcome;
  reason: string;
  message: string;
  policyId: string;
  policyVersion: number;
  proposalId: string;
};

type Message = {
  id: string;
  role: "user" | "mandate";
  text: string;
  decision?: Decision;
};

const SCALE = 10n ** 24n;

function parseTransfer(input: string) {
  const match = input.trim().match(/^(?:send|transfer)\s+([0-9]+(?:\.[0-9]{1,24})?)\s+near\s+to\s+([a-z0-9._-]{2,64})\.?$/i);
  if (!match) return null;

  const [whole, fraction = ""] = match[1].split(".");
  const amountAtomic = (BigInt(whole) * SCALE + BigInt((fraction + "0".repeat(24)).slice(0, 24))).toString();
  if (BigInt(amountAtomic) <= 0n) return null;

  return { amount: match[1], amountAtomic, target: match[2].toLowerCase() };
}

export function AgentChat() {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "mandate",
      text: "I'm the MANDATE chat prototype. Try: “Send 0.1 NEAR to alice.near”. I'll prepare the proposal and ask the policy engine to inspect it. I cannot sign or send funds."
    }
  ]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const command = input.trim();
    if (!command || busy) return;

    setInput("");
    setBusy(true);
    setMessages(current => [...current, { id: crypto.randomUUID(), role: "user", text: command }]);

    const parsed = parseTransfer(command);
    if (!parsed) {
      setMessages(current => [...current, {
        id: crypto.randomUUID(),
        role: "mandate",
        text: "I couldn't safely turn that into a supported proposal. For this prototype, use this exact format: “Send 0.1 NEAR to alice.near”. Only NEAR transfers are supported here; I won't guess missing details or interpret other actions."
      }]);
      setBusy(false);
      return;
    }

    const proposal = {
      id: crypto.randomUUID(),
      agentId: "mandate-chat-prototype",
      actionType: "transfer",
      asset: "NEAR",
      amountAtomic: parsed.amountAtomic,
      target: parsed.target
    };

    try {
      const response = await fetch("/api/inspect", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ proposal })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? "The inspection service is unavailable.");

      const decision = data.decision as Decision;
      const explanation = decision.outcome === "ALLOW"
        ? "The active policy passed this proposal. This is an inspection result only; no wallet was called and no funds were moved."
        : decision.outcome === "BLOCK"
          ? "MANDATE stopped this proposal. No execution was attempted."
          : "The policy requires owner confirmation. This prototype records the requirement but does not execute or approve the transfer.";

      setMessages(current => [...current, {
        id: crypto.randomUUID(),
        role: "mandate",
        text: `I checked a transfer of ${parsed.amount} NEAR to ${parsed.target}. ${explanation}`,
        decision
      }]);
    } catch (error) {
      setMessages(current => [...current, {
        id: crypto.randomUUID(),
        role: "mandate",
        text: `Inspection failed closed: ${error instanceof Error ? error.message : "Unknown error"}. No action was authorized.`
      }]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="agent-workspace">
      <div className="agent-intro">
        <span className="eyebrow">MANDATE AGENT · PROTOTYPE</span>
        <h1>Talk to your agent.</h1>
        <p>Describe a proposed action in plain language. MANDATE checks the structured proposal against your saved security policy.</p>
        <div className="agent-boundary"><span className="live-dot" /> Policy engine remains in control <b>·</b> No wallet connected <b>·</b> No funds move</div>
      </div>

      <div className="agent-chat-panel">
        <div className="agent-chat-heading">
          <div><span className="agent-avatar">M</span><span><strong>MANDATE assistant</strong><small>Command parser prototype · Policy checks are deterministic</small></span></div>
          <a href="/">Back to dashboard</a>
        </div>

        <div className="agent-messages" aria-live="polite">
          {messages.map(message => (
            <div className={`agent-message ${message.role}`} key={message.id}>
              <div className="agent-message-label">{message.role === "user" ? "YOU" : "MANDATE"}</div>
              <p>{message.text}</p>
              {message.decision && (
                <div className={`agent-decision ${message.decision.outcome.toLowerCase()}`}>
                  <strong>{message.decision.outcome.replace("_", " ")}</strong>
                  <span>{message.decision.reason.replaceAll("_", " ")}</span>
                  <small>Policy version {message.decision.policyVersion} · Ref {message.decision.proposalId}</small>
                </div>
              )}
            </div>
          ))}
          {busy && <div className="agent-typing">MANDATE is inspecting the proposal…</div>}
        </div>

        <form className="agent-composer" onSubmit={submit}>
          <label htmlFor="agent-command">Your instruction</label>
          <div><input id="agent-command" value={input} onChange={event => setInput(event.target.value)} placeholder="Send 0.1 NEAR to alice.near" disabled={busy} autoComplete="off" /><button type="submit" disabled={busy || !input.trim()}>{busy ? "Checking…" : "Inspect →"}</button></div>
          <small>Supported in this first prototype: NEAR transfers only. Do not enter private keys or recovery phrases.</small>
        </form>
      </div>
      <p className="agent-prototype-note">This is a constrained command-parser demo, not an LLM-powered agent yet. An ALLOW decision is not a transaction signature or execution authorization.</p>
    </section>
  );
}
