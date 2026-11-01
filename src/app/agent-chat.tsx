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
  walletProposalId?: string;
};

import { parseNearTransferCommand } from "@/agent/parse-command";
import { NearWalletPanel } from "@/app/near-wallet-panel";

export function AgentChat() {
  const [input, setInput] = useState("");
  const [busy, setBusy] = useState(false);
  const [messages, setMessages] = useState<Message[]>([
    {
      id: "welcome",
      role: "mandate",
      text: "I'm the MANDATE chat prototype. Try: “Send 0.001 NEAR to confirmwithmandate.testnet”. I'll inspect the proposal and, when eligible, let you explicitly sign the owner approval and transaction in your NEAR wallet."
    }
  ]);

  async function submit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    const command = input.trim();
    if (!command || busy) return;

    setInput("");
    setBusy(true);
    setMessages(current => [...current, { id: crypto.randomUUID(), role: "user", text: command }]);

    const parsed = parseNearTransferCommand(command);
    if (!parsed) {
      setMessages(current => [...current, {
        id: crypto.randomUUID(),
        role: "mandate",
        text: "I couldn't safely turn that into a supported proposal. Use a command like “Send 0.001 NEAR to confirmwithmandate.testnet”. Only NEAR transfers are supported here; I won't guess missing details or interpret other actions."
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
      target: parsed.target,
      network: "testnet"
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
      const isExactWalletTest = parsed.amountAtomic === "1000000000000000000000" &&
        parsed.target === "confirmwithmandate.testnet";
      const canShowWalletApproval = isExactWalletTest &&
        (decision.outcome === "ALLOW" || decision.outcome === "REQUIRE_APPROVAL");
      const explanation = decision.outcome === "ALLOW"
        ? (canShowWalletApproval
            ? "The active policy passed this exact Testnet proposal. You can now request wallet verification and explicitly approve the transfer."
            : "The active policy passed inspection, but this proposal is outside the fixed wallet execution test. No funds were moved.")
        : decision.outcome === "BLOCK"
          ? "MANDATE stopped this proposal. No execution was attempted."
          : (canShowWalletApproval
              ? "The policy requires owner confirmation. Sign the proposal-specific approval message in your connected NEAR wallet before the wallet can request the transfer."
              : "The policy requires owner confirmation, but this proposal is outside the fixed wallet execution test. It cannot be signed or executed through this prototype.");

      setMessages(current => [...current, {
        id: crypto.randomUUID(),
        role: "mandate",
        text: `I checked a transfer of ${parsed.amount} NEAR to ${parsed.target}. ${explanation}`,
        decision,
        ...(canShowWalletApproval ? { walletProposalId: decision.proposalId } : {})
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
        <div className="agent-boundary"><span className="live-dot" /> Policy engine remains in control <b>·</b> Wallet signing is explicit <b>·</b> Testnet only</div>
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
              {message.walletProposalId && (
                <div className="agent-wallet-approval">
                  <p>Exact supported test transaction: 0.001 NEAR to confirmwithmandate.testnet (NEAR Testnet).</p>
                  <NearWalletPanel proposalId={message.walletProposalId} />
                </div>
              )}
            </div>
          ))}
          {busy && <div className="agent-typing">MANDATE is inspecting the proposal…</div>}
        </div>

        <form className="agent-composer" onSubmit={submit}>
          <label htmlFor="agent-command">Your instruction</label>
          <div><input id="agent-command" value={input} onChange={event => setInput(event.target.value)} placeholder="Send 0.001 NEAR to confirmwithmandate.testnet" disabled={busy} autoComplete="off" /><button type="submit" disabled={busy || !input.trim()}>{busy ? "Checking…" : "Inspect →"}</button></div>
          <small>Supported in this first prototype: NEAR transfers only. Do not enter private keys or recovery phrases.</small>
        </form>
      </div>
      <p className="agent-prototype-note">This is a constrained command-parser demo, not an LLM-powered agent yet. Inspection alone never authorizes execution; the supported wallet flow requires a fresh owner signature and a separate transaction approval.</p>
    </section>
  );
}
