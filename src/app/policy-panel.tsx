"use client";

import { useEffect, useState } from "react";

type Policy = {
  id: string; name: string; version: number; active: boolean;
  max_amount_atomic: string; allowed_recipients: string[]; allowed_action_types: string[];
  require_approval_for_token_approvals: boolean; require_approval_for_all_actions: boolean;
};

const ACTIONS = ["transfer", "token_approval"] as const;

export function PolicyPanel() {
  const [policy, setPolicy] = useState<Policy | null>(null);
  const [name, setName] = useState("My agent policy");
  const [max, setMax] = useState("1000000000000000000000000");
  const [recipients, setRecipients] = useState("alice.near, treasury.near");
  const [actions, setActions] = useState<string[]>(["transfer", "token_approval"]);
  const [approval, setApproval] = useState(true);
  const [allApproval, setAllApproval] = useState(false);
  const [active, setActive] = useState(true);
  const [message, setMessage] = useState("Loading your private policy…");
  const [busy, setBusy] = useState(false);

  useEffect(() => {
    fetch("/api/policies").then(async r => {
      const data = await r.json();
      if (!r.ok) throw new Error(data.error ?? "Could not load policy.");
      if (data.policy) {
        const p = data.policy as Policy;
        setPolicy(p); setName(p.name); setMax(p.max_amount_atomic);
        setRecipients(p.allowed_recipients.join(", ")); setActions(p.allowed_action_types);
        setApproval(p.require_approval_for_token_approvals);
        setAllApproval(p.require_approval_for_all_actions); setActive(p.active);
        setMessage("Your saved policy is loaded.");
      } else setMessage("No policy yet. Set your rules and save to begin.");
    }).catch(e => setMessage(e instanceof Error ? e.message : "Policy unavailable."));
  }, []);

  function toggleAction(action: string) {
    setActions(current => current.includes(action) ? current.filter(x => x !== action) : [...current, action]);
  }

  async function save() {
    setBusy(true); setMessage("");
    try {
      const response = await fetch("/api/policies", {
        method: "PUT", headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          name, maxAmountAtomic: max.trim(),
          allowedRecipients: recipients.split(",").map(x => x.trim()).filter(Boolean),
          allowedActionTypes: actions, requireApprovalForTokenApprovals: approval,
          requireApprovalForAllActions: allApproval, active
        })
      });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error ?? "Could not save policy.");
      setPolicy(data.policy); setMessage("Policy saved securely. New inspections will use this version.");
    } catch (e) { setMessage(e instanceof Error ? e.message : "Could not save policy."); }
    finally { setBusy(false); }
  }

  return <section className="panel policy-panel" id="policy">
    <div className="panel-heading"><div><span className="step">04</span><h3>Your security policy</h3></div><span className="muted-tag">{policy ? `VERSION ${policy.version}` : "OWNER CONFIGURATION"}</span></div>
    <p className="section-copy">These rules are stored in your private MANDATE account and used by the server when it inspects actions.</p>
    <div className="policy-fields">
      <label>Policy name<input value={name} onChange={e => setName(e.target.value)} maxLength={100}/></label>
      <label>Maximum amount (atomic units)<input value={max} onChange={e => setMax(e.target.value)} inputMode="numeric" placeholder="Positive integer only"/></label>
      <label className="wide">Approved recipients (comma-separated)<input value={recipients} onChange={e => setRecipients(e.target.value)} placeholder="alice.near, treasury.near"/></label>
      <div className="wide policy-checks"><strong>Allowed action types</strong>{ACTIONS.map(a => <label key={a}><input type="checkbox" checked={actions.includes(a)} onChange={() => toggleAction(a)}/>{a.replace("_"," ")}</label>)}</div>
      <label className="wide policy-checks"><input type="checkbox" checked={approval} onChange={e => setApproval(e.target.checked)}/> Require owner approval for token approvals</label>
      <label className="wide policy-checks"><input type="checkbox" checked={allApproval} onChange={e => setAllApproval(e.target.checked)}/> Require owner approval for every permitted action</label>
      <label className="wide policy-checks"><input type="checkbox" checked={active} onChange={e => setActive(e.target.checked)}/> Policy active</label>
    </div>
    <div className="policy-actions"><button className="inspect-button" onClick={save} disabled={busy || actions.length === 0}>{busy ? "Saving policy…" : "Save security policy →"}</button><span role="status">{message}</span></div>
    <p className="secure-note">Swaps and contract calls remain blocked until their transaction details can be verified.</p>
  </section>;
}
