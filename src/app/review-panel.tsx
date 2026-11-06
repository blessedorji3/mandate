"use client";

import { FormEvent, useCallback, useEffect, useState } from "react";
import Link from "next/link";
import { createClient } from "@/lib/supabase/client";

type Report = {
  id: string;
  network: string;
  account_id: string;
  status: string;
  reason: string;
  evidence_ref: string;
  evidence_sha256: string | null;
  source_type: string;
  reporter_owner_id: string;
  created_at: string;
};

type AuditEvent = {
  id: string;
  actor_owner_id: string | null;
  subject_owner_id: string | null;
  report_id: string | null;
  action: string;
  reason: string;
  before_state: Record<string, unknown> | null;
  after_state: Record<string, unknown> | null;
  created_at: string;
};

type SourceType = "chain_tx" | "explorer" | "security_advisory" | "other";

async function invokeAction<T extends Record<string, unknown>>(body: Record<string, unknown>): Promise<T> {
  const supabase = createClient();
  const { data, error } = await supabase.functions.invoke("near-transfer-authorization", { body });
  if (error) throw new Error(error.message || "The MANDATE review service is unavailable.");
  if (!data || typeof data !== "object" || Array.isArray(data)) {
    throw new Error("MANDATE returned an invalid review response.");
  }
  if (typeof data.error === "string") throw new Error(data.error);
  return data as T;
}

function readableError(error: unknown) {
  return error instanceof Error ? error.message : "The request could not be completed.";
}

function shortId(value: string | null) {
  if (!value) return "System";
  return `${value.slice(0, 8)}…${value.slice(-6)}`;
}

export function BlocklistReviewPanel() {
  const [reports, setReports] = useState<Report[]>([]);
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [role, setRole] = useState<"admin" | "reviewer" | "none">("none");
  const [loading, setLoading] = useState(true);
  const [refreshing, setRefreshing] = useState(false);
  const [busyId, setBusyId] = useState("");
  const [notes, setNotes] = useState<Record<string, string>>({});
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("");

  const [accountId, setAccountId] = useState("");
  const [reason, setReason] = useState("");
  const [evidenceRef, setEvidenceRef] = useState("");
  const [sourceType, setSourceType] = useState<SourceType>("explorer");
  const [submittingReport, setSubmittingReport] = useState(false);

  const [subjectOwnerId, setSubjectOwnerId] = useState("");
  const [provisionReason, setProvisionReason] = useState("");
  const [provisionAction, setProvisionAction] = useState<"grant" | "revoke">("grant");
  const [provisioning, setProvisioning] = useState(false);

  const load = useCallback(async (quiet = false) => {
    if (quiet) setRefreshing(true);
    else setLoading(true);
    setError("");
    try {
      const queue = await invokeAction<{ reports?: Report[] }>({ action: "blocklist_review_queue" });
      setReports(Array.isArray(queue.reports) ? queue.reports : []);

      try {
        const audit = await invokeAction<{ events?: AuditEvent[] }>({ action: "blocklist_audit", limit: 50 });
        setRole("admin");
        setEvents(Array.isArray(audit.events) ? audit.events : []);
      } catch {
        // Queue access already established reviewer membership. Audit is admin-only.
        setRole("reviewer");
        setEvents([]);
      }
    } catch (cause) {
      setRole("none");
      setReports([]);
      setEvents([]);
      setError(readableError(cause));
    } finally {
      setLoading(false);
      setRefreshing(false);
    }
  }, []);

  useEffect(() => { void load(); }, [load]);

  async function review(report: Report, decision: "confirmed" | "rejected") {
    const reviewNote = (notes[report.id] ?? "").trim();
    if (reviewNote.length < 8) {
      setError("Add a review note of at least 8 characters before recording a decision.");
      return;
    }
    setBusyId(report.id);
    setError("");
    setNotice("");
    try {
      const result = await invokeAction<{ reviewed?: boolean; message?: string }>({
        action: "blocklist_report_review",
        reportId: report.id,
        decision,
        reviewNote,
      });
      if (result.reviewed !== true) throw new Error("The review decision was not confirmed.");
      setNotice(decision === "confirmed"
        ? "Report confirmed. It is now eligible to produce a non-overridable BLOCK for the reported Testnet account."
        : "Report rejected and retained in the audit history. It will not be returned as a blocklist signal.");
      setNotes(current => ({ ...current, [report.id]: "" }));
      await load(true);
    } catch (cause) {
      setError(readableError(cause));
    } finally {
      setBusyId("");
    }
  }

  async function submitReport(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    setSubmittingReport(true);
    setError("");
    setNotice("");
    try {
      const result = await invokeAction<{ submitted?: boolean; message?: string }>({
        action: "blocklist_report_submit",
        accountId: accountId.trim().toLowerCase(),
        reason: reason.trim(),
        evidenceRef: evidenceRef.trim(),
        sourceType,
      });
      if (result.submitted !== true) throw new Error("MANDATE did not confirm report submission.");
      setNotice(result.message ?? "Report submitted for independent review. It is not an active block.");
      setAccountId("");
      setReason("");
      setEvidenceRef("");
    } catch (cause) {
      setError(readableError(cause));
    } finally {
      setSubmittingReport(false);
    }
  }

  async function provisionReviewer(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();
    if (role !== "admin") return;
    setProvisioning(true);
    setError("");
    setNotice("");
    try {
      const result = await invokeAction<{ provisioned?: boolean; revoked?: boolean }>({
        action: "blocklist_reviewer_provision",
        subjectOwnerId: subjectOwnerId.trim(),
        provisioningAction: provisionAction,
        reason: provisionReason.trim(),
      });
      if (provisionAction === "grant" && result.provisioned !== true) {
        throw new Error("MANDATE did not confirm the reviewer assignment.");
      }
      if (provisionAction === "revoke" && result.revoked !== true) {
        throw new Error("MANDATE did not confirm the reviewer revocation.");
      }
      setNotice(provisionAction === "grant"
        ? "Reviewer role granted. The account can now access the review queue."
        : "Reviewer role revoked. The account can no longer access the review queue.");
      setSubjectOwnerId("");
      setProvisionReason("");
      await load(true);
    } catch (cause) {
      setError(readableError(cause));
    } finally {
      setProvisioning(false);
    }
  }

  return (
    <div className="blocklist-workspace">
      <header className="blocklist-topbar">
        <Link className="brand" href="/"><span className="brand-mark">M</span><span>MANDATE<small>SECURITY LAYER</small></span></Link>
        <Link className="blocklist-back" href="/">← Back to workspace</Link>
      </header>

      <div className="blocklist-intro">
        <span className="eyebrow">COUNTERPARTY GOVERNANCE · NEAR TESTNET</span>
        <h1>Review with <em>evidence.</em></h1>
        <p>Pending reports are evidence submissions, not block decisions. An independent active reviewer must confirm or reject each report. Confirmed reports become non-overridable BLOCK evidence.</p>
        <div className="agent-boundary"><span className="live-dot" /> Authenticated operator <b>·</b> Role checked by database <b>·</b> No wallet signing or transfers on this page</div>
      </div>

      {(error || notice) && (
        <div className={error ? "blocklist-alert is-error" : "blocklist-alert is-success"} role="status">
          <strong>{error ? "Action not completed" : "Update"}</strong>
          <span>{error || notice}</span>
        </div>
      )}

      <section className="blocklist-role-card">
        <div>
          <span className="blocklist-kicker">ACCESS STATUS</span>
          <h2>{loading ? "Checking your role…" : role === "admin" ? "Administrator access" : role === "reviewer" ? "Reviewer access" : "Reviewer access required"}</h2>
          <p>{loading
            ? "Checking the signed-in account against the private reviewer registry."
            : role === "admin"
              ? "You can review reports, provision or revoke reviewer assignments, and inspect the audit trail."
              : role === "reviewer"
                ? "You can review pending reports. Reviewer provisioning and global audit history are administrator-only."
                : "This account has no active reviewer role. You can submit evidence below, but the review queue is restricted."}</p>
        </div>
        <span className={role === "none" ? "blocklist-role-pill is-off" : "blocklist-role-pill"}>{loading ? "CHECKING" : role.toUpperCase()}</span>
      </section>

      <section className="blocklist-section">
        <div className="blocklist-section-heading">
          <div><span className="blocklist-kicker">01 · INDEPENDENT REVIEW</span><h2>Pending reports</h2><p>Review evidence carefully. A report cannot be reviewed by the same account that submitted it.</p></div>
          <button className="outline-button" onClick={() => void load(true)} disabled={loading || refreshing}>{refreshing ? "Refreshing…" : "↻ Refresh queue"}</button>
        </div>
        {loading ? <div className="blocklist-empty">Checking role and loading the protected review queue…</div>
          : role === "none" ? <div className="blocklist-empty">The review queue is not available to this account. Ask the project administrator to provision your Auth user ID as a reviewer.</div>
          : reports.length === 0 ? <div className="blocklist-empty"><strong>No pending reports.</strong><span>New evidence submissions will appear here after they are recorded by MANDATE.</span></div>
          : <div className="blocklist-report-list">
            {reports.map(report => (
              <article className="blocklist-report" key={report.id}>
                <div className="blocklist-report-head">
                  <div><span className="blocklist-kicker">PENDING · {report.network.toUpperCase()}</span><h3>{report.account_id}</h3></div>
                  <span className="blocklist-pending-pill">PENDING REVIEW</span>
                </div>
                <p className="blocklist-report-reason">{report.reason}</p>
                <dl className="blocklist-report-meta">
                  <div><dt>Evidence source</dt><dd>{report.source_type.replaceAll("_", " ")}</dd></div>
                  <div><dt>Submitted</dt><dd>{new Date(report.created_at).toLocaleString()}</dd></div>
                  <div><dt>Reporter</dt><dd><code>{shortId(report.reporter_owner_id)}</code></dd></div>
                  {report.evidence_sha256 && <div><dt>Evidence SHA-256</dt><dd><code>{report.evidence_sha256}</code></dd></div>}
                </dl>
                <a className="blocklist-evidence-link" href={report.evidence_ref.startsWith("https://") ? report.evidence_ref : `https://testnet.nearblocks.io/txns/${encodeURIComponent(report.evidence_ref)}`} target="_blank" rel="noreferrer noopener">
                  Open supporting evidence ↗
                </a>
                <label className="blocklist-field-label" htmlFor={`note-${report.id}`}>Reviewer note (required)</label>
                <textarea id={`note-${report.id}`} value={notes[report.id] ?? ""} onChange={event => setNotes(current => ({ ...current, [report.id]: event.target.value }))} maxLength={500} minLength={8} placeholder="Explain the evidence and why this report should be confirmed or rejected." />
                <div className="blocklist-review-actions">
                  <button className="blocklist-confirm-button" onClick={() => void review(report, "confirmed")} disabled={busyId === report.id || (notes[report.id] ?? "").trim().length < 8}>{busyId === report.id ? "Recording…" : "Confirm report"}</button>
                  <button className="blocklist-reject-button" onClick={() => void review(report, "rejected")} disabled={busyId === report.id || (notes[report.id] ?? "").trim().length < 8}>{busyId === report.id ? "Recording…" : "Reject report"}</button>
                </div>
                <p className="blocklist-caution">Confirm only when the supplied evidence supports the reported account. Confirmation creates a non-overridable BLOCK signal.</p>
              </article>
            ))}
          </div>}
      </section>

      <section className="blocklist-section">
        <div className="blocklist-section-heading"><div><span className="blocklist-kicker">02 · EVIDENCE INTAKE</span><h2>Submit a Testnet report</h2><p>Any signed-in account may submit evidence. Submission never blocks an account automatically.</p></div></div>
        <form className="blocklist-form" onSubmit={submitReport}>
          <label>NEAR Testnet account ID<input value={accountId} onChange={event => setAccountId(event.target.value)} placeholder="example.testnet" autoComplete="off" required pattern="[a-z0-9]+([-_][a-z0-9]+)*(\.[a-z0-9]+([-_][a-z0-9]+)*)*\.testnet" maxLength={64} /></label>
          <label>Reason<textarea value={reason} onChange={event => setReason(event.target.value)} placeholder="Describe the observed risk and why the account should be reviewed." minLength={8} maxLength={500} required /></label>
          <label>Evidence reference<input value={evidenceRef} onChange={event => setEvidenceRef(event.target.value)} placeholder="HTTPS explorer/advisory URL or NEAR transaction hash" minLength={8} maxLength={2048} required /></label>
          <label>Evidence source<select value={sourceType} onChange={event => setSourceType(event.target.value as SourceType)}><option value="explorer">Block explorer</option><option value="chain_tx">On-chain transaction</option><option value="security_advisory">Security advisory</option><option value="other">Other</option></select></label>
          <button className="inspect-button" type="submit" disabled={submittingReport || !accountId.trim() || reason.trim().length < 8 || evidenceRef.trim().length < 8}>{submittingReport ? "Submitting…" : "Submit pending report →"}</button>
        </form>
        <p className="blocklist-footnote">Do not submit private keys, seed phrases, passwords, or personal information. Reports are retained with reviewer decisions in the audit history.</p>
      </section>

      {role === "admin" && (
        <>
          <section className="blocklist-section">
            <div className="blocklist-section-heading"><div><span className="blocklist-kicker">03 · ACCESS GOVERNANCE</span><h2>Manage reviewer access</h2><p>Use the exact Supabase Auth user UUID of the person being provisioned. Admin roles are bootstrap-only.</p></div></div>
            <form className="blocklist-form" onSubmit={provisionReviewer}>
              <label>Supabase Auth user UUID<input value={subjectOwnerId} onChange={event => setSubjectOwnerId(event.target.value)} placeholder="xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" required pattern="[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-8][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}" /></label>
              <label>Action<select value={provisionAction} onChange={event => setProvisionAction(event.target.value as "grant" | "revoke")}><option value="grant">Grant reviewer</option><option value="revoke">Revoke reviewer</option></select></label>
              <label>Reason<textarea value={provisionReason} onChange={event => setProvisionReason(event.target.value)} placeholder="Record why this reviewer access change is required." minLength={8} maxLength={500} required /></label>
              <button className="inspect-button" type="submit" disabled={provisioning || !subjectOwnerId.trim() || provisionReason.trim().length < 8}>{provisioning ? "Updating role…" : provisionAction === "grant" ? "Grant reviewer access →" : "Revoke reviewer access →"}</button>
            </form>
          </section>

          <section className="blocklist-section">
            <div className="blocklist-section-heading"><div><span className="blocklist-kicker">04 · IMMUTABLE RECORD</span><h2>Audit history</h2><p>Latest role changes and report submissions or decisions. Records are append-only.</p></div><span className="blocklist-audit-count">{events.length} events</span></div>
            {events.length === 0 ? <div className="blocklist-empty">No audit events are recorded yet.</div> : <div className="blocklist-audit-list">{events.map(event => (
              <article className="blocklist-audit-event" key={event.id}>
                <div><strong>{event.action.replaceAll("_", " ")}</strong><small>{new Date(event.created_at).toLocaleString()}</small></div>
                <p>{event.reason}</p>
                <small>Actor {shortId(event.actor_owner_id)} · Subject {shortId(event.subject_owner_id)}{event.report_id ? ` · Report ${shortId(event.report_id)}` : ""}</small>
                <details><summary>View before / after snapshots</summary><pre>{JSON.stringify({ before: event.before_state, after: event.after_state }, null, 2)}</pre></details>
              </article>
            ))}</div>}
          </section>
        </>
      )}

      <footer className="blocklist-footer"><span>MANDATE · Intelligence with boundaries.</span><span>Testnet governance only · <Link href="/">Return to workspace</Link></span></footer>
    </div>
  );
}
