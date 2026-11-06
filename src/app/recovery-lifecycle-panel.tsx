"use client";

import { useEffect, useRef, useState } from "react";
import { createClient } from "@/lib/supabase/client";
import {
  createMeteorRecoverySigner,
  signExactMeteorRecoveryChallenge,
  type MeteorRecoveryChallenge,
  type MeteorRecoverySigner,
} from "@/lib/meteor-recovery-signer";

type RecoveryRequest = {
  id: string;
  status: string;
  newAccountId: string;
  startedAt: string;
  availableAt: string;
  secondsRemaining: number;
};

type PreparedChallenge = MeteorRecoveryChallenge & {
  challengeId: string;
  requestId: string;
  action: "start" | "finalize";
  expiresAt: number;
};

async function recoveryRequest(body: Record<string, unknown>) {
  const supabase = createClient();
  const { data, error } = await supabase.functions.invoke("near-transfer-authorization", { body });
  if (error) throw new Error(error.message || "MANDATE recovery service is unavailable.");
  if (!data || typeof data !== "object") throw new Error("MANDATE returned an invalid recovery response.");
  if ("error" in data && typeof data.error === "string") throw new Error(data.error);
  return data as Record<string, any>;
}

export function RecoveryLifecyclePanel() {
  const signerRef = useRef<MeteorRecoverySigner | null>(null);
  const [ready, setReady] = useState(false);
  const [replacementAccountId, setReplacementAccountId] = useState("");
  const [activeWalletAccountId, setActiveWalletAccountId] = useState<string | null>(null);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [request, setRequest] = useState<RecoveryRequest | null>(null);
  const [secondsRemaining, setSecondsRemaining] = useState(0);
  const [challenge, setChallenge] = useState<PreparedChallenge | null>(null);
  const [challengeSecondsRemaining, setChallengeSecondsRemaining] = useState(0);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("Checking wallet recovery eligibility…");
  const [hasHistory, setHasHistory] = useState(false);
  const [codeEstablished, setCodeEstablished] = useState(false);
  const [rotatedCode, setRotatedCode] = useState("");
  const [copied, setCopied] = useState(false);

  async function refreshStatus() {
    const state = await recoveryRequest({ action: "recovery_lifecycle" });
    setHasHistory(state.hasWalletHistory === true);
    setCodeEstablished(state.codeEstablished === true && state.codeConsumed !== true);
    setActiveWalletAccountId(
      typeof state.activeWalletAccountId === "string" ? state.activeWalletAccountId : null,
    );
    const next = state.request && state.request.status === "pending"
      ? state.request as RecoveryRequest
      : null;
    setRequest(next);
    setSecondsRemaining(Number(next?.secondsRemaining ?? 0));
    if (next) setNotice("Recovery is pending. All MANDATE financial authorizations are frozen.");
    else if (state.request?.status === "completed") setNotice("The latest wallet recovery has completed.");
    else if (state.request?.status === "cancelled") setNotice("The previous recovery request was cancelled.");
    else setNotice("No wallet recovery is currently pending.");
  }

  useEffect(() => {
    let active = true;
    async function initialize() {
      try {
        // Prepare the official Meteor SDK before the signing button is pressed.
        // Its signMessage method opens the wallet popup directly from the
        // user's click, avoiding a popup blocked after an awaited API request.
        const [, signer] = await Promise.all([
          refreshStatus(),
          createMeteorRecoverySigner(),
        ]);
        if (!active) return;
        signerRef.current = signer;
        setReady(true);
      } catch (cause) {
        if (!active) return;
        setError(cause instanceof Error ? cause.message : "Could not load wallet recovery.");
        setNotice("Recovery status or Meteor signing is unavailable. Do not attempt wallet replacement.");
      }
    }
    void initialize();
    return () => {
      active = false;
      signerRef.current = null;
    };
  }, []);

  useEffect(() => {
    if (!request || secondsRemaining <= 0) return;
    const timer = window.setInterval(() => {
      setSecondsRemaining(value => Math.max(0, value - 1));
    }, 1000);
    return () => window.clearInterval(timer);
  }, [request?.id, request?.availableAt, secondsRemaining > 0]);

  useEffect(() => {
    if (!challenge) {
      setChallengeSecondsRemaining(0);
      return;
    }
    const update = () => {
      const remaining = Math.max(0, Math.ceil((challenge.expiresAt - Date.now()) / 1000));
      setChallengeSecondsRemaining(remaining);
      if (remaining === 0) {
        setChallenge(null);
        setNotice("The signing challenge expired. Prepare a fresh challenge before signing.");
      }
    };
    update();
    const timer = window.setInterval(update, 1000);
    return () => window.clearInterval(timer);
  }, [challenge?.challengeId, challenge?.expiresAt]);

  function formatRemaining(seconds: number) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, "0")}:${minutes.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  }

  function validReplacementAccount(value: string) {
    return /^[a-z0-9._-]{2,64}\.testnet$/.test(value.trim());
  }

  async function prepareStartRecovery() {
    if (busy || !ready || request || !hasHistory || !codeEstablished) return;
    const accountId = replacementAccountId.trim().toLowerCase();
    if (!validReplacementAccount(accountId)) {
      setError("Enter a valid NEAR Testnet account, such as replacement.testnet.");
      return;
    }
    if (accountId === activeWalletAccountId) {
      setError("The replacement must be different from your currently active MANDATE wallet.");
      return;
    }
    if (!/^MND-[0-9A-F]{64}$/.test(recoveryCode.trim().toUpperCase())) {
      setError("Enter your complete independent MANDATE recovery code.");
      return;
    }

    setBusy(true);
    setError("");
    setChallenge(null);
    try {
      const result = await recoveryRequest({
        action: "recovery_start_challenge",
        accountId,
        recoveryCode: recoveryCode.trim().toUpperCase(),
      });
      const next: PreparedChallenge = {
        challengeId: result.challengeId,
        requestId: result.requestId,
        action: "start",
        accountId: result.accountId,
        publicKey: result.publicKey,
        message: result.message,
        recipient: result.recipient,
        nonceHex: result.nonceHex,
        expiresAt: Date.now() + Number(result.expiresInSeconds ?? 300) * 1000,
      };
      setChallenge(next);
      setReplacementAccountId(accountId);
      setNotice(
        `MANDATE verified that ${accountId} has an active FullAccess key. Press the signing button and choose this exact account in Meteor.`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not prepare wallet recovery.");
      setNotice("No recovery request was started. Your existing wallet links and funds are unchanged.");
    } finally {
      setBusy(false);
    }
  }

  async function signAndStartRecovery() {
    if (busy || !ready || !challenge || challenge.action !== "start") return;
    if (challengeSecondsRemaining <= 0) {
      setChallenge(null);
      setError("The signing challenge expired. Prepare a new one.");
      return;
    }
    const signer = signerRef.current;
    if (!signer) {
      setError("Meteor signing is not ready. Reload this page and try again.");
      return;
    }

    // This call is intentionally made directly from this button handler.
    // Meteor opens its popup synchronously before the next awaited operation.
    setBusy(true);
    setError("");
    try {
      setNotice(`Waiting for Meteor to sign for ${challenge.accountId}…`);
      const signedMessage = await signExactMeteorRecoveryChallenge(signer, challenge);
      const result = await recoveryRequest({
        action: "recovery_start_verify",
        challengeId: challenge.challengeId,
        signedMessage,
        recoveryCode: recoveryCode.trim().toUpperCase(),
      });
      setChallenge(null);
      setRecoveryCode("");
      setRequest(result.request ?? null);
      setSecondsRemaining(Number(result.request?.secondsRemaining ?? 86400));
      setNotice(result.message || "Recovery started. Financial authorizations are frozen for 24 hours.");
      await refreshStatus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not verify the replacement wallet signature.");
      setNotice("Recovery was not started. The existing wallet remains unchanged.");
    } finally {
      setBusy(false);
    }
  }

  async function prepareFinalizeRecovery() {
    if (busy || !ready || !request || secondsRemaining > 0) return;
    setBusy(true);
    setError("");
    setChallenge(null);
    try {
      const result = await recoveryRequest({ action: "recovery_finalize_challenge" });
      const next: PreparedChallenge = {
        challengeId: result.challengeId,
        requestId: result.requestId,
        action: "finalize",
        accountId: result.accountId,
        publicKey: result.publicKey,
        message: result.message,
        recipient: result.recipient,
        nonceHex: result.nonceHex,
        expiresAt: Date.now() + Number(result.expiresInSeconds ?? 300) * 1000,
      };
      setChallenge(next);
      setNotice(
        `The 24-hour delay has elapsed. Press the signing button and authorize ${next.accountId} in Meteor to complete the replacement.`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not prepare final recovery confirmation.");
    } finally {
      setBusy(false);
    }
  }

  async function signAndFinalizeRecovery() {
    if (busy || !ready || !request || !challenge || challenge.action !== "finalize") return;
    if (challengeSecondsRemaining <= 0) {
      setChallenge(null);
      setError("The signing challenge expired. Prepare a new one.");
      return;
    }
    const signer = signerRef.current;
    if (!signer) {
      setError("Meteor signing is not ready. Reload this page and try again.");
      return;
    }

    setBusy(true);
    setError("");
    try {
      setNotice(`Waiting for Meteor to sign the final replacement for ${challenge.accountId}…`);
      const signedMessage = await signExactMeteorRecoveryChallenge(signer, challenge);
      const result = await recoveryRequest({
        action: "recovery_finalize_verify",
        challengeId: challenge.challengeId,
        signedMessage,
      });
      setChallenge(null);
      if (typeof result.recoveryCode !== "string") {
        throw new Error("Wallet recovery completed but MANDATE did not return the rotated recovery code. Contact support before continuing.");
      }
      setRotatedCode(result.recoveryCode);
      setCodeEstablished(true);
      setNotice(result.message || "Wallet recovery completed. Save your new recovery code.");
      await refreshStatus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not finalize wallet recovery.");
      setNotice("Recovery remains pending. The existing wallet links are unchanged; authorizations remain frozen.");
    } finally {
      setBusy(false);
    }
  }

  async function cancelRecovery() {
    if (busy || !request || !recoveryCode.trim()) return;
    setBusy(true);
    setError("");
    try {
      const result = await recoveryRequest({
        action: "recovery_cancel",
        requestId: request.id,
        recoveryCode: recoveryCode.trim().toUpperCase(),
      });
      setRequest(null);
      setChallenge(null);
      setRecoveryCode("");
      setNotice(result.message || "Recovery cancelled.");
      await refreshStatus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not cancel recovery.");
    } finally {
      setBusy(false);
    }
  }

  if (!hasHistory) return null;

  return (
    <section className="panel recovery-code-panel recovery-lifecycle-panel">
      <div className="panel-heading">
        <div><span className="step">03</span><h3>Wallet replacement & recovery</h3></div>
        <span className="muted-tag">24-HOUR SECURITY DELAY</span>
      </div>
      <p className="near-wallet-notice">{notice}</p>
      {request ? (
        <div className="recovery-pending">
          <strong>Recovery request pending</strong>
          <p>Replacement wallet: <code>{request.newAccountId}</code></p>
          <div className="recovery-countdown">
            <span>{secondsRemaining > 0 ? "TIME UNTIL FINALIZATION" : "WAITING PERIOD COMPLETE"}</span>
            <strong>{formatRemaining(secondsRemaining)}</strong>
          </div>
          <p>During this period, MANDATE blocks new financial authorizations and invalidates outstanding transfer challenges and receipts. All existing wallet links remain unchanged until finalization. After the final signature, every existing active wallet link will be revoked in MANDATE and only the replacement wallet will remain active. NEAR on-chain keys and funds are not changed by this process.</p>
          {secondsRemaining === 0 && !challenge && (
            <button className="outline-button" onClick={prepareFinalizeRecovery} disabled={busy || !ready}>
              {busy ? "Preparing confirmation…" : "Prepare final replacement signature →"}
            </button>
          )}
          {challenge?.action === "finalize" && (
            <div className="near-transfer-box">
              <p>Challenge expires in <strong>{formatRemaining(challengeSecondsRemaining)}</strong>. The requested account and FullAccess key have been checked again by MANDATE.</p>
              <p>Replacement account: <code>{challenge.accountId}</code></p>
              <button className="inspect-button" onClick={signAndFinalizeRecovery} disabled={busy || !ready || challengeSecondsRemaining <= 0}>
                {busy ? "Waiting for Meteor…" : "Sign with this exact account & finalize →"}
              </button>
            </div>
          )}
          {secondsRemaining > 0 && (
            <p className="near-wallet-notice">Finalization becomes available when the 24-hour delay ends. The replacement account must sign again.</p>
          )}
          <label htmlFor="recovery-cancel-code">Independent recovery code to cancel</label>
          <input id="recovery-cancel-code" value={recoveryCode} onChange={event => setRecoveryCode(event.target.value.toUpperCase())} placeholder="MND-…" autoComplete="off" />
          <button className="outline-button" onClick={cancelRecovery} disabled={busy || !recoveryCode.trim()}>
            {busy ? "Please wait…" : "Cancel pending recovery"}
          </button>
        </div>
      ) : (
        <div className="near-transfer-box">
          <p>To replace the wallet set after loss or compromise, enter the replacement NEAR Testnet account and prove control of its FullAccess key in Meteor. Preparing a challenge does not start recovery. The 24-hour security delay begins only after Meteor signs and MANDATE verifies the exact account and key.</p>
          <label htmlFor="recovery-replacement-account">Replacement NEAR Testnet account</label>
          <input
            id="recovery-replacement-account"
            value={replacementAccountId}
            onChange={event => {
              setReplacementAccountId(event.target.value.trim().toLowerCase());
              setChallenge(null);
            }}
            placeholder="replacement.testnet"
            autoComplete="off"
            spellCheck={false}
          />
          <p className="near-wallet-notice">
            Current active MANDATE wallet: <code>{activeWalletAccountId ?? "Not available"}</code>.
            The replacement must be a different account.
          </p>
          <label htmlFor="recovery-start-code">Independent MANDATE recovery code</label>
          <input id="recovery-start-code" value={recoveryCode} onChange={event => {
            setRecoveryCode(event.target.value.toUpperCase());
            setChallenge(null);
          }} placeholder="MND-…" autoComplete="off" />
          {!challenge && (
            <button className="outline-button" onClick={prepareStartRecovery} disabled={busy || !ready || !replacementAccountId.trim() || !recoveryCode.trim() || !codeEstablished}>
              {busy ? "Preparing recovery challenge…" : "Check account & prepare signature →"}
            </button>
          )}
          {challenge?.action === "start" && (
            <div className="near-transfer-box">
              <p>MANDATE found the requested account's FullAccess key. The challenge expires in <strong>{formatRemaining(challengeSecondsRemaining)}</strong>.</p>
              <p>Exact requested account: <code>{challenge.accountId}</code></p>
              <button className="inspect-button" onClick={signAndStartRecovery} disabled={busy || !ready || challengeSecondsRemaining <= 0}>
                {busy ? "Waiting for Meteor…" : "Open Meteor & sign for this exact account →"}
              </button>
            </div>
          )}
        </div>
      )}
      {rotatedCode && (
        <div className="recovery-code-reveal">
          <strong>New recovery code — shown only once</strong>
          <code>{rotatedCode}</code>
          <button className="outline-button" onClick={async () => {
            try {
              await navigator.clipboard.writeText(rotatedCode);
              setCopied(true);
            } catch {
              setError("Clipboard access failed. Select and copy the recovery code manually.");
            }
          }}>{copied ? "Copied ✓" : "Copy new recovery code"}</button>
          <p>The previous recovery code is now invalid. Store this new code privately and securely.</p>
        </div>
      )}
      {error && <p className="near-wallet-error" role="alert">{error}</p>}
      <div className="near-wallet-boundary">
        <strong>Recovery security</strong>
        <span>Starting recovery requires your independent MANDATE recovery code and a fresh NEP-413 signature from the exact replacement Testnet account and its verified FullAccess key. The replacement is not activated until the 24-hour delay ends and that same account and key sign again. Cancellation requires the independent recovery code. MANDATE never asks for a seed phrase or private key.</span>
      </div>
    </section>
  );
}
