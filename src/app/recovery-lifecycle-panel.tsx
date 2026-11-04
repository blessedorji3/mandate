"use client";

import { useEffect, useRef, useState } from "react";
import type { Account, NearConnector } from "@hot-labs/near-connect";
import { createClient } from "@/lib/supabase/client";

type RecoveryRequest = {
  id: string;
  status: string;
  newAccountId: string;
  startedAt: string;
  availableAt: string;
  secondsRemaining: number;
};

async function recoveryRequest(body: Record<string, unknown>) {
  const supabase = createClient();
  const { data, error } = await supabase.functions.invoke("near-transfer-authorization", { body });
  if (error) throw new Error(error.message || "MANDATE recovery service is unavailable.");
  if (!data || typeof data !== "object") throw new Error("MANDATE returned an invalid recovery response.");
  if ("error" in data && typeof data.error === "string") throw new Error(data.error);
  return data as Record<string, any>;
}

function fromHex(value: string) {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error("The recovery challenge was malformed.");
  return Uint8Array.from(value.match(/.{2}/g)!, part => Number.parseInt(part, 16));
}

export function RecoveryLifecyclePanel() {
  const connectorRef = useRef<NearConnector | null>(null);
  const [ready, setReady] = useState(false);
  const [accountId, setAccountId] = useState("");
  const [recoveryCode, setRecoveryCode] = useState("");
  const [replacementAccount, setReplacementAccount] = useState("");
  const [request, setRequest] = useState<RecoveryRequest | null>(null);
  const [secondsRemaining, setSecondsRemaining] = useState(0);
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
    const next = state.request && state.request.status === "pending"
      ? state.request as RecoveryRequest : null;
    setRequest(next);
    setSecondsRemaining(Number(next?.secondsRemaining ?? 0));
    setReplacementAccount(next?.newAccountId ?? "");
    if (next) setNotice("Recovery is pending. All MANDATE financial authorizations are frozen.");
    else if (state.request?.status === "completed") setNotice("The latest wallet recovery has completed.");
    else if (state.request?.status === "cancelled") setNotice("The previous recovery request was cancelled.");
    else setNotice("No wallet recovery is currently pending.");
  }

  useEffect(() => {
    let active = true;
    let connector: NearConnector | null = null;
    const onSignIn = (event: { accounts: Account[] }) => {
      if (active) setAccountId(event.accounts[0]?.accountId ?? "");
    };
    const onSignOut = () => {
      if (active) setAccountId("");
    };
    async function initialize() {
      try {
        await refreshStatus();
        const { NearConnector } = await import("@hot-labs/near-connect");
        connector = new NearConnector({ network: "testnet", features: { testnet: true }, autoConnect: false });
        connectorRef.current = connector;
        connector.on("wallet:signIn", onSignIn);
        connector.on("wallet:signOut", onSignOut);
        await connector.whenManifestLoaded;
        if (active) setReady(true);
      } catch (cause) {
        if (active) {
          setError(cause instanceof Error ? cause.message : "Could not load wallet recovery.");
          setNotice("Recovery status unavailable. Do not attempt wallet replacement.");
        }
      }
    }
    void initialize();
    return () => {
      active = false;
      if (connector) {
        connector.off("wallet:signIn", onSignIn);
        connector.off("wallet:signOut", onSignOut);
      }
    };
  }, []);

  useEffect(() => {
    if (!request || secondsRemaining <= 0) return;
    const timer = window.setInterval(() => setSecondsRemaining(value => Math.max(0, value - 1)), 1000);
    return () => window.clearInterval(timer);
  }, [request?.id, request?.availableAt, secondsRemaining > 0]);

  function formatRemaining(seconds: number) {
    const hours = Math.floor(seconds / 3600);
    const minutes = Math.floor((seconds % 3600) / 60);
    const secs = seconds % 60;
    return `${hours.toString().padStart(2, "0")}:${minutes.toString().padStart(2, "0")}:${secs.toString().padStart(2, "0")}`;
  }

  async function connectReplacementWallet() {
    if (!ready || busy) return;
    setBusy(true); setError("");
    try {
      const connector = connectorRef.current;
      if (!connector) throw new Error("NEAR Testnet wallet connector is unavailable.");
      await connector.connect();
      const connected = await connector.getConnectedWallet();
      const next = connected.accounts[0]?.accountId ?? "";
      if (!next) throw new Error("No NEAR account was returned by the wallet.");
      setAccountId(next);
      setNotice(`Replacement wallet connected: ${next}. It is not authorized yet.`);
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not connect replacement wallet.");
    } finally { setBusy(false); }
  }

  async function signChallenge(action: "start" | "finalize", challenge: Record<string, any>) {
    const connector = connectorRef.current;
    if (!connector || accountId !== challenge.accountId) {
      throw new Error("Connect the exact replacement wallet named in the recovery challenge.");
    }
    const wallet = await connector.wallet();
    if (typeof wallet.signMessage !== "function") throw new Error("This wallet does not support NEP-413 message signing.");
    setNotice(action === "start"
      ? "Review and sign the recovery request. This starts a 24-hour freeze; it does not move funds."
      : "The 24-hour delay has elapsed. Review and sign the final replacement confirmation.");
    const signedMessage = await wallet.signMessage({
      message: challenge.message,
      recipient: challenge.recipient,
      nonce: fromHex(challenge.nonceHex),
      network: "testnet",
      signerId: challenge.accountId,
    });
    return signedMessage;
  }

  async function startRecovery() {
    if (busy || request || !codeEstablished || !hasHistory || !recoveryCode.trim()) return;
    setBusy(true); setError("");
    try {
      const challenge = await recoveryRequest({
        action: "recovery_start_challenge",
        accountId,
        recoveryCode: recoveryCode.trim().toUpperCase(),
      });
      const signedMessage = await signChallenge("start", challenge);
      const result = await recoveryRequest({
        action: "recovery_start_verify",
        challengeId: challenge.challengeId,
        signedMessage,
        recoveryCode: recoveryCode.trim().toUpperCase(),
      });
      setRequest(result.request ?? null);
      setSecondsRemaining(Number(result.request?.secondsRemaining ?? 86400));
      setRecoveryCode("");
      setNotice(result.message || "Recovery started. Financial authorizations are frozen for 24 hours.");
      await refreshStatus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not start wallet recovery.");
      setNotice("Recovery was not started. The existing wallet remains unchanged.");
    } finally { setBusy(false); }
  }

  async function finalizeRecovery() {
    if (busy || !request || secondsRemaining > 0) return;
    setBusy(true); setError("");
    try {
      const challenge = await recoveryRequest({ action: "recovery_finalize_challenge" });
      const signedMessage = await signChallenge("finalize", challenge);
      const result = await recoveryRequest({
        action: "recovery_finalize_verify",
        challengeId: challenge.challengeId,
        signedMessage,
      });
      setRequest(null);
      if (typeof result.recoveryCode !== "string") throw new Error("Wallet recovery completed but MANDATE did not return the rotated recovery code. Contact support before continuing.");
      setRotatedCode(result.recoveryCode);
      setCodeEstablished(true);
      setNotice(result.message || "Wallet recovery completed. Save your new recovery code.");
      await refreshStatus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not finalize wallet recovery.");
      setNotice("Recovery remains pending. The existing wallet is unchanged; authorizations remain frozen.");
    } finally { setBusy(false); }
  }

  async function cancelRecovery() {
    if (busy || !request || !recoveryCode.trim()) return;
    setBusy(true); setError("");
    try {
      const result = await recoveryRequest({
        action: "recovery_cancel",
        requestId: request.id,
        recoveryCode: recoveryCode.trim().toUpperCase(),
      });
      setRequest(null);
      setRecoveryCode("");
      setNotice(result.message || "Recovery cancelled.");
      await refreshStatus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not cancel recovery.");
    } finally { setBusy(false); }
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
          {secondsRemaining === 0 && (
            <button className="inspect-button" onClick={finalizeRecovery} disabled={busy || accountId !== request.newAccountId}>
              {busy ? "Verifying replacement…" : "Sign & finalize wallet replacement →"}
            </button>
          )}
          {secondsRemaining > 0 && (
            <p className="near-wallet-notice">Finalization will unlock automatically when the 24-hour delay ends. Reconnect the replacement wallet before finalizing.</p>
          )}
          <label htmlFor="recovery-cancel-code">Independent recovery code to cancel</label>
          <input id="recovery-cancel-code" value={recoveryCode} onChange={event => setRecoveryCode(event.target.value.toUpperCase())} placeholder="MND-…" autoComplete="off" />
          <button className="outline-button" onClick={cancelRecovery} disabled={busy || !recoveryCode.trim()}>
            {busy ? "Please wait…" : "Cancel pending recovery"}
          </button>
        </div>
      ) : (
        <div className="near-transfer-box">
          <p>To replace the wallet set after loss or compromise, connect a replacement NEAR Testnet wallet and provide your independent recovery code. This starts a 24-hour security delay. Finalization revokes every existing active wallet link in MANDATE and leaves only the replacement wallet active; it does not revoke on-chain keys or move funds.</p>
          <button className="outline-button" onClick={connectReplacementWallet} disabled={!ready || busy}>
            {busy ? "Please wait…" : accountId ? `Connected: ${accountId}` : "Connect replacement wallet"}
          </button>
          <label htmlFor="recovery-start-code">Independent MANDATE recovery code</label>
          <input id="recovery-start-code" value={recoveryCode} onChange={event => setRecoveryCode(event.target.value.toUpperCase())} placeholder="MND-…" autoComplete="off" />
          <button className="inspect-button" onClick={startRecovery} disabled={busy || !ready || !accountId || !recoveryCode.trim() || !codeEstablished}>
            {busy ? "Verifying recovery…" : "Start 24-hour wallet recovery →"}
          </button>
        </div>
      )}
      {rotatedCode && (
        <div className="recovery-code-reveal">
          <strong>New recovery code — shown only once</strong>
          <code>{rotatedCode}</code>
          <button className="outline-button" onClick={async () => {
            try { await navigator.clipboard.writeText(rotatedCode); setCopied(true); }
            catch { setError("Clipboard access failed. Select and copy the recovery code manually."); }
          }}>{copied ? "Copied ✓" : "Copy new recovery code"}</button>
          <p>The previous recovery code is now invalid. Store this new code privately and securely.</p>
        </div>
      )}
      {error && <p className="near-wallet-error" role="alert">{error}</p>}
      <div className="near-wallet-boundary">
        <strong>Recovery security</strong>
        <span>Starting recovery requires your MANDATE recovery code and a fresh signature from the replacement wallet. The replacement is not activated until the 24-hour delay ends and that wallet signs again. Cancellation requires the independent recovery code. No seed phrase or private key is requested.</span>
      </div>
    </section>
  );
}
