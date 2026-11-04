"use client";

import { useEffect, useRef, useState } from "react";
import type { Account, NearConnector } from "@hot-labs/near-connect";
import { createClient } from "@/lib/supabase/client";
import { inspectRecoveryWalletResponse, type SafeWalletDiagnostic } from "@/lib/recovery-wallet-diagnostic";

type HistoricalWallet = { accountId: string; revoked: boolean };

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error("The recovery challenge was malformed.");
  return Uint8Array.from(value.match(/.{2}/g)!, part => Number.parseInt(part, 16));
}

async function recoveryRequest(body: Record<string, unknown>) {
  const supabase = createClient();
  const { data, error } = await supabase.functions.invoke("near-transfer-authorization", { body });
  if (error) {
    // FunctionsHttpError carries the Edge Function response in context.
    // Surface the server's safe JSON error instead of the SDK's generic
    // "non-2xx status code" message, without logging credentials or signatures.
    const context = (error as { context?: Response }).context;
    if (context && typeof context.clone === "function") {
      try {
        const payload = await context.clone().json();
        if (payload && typeof payload.error === "string") throw new Error(payload.error);
      } catch (cause) {
        if (cause instanceof Error && cause.message !== "Unexpected end of JSON input") throw cause;
      }
    }
    throw new Error(error.message || "MANDATE recovery service is unavailable.");
  }
  if (!data || typeof data !== "object") throw new Error("MANDATE returned an invalid recovery response.");
  if ("error" in data && typeof data.error === "string") throw new Error(data.error);
  return data as Record<string, any>;
}

export function RecoveryCodePanel() {
  const connectorRef = useRef<NearConnector | null>(null);
  const [historicalWallets, setHistoricalWallets] = useState<HistoricalWallet[]>([]);
  const [selectedWallet, setSelectedWallet] = useState("");
  const [connectedAccount, setConnectedAccount] = useState("");
  const [hasHistory, setHasHistory] = useState(false);
  const [activeWallet, setActiveWallet] = useState("");
  const [established, setEstablished] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("Checking independent recovery status…");
  const [safeDiagnostic, setSafeDiagnostic] = useState<SafeWalletDiagnostic | null>(null);

  useEffect(() => {
    let active = true;
    let connector: NearConnector | null = null;
    const onSignIn = (event: { accounts: Account[] }) => {
      if (active) setConnectedAccount(event.accounts[0]?.accountId ?? "");
    };
    const onSignOut = () => {
      if (active) setConnectedAccount("");
    };

    async function initialize() {
      try {
        const status = await recoveryRequest({ action: "recovery_setup_status" });
        if (!active) return;
        setEstablished(status.established === true);
        setHasHistory(status.hasWalletHistory === true);
        const wallets = Array.isArray(status.historicalWallets) ? status.historicalWallets : [];
        setHistoricalWallets(wallets);
        setSelectedWallet(wallets[0]?.accountId ?? "");
        if (status.established === true) {
          const lifecycle = await recoveryRequest({ action: "recovery_lifecycle" });
          const active = typeof lifecycle.activeWalletAccountId === "string" ? lifecycle.activeWalletAccountId : "";
          setActiveWallet(active);
          setSelectedWallet(active);
        }
        setNotice(status.established
          ? "An independent recovery code is already established. It cannot be displayed again."
          : status.hasWalletHistory
            ? "This existing account must prove control of a previously registered wallet before creating its recovery code."
            : "Create your independent recovery code before registering your first NEAR wallet.");
        if (status.hasWalletHistory === true || status.established === true) {
          const { NearConnector } = await import("@hot-labs/near-connect");
          connector = new NearConnector({ network: "testnet", features: { testnet: true }, autoConnect: false });
          connectorRef.current = connector;
          connector.on("wallet:signIn", onSignIn);
          connector.on("wallet:signOut", onSignOut);
          await connector.whenManifestLoaded;
          if (active) setReady(true);
        }
      } catch (cause) {
        if (active) {
          setError(cause instanceof Error ? cause.message : "Could not load recovery setup.");
          setNotice("Recovery status unavailable. Wallet registration must remain disabled.");
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

  async function connectHistoricalWallet() {
    if (!ready || busy) return;
    setBusy(true);
    setError("");
    try {
      const connector = connectorRef.current;
      if (!connector) throw new Error("NEAR wallet connector is unavailable.");
      await connector.connect();
      const connected = await connector.getConnectedWallet();
      const account = connected.accounts[0]?.accountId ?? "";
      setConnectedAccount(account);
      if (!account || account !== selectedWallet) {
        throw new Error("Connect the selected registered NEAR wallet.");
      }
      setNotice("Registered NEAR wallet connected. You can continue with the requested security action.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not connect the historical wallet.");
    } finally {
      setBusy(false);
    }
  }

  async function createRecoveryCode() {
    if (busy || established || recoveryCode) return;
    setBusy(true);
    setError("");
    try {
      const challenge = await recoveryRequest({
        action: "recovery_setup_challenge",
        ...(hasHistory ? { historicalAccountId: selectedWallet } : {}),
      });
      let signedMessage: Record<string, unknown> | undefined;
      if (challenge.requiresWalletSignature === true) {
        const connector = connectorRef.current;
        if (!connector || connectedAccount !== selectedWallet) {
          throw new Error("Connect the selected historical NEAR wallet first.");
        }
        const wallet = await connector.wallet();
        if (typeof wallet.signMessage !== "function") {
          throw new Error("This wallet does not support NEP-413 message signing.");
        }
        setNotice("Review and sign the recovery-enrollment message. This signature does not move funds…");
        signedMessage = await wallet.signMessage({
          message: challenge.message,
          recipient: challenge.recipient,
          nonce: fromHex(challenge.nonceHex),
          network: "testnet",
          signerId: selectedWallet,
        }) as unknown as Record<string, unknown>;
      }
      const result = await recoveryRequest({
        action: "recovery_setup_verify",
        challengeId: challenge.challengeId,
        ...(signedMessage ? { signedMessage } : {}),
      });
      if (result.established !== true || typeof result.recoveryCode !== "string") {
        throw new Error("MANDATE did not confirm recovery-code creation.");
      }
      setRecoveryCode(result.recoveryCode);
      setEstablished(true);
      setNotice("Recovery code created. Save it now; it will not be shown again.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Recovery-code setup failed.");
      setNotice("Recovery code was not established.");
    } finally {
      setBusy(false);
    }
  }

  async function resetRecoveryCode() {
    if (!ready || busy || !established || !activeWallet || recoveryCode) return;
    setBusy(true);
    setError("");
    try {
      const connector = connectorRef.current;
      if (!connector || connectedAccount !== activeWallet) {
        throw new Error("Connect your currently active registered wallet before resetting the code.");
      }
      const challenge = await recoveryRequest({ action: "recovery_code_reset_challenge" });
      if (challenge.accountId !== activeWallet || typeof challenge.publicKey !== "string") {
        throw new Error("MANDATE did not issue a challenge for your active registered wallet.");
      }
      const wallet = await connector.wallet();
      if (typeof wallet.signMessage !== "function") throw new Error("This wallet does not support NEP-413 message signing.");
      setNotice("Review the recovery-code reset message in your wallet. It changes only the recovery code and does not move funds…");
      const nonceBytes = fromHex(challenge.nonceHex);
      const walletRequest = {
        message: challenge.message,
        recipient: challenge.recipient,
        callbackUrl: challenge.callbackUrl,
        nonce: nonceBytes,
        network: "testnet" as const,
        signerId: activeWallet,
      };
      const walletSignedMessage = await wallet.signMessage(walletRequest);
      const diagnostic = await inspectRecoveryWalletResponse({
        challengeMessage: challenge.message,
        challengeRecipient: challenge.recipient,
        challengeCallbackUrl: challenge.callbackUrl,
        walletRequestCallbackUrl: walletRequest.callbackUrl,
        walletRequestMessage: walletRequest.message,
        walletRequestRecipient: walletRequest.recipient,
        browserOrigin: window.location.origin,
        browserHref: window.location.href,
        nonce: nonceBytes,
        expectedAccountId: challenge.accountId,
        expectedPublicKey: challenge.publicKey,
        walletResponse: walletSignedMessage,
      });
      setSafeDiagnostic(diagnostic);
      setNotice("Diagnostic captured. No recovery-code reset was submitted; your existing recovery code remains unchanged.");
      return;
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Recovery-code reset failed.");
      setNotice("Recovery code was not reset.");
    } finally { setBusy(false); }
  }

  async function copyRecoveryCode() {
    if (!recoveryCode) return;
    try {
      await navigator.clipboard.writeText(recoveryCode);
      setCopied(true);
    } catch {
      setError("Clipboard access failed. Select and copy the recovery code manually.");
    }
  }

  return (
    <section className="panel recovery-code-panel">
      <div className="panel-heading">
        <div><span className="step">02</span><h3>Independent recovery code</h3></div>
        <span className="muted-tag">ACCOUNT SECURITY</span>
      </div>
      <p className="near-wallet-notice">{notice}</p>
      {established && !recoveryCode && (
        <div className="near-transfer-box">
          <strong>Recovery code already established</strong>
          <p>The original code cannot be displayed again. If you did not save it, you can replace it by proving control of your currently active registered wallet.</p>
          <p><strong>Active wallet:</strong> {activeWallet || "Could not determine the active wallet."}</p>
          <button className="outline-button" onClick={connectHistoricalWallet} disabled={!ready || busy || !activeWallet}>
            {busy ? "Please wait…" : connectedAccount === activeWallet ? "Active wallet connected ✓" : "Connect active wallet"}
          </button>
          <button className="inspect-button" onClick={resetRecoveryCode} disabled={!ready || busy || !activeWallet || connectedAccount !== activeWallet}>
            {busy ? "Verifying wallet signature…" : "Reset recovery code →"}
          </button>
          <p>This reset does not change your registered wallet, move funds, or start the 24-hour wallet recovery process.</p>
        </div>
      )}
      {!established && hasHistory && (
        <div className="near-transfer-box">
          <label htmlFor="recovery-historical-wallet">Previously registered wallet</label>
          <select id="recovery-historical-wallet" value={selectedWallet} onChange={event => { setSelectedWallet(event.target.value); setConnectedAccount(""); }}>
            {historicalWallets.map(wallet => (
              <option key={wallet.accountId} value={wallet.accountId}>
                {wallet.accountId}{wallet.revoked ? " (revoked in MANDATE)" : ""}
              </option>
            ))}
          </select>
          <p>Connect this wallet and sign a fresh ownership message. This does not send a transaction.</p>
          <button className="outline-button" onClick={connectHistoricalWallet} disabled={!ready || busy || !selectedWallet}>
            {busy ? "Please wait…" : connectedAccount === selectedWallet ? "Historical wallet connected ✓" : "Connect historical wallet"}
          </button>
        </div>
      )}
      {!established && !recoveryCode && (
        <button className="inspect-button" onClick={createRecoveryCode} disabled={busy || (hasHistory && (!selectedWallet || connectedAccount !== selectedWallet))}>
          {busy ? "Establishing recovery…" : "Generate my recovery code →"}
        </button>
      )}
      {recoveryCode && (
        <div className="recovery-code-reveal">
          <strong>Save this code now — it is shown only once</strong>
          <code>{recoveryCode}</code>
          <button className="outline-button" onClick={copyRecoveryCode}>{copied ? "Copied ✓" : "Copy recovery code"}</button>
          <p>Store it somewhere private and secure, preferably offline. Do not share it with anyone or paste it into chats. MANDATE stores only a cryptographic hash.</p>
        </div>
      )}
      {safeDiagnostic && (
        <div className="near-transfer-box" role="status" aria-live="polite">
          <strong>Safe Meteor signing diagnostic</strong>
          <p>Diagnostic-only run: the signed response was not submitted to the reset endpoint.</p>
          <pre>{JSON.stringify(safeDiagnostic, null, 2)}</pre>
        </div>
      )}
      {error && <p className="near-wallet-error" role="alert">{error}</p>}
    </section>
  );
}
