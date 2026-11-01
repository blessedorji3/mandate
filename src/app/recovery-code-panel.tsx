"use client";

import { useEffect, useRef, useState } from "react";
import type { Account, NearConnector } from "@hot-labs/near-connect";
import { createClient } from "@/lib/supabase/client";

type HistoricalWallet = { accountId: string; revoked: boolean };

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error("The recovery challenge was malformed.");
  return Uint8Array.from(value.match(/.{2}/g)!, part => Number.parseInt(part, 16));
}

async function recoveryRequest(body: Record<string, unknown>) {
  const supabase = createClient();
  const { data, error } = await supabase.functions.invoke("near-transfer-authorization", { body });
  if (error) throw new Error(error.message || "MANDATE recovery service is unavailable.");
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
  const [established, setEstablished] = useState(false);
  const [recoveryCode, setRecoveryCode] = useState("");
  const [copied, setCopied] = useState(false);
  const [busy, setBusy] = useState(false);
  const [ready, setReady] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("Checking independent recovery status…");

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
        const { NearConnector } = await import("@hot-labs/near-connect");
        connector = new NearConnector({ network: "testnet", features: { testnet: true }, autoConnect: false });
        connectorRef.current = connector;
        connector.on("wallet:signIn", onSignIn);
        connector.on("wallet:signOut", onSignOut);
        await connector.whenManifestLoaded;
        if (active) setReady(true);
        setEstablished(status.established === true);
        setHasHistory(status.hasWalletHistory === true);
        const wallets = Array.isArray(status.historicalWallets) ? status.historicalWallets : [];
        setHistoricalWallets(wallets);
        setSelectedWallet(wallets[0]?.accountId ?? "");
        setNotice(status.established
          ? "An independent recovery code is already established. It cannot be displayed again."
          : status.hasWalletHistory
            ? "This existing account must prove control of a previously registered wallet before creating its recovery code."
            : "Create your independent recovery code before registering your first NEAR wallet.");
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
        throw new Error("Connect the previously registered wallet selected above.");
      }
      setNotice("Historical wallet connected. You can now create the recovery code.");
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
          <p>For security, MANDATE cannot display the original code again. Keep the copy you saved in a safe place.</p>
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
      {error && <p className="near-wallet-error" role="alert">{error}</p>}
    </section>
  );
}
