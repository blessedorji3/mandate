"use client";

import { useEffect, useRef, useState } from "react";
import type { Account, NearConnector } from "@hot-labs/near-connect";
import { createClient } from "@/lib/supabase/client";

const TRANSFER = {
  receiverId: "confirmwithmandate.testnet",
  amountAtomic: "1000000000000000000000",
  amountLabel: "0.001 NEAR",
} as const;

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2})+$/.test(value)) throw new Error("The authorization challenge was malformed.");
  return Uint8Array.from(value.match(/.{2}/g)!, (part) => Number.parseInt(part, 16));
}

async function authorizationRequest(body: Record<string, unknown>) {
  const supabase = createClient();
  const { data, error } = await supabase.functions.invoke("near-transfer-authorization", { body });
  if (error) throw new Error(error.message || "MANDATE authorization service is unavailable.");
  if (!data || typeof data !== "object") throw new Error("MANDATE returned an invalid authorization response.");
  if ("error" in data && typeof data.error === "string") throw new Error(data.error);
  return data as Record<string, any>;
}

export function NearWalletPanel({ proposalId }: { proposalId?: string }) {
  const connectorRef = useRef<NearConnector | null>(null);
  const [accountId, setAccountId] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("Preparing secure wallet connection…");
  const [txHash, setTxHash] = useState("");
  const [receipt, setReceipt] = useState("");

  useEffect(() => {
    let active = true;
    let connector: NearConnector | null = null;

    const handleSignIn = (event: { accounts: Account[] }) => {
      if (!active) return;
      setAccountId(event.accounts[0]?.accountId ?? null);
      setNotice("Wallet connected to NEAR Testnet.");
      setError("");
    };
    const handleSignOut = () => {
      if (!active) return;
      setAccountId(null);
      setNotice("Wallet disconnected.");
    };

    async function initialize() {
      try {
        const { NearConnector } = await import("@hot-labs/near-connect");
        connector = new NearConnector({
          network: "testnet",
          features: { testnet: true },
          autoConnect: false
        });
        connectorRef.current = connector;
        connector.on("wallet:signIn", handleSignIn);
        connector.on("wallet:signOut", handleSignOut);
        await connector.whenManifestLoaded;
        if (!active) return;
        setReady(true);

        try {
          const connected = await connector.getConnectedWallet();
          if (active) {
            setAccountId(connected.accounts[0]?.accountId ?? null);
            if (connected.accounts[0]) setNotice("Existing NEAR Testnet connection restored.");
            else setNotice("Ready to connect a NEAR Testnet wallet.");
          }
        } catch {
          if (active) setNotice("Ready to connect a NEAR Testnet wallet.");
        }
      } catch {
        if (active) {
          setError("The wallet connector could not load. Check your connection and reload this page.");
          setNotice("Wallet connector unavailable.");
        }
      }
    }

    void initialize();
    return () => {
      active = false;
      if (connector) {
        connector.off("wallet:signIn", handleSignIn);
        connector.off("wallet:signOut", handleSignOut);
      }
    };
  }, []);

  async function connectWallet() {
    const connector = connectorRef.current;
    if (!connector || busy) return;
    setBusy(true);
    setError("");
    setNotice("Waiting for you to choose and approve a wallet…");
    try {
      await connector.connect();
      try {
        const connected = await connector.getConnectedWallet();
        setAccountId(connected.accounts[0]?.accountId ?? null);
        setNotice("Wallet connected to NEAR Testnet.");
      } catch {
        // The wallet sign-in event will update the connected account.
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Wallet connection was cancelled or failed.");
      setNotice("No wallet connection was established.");
    } finally {
      setBusy(false);
    }
  }

  async function disconnectWallet() {
    const connector = connectorRef.current;
    if (!connector || busy) return;
    setBusy(true);
    setError("");
    try {
      await connector.disconnect();
      setAccountId(null);
      setNotice("Wallet disconnected.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not disconnect this wallet.");
    } finally {
      setBusy(false);
    }
  }

  async function retryTransactionVerification() {
    if (!txHash || !receipt || !accountId || busy) return;
    setBusy(true);
    setError("");
    setNotice("Retrying verification of the existing transaction only. No new transfer will be sent…");
    try {
      const chainResult = await authorizationRequest({
        action: "verify_transaction",
        transactionHash: txHash,
        signerAccountId: accountId,
        receipt,
      });
      if (chainResult.verified !== true || chainResult.authorizationBound !== true ||
          chainResult.receiverId !== TRANSFER.receiverId ||
          chainResult.amountAtomic !== TRANSFER.amountAtomic) {
        throw new Error("MANDATE has not yet verified and bound this existing transaction.");
      }
      setNotice("Verified on NEAR Testnet: the exact 0.001 NEAR transfer reached the confirmed recipient.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not verify the existing transaction yet.");
      setNotice("The existing transaction remains locked. Do not send it again.");
    } finally {
      setBusy(false);
    }
  }

  async function executeTestTransfer() {
    const connector = connectorRef.current;
    if (!connector || !accountId || busy || txHash) return;
    setBusy(true);
    setError("");
    setNotice("Checking your active MANDATE policy…");
    try {
      const challenge = await authorizationRequest({
        action: "challenge",
        signerAccountId: accountId,
        ...(proposalId ? { proposalId } : {}),
      });
      if (!["ALLOW", "REQUIRE_APPROVAL"].includes(challenge.decision?.outcome) ||
          (proposalId && challenge.decision?.proposalId !== proposalId) ||
          challenge.intent?.receiverId !== TRANSFER.receiverId ||
          challenge.intent?.amountAtomic !== TRANSFER.amountAtomic) {
        throw new Error("MANDATE did not authorize a challenge for this exact proposal. Nothing was sent.");
      }

      setNotice(challenge.decision.outcome === "REQUIRE_APPROVAL"
        ? "Owner approval is required. Review the exact transfer and sign the approval message in your NEAR wallet…"
        : "Policy ALLOW. Requesting a wallet signature to prove account ownership…");
      const wallet = await connector.wallet();
      if (typeof wallet.signMessage !== "function" ||
          typeof wallet.signAndSendTransaction !== "function") {
        throw new Error("This wallet does not support the signing features required by MANDATE.");
      }
      const signedMessage = await wallet.signMessage({
        message: challenge.message,
        recipient: challenge.recipient,
        nonce: fromHex(challenge.nonceHex),
        network: "testnet",
        signerId: accountId,
      });

      setNotice("Verifying your wallet signature and re-checking the policy…");
      const verified = await authorizationRequest({
        action: "verify",
        challengeId: challenge.challengeId,
        signedMessage,
      });
      if (verified.authorized !== true || typeof verified.receipt !== "string") {
        throw new Error("MANDATE did not issue a one-time authorization. Nothing was sent.");
      }

      setReceipt(verified.receipt);
      setNotice("Consuming the one-time authorization. Next, your wallet will ask you to approve the transfer…");
      const consumed = await authorizationRequest({
        action: "consume",
        receipt: verified.receipt,
        signerAccountId: accountId,
      });
      if (consumed.consumed !== true) {
        throw new Error("The one-time authorization could not be consumed. Nothing was sent.");
      }

      const outcome = await wallet.signAndSendTransaction({
        network: "testnet",
        signerId: accountId,
        receiverId: TRANSFER.receiverId,
        actions: [{ type: "Transfer", params: { deposit: TRANSFER.amountAtomic } }],
      });
      const hash = outcome?.transaction?.hash ?? outcome?.transaction_outcome?.id;
      if (typeof hash !== "string" || !hash) {
        throw new Error("The wallet returned without a transaction hash. Check your wallet activity before retrying.");
      }
      setTxHash(hash);
      setNotice("Transaction submitted. Independently verifying the exact transfer on NEAR Testnet…");
      const chainResult = await authorizationRequest({
        action: "verify_transaction",
        transactionHash: hash,
        signerAccountId: accountId,
        receipt: verified.receipt,
      });
      if (chainResult.verified !== true || chainResult.authorizationBound !== true ||
          chainResult.receiverId !== TRANSFER.receiverId ||
          chainResult.amountAtomic !== TRANSFER.amountAtomic) {
        throw new Error("MANDATE could not verify the exact transfer on NEAR Testnet. Check the explorer before retrying.");
      }
      setNotice("Verified on NEAR Testnet: the exact 0.001 NEAR transfer reached the confirmed recipient.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "The transfer was cancelled or failed. Check wallet activity before retrying.");
      setNotice("No successful transaction was confirmed by MANDATE.");
    } finally {
      setBusy(false);
    }
  }

  return (
    <section className="panel near-wallet-panel">
      <div className="panel-heading">
        <div><span className="step">01</span><h3>NEAR Testnet wallet</h3></div>
        <span className="muted-tag">TESTNET ONLY</span>
      </div>
      <div className="near-wallet-network"><span className="live-dot" /> NEAR TESTNET <span>·</span> Wallet-controlled signing</div>
      {accountId ? (
        <div className="near-wallet-connected">
          <span className="near-wallet-check">✓</span>
          <div><strong>Wallet connected</strong><code>{accountId}</code></div>
          <button className="outline-button" onClick={disconnectWallet} disabled={busy}>{busy ? "Please wait…" : "Disconnect"}</button>
        </div>
      ) : (
        <div className="near-wallet-empty">
          <div className="near-wallet-symbol">N</div>
          <h3>{ready ? "Connect your NEAR wallet" : "Loading wallet options…"}</h3>
          <p>Choose a wallet that supports NEAR Testnet. Your wallet keeps control of your keys and asks you to approve any future transaction.</p>
          <button className="inspect-button" onClick={connectWallet} disabled={!ready || busy}>
            {busy ? "Connecting…" : "Connect NEAR wallet →"}
          </button>
        </div>
      )}
      {accountId && (
        <div className="near-transfer-box">
          <div>
            <strong>{proposalId ? "Owner-approved Agent Chat transfer" : "MANDATE-protected test transfer"}</strong>
            <p>{TRANSFER.amountLabel} to {TRANSFER.receiverId}</p>
          </div>
          <button className="inspect-button" onClick={executeTestTransfer} disabled={busy || Boolean(txHash)}>
            {busy ? "Working…" : txHash ? "Transaction submitted — sending locked" : proposalId ? "Approve, sign & send this proposal →" : "Authorize & send test transfer →"}
          </button>
          <p className="near-wallet-notice" role="status">{notice}</p>
          {txHash && receipt && error && (
            <button className="outline-button" onClick={retryTransactionVerification} disabled={busy}>Retry verification only (no transfer)</button>
          )}
          {txHash && (
            <p className="near-wallet-notice">
              Transaction: <a href={`https://testnet.nearblocks.io/txns/${encodeURIComponent(txHash)}`} target="_blank" rel="noreferrer">{txHash}</a>
            </p>
          )}
          {error && <p className="near-wallet-error" role="alert">{error}</p>}
        </div>
      )}
      {!accountId && <p className="near-wallet-notice" role="status">{notice}</p>}
      {error && !accountId && <p className="near-wallet-error" role="alert">{error}</p>}
      <div className="near-wallet-boundary">
        <strong>Security boundary</strong>
        <span>MANDATE checks the policy, verifies a NEP-413 full-access wallet signature, and consumes a short-lived one-time authorization before requesting the transaction. Your wallet still requires your explicit approval. Never enter a recovery phrase or private key into MANDATE.</span>
      </div>
    </section>
  );
}
