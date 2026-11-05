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
  if (error) {
    let message = error.message || "MANDATE authorization service is unavailable.";
    const context = (error as unknown as { context?: Response }).context;
    if (context instanceof Response) {
      try {
        const payload = await context.clone().json();
        if (payload && typeof payload.error === "string") message = payload.error;
      } catch {
        // Preserve the SDK message for non-JSON responses.
      }
    }
    throw new Error(message);
  }
  if (!data || typeof data !== "object") throw new Error("MANDATE returned an invalid authorization response.");
  if ("error" in data && typeof data.error === "string") throw new Error(data.error);
  return data as Record<string, any>;
}

type OwnerWallet = {
  accountId: string;
  publicKey: string;
  verifiedAt: string;
  revokedAt: string | null;
  active: boolean;
};

export function NearWalletPanel({
  proposalId,
  riskReviewRequired = false,
}: {
  proposalId?: string;
  riskReviewRequired?: boolean;
}) {
  const connectorRef = useRef<NearConnector | null>(null);
  const [accountId, setAccountId] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("Preparing secure wallet connection…");
  const [txHash, setTxHash] = useState("");
  const [receipt, setReceipt] = useState("");
  const [authorizationConsumed, setAuthorizationConsumed] = useState(false);
  const [riskReviewed, setRiskReviewed] = useState(false);
  const [walletRegistered, setWalletRegistered] = useState(false);
  const [wallets, setWallets] = useState<OwnerWallet[]>([]);
  const [walletToRevoke, setWalletToRevoke] = useState("");

  async function refreshWallets(): Promise<OwnerWallet[]> {
    const data = await authorizationRequest({ action: "wallet_list" });
    const rows = (Array.isArray(data.wallets) ? data.wallets : []) as OwnerWallet[];
    setWallets(rows);
    return rows;
  }

  useEffect(() => {
    let active = true;
    let connector: NearConnector | null = null;

    const handleSignIn = (event: { accounts: Account[] }) => {
      if (!active) return;
      setAccountId(event.accounts[0]?.accountId ?? null);
      setWalletRegistered(false);
      setRiskReviewed(false);
      setNotice("Checking registered owner wallet status…");
      setError("");
    };
    const handleSignOut = () => {
      if (!active) return;
      setAccountId(null);
      setWalletRegistered(false);
      setRiskReviewed(false);
      setNotice("Wallet disconnected.");
      setTxHash("");
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
          const inventory = await refreshWallets();
          const connected = await connector.getConnectedWallet();
          if (active) {
            const restored = connected.accounts[0]?.accountId ?? null;
            setAccountId(restored);
            if (restored) {
              const registered = inventory.some(wallet => wallet.accountId === restored && wallet.active);
              setWalletRegistered(registered);
              setNotice(registered ? "Connected wallet is verified on this MANDATE account." : "This wallet is not linked yet. Verify it before using it.");
            } else {
              setWalletRegistered(false);
              setNotice("Your linked-wallet inventory is ready. Connect a wallet to add or use it.");
            }
          }
        } catch {
          if (active) setNotice("Wallet inventory could not be loaded. Refresh before authorizing transfers.");
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
        const connectedAccount = connected.accounts[0]?.accountId ?? null;
        setAccountId(connectedAccount);
        if (connectedAccount) {
          const inventory = await refreshWallets();
          const registered = inventory.some(wallet => wallet.accountId === connectedAccount && wallet.active);
          setWalletRegistered(registered);
          setNotice(registered ? "Connected wallet is verified on this MANDATE account." : "This wallet is not linked yet. Verify it to add it to this account.");
        }
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

  async function registerOwnerWallet() {
    const connector = connectorRef.current;
    if (!connector || !accountId || busy || txHash) return;
    setBusy(true); setError(""); setNotice("Creating a one-time wallet ownership challenge…");
    try {
      const challenge = await authorizationRequest({ action: "register_wallet_challenge", accountId });
      const wallet = await connector.wallet();
      if (typeof wallet.signMessage !== "function") throw new Error("This wallet does not support NEP-413 message signing.");
      setNotice("Review and sign the wallet-registration message. This signature does not move funds…");
      const signedMessage = await wallet.signMessage({
        message: challenge.message, recipient: challenge.recipient,
        nonce: fromHex(challenge.nonceHex), network: "testnet", signerId: accountId,
      });
      const result = await authorizationRequest({ action: "register_wallet_verify", challengeId: challenge.challengeId, signedMessage });
      if (result.registered !== true || result.accountId !== accountId) throw new Error("MANDATE did not confirm this wallet registration.");
      await refreshWallets();
      setWalletRegistered(true); setNotice("Wallet ownership verified and added to your MANDATE account.");
    } catch (cause) {
      setWalletRegistered(false); setError(cause instanceof Error ? cause.message : "Wallet registration failed.");
      setNotice("Wallet is not registered. Transfers remain disabled.");
    } finally { setBusy(false); }
  }

  async function revokeSelectedWallet() {
    const connector = connectorRef.current;
    const targetAccountId = walletToRevoke;
    if (!connector || !accountId || !walletRegistered || !targetAccountId ||
        targetAccountId === accountId || busy) return;
    setBusy(true);
    setError("");
    try {
      const challenge = await authorizationRequest({
        action: "wallet_revoke_challenge",
        targetAccountId,
        signerAccountId: accountId,
      });
      const wallet = await connector.wallet();
      if (typeof wallet.signMessage !== "function") {
        throw new Error("This wallet does not support NEP-413 message signing.");
      }
      setNotice("Review the wallet-removal request. This removes the selected wallet from MANDATE only; it does not move funds or revoke NEAR keys.");
      const signedMessage = await wallet.signMessage({
        message: challenge.message,
        recipient: challenge.recipient,
        nonce: fromHex(challenge.nonceHex),
        network: "testnet",
        signerId: accountId,
      });
      const result = await authorizationRequest({
        action: "wallet_revoke_verify",
        challengeId: challenge.challengeId,
        signedMessage,
      });
      if (result.revoked !== true || result.accountId !== targetAccountId) {
        throw new Error("MANDATE did not confirm removal of the selected wallet.");
      }
      const inventory = await refreshWallets();
      setWalletToRevoke("");
      setNotice(`${targetAccountId} was removed from MANDATE. Its NEAR on-chain keys and funds were not changed.`);
      setWalletRegistered(inventory.some(wallet => wallet.accountId === accountId && wallet.active));
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not remove this wallet from MANDATE.");
    } finally {
      setBusy(false);
    }
  }


  async function reviewCounterpartyRisk() {
    const connector = connectorRef.current;
    if (!connector || !accountId || !walletRegistered || !proposalId ||
        !riskReviewRequired || busy || riskReviewed || txHash) return;
    setBusy(true);
    setError("");
    setNotice("Preparing a signed acknowledgement for this exact counterparty warning…");
    try {
      const challenge = await authorizationRequest({
        action: "risk_review_challenge",
        proposalId,
        signerAccountId: accountId,
      });
      if (typeof challenge.challengeId !== "string" ||
          challenge.signerAccountId !== accountId ||
          typeof challenge.message !== "string" ||
          typeof challenge.nonceHex !== "string") {
        throw new Error("MANDATE did not create a valid proposal-bound risk-review challenge.");
      }

      const wallet = await connector.wallet();
      if (typeof wallet.signMessage !== "function") {
        throw new Error("This wallet does not support NEP-413 message signing.");
      }
      setNotice("Read the risk acknowledgement carefully. This signature accepts the warning only; it does not approve or send a transaction…");
      const signedMessage = await wallet.signMessage({
        message: challenge.message,
        recipient: challenge.recipient,
        nonce: fromHex(challenge.nonceHex),
        // Pin a deterministic callback URL so callback-aware wallet adapters
        // and the server verifier sign/verify the same NEP-413 payload.
        // The connector runtime forwards callbackUrl, but its older public
        // SignMessageParams type does not yet declare this optional field.
        callbackUrl: window.location.origin,
        network: "testnet",
        signerId: accountId,
      } as Parameters<typeof wallet.signMessage>[0] & { callbackUrl: string });
      const result = await authorizationRequest({
        action: "risk_review_verify",
        challengeId: challenge.challengeId,
        signedMessage,
      });
      if (result.reviewed !== true || result.proposalId !== proposalId ||
          result.riskFingerprint !== challenge.riskFingerprint) {
        throw new Error("MANDATE did not confirm the review for this exact proposal and risk evidence.");
      }
      setRiskReviewed(true);
      setNotice("Counterparty warning acknowledged for this proposal only. The risk outcome remains WARN. You must still approve the exact transaction separately in your NEAR wallet.");
    } catch (cause) {
      setRiskReviewed(false);
      setError(cause instanceof Error ? cause.message : "The counterparty risk review could not be completed.");
      setNotice("No risk acknowledgement was recorded. The transfer remains locked.");
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
    if (!connector || !accountId || !walletRegistered || busy || txHash ||
        (riskReviewRequired && !riskReviewed)) return;
    setBusy(true);
    setError("");
    setNotice("Checking your active MANDATE policy and the reviewed risk evidence…");
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
      setAuthorizationConsumed(true);

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
      if (riskReviewRequired && !txHash) setRiskReviewed(false);
      setError(cause instanceof Error ? cause.message : "The transfer was cancelled or failed. Check wallet activity before retrying.");
      setNotice(riskReviewRequired && !txHash
        ? "The risk acknowledgement may have expired or been consumed. Refresh the review before trying again."
        : "No successful transaction was confirmed by MANDATE.");
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
      {wallets.length > 0 && (
        <div className="near-transfer-box">
          <strong>Your MANDATE wallet links</strong>
          <p>Each listed wallet has been independently verified. Browser disconnect does not remove a wallet from this list.</p>
          <div className="scenario-list">
            {wallets.map(wallet => (
              <div className="scenario wallet-link-row" key={wallet.accountId}>
                <span className="scenario-text">
                  <strong>{wallet.accountId}</strong>
                  <small>{wallet.active ? "Active and verified" : "Revoked in MANDATE"} · Verified {new Date(wallet.verifiedAt).toLocaleDateString()}</small>
                </span>
                <span className={`wallet-link-status ${wallet.active ? "is-active" : "is-revoked"}`}>{wallet.active ? "ACTIVE" : "REVOKED"}</span>
              </div>
            ))}
          </div>
          {wallets.filter(wallet => wallet.active && wallet.accountId !== accountId).length > 0 && (
            <div className="wallet-revoke-controls">
              <label className="wallet-revoke-label" htmlFor="mandate-wallet-remove">Remove a linked wallet</label>
              <div className="wallet-revoke-actions">
                <select
                  id="mandate-wallet-remove"
                  value={walletToRevoke}
                  onChange={event => setWalletToRevoke(event.target.value)}
                  disabled={busy || !walletRegistered}
                  aria-describedby="wallet-removal-help"
                >
                  <option value="">Choose another active wallet</option>
                  {wallets.filter(wallet => wallet.active && wallet.accountId !== accountId).map(wallet => (
                    <option key={wallet.accountId} value={wallet.accountId}>{wallet.accountId}</option>
                  ))}
                </select>
                <button className="outline-button wallet-revoke-button" onClick={revokeSelectedWallet} disabled={busy || !walletRegistered || !walletToRevoke}>
                  {busy ? "Please wait…" : "Verify & remove selected wallet"}
                </button>
              </div>
              <p id="wallet-removal-help">Removal requires a fresh signature from the different connected wallet. The last active wallet cannot be removed this way; use the existing 24-hour recovery process for that.</p>
            </div>
          )}
        </div>
      )}
      {accountId && !walletRegistered && (
        <div className="near-transfer-box">
          <strong>Register this wallet to your MANDATE account</strong>
          <p>A one-time NEP-413 signature proves you control this NEAR Testnet account. It does not move funds.</p>
          <button className="inspect-button" onClick={registerOwnerWallet} disabled={busy || Boolean(txHash)}>
            {busy ? "Verifying wallet…" : "Register & verify owner wallet →"}
          </button>
          {error && <p className="near-wallet-error" role="alert">{error}</p>}
        </div>
      )}
      {accountId && walletRegistered && (
        <p className="near-wallet-notice" role="status">✓ This wallet is registered and verified for your signed-in MANDATE account.</p>
      )}
      {accountId && walletRegistered && riskReviewRequired && !riskReviewed && (
        <div className="near-transfer-box">
          <strong>Counterparty risk acknowledgement required</strong>
          <p>The destination received a WARN result. Your NEP-413 signature acknowledges this exact proposal and its current evidence fingerprint. It does not change WARN to ALLOW and does not approve a transaction.</p>
          <button className="inspect-button" onClick={reviewCounterpartyRisk} disabled={busy || !proposalId || Boolean(txHash)}>
            {busy ? "Preparing review…" : "Review warning & sign acknowledgement →"}
          </button>
          <p className="near-wallet-notice" role="status">The acknowledgement expires after five minutes and can be used once. A fresh risk check is required before authorization.</p>
          {error && <p className="near-wallet-error" role="alert">{error}</p>}
        </div>
      )}
      {accountId && walletRegistered && riskReviewRequired && riskReviewed && (
        <p className="near-wallet-notice" role="status">✓ Risk acknowledgement recorded for this proposal only. The underlying risk outcome remains WARN; transaction approval is still required separately.</p>
      )}
      {accountId && walletRegistered && (
        <div className="near-transfer-box">
          <div>
            <strong>{proposalId ? "Owner-approved Agent Chat transfer" : "MANDATE-protected test transfer"}</strong>
            <p>{TRANSFER.amountLabel} to {TRANSFER.receiverId}</p>
          </div>
          <button className="inspect-button" onClick={executeTestTransfer} disabled={busy || !walletRegistered || Boolean(txHash) || authorizationConsumed || (riskReviewRequired && !riskReviewed)}>
            {busy ? "Working…" : txHash ? "Transaction submitted — sending locked" : authorizationConsumed ? "Authorization consumed — sending locked" : riskReviewRequired && !riskReviewed ? "Complete signed risk review first" : proposalId ? "Approve, sign & send this proposal →" : "Authorize & send test transfer →"}
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
        <span>MANDATE requires a registered owner wallet, verifies its NEP-413 full-access signature, re-checks policy and consumes a short-lived one-time authorization before requesting the transaction. Your wallet still requires your explicit approval. Never enter a recovery phrase or private key into MANDATE.</span>
      </div>
    </section>
  );
}
