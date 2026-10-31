"use client";

import { useEffect, useRef, useState } from "react";
import type { Account, NearConnector } from "@hot-labs/near-connect";

export function NearWalletPanel() {
  const connectorRef = useRef<NearConnector | null>(null);
  const [accountId, setAccountId] = useState<string | null>(null);
  const [ready, setReady] = useState(false);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [notice, setNotice] = useState("Preparing secure wallet connection…");

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

  return (
    <section className="panel near-wallet-panel">
      <div className="panel-heading">
        <div><span className="step">01</span><h3>NEAR Testnet wallet</h3></div>
        <span className="muted-tag">TESTNET ONLY</span>
      </div>
      <div className="near-wallet-network"><span className="live-dot" /> NEAR TESTNET <span>·</span> Chain connection only</div>
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
      <p className="near-wallet-notice" role="status">{notice}</p>
      {error && <p className="near-wallet-error" role="alert">{error}</p>}
      <div className="near-wallet-boundary">
        <strong>Security boundary</strong>
        <span>This step only connects the wallet and reads the public account ID. It does not sign, broadcast, or move funds. Never enter a recovery phrase or private key into MANDATE.</span>
      </div>
    </section>
  );
}
