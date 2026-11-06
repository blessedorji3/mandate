"use client";

import { useEffect, useState } from "react";
import { createClient } from "@/lib/supabase/client";
import { normalizeNearSignedMessage } from "@/lib/near-signed-message";
import { useNearWalletConnector } from "@/app/near-wallet-connector-context";
import {
  uniqueConnectedAccountIds,
  validateReplacementWalletSelection,
} from "@/lib/recovery-wallet-selection";

type RecoveryRequest = {
  id: string;
  status: string;
  newAccountId: string;
  startedAt: string;
  availableAt: string;
  secondsRemaining: number;
};

type PreparedChallenge = {
  challengeId: string;
  requestId?: string;
  action: "start" | "finalize";
  accountId: string;
  publicKey: string;
  message: string;
  recipient: string;
  nonceHex: string;
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

function fromHex(value: string): Uint8Array {
  if (!/^(?:[0-9a-f]{2}){32}$/.test(value)) {
    throw new Error("MANDATE returned an invalid 32-byte recovery nonce.");
  }
  return Uint8Array.from(
    value.match(/.{2}/g)!,
    (part) => Number.parseInt(part, 16),
  );
}

function validTestnetAccount(value: string) {
  return /^[a-z0-9._-]{2,64}\.testnet$/.test(value);
}

export function RecoveryLifecyclePanel() {
  const { connector, setRecoveryMode } = useNearWalletConnector();
  const [ready, setReady] = useState(false);
  const [connectedAccounts, setConnectedAccounts] = useState<string[]>([]);
  const [selectedReplacementAccountId, setSelectedReplacementAccountId] = useState("");
  const [activeWalletAccountIds, setActiveWalletAccountIds] = useState<string[]>([]);
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
    const [state, inventory] = await Promise.all([
      recoveryRequest({ action: "recovery_lifecycle" }),
      recoveryRequest({ action: "wallet_list" }),
    ]);
    setHasHistory(state.hasWalletHistory === true);
    setCodeEstablished(state.codeEstablished === true && state.codeConsumed !== true);
    setActiveWalletAccountIds(
      (Array.isArray(inventory.wallets) ? inventory.wallets : [])
        .filter((wallet: { active?: boolean; accountId?: string }) =>
          wallet.active === true && typeof wallet.accountId === "string",
        )
        .map((wallet: { accountId: string }) => wallet.accountId),
    );

    const next = state.request && state.request.status === "pending"
      ? state.request as RecoveryRequest
      : null;
    setRequest(next);
    setSecondsRemaining(Number(next?.secondsRemaining ?? 0));
    setRecoveryMode(next !== null);

    if (next) {
      setNotice("Recovery is pending. All MANDATE financial authorizations are frozen.");
    } else if (state.request?.status === "completed") {
      setNotice("The latest wallet recovery has completed.");
    } else if (state.request?.status === "cancelled") {
      setNotice("The previous recovery request was cancelled.");
    } else {
      setNotice("No wallet recovery is currently pending.");
    }
  }

  useEffect(() => {
    let active = true;
    async function initialize() {
      try {
        await refreshStatus();
        if (active && connector) setReady(true);
      } catch (cause) {
        if (!active) return;
        setError(cause instanceof Error ? cause.message : "Could not load wallet recovery.");
        setNotice("Recovery status is unavailable. Do not attempt wallet replacement.");
      }
    }
    if (connector) void initialize();
    else setReady(false);
    return () => {
      active = false;
    };
  }, [connector]);

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

  async function connectReplacementWallet() {
    if (!connector || busy || !ready || challenge) return;
    setBusy(true);
    setError("");
    setChallenge(null);
    setConnectedAccounts([]);
    setSelectedReplacementAccountId("");
    setRecoveryMode(true);

    try {
      // Clear only the current browser-to-dApp wallet session before asking
      // the owner to connect again. This calls the normal connector sign-out;
      // it does not revoke any MANDATE database wallet link or NEAR on-chain key.
      let currentWallet: Awaited<ReturnType<typeof connector.getConnectedWallet>> | null = null;
      try {
        currentWallet = await connector.getConnectedWallet();
      } catch {
        // There may be no current browser wallet session.
      }
      if (currentWallet) {
        setNotice("Disconnecting the current browser wallet session. Your existing MANDATE wallet registration remains active…");
        // If sign-out fails, stop instead of layering a new connection over an
        // unknown old session.
        await connector.disconnect(currentWallet.wallet);
      }

      setNotice("Opening the normal NEAR Testnet wallet selector. Choose Meteor Wallet (or another Testnet wallet), then select the replacement account inside your wallet.");

      // Reuse the same normal NearConnector used by the main wallet panel.
      // connect() presents the standard wallet picker and lets the wallet UI
      // decide which account the owner is connecting. No account ID is sent to
      // Meteor to force a particular account to open.
      await connector.connect();

      const connected = await connector.getConnectedWallet();
      const accountIds = uniqueConnectedAccountIds(connected.accounts);

      if (accountIds.length === 0) {
        throw new Error("The wallet connection completed without returning a Testnet account.");
      }

      setConnectedAccounts(accountIds);

      const expectedAccountId = request?.newAccountId;
      if (expectedAccountId) {
        if (!accountIds.includes(expectedAccountId)) {
          setNotice(
            `The wallet connected ${accountIds.join(", ")}, but this pending recovery requires ${expectedAccountId}. Connect the correct replacement account to continue.`,
          );
          setError("The connected wallet is not the replacement account recorded by the pending recovery.");
          return;
        }
        setSelectedReplacementAccountId(expectedAccountId);
        setNotice(`Connected the recorded replacement account ${expectedAccountId}. Prepare the final confirmation when the 24-hour delay has elapsed.`);
        return;
      }

      // If the wallet returned one account, that is the account the owner
      // selected in the wallet UI. If it returned several, make the owner
      // explicitly choose one in this panel before a challenge is created.
      if (accountIds.length === 1) {
        const accountId = accountIds[0];
        if (activeWalletAccountIds.includes(accountId)) {
          setNotice(`${accountId} is already an active MANDATE wallet. Select a different account in your wallet and connect again.`);
          setError("The replacement must be a different wallet from every currently active MANDATE wallet.");
          return;
        }
        setSelectedReplacementAccountId(accountId);
        setNotice(`Wallet connected. MANDATE received ${accountId}. Confirm this account below before preparing recovery.`);
      } else {
        setNotice("Wallet connected. Choose the replacement account returned by your wallet, then prepare the recovery challenge.");
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Wallet connection was cancelled or failed.");
      if (!request) setRecoveryMode(false);
      setNotice("No recovery challenge was prepared and no recovery process was started.");
    } finally {
      setBusy(false);
    }
  }

  function chooseReplacementAccount(accountId: string) {
    setSelectedReplacementAccountId(accountId);
    setChallenge(null);
    setError("");
    if (activeWalletAccountIds.includes(accountId)) {
      setNotice("That account is already an active MANDATE wallet. Choose a different account.");
    } else {
      setNotice(`Selected ${accountId}. MANDATE will verify its FullAccess key before requesting a signature.`);
    }
  }

  async function prepareStartRecovery() {
    const accountId = selectedReplacementAccountId;
    if (busy || !ready || !connector || request || !hasHistory || !codeEstablished) return;
    if (!accountId || !connectedAccounts.includes(accountId)) {
      setError("Connect a replacement wallet and select the account it returned before continuing.");
      return;
    }
    if (!validTestnetAccount(accountId)) {
      setError("The selected wallet account is not a valid NEAR Testnet account.");
      return;
    }
    const selectionError = validateReplacementWalletSelection({
      accountId,
      connectedAccountIds: connectedAccounts,
      activeWalletAccountIds,
    });
    if (selectionError) {
      setError(selectionError);
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
      if (result.accountId !== accountId || typeof result.publicKey !== "string") {
        throw new Error("MANDATE did not bind the challenge to the account selected in your wallet.");
      }

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
      setNotice(
        `MANDATE found an active FullAccess key for ${accountId}. The next step asks that connected wallet to sign a recovery message. It is not a transaction.`,
      );
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not prepare wallet recovery.");
      setNotice("No recovery request was started. Your existing MANDATE wallet links and funds are unchanged.");
    } finally {
      setBusy(false);
    }
  }

  async function signPreparedChallenge() {
    if (busy || !ready || !connector || !challenge || challengeSecondsRemaining <= 0) return;
    setBusy(true);
    setError("");

    try {
      const connected = await connector.getConnectedWallet();
      if (!connected.accounts.some(account => account.accountId === challenge.accountId)) {
        throw new Error("The currently connected wallet is not the replacement account selected for this recovery.");
      }

      const signedRaw = await connected.wallet.signMessage({
        message: challenge.message,
        recipient: challenge.recipient,
        nonce: fromHex(challenge.nonceHex),
        network: "testnet",
        signerId: challenge.accountId,
      });
      const signedMessage = normalizeNearSignedMessage(signedRaw);

      if (signedMessage.accountId !== challenge.accountId) {
        throw new Error("The wallet signed with a different account. MANDATE will not start recovery.");
      }
      if (signedMessage.publicKey !== challenge.publicKey) {
        throw new Error("The wallet signed with a key different from the challenge-bound FullAccess key.");
      }

      if (challenge.action === "start") {
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
      } else {
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
        setRequest(null);
        setSelectedReplacementAccountId(challenge.accountId);
        setRecoveryMode(false);
        setNotice(result.message || "Wallet recovery completed. Save your new recovery code.");
        await refreshStatus();
        window.dispatchEvent(new CustomEvent("mandate:wallet-inventory-changed"));
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not verify the selected wallet signature.");
      setNotice(
        challenge.action === "start"
          ? "Recovery was not started. Existing wallet links remain unchanged."
          : "Recovery remains pending. Existing wallet links remain unchanged and authorizations remain frozen.",
      );
    } finally {
      setBusy(false);
    }
  }

  async function prepareFinalizeRecovery() {
    if (busy || !ready || !connector || !request || secondsRemaining > 0) return;
    const selectionError = validateReplacementWalletSelection({
      accountId: selectedReplacementAccountId,
      connectedAccountIds: connectedAccounts,
      activeWalletAccountIds,
      expectedAccountId: request.newAccountId,
    });
    if (selectionError) {
      setError(selectionError);
      return;
    }

    setBusy(true);
    setError("");
    setChallenge(null);
    try {
      const result = await recoveryRequest({ action: "recovery_finalize_challenge" });
      if (result.accountId !== request.newAccountId) {
        throw new Error("MANDATE returned a finalization challenge for a different account than the pending replacement.");
      }
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
      setNotice("The 24-hour delay has elapsed. The connected replacement wallet will sign one final confirmation.");
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not prepare final recovery confirmation.");
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
      setRecoveryMode(false);
      setNotice(result.message || "Recovery cancelled. Wallet registrations remain unchanged.");
      await refreshStatus();
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Could not cancel recovery.");
    } finally {
      setBusy(false);
    }
  }

  if (!hasHistory) return null;

  const selectedAccountIsActive = activeWalletAccountIds.includes(selectedReplacementAccountId);
  const selectedAccountSelectionError = selectedReplacementAccountId
    ? validateReplacementWalletSelection({
        accountId: selectedReplacementAccountId,
        connectedAccountIds: connectedAccounts,
        activeWalletAccountIds,
        expectedAccountId: request?.newAccountId,
      })
    : "Connect a replacement wallet and select an account first.";
  const selectedAccountIsExpected = selectedAccountSelectionError === null;

  return (
    <section className="panel recovery-code-panel recovery-lifecycle-panel">
      <div className="panel-heading">
        <div><span className="step">03</span><h3>Wallet replacement & recovery</h3></div>
        <span className="muted-tag">24-HOUR SECURITY DELAY</span>
      </div>
      <p className="near-wallet-notice">{notice}</p>

      <div className="near-transfer-box">
        <strong>Connect your replacement wallet</strong>
        <p>Use the same normal NEAR Testnet wallet connection as the section above. MANDATE opens the wallet selector; you choose Meteor Wallet and select the account yourself inside your wallet. MANDATE does not ask for an account name or try to open a wallet by ID.</p>
        <p>Connecting here changes only the current browser wallet session. It does not remove or revoke the old wallet link in MANDATE. That link remains active throughout the 24-hour delay.</p>
        <button className="outline-button" onClick={connectReplacementWallet} disabled={!ready || busy || Boolean(challenge)}>
          {busy ? "Connecting…" : request ? "Reconnect replacement wallet →" : "Connect replacement wallet →"}
        </button>

        {connectedAccounts.length > 0 && (
          <>
            {connectedAccounts.length > 1 ? (
              <>
                <label htmlFor="replacement-account-select">Choose the account returned by your wallet</label>
                <select
                  id="replacement-account-select"
                  value={selectedReplacementAccountId}
                  onChange={event => chooseReplacementAccount(event.target.value)}
                  disabled={busy || Boolean(challenge)}
                >
                  <option value="">Select the replacement account</option>
                  {connectedAccounts.map(accountId => (
                    <option key={accountId} value={accountId}>{accountId}</option>
                  ))}
                </select>
              </>
            ) : (
              <p className="near-wallet-notice">Wallet-selected account: <code>{connectedAccounts[0]}</code></p>
            )}
            {selectedReplacementAccountId && (
              <p className="near-wallet-notice" role="status">
                {selectedAccountIsActive
                  ? "This account is already an active MANDATE wallet. Choose a different replacement account."
                  : request && !selectedAccountIsExpected
                    ? `The pending recovery requires ${request.newAccountId}.`
                    : `Selected replacement account: ${selectedReplacementAccountId}`}
              </p>
            )}
          </>
        )}
      </div>

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
            <button className="outline-button" onClick={prepareFinalizeRecovery} disabled={busy || !ready || !selectedAccountIsExpected}>
              {busy ? "Preparing confirmation…" : "Prepare final replacement signature →"}
            </button>
          )}
          <label htmlFor="recovery-cancel-code">Independent recovery code to cancel</label>
          <input id="recovery-cancel-code" value={recoveryCode} onChange={event => setRecoveryCode(event.target.value.toUpperCase())} placeholder="MND-…" autoComplete="off" />
          <button className="outline-button" onClick={cancelRecovery} disabled={busy || !recoveryCode.trim()}>
            {busy ? "Please wait…" : "Cancel pending recovery"}
          </button>
        </div>
      ) : (
        <div className="near-transfer-box">
          <p>Once the replacement account has been connected and selected, MANDATE checks that it has a valid active FullAccess key before preparing the ownership proof.</p>
          <label htmlFor="recovery-start-code">Independent MANDATE recovery code</label>
          <input
            id="recovery-start-code"
            value={recoveryCode}
            onChange={event => {
              setRecoveryCode(event.target.value.toUpperCase());
              setChallenge(null);
            }}
            placeholder="MND-…"
            autoComplete="off"
          />
          <button
            className="outline-button"
            onClick={prepareStartRecovery}
            disabled={busy || !ready || !selectedAccountIsExpected || !recoveryCode.trim() || !codeEstablished}
          >
            {busy ? "Preparing recovery challenge…" : "Check selected account & prepare signature →"}
          </button>
        </div>
      )}

      {challenge && (
        <div className="near-transfer-box">
          <p>
            {challenge.action === "start"
              ? "Review the selected replacement account before signing. This is an off-chain ownership proof, not a NEAR transaction."
              : "The 24-hour delay has elapsed. Review the selected replacement account before the final off-chain confirmation."}
          </p>
          <p>Account selected through your wallet: <code>{challenge.accountId}</code></p>
          <p>Challenge expires in <strong>{formatRemaining(challengeSecondsRemaining)}</strong>.</p>
          <p>Challenge key: <code>{challenge.publicKey}</code></p>
          <button
            className="inspect-button"
            onClick={signPreparedChallenge}
            disabled={busy || !ready || challengeSecondsRemaining <= 0}
          >
            {busy
              ? "Waiting for your wallet…"
              : challenge.action === "start"
                ? "Sign with the connected replacement wallet →"
                : "Sign final replacement confirmation →"}
          </button>
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
        <span>Starting recovery requires your independent MANDATE recovery code and a fresh NEP-413 signature from the account you selected in the normal wallet connection flow. MANDATE checks that exact account and key against its Testnet FullAccess evidence. The replacement is not activated until the 24-hour delay ends and the same account signs again. Cancellation requires the independent recovery code. MANDATE never asks for a seed phrase or private key.</span>
      </div>
    </section>
  );
}
