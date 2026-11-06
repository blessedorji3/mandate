"use client";

import { NearWalletConnectorProvider } from "@/app/near-wallet-connector-context";
import { NearWalletPanel } from "@/app/near-wallet-panel";
import { RecoveryCodePanel } from "@/app/recovery-code-panel";
import { RecoveryLifecyclePanel } from "@/app/recovery-lifecycle-panel";

export function WalletClientPanels() {
  return (
    <NearWalletConnectorProvider>
      <NearWalletPanel />
      <RecoveryCodePanel />
      <RecoveryLifecyclePanel />
    </NearWalletConnectorProvider>
  );
}
