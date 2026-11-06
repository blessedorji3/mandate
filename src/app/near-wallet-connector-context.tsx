"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { NearConnector } from "@hot-labs/near-connect";

type NearWalletConnectorContextValue = {
  connector: NearConnector | null;
  recoveryMode: boolean;
  setRecoveryMode: (active: boolean) => void;
};

const NearWalletConnectorContext = createContext<NearWalletConnectorContextValue>({
  connector: null,
  recoveryMode: false,
  setRecoveryMode: () => undefined,
});

export function NearWalletConnectorProvider({ children }: { children: ReactNode }) {
  const [connector, setConnector] = useState<NearConnector | null>(null);
  const [recoveryMode, setRecoveryMode] = useState(false);

  useEffect(() => {
    let active = true;

    async function initialize() {
      try {
        const { NearConnector } = await import("@hot-labs/near-connect");
        const instance = new NearConnector({
          network: "testnet",
          features: { testnet: true },
          autoConnect: false,
        });
        await instance.whenManifestLoaded;
        if (active) setConnector(instance);
      } catch {
        if (active) setConnector(null);
      }
    }

    void initialize();
    return () => {
      active = false;
    };
  }, []);

  return (
    <NearWalletConnectorContext.Provider value={{ connector, recoveryMode, setRecoveryMode }}>
      {children}
    </NearWalletConnectorContext.Provider>
  );
}

export function useNearWalletConnector() {
  return useContext(NearWalletConnectorContext);
}
