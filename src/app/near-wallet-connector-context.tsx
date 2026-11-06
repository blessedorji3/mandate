"use client";

import { createContext, useContext, useEffect, useState, type ReactNode } from "react";
import type { NearConnector } from "@hot-labs/near-connect";

const NearWalletConnectorContext = createContext<NearConnector | null>(null);

export function NearWalletConnectorProvider({ children }: { children: ReactNode }) {
  const [connector, setConnector] = useState<NearConnector | null>(null);

  useEffect(() => {
    let active = true;
    let instance: NearConnector | null = null;

    async function initialize() {
      try {
        const { NearConnector } = await import("@hot-labs/near-connect");
        instance = new NearConnector({
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
    <NearWalletConnectorContext.Provider value={connector}>
      {children}
    </NearWalletConnectorContext.Provider>
  );
}

export function useNearWalletConnector() {
  return useContext(NearWalletConnectorContext);
}
