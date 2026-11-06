import { redirect } from "next/navigation";

export const dynamic = "force-dynamic";

import { createClient } from "@/lib/supabase/server";
import { WalletClientPanels } from "@/app/wallet-client-panels";

export default async function WalletPage() {
  const supabase = await createClient();
  const { data: { user } } = await supabase.auth.getUser();
  if (!user) redirect("/login");

  return (
    <main className="agent-page-shell">
      <div className="agent-workspace">
        <div className="agent-intro">
          <span className="eyebrow">MANDATE · WALLET CONNECTION</span>
          <h1>Your wallet. <em>Your control.</em></h1>
          <p>Connect a NEAR Testnet account. MANDATE will inspect proposed actions separately from the wallet that signs them.</p>
          <div className="agent-boundary"><span className="live-dot" /> Testnet only <b>·</b> Non-custodial connection <b>·</b> No automatic transactions</div>
        </div>
        <WalletClientPanels />
        <p className="agent-prototype-note"><a href="/">Back to MANDATE dashboard</a> · <a href="/agent">Open agent chat</a></p>
      </div>
    </main>
  );
}
