import type { SupabaseClient } from "@supabase/supabase-js";
import type { CounterpartyRiskServiceDependencies } from "./counterparty-risk-service.ts";

/**
 * Service-role-only adapter. The caller must create this client on a trusted
 * server and derive ownerId from the authenticated session or API-key record.
 */
export function createSupabaseRiskDependencies(
  admin: SupabaseClient,
): Pick<CounterpartyRiskServiceDependencies, "findBlocklistRecord" | "countPreviousInteractions"> {
  return {
    findBlocklistRecord: async (network, accountId) => {
      const { data, error } = await admin.rpc("lookup_counterparty_blocklist", {
        p_network: network,
        p_account_id: accountId,
      });
      if (error) throw new Error("Shared counterparty blocklist lookup is unavailable.");
      if (Array.isArray(data)) return data[0] ?? null;
      return data ?? null;
    },
    countPreviousInteractions: async (ownerId, network, targetAccountId, excludeProposalId) => {
      // The current product is Testnet-only. Include legacy receipts that predate a stored network tag.
      let query = admin
        .from("authorization_decisions")
        .select("id", { count: "exact", head: true })
        .eq("owner_id", ownerId)
        .filter("proposal->>target", "eq", targetAccountId);
      if (excludeProposalId) {
        // Exclude the receipt created for this very inspection.
        query = query.neq("proposal_id", excludeProposalId);
      }
      const { count, error } = await query;
      if (error || count === null) {
        throw new Error("Owner-scoped MANDATE interaction history is unavailable.");
      }
      return count;
    },
  };
}
