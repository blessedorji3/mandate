import { describe, expect, it } from "vitest";
import { evaluateCounterpartyRisk } from "../../src/security/counterparty-risk";
const complete={
 accountId:"alice.testnet",evaluatedAt:"2026-11-03T00:00:00.000Z",accountAgeDays:90,lastActivityDays:2,
 isContract:false,previousInteractions:0,
 signals:[{name:"near_rpc_account",status:"verified" as const,observedAt:new Date().toISOString(),source:"NEAR RPC",summary:"Account state verified."}]
};
describe("evaluateCounterpartyRisk",()=>{
 it("allows only complete verified signals",()=>expect(evaluateCounterpartyRisk(complete).outcome).toBe("ALLOW"));
 it("warns when historical evidence is missing",()=>expect(evaluateCounterpartyRisk({...complete,accountAgeDays:null}).outcome).toBe("WARN"));
 it("blocks a confirmed blocklist record with review evidence",()=>expect(evaluateCounterpartyRisk({...complete,blocklist:{status:"confirmed",evidenceRef:"sha256:abc123",reason:"Verified malicious drain contract",reviewedAt:new Date().toISOString()}}).outcome).toBe("BLOCK"));
 it("does not block on a pending report",()=>expect(evaluateCounterpartyRisk({...complete,blocklist:{status:"pending",evidenceRef:"https://example.invalid/report",reason:"Unverified user report"}}).outcome).toBe("WARN"));
 it("fails closed for malformed input",()=>{const r=evaluateCounterpartyRisk({accountId:"alice.testnet",signals:"bad"});expect(r.outcome).toBe("WARN");expect(r.requiresHumanApproval).toBe(true)});
 it("warns when contract history is unavailable",()=>expect(evaluateCounterpartyRisk({...complete,isContract:true,contractCodeHash:"hash",codeChangedRecently:null}).outcome).toBe("WARN"));
 it("warns on stale evidence",()=>expect(evaluateCounterpartyRisk({...complete,signals:[{...complete.signals[0],observedAt:"2026-10-01T00:00:00.000Z"}]}).outcome).toBe("WARN"));
});
