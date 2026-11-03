import { describe, expect, it } from "vitest";
import { applyCounterpartyRiskGate } from "../../src/security/risk-gated-execution";
import type { CounterpartyRiskDecision } from "../../src/security/counterparty-risk";
const decision=(outcome:"ALLOW"|"WARN"|"BLOCK"):CounterpartyRiskDecision=>({outcome,reasons:["test evidence"],evidence:[],accountId:"alice.testnet",evaluatedAt:new Date().toISOString(),requiresHumanApproval:outcome!=="ALLOW"});
describe("agent-side counterparty risk gate",()=>{
 it("continues only for ALLOW",()=>expect(applyCounterpartyRiskGate(decision("ALLOW")).status).toBe("CONTINUE"));
 it("pauses WARN until trusted owner approval",()=>expect(applyCounterpartyRiskGate(decision("WARN")).status).toBe("PAUSE_FOR_OWNER"));
 it("continues WARN only after owner approval is verified",()=>expect(applyCounterpartyRiskGate(decision("WARN"),true).status).toBe("CONTINUE_AFTER_OWNER_APPROVAL"));
 it("never lets approval override BLOCK",()=>expect(applyCounterpartyRiskGate(decision("BLOCK"),true).status).toBe("STOP"));
});
