export type RiskOutcome = "ALLOW" | "WARN" | "BLOCK";
export type EvidenceStatus = "verified" | "unavailable" | "stale" | "unverified";
export type RiskSignal = { name:string; status:EvidenceStatus; observedAt?:string; source?:string; summary:string; value?:string|number|boolean|null };
export type BlocklistEvidence = { status:"confirmed"|"pending"|"rejected"; evidenceRef:string; reason:string; reviewedAt?:string };
export type CounterpartyRiskInput = {
  accountId:string; evaluatedAt:string; accountAgeDays?:number|null; lastActivityDays?:number|null;
  isContract?:boolean|null; contractCodeHash?:string|null; codeChangedRecently?:boolean|null;
  previousInteractions?:number|null; signals:RiskSignal[]; blocklist?:BlocklistEvidence|null;
};
export type CounterpartyRiskDecision = {
  outcome:RiskOutcome; reasons:string[]; evidence:RiskSignal[]; accountId:string;
  evaluatedAt:string; requiresHumanApproval:boolean;
};
const ACCOUNT_ID=/^(?:[a-z0-9_-]+\.)*[a-z0-9_-]+$/;
const MAX_SIGNALS=32, MAX_TEXT=500, MAX_EVIDENCE_AGE_MS=24*60*60*1000;
function record(v:unknown):v is Record<string,unknown>{return typeof v==="object"&&v!==null&&!Array.isArray(v)}
function date(v:unknown):v is string{return typeof v==="string"&&Number.isFinite(Date.parse(v))}
function txt(v:unknown):v is string{return typeof v==="string"&&v.trim().length>0&&v.length<=MAX_TEXT}
function signal(v:unknown):v is RiskSignal{
 if(!record(v))return false;
 return txt(v.name)&&["verified","unavailable","stale","unverified"].includes(String(v.status))&&txt(v.summary)&&
 (v.source===undefined||txt(v.source))&&(v.observedAt===undefined||date(v.observedAt))&&
 (v.value===undefined||v.value===null||["string","number","boolean"].includes(typeof v.value))&&
 (typeof v.value!=="number"||Number.isFinite(v.value));
}
/** Risk result only: never signs, broadcasts, or replaces owner policy authorization. */
export function evaluateCounterpartyRisk(input:unknown):CounterpartyRiskDecision{
 const fallback:CounterpartyRiskDecision={outcome:"WARN",reasons:["Risk input is incomplete or malformed; human review is required."],evidence:[],accountId:record(input)&&typeof input.accountId==="string"?input.accountId.slice(0,128):"unknown",evaluatedAt:new Date().toISOString(),requiresHumanApproval:true};
 if(!record(input)||typeof input.accountId!=="string"||!ACCOUNT_ID.test(input.accountId)||!date(input.evaluatedAt)||
 !Array.isArray(input.signals)||input.signals.length>MAX_SIGNALS||!input.signals.every(signal))return fallback;
 const d=input as unknown as CounterpartyRiskInput, reasons:string[]=[], evidence=d.signals.slice();
 let outcome:RiskOutcome="ALLOW";
 const warn=(s:string)=>{if(outcome!=="BLOCK")outcome="WARN";reasons.push(s)};
 const block=(s:string)=>{outcome="BLOCK";reasons.push(s)};
 if(d.blocklist?.status==="confirmed"){
  if(!txt(d.blocklist.evidenceRef)||!txt(d.blocklist.reason)||!date(d.blocklist.reviewedAt))warn("Blocklist record lacks complete review evidence; it cannot be treated as confirmed.");
  else block("Counterparty is on the reviewed MANDATE blocklist: "+d.blocklist.reason);
 }else if(d.blocklist?.status==="pending")warn("A blocklist report is pending review; owner approval is required.");
 if(d.accountAgeDays==null||!Number.isFinite(d.accountAgeDays)||d.accountAgeDays<0)warn("Account age is not verified from historical chain data.");
 else if(d.accountAgeDays<7)warn("Counterparty account is less than seven days old.");
 if(d.lastActivityDays==null||!Number.isFinite(d.lastActivityDays)||d.lastActivityDays<0)warn("Recent activity is not verified from indexed chain history.");
 else if(d.lastActivityDays>180)warn("Counterparty has been inactive for more than 180 days.");
 if(d.isContract==null)warn("Account type could not be verified from NEAR RPC.");
 else if(d.isContract){
  if(!txt(d.contractCodeHash))warn("Contract code hash is unavailable.");
  if(d.codeChangedRecently==null)warn("Historical contract code changes could not be verified.");
  else if(d.codeChangedRecently)warn("Contract code changed recently; review deployed code.");
 }
 if(d.previousInteractions==null||!Number.isSafeInteger(d.previousInteractions)||d.previousInteractions<0)warn("Previous MANDATE interactions could not be verified.");
 for(const s of evidence){
  if(s.status!=="verified")warn(s.name+" evidence is "+s.status+".");
  if(s.observedAt&&Date.now()-Date.parse(s.observedAt)>MAX_EVIDENCE_AGE_MS)warn(s.name+" evidence is older than 24 hours.");
 }
 if(!reasons.length)reasons.push("Required risk signals are verified and no adverse indicators were found.");
 return {outcome,reasons:[...new Set(reasons)].slice(0,20),evidence,accountId:d.accountId,evaluatedAt:d.evaluatedAt,requiresHumanApproval:outcome!=="ALLOW"};
}
