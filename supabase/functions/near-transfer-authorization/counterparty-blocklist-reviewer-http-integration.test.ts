import { assertEquals } from "jsr:@std/assert@1";

const REPORTER_ID = "81000000-0000-4000-8000-000000000001";
const REVIEWER_ID = "81000000-0000-4000-8000-000000000002";
const ADMIN_ID = "81000000-0000-4000-8000-000000000003";
const SUBJECT_ID = "81000000-0000-4000-8000-000000000004";
const REPORT_ID = "82000000-0000-4000-8000-000000000001";
const ROLE_ID = "83000000-0000-4000-8000-000000000001";
const ORIGIN = "https://mandate-git-feat-phase-2-counterparty-risk-web3pass.vercel.app";
const PROJECT_URL = "https://mandate-blocklist-review-test.invalid";
const TOKENS = new Map([
  ["reporter-token", REPORTER_ID],
  ["reviewer-token", REVIEWER_ID],
  ["admin-token", ADMIN_ID],
]);

function object(value: unknown): Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown> : {};
}

Deno.test("blocklist reviewer HTTP actions use verified Auth actors and audited database RPCs", async () => {
  const originalFetch = globalThis.fetch;
  const originalEnv = {
    url: Deno.env.get("SUPABASE_URL"),
    anon: Deno.env.get("SUPABASE_ANON_KEY"),
    service: Deno.env.get("SUPABASE_SERVICE_ROLE_KEY"),
  };
  const calls: Array<{ name: string; body: Record<string, unknown> }> = [];

  Deno.env.set("SUPABASE_URL", PROJECT_URL);
  Deno.env.set("SUPABASE_ANON_KEY", "test-anon-key");
  Deno.env.set("SUPABASE_SERVICE_ROLE_KEY", "test-service-role-key");

  globalThis.fetch = (async (input: RequestInfo | URL, init?: RequestInit) => {
    const url = String(input);
    const headers = new Headers(init?.headers);
    const body = typeof init?.body === "string" ? object(JSON.parse(init.body)) : {};
    if (url.endsWith("/auth/v1/user")) {
      const token = (headers.get("authorization") ?? "").replace(/^Bearer /, "");
      const userId = TOKENS.get(token);
      return userId ? Response.json({ id: userId }) : Response.json({ message: "Invalid JWT" }, { status: 401 });
    }
    const rpcName = url.match(/\/rest\/v1\/rpc\/([^/?]+)/)?.[1];
    if (rpcName) {
      calls.push({ name: rpcName, body });
      if (rpcName === "submit_counterparty_blocklist_report_v1") return Response.json(REPORT_ID);
      if (rpcName === "list_counterparty_blocklist_review_queue_v1") return Response.json([{
        id: REPORT_ID, network: "testnet", account_id: "flagged.testnet",
        status: "pending", reason: "Suspicious deployment behavior",
        evidence_ref: "https://evidence.example/report/42",
        evidence_sha256: null, source_type: "explorer",
        reporter_owner_id: REPORTER_ID, created_at: "2026-11-05T10:00:00.000Z",
      }]);
      if (rpcName === "review_counterparty_blocklist_report_v1") return Response.json(true);
      if (rpcName === "provision_counterparty_blocklist_reviewer_v1") {
        if (body.p_actor_owner_id === REVIEWER_ID) {
          return Response.json({ code: "P0001", message: "Active blocklist administrator role is required" }, { status: 400 });
        }
        return Response.json(ROLE_ID);
      }
      if (rpcName === "list_counterparty_blocklist_audit_v1") return Response.json([{
        id: "84000000-0000-4000-8000-000000000001",
        actor_owner_id: ADMIN_ID, subject_owner_id: SUBJECT_ID, report_id: REPORT_ID,
        action: "report_confirmed", reason: "Evidence reviewed independently",
        before_state: { status: "pending" }, after_state: { status: "confirmed" },
        created_at: "2026-11-05T10:01:00.000Z",
      }]);
      return Response.json({ message: "Unexpected RPC" }, { status: 500 });
    }
    return Response.json({ message: "Unexpected request", url }, { status: 500 });
  }) as typeof fetch;

  try {
    const { handleRequest } = await import("./index.ts");
    const post = async (token: string, action: string, fields: Record<string, unknown> = {}) => {
      const request = new Request(PROJECT_URL + "/functions/v1/near-transfer-authorization", {
        method: "POST",
        headers: {
          origin: ORIGIN,
          "content-type": "application/json",
          authorization: "Bearer " + token,
        },
        body: JSON.stringify({
          action, ...fields,
          // Deliberately forged browser owner must never be trusted.
          ownerId: "81000000-0000-4000-8000-000000000099",
        }),
      });
      const response = await handleRequest(request);
      return { response, body: object(await response.json()) };
    };

    const submitted = await post("reporter-token", "blocklist_report_submit", {
      accountId: "flagged.testnet",
      reason: "Suspicious deployment behavior requires independent review.",
      evidenceRef: "https://evidence.example/report/42",
      sourceType: "explorer",
    });
    assertEquals(submitted.response.status, 201, JSON.stringify(submitted.body));
    assertEquals(submitted.body.submitted, true);
    assertEquals(submitted.body.status, "pending");

    const queue = await post("reviewer-token", "blocklist_review_queue");
    assertEquals(queue.response.status, 200, JSON.stringify(queue.body));
    assertEquals((queue.body.reports as unknown[])?.length, 1);

    const reviewed = await post("reviewer-token", "blocklist_report_review", {
      reportId: REPORT_ID,
      decision: "confirmed",
      reviewNote: "Evidence independently verified against the reported transaction.",
    });
    assertEquals(reviewed.response.status, 200, JSON.stringify(reviewed.body));
    assertEquals(reviewed.body.reviewed, true);

    const reviewerCannotProvision = await post("reviewer-token", "blocklist_reviewer_provision", {
      subjectOwnerId: SUBJECT_ID,
      provisioningAction: "grant",
      reason: "Reviewer attempts unauthorized role grant.",
    });
    assertEquals(reviewerCannotProvision.response.status, 403);

    const granted = await post("admin-token", "blocklist_reviewer_provision", {
      subjectOwnerId: SUBJECT_ID,
      provisioningAction: "grant",
      reason: "Reviewer identity approved by the project administrator.",
    });
    assertEquals(granted.response.status, 200, JSON.stringify(granted.body));
    assertEquals(granted.body.provisioned, true);
    assertEquals(granted.body.roleId, ROLE_ID);

    const audit = await post("admin-token", "blocklist_audit", { limit: 50 });
    assertEquals(audit.response.status, 200, JSON.stringify(audit.body));
    assertEquals((audit.body.events as unknown[])?.length, 1);

    const expectedActors = new Map([
      ["submit_counterparty_blocklist_report_v1", REPORTER_ID],
      ["list_counterparty_blocklist_review_queue_v1", REVIEWER_ID],
      ["review_counterparty_blocklist_report_v1", REVIEWER_ID],
      ["list_counterparty_blocklist_audit_v1", ADMIN_ID],
    ]);
    for (const call of calls.filter((item) => item.name !== "provision_counterparty_blocklist_reviewer_v1")) {
      const expected = expectedActors.get(call.name);
      assertEquals(call.body.p_reporter_owner_id ?? call.body.p_actor_owner_id ?? call.body.p_reviewer_owner_id, expected);
    }
    assertEquals(
      calls.filter((call) => call.name === "provision_counterparty_blocklist_reviewer_v1")
        .map((call) => call.body.p_actor_owner_id),
      [REVIEWER_ID, ADMIN_ID],
      "the failed reviewer attempt and successful admin grant must use their JWT-backed identities",
    );
    assertEquals(calls.filter((call) => call.name === "review_counterparty_blocklist_report_v1")[0]?.body.p_reviewer_owner_id, REVIEWER_ID);
    assertEquals(calls.filter((call) => call.name === "submit_counterparty_blocklist_report_v1")[0]?.body.p_reporter_owner_id, REPORTER_ID);
  } finally {
    globalThis.fetch = originalFetch;
    for (const [key, value] of Object.entries({
      SUPABASE_URL: originalEnv.url,
      SUPABASE_ANON_KEY: originalEnv.anon,
      SUPABASE_SERVICE_ROLE_KEY: originalEnv.service,
    })) {
      if (value === undefined) Deno.env.delete(key);
      else Deno.env.set(key, value);
    }
  }
});
