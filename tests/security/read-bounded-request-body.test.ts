import { describe, expect, it } from "vitest";
import { readBoundedRequestText, RequestBodyTooLargeError } from "../../src/security/read-bounded-request-body";

describe("readBoundedRequestText", () => {
  it("accepts a bounded body without Content-Length", async () => {
    const request = new Request("https://mandate.invalid", { method: "POST", body: '{"proposal":{}}' });
    expect(await readBoundedRequestText(request, 32)).toBe('{"proposal":{}}');
  });

  it("rejects an oversized body when Content-Length is absent", async () => {
    const bytes = new Uint8Array(20).fill(120);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(bytes); controller.close(); },
    });
    const request = new Request("https://mandate.invalid", { method: "POST", body: stream, duplex: "half" } as RequestInit);
    await expect(readBoundedRequestText(request, 16)).rejects.toBeInstanceOf(RequestBodyTooLargeError);
  });

  it("rejects a body whose Content-Length is understated", async () => {
    const bytes = new Uint8Array(20).fill(120);
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(bytes); controller.close(); },
    });
    const request = new Request("https://mandate.invalid", {
      method: "POST",
      headers: { "content-length": "1" },
      body: stream,
      duplex: "half",
    } as RequestInit);
    await expect(readBoundedRequestText(request, 16)).rejects.toBeInstanceOf(RequestBodyTooLargeError);
  });

  it("rejects invalid UTF-8 instead of parsing replacement characters", async () => {
    const stream = new ReadableStream<Uint8Array>({
      start(controller) { controller.enqueue(new Uint8Array([0xff, 0xfe])); controller.close(); },
    });
    const request = new Request("https://mandate.invalid", { method: "POST", body: stream, duplex: "half" } as RequestInit);
    await expect(readBoundedRequestText(request, 16)).rejects.toThrow();
  });
});
