import assert from "node:assert/strict";

import { GoDaddyDnsProvider, relativeRecordName } from "./godaddy_provider.ts";

Deno.test("relativeRecordName keeps names relative to the configured zone", () => {
  assert.equal(relativeRecordName("_acme-challenge.example.com", "example.com"), "_acme-challenge");
  assert.equal(
    relativeRecordName("_acme-challenge.api.example.com.", "example.com"),
    "_acme-challenge.api",
  );
  assert.throws(
    () => relativeRecordName("_acme-challenge.example.net", "example.com"),
    /outside the configured GoDaddy zone/,
  );
});

Deno.test("provider creates and deletes exactly the returned GoDaddy recordId", async () => {
  const requests: Array<{ url: string; init?: RequestInit }> = [];
  const fakeFetch = async (
    input: string | URL | Request,
    init?: RequestInit,
  ): Promise<Response> => {
    requests.push({ url: String(input), init });
    if (init?.method === "POST") {
      return await Promise.resolve(
        new Response(
          JSON.stringify({ recordId: "record/123", type: "TXT" }),
          { status: 201, headers: { "Content-Type": "application/json" } },
        ),
      );
    }
    return await Promise.resolve(new Response(null, { status: 204 }));
  };
  const provider = new GoDaddyDnsProvider({
    token: "test-token",
    zone: "example.com",
    fetch: fakeFetch as typeof fetch,
  });

  const handle = await provider.present({
    fqdn: "_acme-challenge.api.example.com",
    value: "challenge-value",
  });
  await provider.cleanup(handle);

  assert.equal(handle.id, "record/123");
  assert.equal(requests.length, 2);
  assert.equal(
    requests[0].url,
    "https://api.godaddy.com/v3/domains/zones/example.com/dns-records",
  );
  assert.equal(new Headers(requests[0].init?.headers).get("authorization"), "Bearer test-token");
  assert.deepEqual(JSON.parse(String(requests[0].init?.body)), {
    type: "TXT",
    name: "_acme-challenge.api",
    data: "challenge-value",
    ttl: 600,
  });
  assert.equal(
    requests[1].url,
    "https://api.godaddy.com/v3/domains/zones/example.com/dns-records/record%2F123",
  );
  assert.equal(requests[1].init?.method, "DELETE");
});

Deno.test("cleanup treats an already absent record as complete", async () => {
  const provider = new GoDaddyDnsProvider({
    token: "test-token",
    zone: "example.com",
    fetch: (() =>
      Promise.resolve(
        new Response(
          JSON.stringify({ code: "NOT_FOUND", message: "missing" }),
          { status: 404 },
        ),
      )) as typeof fetch,
  });

  await provider.cleanup({
    fqdn: "_acme-challenge.example.com",
    value: "challenge-value",
    id: "already-gone",
  });
});

Deno.test("API errors expose useful details without including the PAT", async () => {
  const provider = new GoDaddyDnsProvider({
    token: "secret-pat-value",
    zone: "example.com",
    fetch: (() =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            code: "ACCESS_DENIED",
            message: "scope missing for secret-pat-value",
          }),
          { status: 403, statusText: "Forbidden" },
        ),
      )) as typeof fetch,
  });

  await assert.rejects(
    provider.present({ fqdn: "_acme-challenge.example.com", value: "value" }),
    (error: unknown) => {
      assert(error instanceof Error);
      assert.match(error.message, /403 Forbidden.*ACCESS_DENIED.*scope missing/);
      assert.doesNotMatch(error.message, /secret-pat-value/);
      return true;
    },
  );
});
