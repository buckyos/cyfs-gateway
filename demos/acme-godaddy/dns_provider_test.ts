import assert from "node:assert/strict";

import { acmeClientDns01TxtValue, dns01RecordName } from "./dns_provider.ts";

Deno.test("dns01RecordName maps apex and wildcard authorizations to the same owner", () => {
  assert.equal(dns01RecordName("example.com"), "_acme-challenge.example.com");
  assert.equal(dns01RecordName("*.example.com."), "_acme-challenge.example.com");
});

Deno.test("acme-client DNS-01 callback value is not hashed a second time", () => {
  const callbackValue = "61rBZ_4knHblO0MNoxFsXZ_eTFUHum0B6IVRbhvUn5I";
  assert.equal(
    acmeClientDns01TxtValue(callbackValue),
    callbackValue,
  );
  assert.throws(
    () => acmeClientDns01TxtValue("token.thumbprint"),
    /invalid DNS-01 TXT value/,
  );
});
