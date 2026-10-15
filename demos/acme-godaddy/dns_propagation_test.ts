import assert from "node:assert/strict";

import { waitForAuthoritativeTxt } from "./dns_propagation.ts";

const FQDN = "_acme-challenge.example.com";
const TXT = "test-txt-value";
const SERVERS = [
  { name: "ns1.example.net", address: "192.0.2.1" },
  { name: "ns2.example.net", address: "192.0.2.2" },
];

function simulation(visible: (at: number, server: string) => boolean) {
  let at = 0;
  const sleeps: number[] = [];
  const checks: Array<{ at: number; server: string }> = [];
  return {
    sleeps,
    checks,
    runtime: {
      now: () => at,
      sleep: (milliseconds: number) => {
        assert.ok(milliseconds > 0, "polling must never busy-loop");
        sleeps.push(milliseconds);
        at += milliseconds;
        return Promise.resolve();
      },
      resolveServers: () => Promise.resolve(SERVERS),
      hasTxt: (fqdn: string, value: string, server: string) => {
        assert.equal(fqdn, FQDN);
        assert.equal(value, TXT);
        checks.push({ at, server });
        return Promise.resolve(visible(at, server));
      },
    },
  };
}

Deno.test("zero propagation delay preserves immediate authoritative success", async () => {
  const fake = simulation(() => true);
  await waitForAuthoritativeTxt(FQDN, TXT, {
    zone: "example.com",
    timeoutMs: 600_000,
    intervalMs: 5_000,
  }, fake.runtime);
  assert.equal(fake.checks.length, SERVERS.length);
  assert.deepEqual(fake.sleeps, []);
});

Deno.test("propagation delay retains the record and rechecks every server before completion", async () => {
  const fake = simulation(() => true);
  await waitForAuthoritativeTxt(FQDN, TXT, {
    zone: "example.com",
    timeoutMs: 600_000,
    intervalMs: 5_000,
    delayMs: 180_000,
  }, fake.runtime);
  assert.equal(fake.runtime.now(), 180_000);
  assert.equal(fake.sleeps.length, 36);
  assert.ok(fake.sleeps.every((milliseconds) => milliseconds === 5_000));
  assert.deepEqual(
    fake.checks.slice(-2),
    SERVERS.map(({ address }) => ({
      at: 180_000,
      server: address,
    })),
  );
});

Deno.test("temporary disappearance resets the propagation delay", async () => {
  const fake = simulation((at, server) => at !== 10_000 || server !== SERVERS[1].address);
  await waitForAuthoritativeTxt(FQDN, TXT, {
    zone: "example.com",
    timeoutMs: 60_000,
    intervalMs: 5_000,
    delayMs: 20_000,
  }, fake.runtime);
  assert.equal(fake.runtime.now(), 35_000);
  assert.ok(fake.checks.some((check) => check.at === 10_000));
});

Deno.test("late visibility cannot bypass the delay when the total timeout expires", async () => {
  const fake = simulation((at) => at >= 40_000);
  await assert.rejects(
    waitForAuthoritativeTxt(FQDN, TXT, {
      zone: "example.com",
      timeoutMs: 60_000,
      intervalMs: 10_000,
      delayMs: 30_000,
    }, fake.runtime),
    /propagation delay did not complete/,
  );
  assert.equal(fake.runtime.now(), 60_000);
});

Deno.test("missing TXT expires at the total timeout without a zero-duration loop", async () => {
  const fake = simulation(() => false);
  await assert.rejects(
    waitForAuthoritativeTxt(FQDN, TXT, {
      zone: "example.com",
      timeoutMs: 12_000,
      intervalMs: 5_000,
    }, fake.runtime),
    /not visible on: ns1\.example\.net, ns2\.example\.net/,
  );
  assert.deepEqual(fake.sleeps, [5_000, 5_000, 2_000]);
});

Deno.test("invalid delay and timeout combinations fail before DNS lookup", async () => {
  for (const delayMs of [-1, NaN, Infinity, 10_000, 20_000]) {
    const fake = simulation(() => true);
    await assert.rejects(
      waitForAuthoritativeTxt(FQDN, TXT, {
        zone: "example.com",
        timeoutMs: 10_000,
        intervalMs: 1_000,
        delayMs,
      }, fake.runtime),
      /delay must be nonnegative and less than timeout/,
    );
    assert.deepEqual(fake.checks, []);
  }
});
