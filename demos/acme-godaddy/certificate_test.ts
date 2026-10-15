import assert from "node:assert/strict";
import * as path from "node:path";

import { inspectExistingCertificate, installCertificate } from "./certificate.ts";
import {
  identityPaths,
  type IdentityStorage,
  orderStateDirectory,
  resolveIdentityStorage,
  sha256,
} from "./identity.ts";

const PRODUCTION = "https://acme-v02.api.letsencrypt.org/directory";
const STAGING = "https://acme-staging-v02.api.letsencrypt.org/directory";
const DOMAINS = ["example.com", "*.example.com"];

Deno.test("identity roots follow BuckyOS env/CLI precedence and isolate all nonproduction roots", () => {
  const names = ["BUCKYOS_ROOT", "BUCKYOS_IDENTITY_ROOT", "BUCKYOS_SECURITY_ROOT"];
  const previous = names.map((name) => Deno.env.get(name));
  try {
    names.forEach((name) => Deno.env.delete(name));
    assert.equal(resolveIdentityStorage({}, PRODUCTION).publicRoot, "/opt/buckyos/local/identity");
    Deno.env.set("BUCKYOS_ROOT", "/tmp/test-buckyos");
    assert.equal(resolveIdentityStorage({}, PRODUCTION).securityRoot, "/tmp/test-buckyos/security");
    Deno.env.set("BUCKYOS_IDENTITY_ROOT", "/tmp/test-public");
    Deno.env.set("BUCKYOS_SECURITY_ROOT", "/tmp/test-private");
    assert.equal(resolveIdentityStorage({}, PRODUCTION).publicRoot, "/tmp/test-public");
    const options = {
      buckyosRoot: "/tmp/cli-buckyos",
      identityRoot: "/tmp/cli-public",
      securityRoot: "/tmp/cli-private",
      stateRoot: "/tmp/cli-state",
    };
    const live = resolveIdentityStorage(options, PRODUCTION);
    assert.deepEqual(live, {
      publicRoot: options.identityRoot,
      securityRoot: options.securityRoot,
      stateRoot: options.stateRoot,
    });
    const staged = resolveIdentityStorage(options, STAGING);
    const isolated = path.join(options.stateRoot, "authorities", sha256(STAGING));
    assert.equal(staged.publicRoot, path.join(isolated, "identity"));
    assert.equal(staged.securityRoot, path.join(isolated, "security"));
    assert.equal(staged.stateRoot, path.join(isolated, "state"));
    assert.notEqual(
      staged.publicRoot,
      resolveIdentityStorage(options, "https://ca.test/dir").publicRoot,
    );
    assert.equal(
      orderStateDirectory(live, DOMAINS, PRODUCTION),
      orderStateDirectory(live, [...DOMAINS].reverse().concat(DOMAINS), PRODUCTION),
    );
    assert.notEqual(
      orderStateDirectory(live, DOMAINS, PRODUCTION),
      orderStateDirectory(live, [DOMAINS[0]], PRODUCTION),
    );
    assert.notEqual(
      orderStateDirectory(live, DOMAINS, PRODUCTION),
      orderStateDirectory(live, DOMAINS, STAGING),
    );
    assert.throws(() =>
      resolveIdentityStorage({
        identityRoot: "/tmp/public",
        securityRoot: "/tmp/public/security",
      }, PRODUCTION), /outside the public identity root/);
    assert.throws(() => identityPaths(live, "../../escape"), /invalid DNS identity/);
  } finally {
    names.forEach((name, i) => {
      if (previous[i] === undefined) Deno.env.delete(name);
      else Deno.env.set(name, previous[i]!);
    });
  }
});

Deno.test("one SAN order installs exact and wildcard BuckyOS identities with private modes", async () => {
  await withStorage(async (storage) => {
    await installCertificate(storage, DOMAINS, PRODUCTION, 30, VALID_CERT, TEST_KEY);
    for (const domain of DOMAINS) {
      const files = identityPaths(storage, domain);
      const publicFiles = [];
      for await (const entry of Deno.readDir(path.dirname(files.cert))) {
        publicFiles.push(entry.name);
      }
      assert.deepEqual(publicFiles.sort(), [
        "server.cert.pem",
        "server.chain.pem",
        "server.fullchain.pem",
        "server.meta.json",
      ]);
      const metadata = JSON.parse(await Deno.readTextFile(files.metadata));
      assert.equal(metadata.schema, "buckyos.identity.x509.metadata.v1");
      assert.equal(metadata.raw_host_uri, files.dirName);
      assert.equal(metadata.did, `did:web:${files.dirName}`);
      assert.equal(metadata.dir_name, domain === "example.com" ? domain : "_.example.com");
      assert.equal(metadata.usage, "server");
      assert.deepEqual(metadata.san.dns, [...DOMAINS].sort());
      assert.deepEqual(
        metadata.match,
        domain.startsWith("*.")
          ? { type: "wildcard", host_pattern: domain }
          : { type: "exact", host: domain },
      );
      assert.equal(metadata.paths.key_ref, null);
      assert.match(metadata.certificate.fingerprint_sha256, /^sha256:[0-9a-f]{64}$/);
      assert.match(metadata.certificate.public_key_fingerprint, /^sha256:[0-9a-f]{64}$/);
      assert.equal(await Deno.readTextFile(files.privateKey), TEST_KEY);
      if (Deno.build.os !== "windows") {
        assert.equal((await Deno.stat(files.privateKey)).mode! & 0o777, 0o600);
        assert.equal((await Deno.stat(files.metadata)).mode! & 0o777, 0o644);
      }
    }
    const stateDir = orderStateDirectory(storage, DOMAINS, PRODUCTION);
    assert.equal((await Deno.stat(path.join(stateDir, "state.json"))).isFile, true);
    assert.equal((await inspectExistingCertificate(storage, DOMAINS, PRODUCTION, 30)).renew, false);
    assert.equal(
      (await inspectExistingCertificate(storage, DOMAINS, PRODUCTION, 100_000)).renew,
      true,
    );
    assert.equal(
      (await inspectExistingCertificate(storage, [DOMAINS[0]], PRODUCTION, 30)).renew,
      true,
    );
    assert.equal((await inspectExistingCertificate(storage, DOMAINS, STAGING, 30)).renew, true);
  });
});

Deno.test("renewal inspects every identity, metadata and private key in the order", async () => {
  await withStorage(async (storage) => {
    for (const field of ["metadata", "privateKey", "cert", "chain", "fullchain"] as const) {
      await installCertificate(storage, DOMAINS, PRODUCTION, 30, VALID_CERT, TEST_KEY);
      await Deno.remove(identityPaths(storage, "*.example.com")[field]);
      assert.equal(
        (await inspectExistingCertificate(storage, DOMAINS, PRODUCTION, 30)).renew,
        true,
      );
    }
    await installCertificate(storage, DOMAINS, PRODUCTION, 30, VALID_CERT, TEST_KEY);
    await Deno.writeTextFile(identityPaths(storage, "example.com").privateKey, OTHER_KEY);
    assert.equal((await inspectExistingCertificate(storage, DOMAINS, PRODUCTION, 30)).renew, true);
  });
});

Deno.test("invalid dates, SANs or key cannot replace an existing generation", async () => {
  await withStorage(async (storage) => {
    await installCertificate(storage, DOMAINS, PRODUCTION, 30, VALID_CERT, TEST_KEY);
    const before = await snapshot(storage);
    for (
      const [domains, certificate, key, message] of [
        [DOMAINS, EXPIRED_CERT, TEST_KEY, /not currently valid/],
        [DOMAINS, FUTURE_CERT, TEST_KEY, /not currently valid/],
        [["other.example.com"], VALID_CERT, TEST_KEY, /SANs/],
        [DOMAINS, VALID_CERT, OTHER_KEY, /private key/],
      ] as const
    ) {
      await assert.rejects(
        () => installCertificate(storage, [...domains], PRODUCTION, 30, certificate, key),
        message,
      );
      assert.deepEqual(await snapshot(storage), before);
    }
    assert.equal((await inspectExistingCertificate(storage, DOMAINS, PRODUCTION, 30)).renew, false);
  });
});

Deno.test("staging issuance cannot overwrite production identities or renewal state", async () => {
  await withStorage(async (storage) => {
    await installCertificate(storage, DOMAINS, PRODUCTION, 30, VALID_CERT, TEST_KEY);
    const before = await snapshot(storage);
    const staging = resolveIdentityStorage({
      identityRoot: storage.publicRoot,
      securityRoot: storage.securityRoot,
      stateRoot: storage.stateRoot,
    }, STAGING);
    await installCertificate(staging, DOMAINS, STAGING, 30, VALID_CERT, TEST_KEY);
    assert.deepEqual(await snapshot(storage), before);
    assert.equal((await inspectExistingCertificate(staging, DOMAINS, STAGING, 30)).renew, false);
    assert.equal((await inspectExistingCertificate(storage, DOMAINS, PRODUCTION, 30)).renew, false);
  });
});

async function withStorage(test: (storage: IdentityStorage) => Promise<void>) {
  const root = await Deno.makeTempDir({ prefix: "acme-identity-test-" });
  try {
    await test({
      publicRoot: path.join(root, "local", "identity"),
      securityRoot: path.join(root, "security"),
      stateRoot: path.join(root, "state"),
    });
  } finally {
    await Deno.remove(root, { recursive: true });
  }
}

async function snapshot(storage: IdentityStorage): Promise<Record<string, string>> {
  const files = DOMAINS.flatMap((domain) => {
    const paths = identityPaths(storage, domain);
    return [paths.cert, paths.chain, paths.fullchain, paths.metadata, paths.privateKey];
  });
  files.push(path.join(orderStateDirectory(storage, DOMAINS, PRODUCTION), "state.json"));
  return Object.fromEntries(
    await Promise.all(files.map(async (file) => [
      file,
      await Deno.readTextFile(file),
    ])),
  );
}

// Public, test-only fixtures generated locally; never use these keys for a real identity.
const TEST_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgu7pKGLsLXfHe4a9o
NKn9DkKpwLVyerAadrF5kheINRKhRANCAATOUD6T/pLtkYO77QyGjBRWdER9Uy59
P1HgtKc90/sfhYvI4BolP+eLWqPzTxhQ21+KGSdFHbLJWQMUszciNbg2
-----END PRIVATE KEY-----
`;

const OTHER_KEY = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgDYg6I3hlSuUZN67S
33fkozx69kOpj5hMYN/fBkQg1IehRANCAAQUp252lTnJx6scAQi4QmvWrxHk+ibu
yZp3KPC/+TwAqT7JL/71Jq1XNGeTIJX2HCoOY4HqG/LgT4ej+1jZTzjN
-----END PRIVATE KEY-----
`;

const VALID_CERT = `-----BEGIN CERTIFICATE-----
MIIBWTCB/6ADAgECAhRNSIw/t+8G9UTb6jL2VmMYKXAsMzAKBggqhkjOPQQDAjAW
MRQwEgYDVQQDDAtleGFtcGxlLmNvbTAgFw0yMDAxMDEwMDAwMDBaGA8yMTIwMDEw
MTAwMDAwMFowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIBBggq
hkjOPQMBBwNCAATOUD6T/pLtkYO77QyGjBRWdER9Uy59P1HgtKc90/sfhYvI4Bol
P+eLWqPzTxhQ21+KGSdFHbLJWQMUszciNbg2oykwJzAlBgNVHREEHjAcggtleGFt
cGxlLmNvbYINKi5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNJADBGAiEA1LIoWmn3
tOdR1mlZpEAjR206/pjDYtCfPExC0d/g7kMCIQCKVsbWJvn0OHsC4Jxbdn8f8KAt
EPLBg7sZkiqR2hu2RQ==
-----END CERTIFICATE-----
`;

const EXPIRED_CERT = `-----BEGIN CERTIFICATE-----
MIIBVjCB/aADAgECAhQnCdPa7XjnzC/+lRKmmvLYugx9SjAKBggqhkjOPQQDAjAW
MRQwEgYDVQQDDAtleGFtcGxlLmNvbTAeFw0yMDAxMDEwMDAwMDBaFw0yMTAxMDEw
MDAwMDBaMBYxFDASBgNVBAMMC2V4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZI
zj0DAQcDQgAEzlA+k/6S7ZGDu+0MhowUVnREfVMufT9R4LSnPdP7H4WLyOAaJT/n
i1qj808YUNtfihknRR2yyVkDFLM3IjW4NqMpMCcwJQYDVR0RBB4wHIILZXhhbXBs
ZS5jb22CDSouZXhhbXBsZS5jb20wCgYIKoZIzj0EAwIDSAAwRQIhAOQllJ4l6SZH
G6780VG6CRSINqiQrn1lE9PtpxEH1yI8AiA01PzcSUCHTlxoWC/4v1nK2a9XC4W7
NaX8NRpNaf/RnA==
-----END CERTIFICATE-----
`;

const FUTURE_CERT = `-----BEGIN CERTIFICATE-----
MIIBWzCCAQGgAwIBAgIUZ+EIcqLzUqr9OYcr9JrvveGv23kwCgYIKoZIzj0EAwIw
FjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wIhgPMjEyMDAxMDEwMDAwMDBaGA8yMTIx
MDEwMTAwMDAwMFowFjEUMBIGA1UEAwwLZXhhbXBsZS5jb20wWTATBgcqhkjOPQIB
BggqhkjOPQMBBwNCAATOUD6T/pLtkYO77QyGjBRWdER9Uy59P1HgtKc90/sfhYvI
4BolP+eLWqPzTxhQ21+KGSdFHbLJWQMUszciNbg2oykwJzAlBgNVHREEHjAcggtl
eGFtcGxlLmNvbYINKi5leGFtcGxlLmNvbTAKBggqhkjOPQQDAgNIADBFAiBgcFXR
gtF6hrUta32H+VLEmXh2Eg7SJzN3Iaa4vqMApwIhAPYt7Fp/sVEaezaORPtdOGDL
yIpr9gPQWjMC0HeP9qAI
-----END CERTIFICATE-----
`;
