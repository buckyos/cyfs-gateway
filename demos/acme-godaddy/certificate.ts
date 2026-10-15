import * as path from "node:path";
import { createPrivateKey, X509Certificate } from "node:crypto";
import acme from "acme-client";

import {
  acmeClientDns01TxtValue,
  type Dns01Provider,
  type Dns01RecordHandle,
  dns01RecordName,
} from "./dns_provider.ts";
import {
  identityPaths,
  type IdentityStorage,
  orderStateDirectory,
  sha256,
  validateIdentityStorage,
} from "./identity.ts";

const STATE_FILE = "state.json";

interface CertificateState {
  schemaVersion: 2;
  directoryUrl: string;
  domains: string[];
  issuedAt: string;
  notAfter: string;
  artifacts: Record<string, string>;
}

export interface RenewalDecision {
  renew: boolean;
  reason: string;
  notAfter?: Date;
}

export interface ObtainCertificateOptions {
  directoryUrl: string;
  domains: string[];
  email: string;
  storage: IdentityStorage;
  renewBeforeDays: number;
  provider: Dns01Provider;
  waitForPropagation: (fqdn: string, value: string) => Promise<void>;
  log?: (message: string) => void;
}

export interface ObtainCertificateResult {
  notAfter: Date;
  cleanupWarnings: string[];
}

export async function inspectExistingCertificate(
  storage: IdentityStorage,
  domains: string[],
  directoryUrl: string,
  renewBeforeDays: number,
): Promise<RenewalDecision> {
  const stateDir = await orderStateDirectory(storage, domains, directoryUrl);
  const stateText = await readTextIfExists(path.join(stateDir, STATE_FILE));
  if (!stateText) return { renew: true, reason: "certificate state file does not exist" };
  let state: CertificateState;
  try {
    const parsed = JSON.parse(stateText) as unknown;
    if (!isCertificateState(parsed)) {
      return { renew: true, reason: "state file has an unsupported schema" };
    }
    state = parsed;
  } catch {
    return { renew: true, reason: "state file is invalid" };
  }
  const expectedDomains = sortedUnique(domains);
  if (state.directoryUrl !== directoryUrl || !sameStrings(state.domains, expectedDomains)) {
    return { renew: true, reason: "ACME directory or requested domains changed" };
  }
  let notAfter: Date | undefined;
  for (const domain of expectedDomains) {
    const files = identityPaths(storage, domain);
    const contents: Record<string, string> = {};
    for (
      const file of [files.cert, files.chain, files.fullchain, files.metadata, files.privateKey]
    ) {
      const text = await readTextIfExists(file);
      if (text === undefined || state.artifacts[file] !== sha256(text)) {
        return { renew: true, reason: `identity files missing or changed for ${domain}` };
      }
      contents[file] = text;
    }
    try {
      const validated = validateCertificate(
        contents[files.fullchain],
        contents[files.privateKey],
        expectedDomains,
      );
      notAfter = validated.notAfter;
      if (notAfter.toISOString() !== state.notAfter) {
        return { renew: true, reason: "certificate expiry does not match state" };
      }
      if (notAfter.getTime() - Date.now() <= renewBeforeDays * 86_400_000) {
        return {
          renew: true,
          reason: `certificate expires within ${renewBeforeDays} days`,
          notAfter,
        };
      }
    } catch (error) {
      return { renew: true, reason: `invalid identity certificate: ${errorMessage(error)}` };
    }
  }
  return { renew: false, reason: "all identity certificates are still valid", notAfter };
}

export async function obtainCertificate(
  options: ObtainCertificateOptions,
): Promise<ObtainCertificateResult> {
  validateIdentityStorage(options.storage);
  const stateDir = await orderStateDirectory(
    options.storage,
    options.domains,
    options.directoryUrl,
  );
  await Deno.mkdir(stateDir, { recursive: true, mode: 0o700 });
  const accountKeyPath = path.join(stateDir, "account.key.pem");
  let accountKey = await readTextIfExists(accountKeyPath);
  if (!accountKey) {
    options.log?.("generating a new ACME account key");
    accountKey = (await acme.crypto.createPrivateEcdsaKey("P-256")).toString();
    await writeStagedFiles([{ filePath: accountKeyPath, contents: accountKey, mode: 0o600 }]);
  }

  const certificateKey = await acme.crypto.createPrivateEcdsaKey("P-256");
  const [, csr] = await acme.crypto.createCsr({
    commonName: options.domains[0],
    altNames: [...options.domains],
  }, certificateKey);

  const client = new acme.Client({
    directoryUrl: options.directoryUrl,
    accountKey,
  });
  const pendingRecords = new Map<string, Dns01RecordHandle>();
  const cleanupWarnings: string[] = [];
  let certificate: string;
  let issuanceCompleted = false;

  try {
    certificate = await client.auto({
      csr,
      email: options.email,
      termsOfServiceAgreed: true,
      challengePriority: ["dns-01"],
      // We perform a stronger authoritative-server check in challengeCreateFn.
      skipChallengeVerification: true,
      challengeCreateFn: async (authorization, challenge, keyAuthorization) => {
        if (challenge.type !== "dns-01") {
          throw new Error(`ACME client selected unsupported challenge ${challenge.type}`);
        }

        const fqdn = dns01RecordName(authorization.identifier.value);
        // acme-client already returns the RFC 8555 DNS digest here. Do not hash
        // this callback value a second time.
        const value = acmeClientDns01TxtValue(keyAuthorization);
        options.log?.(`creating TXT ${fqdn} = ${value}`);
        const handle = await options.provider.present({ fqdn, value });
        pendingRecords.set(challenge.url, handle);
        await options.waitForPropagation(fqdn, value);
      },
      challengeRemoveFn: async (_authorization, challenge) => {
        const handle = pendingRecords.get(challenge.url);
        if (!handle) {
          return;
        }
        options.log?.(`removing TXT ${handle.fqdn} (${handle.id})`);
        await options.provider.cleanup(handle);
        pendingRecords.delete(challenge.url);
      },
    });
    issuanceCompleted = true;
  } finally {
    // acme-client intentionally suppresses errors from challengeRemoveFn. Make
    // one final cleanup attempt and surface any orphaned record IDs to callers.
    for (const [challengeUrl, handle] of pendingRecords) {
      try {
        await options.provider.cleanup(handle);
        pendingRecords.delete(challengeUrl);
      } catch (error) {
        const warning = `could not remove TXT ${handle.fqdn} (recordId ${handle.id}): ${
          errorMessage(error)
        }`;
        cleanupWarnings.push(warning);
        if (!issuanceCompleted) {
          options.log?.(`WARNING: ${warning}`);
        }
      }
    }
  }

  const notAfter = await installCertificate(
    options.storage,
    options.domains,
    options.directoryUrl,
    options.renewBeforeDays,
    certificate,
    certificateKey.toString(),
  );
  return { notAfter, cleanupWarnings };
}

/** Validate everything before replacing any active identity material. */
export async function installCertificate(
  storage: IdentityStorage,
  domains: string[],
  directoryUrl: string,
  renewBeforeDays: number,
  certificate: string,
  privateKey: string,
): Promise<Date> {
  const expectedDomains = sortedUnique(domains);
  if (expectedDomains.length === 0) throw new Error("at least one DNS identity is required");
  const { leaf, chain, notBefore, notAfter } = validateCertificate(
    certificate,
    privateKey,
    expectedDomains,
  );
  const stateDir = await orderStateDirectory(storage, expectedDomains, directoryUrl);
  const issuedAt = new Date().toISOString();
  const fullchain = chain.map(ensureTrailingNewline).join("");
  const cert = ensureTrailingNewline(chain[0]);
  const intermediates = chain.slice(1).map(ensureTrailingNewline).join("");
  const certFingerprint = `sha256:${sha256(leaf.raw)}`;
  const publicKeyFingerprint = `sha256:${
    sha256(
      leaf.publicKey.export({ type: "spki", format: "der" }),
    )
  }`;
  const writes: PendingWrite[] = [];
  for (const domain of expectedDomains) {
    const files = identityPaths(storage, domain);
    const metadata = {
      schema: "buckyos.identity.x509.metadata.v1",
      did: `did:web:${files.dirName}`,
      raw_host_uri: files.dirName,
      dir_name: files.dirName,
      usage: "server",
      match: domain.startsWith("*.")
        ? { type: "wildcard", host_pattern: domain }
        : { type: "exact", host: domain },
      certificate: {
        serial_number: leaf.serialNumber,
        issuer: leaf.issuer,
        subject: leaf.subject,
        not_before: notBefore.toISOString(),
        not_after: notAfter.toISOString(),
        fingerprint_sha256: certFingerprint,
        public_key_fingerprint: publicKeyFingerprint,
      },
      san: { dns: expectedDomains, uri: [] },
      paths: {
        cert: "server.cert.pem",
        chain: "server.chain.pem",
        fullchain: "server.fullchain.pem",
        ca: null,
        key_ref: null,
      },
      did_binding: domain.startsWith("*.") ? null : {
        type: "did-web-domain",
        did: `did:web:${domain}`,
        web_origin: `https://${domain}`,
        did_document_url: `https://${domain}/.well-known/did.json`,
      },
      renewal: {
        manager: "acme",
        renew_before: `PT${renewBeforeDays * 86400}S`,
        last_renewed_at: issuedAt,
        state_ref: stateDir,
      },
      updated_at: issuedAt,
      generation: `${issuedAt}-${certFingerprint}`,
    };
    writes.push(
      { filePath: files.cert, contents: cert, mode: 0o644 },
      { filePath: files.chain, contents: intermediates, mode: 0o644 },
      { filePath: files.fullchain, contents: fullchain, mode: 0o644 },
      { filePath: files.metadata, contents: `${JSON.stringify(metadata, null, 2)}\n`, mode: 0o644 },
      { filePath: files.privateKey, contents: privateKey, mode: 0o600 },
    );
  }
  const state: CertificateState = {
    schemaVersion: 2,
    directoryUrl,
    domains: expectedDomains,
    issuedAt,
    notAfter: notAfter.toISOString(),
    artifacts: Object.fromEntries(writes.map((write) => [write.filePath, sha256(write.contents)])),
  };
  // Stage the entire generation before the first rename. Commit state last so an
  // interrupted multi-file install is detected by the next renewal inspection.
  writes.push({
    filePath: path.join(stateDir, STATE_FILE),
    contents: `${JSON.stringify(state, null, 2)}\n`,
    mode: 0o600,
  });
  await writeStagedFiles(writes);
  for (const domain of expectedDomains) {
    try {
      await Deno.remove(identityPaths(storage, domain).keyref);
    } catch (error) {
      if (!(error instanceof Deno.errors.NotFound)) throw error;
    }
  }
  return notAfter;
}

function validateCertificate(certificate: string, privateKey: string, domains: string[]) {
  const chain = acme.crypto.splitPemChain(certificate);
  if (chain.length === 0) throw new Error("ACME server returned an empty certificate chain");
  const leaf = new X509Certificate(chain[0]);
  // Parse every intermediate too; none of the active files should contain malformed PEM.
  for (const intermediate of chain.slice(1)) new X509Certificate(intermediate);
  const notBefore = new Date(leaf.validFrom);
  const notAfter = new Date(leaf.validTo);
  const now = Date.now();
  if (
    !Number.isFinite(notBefore.getTime()) || !Number.isFinite(notAfter.getTime()) ||
    now < notBefore.getTime() || now >= notAfter.getTime()
  ) {
    throw new Error("certificate is not currently valid");
  }
  const info = acme.crypto.readCertificateInfo(chain[0]);
  // SAN is mandatory; a commonName alone cannot authorize an identity directory.
  if (!sameStrings(sortedUnique(info.domains.altNames), domains)) {
    throw new Error("certificate DNS SANs do not match the requested domains");
  }
  if (!leaf.checkPrivateKey(createPrivateKey(privateKey))) {
    throw new Error("certificate does not match its private key");
  }
  return { leaf, chain, notBefore, notAfter };
}

interface PendingWrite {
  filePath: string;
  contents: string;
  mode: number;
}

async function writeStagedFiles(writes: PendingWrite[]): Promise<void> {
  const staged: { temporaryPath: string; filePath: string }[] = [];
  try {
    for (const { filePath, contents, mode } of writes) {
      await Deno.mkdir(path.dirname(filePath), {
        recursive: true,
        mode: mode === 0o600 ? 0o700 : 0o755,
      });
      const temporaryPath = path.join(
        path.dirname(filePath),
        `.${path.basename(filePath)}.${crypto.randomUUID()}.tmp`,
      );
      staged.push({ temporaryPath, filePath });
      const file = await Deno.open(temporaryPath, { write: true, createNew: true, mode });
      try {
        const bytes = new TextEncoder().encode(contents);
        let written = 0;
        while (written < bytes.length) written += await file.write(bytes.subarray(written));
        await file.sync();
      } finally {
        file.close();
      }
      await setModeIfSupported(temporaryPath, mode);
    }
    for (const { temporaryPath, filePath } of staged) await Deno.rename(temporaryPath, filePath);
  } finally {
    for (const { temporaryPath } of staged) {
      try {
        await Deno.remove(temporaryPath);
      } catch (error) {
        if (!(error instanceof Deno.errors.NotFound)) {
          console.warn(
            `could not remove staged identity file ${temporaryPath}: ${errorMessage(error)}`,
          );
        }
      }
    }
  }
}

async function setModeIfSupported(filePath: string, mode: number): Promise<void> {
  try {
    await Deno.chmod(filePath, mode);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotSupported)) throw error;
  }
}

async function readTextIfExists(filePath: string): Promise<string | undefined> {
  try {
    return await Deno.readTextFile(filePath);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) return undefined;
    throw error;
  }
}

function ensureTrailingNewline(value: string): string {
  return !value || value.endsWith("\n") ? value : `${value}\n`;
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isCertificateState(value: unknown): value is CertificateState {
  if (!value || typeof value !== "object") return false;
  const state = value as Partial<CertificateState>;
  return state.schemaVersion === 2 && typeof state.directoryUrl === "string" &&
    Array.isArray(state.domains) && state.domains.length > 0 &&
    state.domains.every((domain) => typeof domain === "string") &&
    typeof state.issuedAt === "string" && typeof state.notAfter === "string" &&
    !!state.artifacts && typeof state.artifacts === "object" &&
    Object.values(state.artifacts).every((digest) => typeof digest === "string");
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
