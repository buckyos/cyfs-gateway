import * as path from "node:path";
import acme from "acme-client";

import {
  acmeClientDns01TxtValue,
  type Dns01Provider,
  type Dns01RecordHandle,
  dns01RecordName,
} from "./dns_provider.ts";

const STATE_FILE = "state.json";
const FULLCHAIN_FILE = "fullchain.pem";

interface CertificateState {
  schemaVersion: 1;
  directoryUrl: string;
  domains: string[];
  issuedAt: string;
  notAfter: string;
  privateKeySha256: string;
  fullchainSha256: string;
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
  outputDir: string;
  provider: Dns01Provider;
  waitForPropagation: (fqdn: string, value: string) => Promise<void>;
  log?: (message: string) => void;
}

export interface ObtainCertificateResult {
  notAfter: Date;
  cleanupWarnings: string[];
}

export async function inspectExistingCertificate(
  outputDir: string,
  domains: string[],
  directoryUrl: string,
  renewBeforeDays: number,
): Promise<RenewalDecision> {
  const stateText = await readTextIfExists(path.join(outputDir, STATE_FILE));
  const certificate = await readTextIfExists(path.join(outputDir, FULLCHAIN_FILE));
  const privateKey = await readTextIfExists(path.join(outputDir, "privkey.pem"));
  if (!stateText || !certificate || !privateKey) {
    return { renew: true, reason: "certificate, private key, or state file does not exist" };
  }

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

  if (state.directoryUrl !== directoryUrl) {
    return { renew: true, reason: "ACME directory changed" };
  }

  const expectedDomains = sortedUnique(domains);
  if (!sameStrings(sortedUnique(state.domains), expectedDomains)) {
    return { renew: true, reason: "requested domain set changed" };
  }
  if (
    state.fullchainSha256 !== await sha256(certificate) ||
    state.privateKeySha256 !== await sha256(privateKey)
  ) {
    return { renew: true, reason: "certificate files do not match the last completed write" };
  }

  try {
    const info = acme.crypto.readCertificateInfo(certificate);
    const certificateDomains = sortedUnique([
      info.domains.commonName,
      ...info.domains.altNames,
    ].filter(Boolean));
    if (!sameStrings(certificateDomains, expectedDomains)) {
      return { renew: true, reason: "certificate SANs do not match the requested domains" };
    }

    const remainingMs = info.notAfter.getTime() - Date.now();
    const renewBeforeMs = renewBeforeDays * 24 * 60 * 60 * 1000;
    if (remainingMs <= renewBeforeMs) {
      return {
        renew: true,
        reason: `certificate expires within ${renewBeforeDays} days`,
        notAfter: info.notAfter,
      };
    }
    return { renew: false, reason: "certificate is still valid", notAfter: info.notAfter };
  } catch {
    return { renew: true, reason: "existing certificate cannot be parsed" };
  }
}

export async function obtainCertificate(
  options: ObtainCertificateOptions,
): Promise<ObtainCertificateResult> {
  await Deno.mkdir(options.outputDir, { recursive: true, mode: 0o700 });

  const accountKeyPath = path.join(options.outputDir, "account.key.pem");
  let accountKey = await readTextIfExists(accountKeyPath);
  if (!accountKey) {
    options.log?.("generating a new ACME account key");
    accountKey = (await acme.crypto.createPrivateEcdsaKey("P-256")).toString();
    await atomicWriteText(accountKeyPath, accountKey, 0o600);
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

  const chain = acme.crypto.splitPemChain(certificate);
  if (chain.length === 0) {
    throw new Error("ACME server returned an empty certificate chain");
  }
  const certificateInfo = acme.crypto.readCertificateInfo(chain[0]);
  const privateKeyText = certificateKey.toString();
  const fullchainText = ensureTrailingNewline(certificate);
  const state: CertificateState = {
    schemaVersion: 1,
    directoryUrl: options.directoryUrl,
    domains: sortedUnique(options.domains),
    issuedAt: new Date().toISOString(),
    notAfter: certificateInfo.notAfter.toISOString(),
    privateKeySha256: await sha256(privateKeyText),
    fullchainSha256: await sha256(fullchainText),
  };

  // Write state last. If the process stops while replacing one of the four
  // artifacts, the old state hashes force a fresh issuance on the next run
  // instead of accepting a mismatched certificate/private-key pair.
  await Promise.all([
    atomicWriteText(path.join(options.outputDir, "privkey.pem"), privateKeyText, 0o600),
    atomicWriteText(
      path.join(options.outputDir, "cert.pem"),
      ensureTrailingNewline(chain[0]),
      0o644,
    ),
    atomicWriteText(
      path.join(options.outputDir, "chain.pem"),
      ensureTrailingNewline(chain.slice(1).join("\n")),
      0o644,
    ),
    atomicWriteText(
      path.join(options.outputDir, FULLCHAIN_FILE),
      fullchainText,
      0o644,
    ),
  ]);
  await atomicWriteText(
    path.join(options.outputDir, STATE_FILE),
    `${JSON.stringify(state, null, 2)}\n`,
    0o600,
  );

  return { notAfter: certificateInfo.notAfter, cleanupWarnings };
}

async function atomicWriteText(filePath: string, contents: string, mode: number): Promise<void> {
  const temporaryPath = path.join(
    path.dirname(filePath),
    `.${path.basename(filePath)}.${crypto.randomUUID()}.tmp`,
  );
  try {
    await Deno.writeTextFile(temporaryPath, contents, { mode });
    await Deno.rename(temporaryPath, filePath);
    await setModeIfSupported(filePath, mode);
  } catch (error) {
    try {
      await Deno.remove(temporaryPath);
    } catch {
      // Preserve the original write/rename error; the random .tmp name is safe
      // to remove manually if filesystem cleanup also failed.
    }
    throw error;
  }
}

async function setModeIfSupported(filePath: string, mode: number): Promise<void> {
  try {
    await Deno.chmod(filePath, mode);
  } catch (error) {
    if (!(error instanceof Deno.errors.NotSupported)) {
      throw error;
    }
  }
}

async function readTextIfExists(filePath: string): Promise<string | undefined> {
  try {
    return await Deno.readTextFile(filePath);
  } catch (error) {
    if (error instanceof Deno.errors.NotFound) {
      return undefined;
    }
    throw error;
  }
}

function ensureTrailingNewline(value: string): string {
  if (!value) {
    return value;
  }
  return value.endsWith("\n") ? value : `${value}\n`;
}

function sortedUnique(values: string[]): string[] {
  return [...new Set(values)].sort();
}

function sameStrings(left: string[], right: string[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function isCertificateState(value: unknown): value is CertificateState {
  if (!value || typeof value !== "object") {
    return false;
  }
  const state = value as Partial<CertificateState>;
  return state.schemaVersion === 1 &&
    typeof state.directoryUrl === "string" &&
    Array.isArray(state.domains) &&
    state.domains.every((domain) => typeof domain === "string") &&
    typeof state.issuedAt === "string" &&
    typeof state.notAfter === "string" &&
    typeof state.privateKeySha256 === "string" &&
    typeof state.fullchainSha256 === "string";
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

async function sha256(value: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), (byte) => byte.toString(16).padStart(2, "0")).join("");
}
