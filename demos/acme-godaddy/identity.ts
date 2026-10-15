import * as path from "node:path";
import { createHash } from "node:crypto";

export interface IdentityStorage {
  publicRoot: string;
  securityRoot: string;
  stateRoot: string;
}

export interface IdentityStorageOptions {
  buckyosRoot?: string;
  identityRoot?: string;
  securityRoot?: string;
  stateRoot?: string;
}

const PRODUCTION_DIRECTORY = "https://acme-v02.api.letsencrypt.org/directory";

export function resolveIdentityStorage(
  options: IdentityStorageOptions,
  directoryUrl: string,
): IdentityStorage {
  const root = options.buckyosRoot ?? Deno.env.get("BUCKYOS_ROOT") ?? "/opt/buckyos";
  const stateRoot = path.resolve(
    options.stateRoot ?? path.join(root, "var", "identity", "state", "acme", "acme-godaddy"),
  );
  // Untrusted/test authorities must never replace identities consumed by live TLS stacks.
  if (directoryUrl !== PRODUCTION_DIRECTORY) {
    const isolated = path.join(stateRoot, "authorities", sha256(directoryUrl));
    return checkedStorage({
      publicRoot: path.join(isolated, "identity"),
      securityRoot: path.join(isolated, "security"),
      stateRoot: path.join(isolated, "state"),
    });
  }
  return checkedStorage({
    publicRoot: path.resolve(
      options.identityRoot ?? Deno.env.get("BUCKYOS_IDENTITY_ROOT") ??
        path.join(root, "local", "identity"),
    ),
    securityRoot: path.resolve(
      options.securityRoot ?? Deno.env.get("BUCKYOS_SECURITY_ROOT") ?? path.join(root, "security"),
    ),
    stateRoot,
  });
}

function checkedStorage(storage: IdentityStorage): IdentityStorage {
  validateIdentityStorage(storage);
  return storage;
}

export function identityPaths(storage: IdentityStorage, domain: string) {
  validateIdentityStorage(storage);
  // CLI inputs are normalized DNS names. Reject paths/DIDs here rather than letting
  // an identity escape either root; this demo only issues DNS identities.
  const hostname = domain.replace(/^\*\./, "");
  if (
    domain !== domain.toLowerCase() || hostname.length > 253 ||
    !hostname.includes(".") ||
    !hostname.split(".").every((label) => /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label))
  ) {
    throw new Error(`invalid DNS identity: ${domain}`);
  }
  const dirName = domain.replace(/^\*\./, "_.");
  const publicDir = path.join(storage.publicRoot, dirName);
  const securityDir = path.join(storage.securityRoot, dirName);
  return {
    dirName,
    cert: path.join(publicDir, "server.cert.pem"),
    chain: path.join(publicDir, "server.chain.pem"),
    fullchain: path.join(publicDir, "server.fullchain.pem"),
    metadata: path.join(publicDir, "server.meta.json"),
    privateKey: path.join(securityDir, "server.private.pem"),
    keyref: path.join(securityDir, "server.keyref.json"),
  };
}

export function validateIdentityStorage(storage: IdentityStorage): void {
  for (const secretRoot of [storage.securityRoot, storage.stateRoot]) {
    const relative = path.relative(path.resolve(storage.publicRoot), path.resolve(secretRoot));
    if (
      relative === "" || (!relative.startsWith(`..${path.sep}`) && relative !== ".." &&
        !path.isAbsolute(relative))
    ) {
      throw new Error("security and ACME state roots must be outside the public identity root");
    }
  }
}

export function orderStateDirectory(
  storage: IdentityStorage,
  domains: string[],
  directoryUrl: string,
): string {
  return path.join(
    storage.stateRoot,
    sha256(directoryUrl),
    sha256(JSON.stringify([...new Set(domains)].sort())),
  );
}

export function sha256(value: string | Uint8Array): string {
  return createHash("sha256").update(value).digest("hex");
}
