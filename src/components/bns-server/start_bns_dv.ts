const APP_ID = "bns_dv";
const DATABASE_ROOT = "/var/lib/bns-backend";
const CLUSTER_CONFIG_PATH = "/etc/cluster_config/cluster_config.json";
const SECURITY_CONFIG_PATH = "/etc/security/security_config.json";
const SETTINGS_KEYS = new Set([
  "contract",
  "chain_id",
  "db",
  "listen",
  "start_block",
  "confirmations",
  "interval_ms",
  "max_block_span",
]);
const REQUIRED_SETTINGS_KEYS = [
  "contract",
  "chain_id",
  "db",
  "listen",
  "start_block",
  "confirmations",
  "interval_ms",
] as const;

type JsonRecord = Record<string, unknown>;

export interface BnsDvConfig {
  readonly rpcUrl: string;
  readonly contract: string;
  readonly chainId: number;
  readonly db: string;
  readonly listen: string;
  readonly startBlock: number;
  readonly confirmations: number;
  readonly intervalMs: number;
  readonly maxBlockSpan: number;
}

function invalid(message: string): never {
  throw new Error(`invalid bns_dv configuration: ${message}`);
}

function record(value: unknown, path: string): JsonRecord {
  if (
    value === null || typeof value !== "object" || Array.isArray(value) ||
    (Object.getPrototypeOf(value) !== Object.prototype &&
      Object.getPrototypeOf(value) !== null)
  ) {
    invalid(`${path} must be an object`);
  }
  return value as JsonRecord;
}

function nonEmptyString(value: unknown, path: string): string {
  if (
    typeof value !== "string" || value.length === 0 ||
    value.trim() !== value || value.includes("\0") ||
    value.includes("\n") || value.includes("\r")
  ) {
    invalid(`${path} must be a non-empty single-line string`);
  }
  return value;
}

function integer(
  value: unknown,
  path: string,
  minimum: number,
): number {
  if (!Number.isSafeInteger(value) || (value as number) < minimum) {
    invalid(
      `${path} must be a safe integer greater than or equal to ${minimum}`,
    );
  }
  return value as number;
}

function contractAddress(value: unknown): string {
  const address = nonEmptyString(value, `apps.${APP_ID}.settings.contract`);
  if (!/^0x[0-9a-fA-F]{40}$/.test(address)) {
    invalid(`apps.${APP_ID}.settings.contract must be a 20-byte hex address`);
  }
  return address;
}

function databasePath(value: unknown): string {
  const path = nonEmptyString(value, `apps.${APP_ID}.settings.db`);
  const prefix = `${DATABASE_ROOT}/`;
  if (!path.startsWith(prefix)) {
    invalid(`apps.${APP_ID}.settings.db must be below ${DATABASE_ROOT}`);
  }
  const segments = path.slice(prefix.length).split("/");
  if (
    segments.some((segment) =>
      segment.length === 0 || segment === "." || segment === ".."
    )
  ) {
    invalid(`apps.${APP_ID}.settings.db must be a normalized file path`);
  }
  return path;
}

function listenAddress(value: unknown): string {
  const listen = nonEmptyString(value, `apps.${APP_ID}.settings.listen`);
  const match = /^127\.0\.0\.1:([0-9]{1,5})$/.exec(listen);
  const port = match === null ? 0 : Number(match[1]);
  if (port < 1 || port > 65535) {
    invalid(
      `apps.${APP_ID}.settings.listen must be a valid IPv4 loopback address`,
    );
  }
  return listen;
}

function chainRpcUrl(value: unknown): string {
  const rpcUrl = nonEmptyString(value, "security.chain_rpc_url");
  let parsed: URL;
  try {
    parsed = new URL(rpcUrl);
  } catch {
    invalid("security.chain_rpc_url must be an absolute URL");
  }
  if (
    (parsed.protocol !== "http:" && parsed.protocol !== "https:") ||
    parsed.hostname.length === 0
  ) {
    invalid("security.chain_rpc_url must use http or https");
  }
  return rpcUrl;
}

export function parseBnsDvConfig(
  clusterConfig: unknown,
  securityConfig: unknown,
): BnsDvConfig {
  const cluster = record(clusterConfig, "cluster config");
  const apps = record(cluster.apps, "apps");
  const app = record(apps[APP_ID], `apps.${APP_ID}`);
  const settings = record(app.settings, `apps.${APP_ID}.settings`);

  const unknownKeys = Object.keys(settings)
    .filter((key) => !SETTINGS_KEYS.has(key))
    .sort();
  if (unknownKeys.length > 0) {
    invalid(
      `apps.${APP_ID}.settings contains unknown keys: ${
        unknownKeys.join(", ")
      }`,
    );
  }
  for (const key of REQUIRED_SETTINGS_KEYS) {
    if (!Object.hasOwn(settings, key)) {
      invalid(`apps.${APP_ID}.settings.${key} is missing`);
    }
  }

  const security = record(securityConfig, "security config");
  return Object.freeze({
    rpcUrl: chainRpcUrl(security.chain_rpc_url),
    contract: contractAddress(settings.contract),
    chainId: integer(settings.chain_id, `apps.${APP_ID}.settings.chain_id`, 1),
    db: databasePath(settings.db),
    listen: listenAddress(settings.listen),
    startBlock: integer(
      settings.start_block,
      `apps.${APP_ID}.settings.start_block`,
      0,
    ),
    confirmations: integer(
      settings.confirmations,
      `apps.${APP_ID}.settings.confirmations`,
      0,
    ),
    intervalMs: integer(
      settings.interval_ms,
      `apps.${APP_ID}.settings.interval_ms`,
      1,
    ),
    maxBlockSpan: integer(
      settings.max_block_span ?? 500,
      `apps.${APP_ID}.settings.max_block_span`,
      1,
    ),
  });
}

export function buildBnsDvArgs(config: BnsDvConfig): string[] {
  return [
    "serve",
    "--rpc",
    config.rpcUrl,
    "--contract",
    config.contract,
    "--chain-id",
    String(config.chainId),
    "--db",
    config.db,
    "--listen",
    config.listen,
    "--start-block",
    String(config.startBlock),
    "--confirmations",
    String(config.confirmations),
    "--interval-ms",
    String(config.intervalMs),
    "--max-block-span",
    String(config.maxBlockSpan),
  ];
}

async function readJson(path: string, label: string): Promise<unknown> {
  let source: string;
  try {
    source = await Deno.readTextFile(path);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`cannot read ${label} at ${path}: ${detail}`);
  }

  try {
    return JSON.parse(source);
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    throw new Error(`cannot parse ${label} at ${path}: ${detail}`);
  }
}

function parentDirectory(path: string): string {
  const separator = path.lastIndexOf("/");
  if (separator <= 0) invalid(`cannot determine parent directory for ${path}`);
  return path.slice(0, separator);
}

async function run(): Promise<number> {
  const [clusterConfig, securityConfig] = await Promise.all([
    readJson(CLUSTER_CONFIG_PATH, "Cluster Config"),
    readJson(SECURITY_CONFIG_PATH, "Security Config"),
  ]);
  const config = parseBnsDvConfig(clusterConfig, securityConfig);
  await Deno.mkdir(parentDirectory(config.db), { recursive: true });

  const binary = new URL("./bns_dv", import.meta.url);
  const child = new Deno.Command(binary, {
    args: buildBnsDvArgs(config),
    stdin: "inherit",
    stdout: "inherit",
    stderr: "inherit",
  }).spawn();

  let shutdownRequested = false;
  const listeners = new Map<Deno.Signal, () => void>();
  for (const signal of ["SIGTERM", "SIGINT"] as const) {
    const listener = () => {
      if (shutdownRequested) return;
      shutdownRequested = true;
      try {
        child.kill(signal);
      } catch {
        // The child may have exited between the signal and this callback.
      }
    };
    listeners.set(signal, listener);
    Deno.addSignalListener(signal, listener);
  }

  try {
    const status = await child.status;
    if (shutdownRequested || status.success) return 0;
    return status.code === 0 ? 1 : status.code;
  } finally {
    for (const [signal, listener] of listeners) {
      Deno.removeSignalListener(signal, listener);
    }
  }
}

if (import.meta.main) {
  try {
    Deno.exit(await run());
  } catch (error) {
    const detail = error instanceof Error ? error.message : String(error);
    console.error(`start_bns_dv: ${detail}`);
    Deno.exit(1);
  }
}
