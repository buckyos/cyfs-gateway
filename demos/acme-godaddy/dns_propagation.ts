export interface DnsPropagationOptions {
  zone: string;
  timeoutMs: number;
  intervalMs: number;
  delayMs?: number;
  log?: (message: string) => void;
}

interface AuthoritativeServer {
  name: string;
  address: string;
}

interface PropagationRuntime {
  now: () => number;
  sleep: (milliseconds: number) => Promise<void>;
  resolveServers: typeof resolveAuthoritativeServers;
  hasTxt: typeof hasTxtValue;
}

/**
 * Wait until every authoritative nameserver can return the new TXT value.
 * Querying authoritative servers avoids a false negative caused by a recursive
 * resolver's cached NXDOMAIN response.
 */
export async function waitForAuthoritativeTxt(
  fqdn: string,
  expectedValue: string,
  options: DnsPropagationOptions,
  runtime: Partial<PropagationRuntime> = {},
): Promise<void> {
  const delayMs = options.delayMs ?? 0;
  if (
    !Number.isFinite(options.timeoutMs) || options.timeoutMs <= 0 ||
    !Number.isFinite(options.intervalMs) || options.intervalMs <= 0 ||
    !Number.isFinite(delayMs) || delayMs < 0 || delayMs >= options.timeoutMs
  ) {
    throw new Error(
      "DNS timeout and interval must be positive; delay must be nonnegative and less than timeout",
    );
  }
  const now = runtime.now ?? Date.now;
  const sleep = runtime.sleep ?? delay;
  const hasTxt = runtime.hasTxt ?? hasTxtValue;
  const deadline = now() + options.timeoutMs;
  const servers = await (runtime.resolveServers ?? resolveAuthoritativeServers)(options.zone);
  options.log?.(
    `authoritative DNS: ${
      servers.map((server) => `${server.name} (${server.address})`).join(", ")
    }`,
  );

  let lastPending = servers.map((server) => server.name);
  let visibleSince: number | undefined;

  while (now() <= deadline) {
    const checks = await Promise.all(
      servers.map(async (server) => ({
        server,
        visible: await hasTxt(fqdn, expectedValue, server.address),
      })),
    );
    lastPending = checks.filter((check) => !check.visible).map((check) => check.server.name);
    const checkedAt = now();
    if (checkedAt > deadline) break;
    if (lastPending.length === 0) {
      if (visibleSince === undefined) {
        visibleSince = checkedAt;
        options.log?.(`TXT ${fqdn} is visible on all authoritative nameservers`);
        if (delayMs > 0) {
          options.log?.(`holding TXT ${fqdn} for ${delayMs / 1000}s before ACME validation`);
        }
      }
      if (checkedAt - visibleSince >= delayMs) return;
    } else {
      visibleSince = undefined;
      options.log?.(`waiting for TXT ${fqdn}; not visible on: ${lastPending.join(", ")}`);
    }

    const remaining = deadline - checkedAt;
    if (remaining <= 0) {
      break;
    }
    const remainingDelay = visibleSince === undefined
      ? options.intervalMs
      : delayMs - (checkedAt - visibleSince);
    await sleep(Math.min(options.intervalMs, remaining, remainingDelay));
  }

  throw new Error(
    lastPending.length > 0
      ? `DNS propagation timed out for ${fqdn}; TXT value was not visible on: ${
        lastPending.join(", ")
      }`
      : `DNS propagation timed out for ${fqdn}; the ${
        delayMs / 1000
      }s propagation delay did not complete`,
  );
}

async function resolveAuthoritativeServers(zone: string): Promise<AuthoritativeServer[]> {
  const names = await Deno.resolveDns(zone, "NS");
  if (names.length === 0) {
    throw new Error(`no authoritative nameservers found for ${zone}`);
  }

  const resolved = await Promise.all(names.map(async (name) => {
    const normalizedName = name.replace(/\.$/, "");
    const ipv4 = await safeResolve(normalizedName, "A");
    if (ipv4.length > 0) {
      return { name: normalizedName, address: ipv4[0] };
    }

    const ipv6 = await safeResolve(normalizedName, "AAAA");
    if (ipv6.length > 0) {
      return { name: normalizedName, address: ipv6[0] };
    }
    return undefined;
  }));

  const servers = resolved.filter((server): server is AuthoritativeServer => server !== undefined);
  if (servers.length !== names.length) {
    const resolvedNames = new Set(servers.map((server) => server.name));
    const missing = names.map((name) => name.replace(/\.$/, ""))
      .filter((name) => !resolvedNames.has(name));
    throw new Error(`could not resolve authoritative nameserver addresses: ${missing.join(", ")}`);
  }
  return servers;
}

async function safeResolve(name: string, type: "A" | "AAAA"): Promise<string[]> {
  try {
    return await Deno.resolveDns(name, type);
  } catch {
    return [];
  }
}

async function hasTxtValue(
  fqdn: string,
  expectedValue: string,
  nameServer: string,
): Promise<boolean> {
  try {
    const records = await Deno.resolveDns(fqdn, "TXT", {
      nameServer: { ipAddr: nameServer, port: 53 },
    });
    return records.some((chunks) => chunks.join("") === expectedValue);
  } catch {
    return false;
  }
}

function delay(milliseconds: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}
