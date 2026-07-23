export interface DnsPropagationOptions {
  zone: string;
  timeoutMs: number;
  intervalMs: number;
  log?: (message: string) => void;
}

interface AuthoritativeServer {
  name: string;
  address: string;
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
): Promise<void> {
  const servers = await resolveAuthoritativeServers(options.zone);
  options.log?.(
    `authoritative DNS: ${
      servers.map((server) => `${server.name} (${server.address})`).join(", ")
    }`,
  );

  const deadline = Date.now() + options.timeoutMs;
  let lastPending = servers.map((server) => server.name);

  while (Date.now() <= deadline) {
    const checks = await Promise.all(
      servers.map(async (server) => ({
        server,
        visible: await hasTxtValue(fqdn, expectedValue, server.address),
      })),
    );
    lastPending = checks.filter((check) => !check.visible).map((check) => check.server.name);
    if (lastPending.length === 0) {
      options.log?.(`TXT ${fqdn} is visible on all authoritative nameservers`);
      return;
    }

    options.log?.(`waiting for TXT ${fqdn}; not visible on: ${lastPending.join(", ")}`);
    const remaining = deadline - Date.now();
    if (remaining <= 0) {
      break;
    }
    await delay(Math.min(options.intervalMs, remaining));
  }

  throw new Error(
    `DNS propagation timed out for ${fqdn}; TXT value was not visible on: ${
      lastPending.join(", ")
    }`,
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
