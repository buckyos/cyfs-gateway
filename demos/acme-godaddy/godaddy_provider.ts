import type { Dns01ChallengeRecord, Dns01Provider, Dns01RecordHandle } from "./dns_provider.ts";

const GODADDY_API_BASE = "https://api.godaddy.com";
const GODADDY_MIN_TTL_SECONDS = 600;
const GODADDY_REQUEST_TIMEOUT_MS = 30_000;

interface GoDaddyDnsRecord {
  recordId?: string;
  type?: string;
  name?: string;
  data?: string;
  ttl?: number;
}

interface GoDaddyErrorBody {
  code?: string;
  message?: string;
  fields?: Array<{ code?: string; message?: string; path?: string }>;
}

export interface GoDaddyProviderOptions {
  /** Personal Access Token with the `domains.dns:update` scope. */
  token: string;
  /** GoDaddy-hosted authoritative zone, for example `example.com`. */
  zone: string;
  fetch?: typeof globalThis.fetch;
}

/**
 * GoDaddy Domains v3 implementation of the generic DNS-01 provider boundary.
 *
 * It uses POST to append one TXT value and retains GoDaddy's recordId. Cleanup
 * therefore removes only this challenge value, even when an apex and wildcard
 * authorization temporarily share the same `_acme-challenge` RRset.
 */
export class GoDaddyDnsProvider implements Dns01Provider {
  readonly zone: string;
  readonly #token: string;
  readonly #fetch: typeof globalThis.fetch;

  constructor(options: GoDaddyProviderOptions) {
    const token = options.token.trim();
    if (!token) {
      throw new Error("GoDaddy PAT is empty");
    }

    this.zone = normalizeDnsName(options.zone);
    if (!this.zone) {
      throw new Error("GoDaddy zone is empty");
    }
    this.#token = token;
    this.#fetch = options.fetch ?? globalThis.fetch;
  }

  async present(record: Dns01ChallengeRecord): Promise<Dns01RecordHandle> {
    const fqdn = normalizeDnsName(record.fqdn);
    const relativeName = relativeRecordName(fqdn, this.zone);
    const url = `${GODADDY_API_BASE}/v3/domains/zones/${encodeURIComponent(this.zone)}/dns-records`;
    let response: Response;
    try {
      response = await this.#fetch(url, {
        method: "POST",
        headers: this.#headers(true),
        signal: AbortSignal.timeout(GODADDY_REQUEST_TIMEOUT_MS),
        body: JSON.stringify({
          type: "TXT",
          name: relativeName,
          data: record.value,
          ttl: GODADDY_MIN_TTL_SECONDS,
        }),
      });
    } catch (error) {
      throw new Error(
        `GoDaddy API request to create TXT ${fqdn} failed: ${
          errorMessage(error).replaceAll(this.#token, "[REDACTED]")
        }; ` +
          "the non-idempotent request may have succeeded, so inspect the zone before retrying",
      );
    }
    const body = await response.text();
    if (response.status !== 201) {
      throw apiError("create TXT record", response, body, this.#token);
    }

    const recordId = readRecordId(body, response.headers.get("location"));
    if (!recordId) {
      throw new Error(
        "GoDaddy created the TXT record but returned no recordId; inspect the zone and remove the challenge record manually",
      );
    }

    return { fqdn, value: record.value, id: recordId };
  }

  async cleanup(record: Dns01RecordHandle): Promise<void> {
    if (!record.id.trim()) {
      throw new Error("refusing to delete a GoDaddy DNS record without a recordId");
    }

    const url = `${GODADDY_API_BASE}/v3/domains/zones/${encodeURIComponent(this.zone)}` +
      `/dns-records/${encodeURIComponent(record.id)}`;
    const response = await this.#fetch(url, {
      method: "DELETE",
      headers: this.#headers(false),
      signal: AbortSignal.timeout(GODADDY_REQUEST_TIMEOUT_MS),
    });
    const body = await response.text();

    // The v3 DELETE operation itself is not idempotent. At this abstraction
    // boundary, however, an already-absent record means cleanup is complete.
    if (response.status === 204 || response.status === 404) {
      return;
    }
    throw apiError(`delete TXT record ${record.id}`, response, body, this.#token);
  }

  #headers(withJsonBody: boolean): Headers {
    const headers = new Headers({ Authorization: `Bearer ${this.#token}` });
    if (withJsonBody) {
      headers.set("Content-Type", "application/json");
    }
    return headers;
  }
}

export function relativeRecordName(fqdn: string, zone: string): string {
  const normalizedFqdn = normalizeDnsName(fqdn);
  const normalizedZone = normalizeDnsName(zone);
  if (normalizedFqdn === normalizedZone) {
    return "@";
  }

  const suffix = `.${normalizedZone}`;
  if (!normalizedFqdn.endsWith(suffix)) {
    throw new Error(`DNS record ${fqdn} is outside the configured GoDaddy zone ${zone}`);
  }
  return normalizedFqdn.slice(0, -suffix.length);
}

function normalizeDnsName(value: string): string {
  return value.trim().toLowerCase().replace(/\.$/, "");
}

function readRecordId(body: string, location: string | null): string | undefined {
  if (body) {
    try {
      const record = JSON.parse(body) as GoDaddyDnsRecord;
      if (typeof record.recordId === "string" && record.recordId) {
        return record.recordId;
      }
    } catch {
      // The documented Location header is a safe fallback for a malformed or
      // unexpectedly empty success body.
    }
  }

  if (!location) {
    return undefined;
  }
  try {
    const pathname = new URL(location, GODADDY_API_BASE).pathname;
    const lastSegment = pathname.split("/").filter(Boolean).at(-1);
    return lastSegment ? decodeURIComponent(lastSegment) : undefined;
  } catch {
    return undefined;
  }
}

function apiError(action: string, response: Response, body: string, secret: string): Error {
  let detail = body.trim();
  try {
    const parsed = JSON.parse(body) as GoDaddyErrorBody;
    const fields = parsed.fields
      ?.map((field) => [field.path, field.code, field.message].filter(Boolean).join(": "))
      .filter(Boolean)
      .join("; ");
    detail = [parsed.code, parsed.message, fields].filter(Boolean).join(" - ") || detail;
  } catch {
    // Keep the plain response body when GoDaddy does not return its JSON error envelope.
  }
  detail = detail.replaceAll(secret, "[REDACTED]");

  return new Error(
    `GoDaddy API failed to ${action}: HTTP ${response.status} ${response.statusText}` +
      (detail ? `: ${detail}` : ""),
  );
}

function errorMessage(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}
