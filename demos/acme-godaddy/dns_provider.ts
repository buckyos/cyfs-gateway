/**
 * Minimal DNS-01 provider boundary.
 *
 * A provider owns only the DNS mutation. ACME account/order handling and DNS
 * propagation checks deliberately stay outside this interface, so another DNS
 * vendor can be added without duplicating the ACME flow.
 */
export interface Dns01ChallengeRecord {
  /** Fully-qualified TXT owner, for example `_acme-challenge.example.com`. */
  fqdn: string;
  /** Base64url-encoded SHA-256 digest of the ACME key authorization. */
  value: string;
}

export interface Dns01RecordHandle extends Dns01ChallengeRecord {
  /** Provider-assigned stable ID used to remove exactly the record we created. */
  id: string;
}

export interface Dns01Provider {
  present(record: Dns01ChallengeRecord): Promise<Dns01RecordHandle>;
  cleanup(record: Dns01RecordHandle): Promise<void>;
}

/**
 * Validate the value passed to acme-client's DNS-01 challenge callback.
 *
 * Despite the callback parameter being named `keyAuthorization`, acme-client
 * has already converted it to BASE64URL(SHA256(keyAuthorization)) for dns-01.
 * Hashing that callback value again produces a TXT record the CA will reject.
 */
export function acmeClientDns01TxtValue(callbackValue: string): string {
  if (!/^[A-Za-z0-9_-]{43}$/.test(callbackValue)) {
    throw new Error("acme-client returned an invalid DNS-01 TXT value");
  }
  return callbackValue;
}

export function dns01RecordName(identifier: string): string {
  const normalized = identifier.trim().toLowerCase().replace(/\.$/, "").replace(/^\*\./, "");
  if (!normalized) {
    throw new Error("ACME authorization returned an empty DNS identifier");
  }
  return `_acme-challenge.${normalized}`;
}
