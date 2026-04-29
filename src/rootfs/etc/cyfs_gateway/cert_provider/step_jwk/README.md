# step_jwk cert provider

`step_jwk` is a `js_extend_cert_provider` package for Smallstep `step-ca`
JWK provisioners. Runtime input is the standard `{ domain, params }`, and the
script returns `{ cert, key }` PEM material.

The package supports four token source modes:

- Client interactive token: run `step ca token <domain>` on the client and put
  the result in `params.token`, `params.ott`, or `params.tokens.<domain>`.
- Admin-distributed token: an administrator signs the token and distributes the
  JWT; configure it the same way as a client token.
- Offline token: run `step ca token <domain> --offline ...` and configure the
  returned JWT as `params.token` or in `params.tokens`.
- Issuer service: configure `params.token_endpoint`; the script POSTs
  `{ domain, sans, csr, audience, ca_fingerprint, sign_url }` and expects text
  or JSON `{ "ott": "..." }` / `{ "token": "..." }`.

Example with an issuer service:

```yaml
cert_providers:
  step-jwk:
    type: js_extend
    script_name: step_jwk
    renew_before_expiry: 2592000
    params:
      ca_url: https://ca.example.com
      ca_fingerprint: "<root-sha256-fingerprint>"
      token_endpoint: https://issuer.example.com/step-ott
      tls_key_pem: |
        -----BEGIN ENCRYPTED PRIVATE KEY-----
        ...
        -----END ENCRYPTED PRIVATE KEY-----
      tls_key_passphrase: "<key-password>"
```

The same certificate parameters can be moved to a separate JSON or YAML file
with `params_path`. Relative paths are resolved from the gateway main config
directory.

```yaml
cert_providers:
  step-jwk:
    type: js_extend
    script_name: step_jwk
    renew_before_expiry: 2592000
    params_path: ./cyfs_gateway/cert_provider/step_jwk/params.yaml
```

Example `params.yaml`:

```yaml
ca_url: https://ca.example.com
ca_fingerprint: "<root-sha256-fingerprint>"
token_endpoint: https://issuer.example.com/step-ott
tls_key_pem: |
  -----BEGIN ENCRYPTED PRIVATE KEY-----
  ...
  -----END ENCRYPTED PRIVATE KEY-----
tls_key_passphrase: "<key-password>"
```

Example with a pre-signed token:

```yaml
cert_providers:
  step-jwk:
    type: js_extend
    script_name: step_jwk
    params:
      ca_url: https://ca.example.com
      token: "<output-of-step-ca-token>"
      tls_key_pem: |
        -----BEGIN RSA PRIVATE KEY-----
        ...
        -----END RSA PRIVATE KEY-----
```

For multiple domains, prefer a token map:

```yaml
params:
  ca_url: https://ca.example.com
  tokens:
    www.example.com: "<ott-for-www.example.com>"
    api.example.com: "<ott-for-api.example.com>"
  tls_keys:
    www.example.com: |
      -----BEGIN ENCRYPTED PRIVATE KEY-----
      ...
      -----END ENCRYPTED PRIVATE KEY-----
    api.example.com: |
      -----BEGIN RSA PRIVATE KEY-----
      ...
      -----END RSA PRIVATE KEY-----
  tls_key_passphrases:
    www.example.com: "<www-key-password>"
```

For local token signing, configure an RSA `provisioner_jwk` or
`provisioner_key_pem`. `provisioner_key_pem` may be encrypted PEM when
`provisioner_key_passphrase` is configured. The default step-ca EC JWK
provisioner should use `token_endpoint`, because this embedded JS runtime does
not expose a confirmed CSPRNG and local EC signing would be unsafe.

`step-ca` provisioner `encryptedKey` JWE is intentionally not decrypted in this
package. For that format, either use a pre-signed token, use an issuer service,
or decrypt it outside the gateway and provide `provisioner_key_pem` /
`provisioner_jwk`.

Supported `params`:

- `ca_url` or `sign_url`: step-ca base URL or explicit `/1.0/sign` URL.
- `ca_fingerprint`: root CA SHA-256 fingerprint used in local JWK tokens.
- `token`, `ott`, `jwt`, `provisioning_token`: optional pre-signed token.
- `tokens`, `otts`, `jwt_tokens`: optional domain-to-token map, with `*` or
  `default` fallback.
- `token_endpoint`: optional service that returns an OTT as text or JSON
  `{ "ott": "..." }`; the request includes the generated CSR.
- `provisioner_jwk` / `provisioner_key_pem`: optional RSA private provisioner
  key for local RS256 OTT signing.
- `provisioner_key_passphrase` / `provisioner_key_password`: passphrase for an
  encrypted `provisioner_key_pem`.
- `tls_key_pem` or `tls_keys.<domain>`: RSA private key used for the CSR and
  returned as `key`.
- `tls_key_passphrase` / `tls_key_password`: passphrase for an encrypted
  `tls_key_pem`.
- `tls_key_passphrases.<domain>`: passphrase map for `tls_keys`.
- `sans`: optional extra DNS SANs.
- `not_before`, `not_after`, `template_data`: forwarded to step-ca sign.
- `append_ca`: set `true` to append the response `ca` PEM when `certChain` is
  absent.
