const rs = require("./vendor/jsrsasign");

function log(message) {
    console.log("[step_jwk] " + message);
}

function safeUrl(value) {
    return String(value).replace(/[?#].*$/, "");
}

function fail(message) {
    log("failed: " + message);
    throw new Error("step_jwk cert provider: " + message);
}

function errorMessage(error) {
    if (error && error.stack) {
        return error.stack;
    }
    if (error && error.message) {
        return error.message;
    }
    return String(error);
}

function asObject(value, name) {
    if (!value || typeof value !== "object" || Array.isArray(value)) {
        fail(name + " must be an object");
    }
    return value;
}

function asString(value, name) {
    if (typeof value !== "string" || value.trim() === "") {
        fail(name + " must be a non-empty string");
    }
    return value.trim();
}

function normalizePem(value, name) {
    return asString(value, name).replace(/\\n/g, "\n").trim() + "\n";
}

function normalizeCaUrl(value) {
    const caUrl = asString(value, "params.ca_url");
    return caUrl.replace(/\/+$/, "");
}

function parseMaybeJson(value, name) {
    if (typeof value === "string") {
        try {
            return JSON.parse(value);
        } catch (e) {
            fail(name + " is not valid JSON: " + e.message);
        }
    }
    return asObject(value, name);
}

function firstString(values) {
    for (let i = 0; i < values.length; i++) {
        const value = values[i];
        if (typeof value === "string" && value.trim() !== "") {
            return value.trim();
        }
    }
    return null;
}

function tokenFromMap(map, domain, name) {
    if (!map) {
        return null;
    }
    const tokens = parseMaybeJson(map, name);
    return firstString([
        tokens[domain],
        tokens["*." + domain.split(".").slice(1).join(".")],
        tokens["*"],
        tokens.default,
    ]);
}

function stringFromMap(map, domain, name) {
    if (!map) {
        return null;
    }
    const values = parseMaybeJson(map, name);
    return firstString([
        values[domain],
        values["*." + domain.split(".").slice(1).join(".")],
        values["*"],
        values.default,
    ]);
}

function staticToken(domain, params) {
    const direct = firstString([
        params.ott,
        params.token,
        params.jwt,
        params.provisioning_token,
    ]);
    if (direct) {
        log("using configured static token for domain=" + domain);
        return direct;
    }

    const mapped =
        tokenFromMap(params.otts, domain, "params.otts") ||
        tokenFromMap(params.tokens, domain, "params.tokens") ||
        tokenFromMap(params.jwt_tokens, domain, "params.jwt_tokens");
    if (mapped) {
        log("using mapped static token for domain=" + domain);
    }
    return mapped;
}

function uniqueArray(values) {
    const seen = {};
    const out = [];
    values.forEach((value) => {
        const key = String(value).trim();
        if (key && !seen[key]) {
            seen[key] = true;
            out.push(key);
        }
    });
    return out;
}

function dnsSans(domain, params) {
    const extra = Array.isArray(params.sans) ? params.sans : [];
    return uniqueArray([domain].concat(extra));
}

function sanObjects(sans) {
    return sans.map((name) => ({ dns: name }));
}

function tlsKeyPassphrase(domain, params) {
    return (
        stringFromMap(params.tls_key_passphrases, domain, "params.tls_key_passphrases") ||
        firstString([
            params.tls_key_passphrase,
            params.tls_key_password,
            params.key_passphrase,
            params.key_password,
        ])
    );
}

function provisionerKeyPassphrase(params) {
    return firstString([
        params.provisioner_key_passphrase,
        params.provisioner_key_password,
        params.key_passphrase,
        params.key_password,
    ]);
}

function keyType(key) {
    if (key && key.type) {
        return key.type;
    }
    if (key && key.curveName) {
        return "EC";
    }
    return "";
}

function requireRsaKey(key, name) {
    if (keyType(key) !== "RSA") {
        fail(name + " must be RSA. Local EC signing is intentionally disabled in this package because the embedded JS runtime does not expose a confirmed CSPRNG.");
    }
}

function csrSigAlg(key, params) {
    if (params.csr_sigalg) {
        return asString(params.csr_sigalg, "params.csr_sigalg");
    }
    requireRsaKey(key, "params.tls_key_pem");
    return "SHA256withRSA";
}

function buildExtensionRequest(extreq) {
    const asn1 = rs.KJUR.asn1;
    const extensions = new asn1.x509.Extensions(extreq);
    const extensionRequest = new asn1.DERSequence({
        array: [
            new asn1.DERObjectIdentifier({ oid: "1.2.840.113549.1.9.14" }),
            new asn1.DERSet({ array: [extensions] }),
        ],
    });
    return new asn1.DERTaggedObject({
        tag: "a0",
        explicit: false,
        obj: new asn1.DERSet({ array: [extensionRequest] }),
    });
}

function pemFromHex(hex, label) {
    if (typeof rs.hextopem === "function") {
        return rs.hextopem(hex, label);
    }
    return rs.KJUR.asn1.ASN1Util.getPEMStringFromHex(hex, label);
}

function hexToBigInt(hex) {
    const value = String(hex || "").replace(/^0+/, "") || "0";
    return BigInt("0x" + value);
}

function bigIntToFixedHex(value, byteLength) {
    const hex = value.toString(16);
    const width = byteLength * 2;
    if (hex.length > width) {
        fail("RSA signature result is longer than modulus");
    }
    return "0".repeat(width - hex.length) + hex;
}

function modPow(base, exponent, modulus) {
    if (modulus === 1n) {
        return 0n;
    }
    let result = 1n;
    base = base % modulus;
    while (exponent > 0n) {
        if ((exponent & 1n) === 1n) {
            result = (result * base) % modulus;
        }
        exponent >>= 1n;
        base = (base * base) % modulus;
    }
    return result;
}

function rsaHashName(sigalg) {
    if (sigalg === "SHA256withRSA" || sigalg === "RS256") {
        return "sha256";
    }
    if (sigalg === "SHA384withRSA" || sigalg === "RS384") {
        return "sha384";
    }
    if (sigalg === "SHA512withRSA" || sigalg === "RS512") {
        return "sha512";
    }
    fail("unsupported RSA signature algorithm " + sigalg);
}

function rsaDigestInfoPrefix(hashName) {
    if (hashName === "sha256") {
        return "3031300d060960864801650304020105000420";
    }
    if (hashName === "sha384") {
        return "3041300d060960864801650304020205000430";
    }
    if (hashName === "sha512") {
        return "3051300d060960864801650304020305000440";
    }
    fail("unsupported RSA hash " + hashName);
}

function rsaPkcs1SignHex(inputHex, key, sigalg) {
    if (!key || !key.n || !key.d) {
        fail("RSA private key is missing n or d");
    }

    const hashName = rsaHashName(sigalg);
    const nHex = key.n.toString(16);
    const dHex = key.d.toString(16);
    const keyBytes = Math.ceil(nHex.length / 2);
    const digestInfo = rsaDigestInfoPrefix(hashName) +
        rs.KJUR.crypto.Util.hashHex(inputHex, hashName);
    const paddingBytes = keyBytes - digestInfo.length / 2 - 3;
    if (paddingBytes < 8) {
        fail("RSA key is too short for " + sigalg);
    }

    const encoded = "0001" + "ff".repeat(paddingBytes) + "00" + digestInfo;
    return bigIntToFixedHex(
        modPow(hexToBigInt(encoded), hexToBigInt(dHex), hexToBigInt(nHex)),
        keyBytes
    );
}

function buildCsr(domain, params, tlsKeyPem) {
    log("csr: parsing tls key domain=" + domain);
    const keyPass = tlsKeyPassphrase(domain, params);
    const key = rs.KEYUTIL.getKey(tlsKeyPem, keyPass);
    log("csr: parsed tls key domain=" + domain + " key_type=" + keyType(key));
    requireRsaKey(key, "params.tls_key_pem");

    const sans = dnsSans(domain, params);
    const subject = params.subject || ("/CN=" + domain);
    const sigalg = csrSigAlg(key, params);
    log(
        "csr: building request domain=" +
            domain +
            " subject=" +
            subject +
            " sans=" +
            sans.join(",") +
            " sigalg=" +
            sigalg
    );

    log("csr: using jsrsasign signer domain=" + domain);
    const asn1 = rs.KJUR.asn1;
    const cri = new asn1.DERSequence({
        array: [
            new asn1.DERInteger({ int: 0 }),
            new asn1.x509.X500Name({ str: subject }),
            new asn1.x509.SubjectPublicKeyInfo(key),
            buildExtensionRequest([
                {
                    extname: "subjectAltName",
                    array: sanObjects(sans),
                },
            ]),
        ],
    });
    const criHex = cri.tohex();
    log("csr: certification request info built domain=" + domain + " hex_len=" + criHex.length);

    const sigHex = rsaPkcs1SignHex(criHex, key, sigalg);
    log("csr: signature generated domain=" + domain + " sig_hex_len=" + sigHex.length);

    const csr = new asn1.DERSequence({
        array: [
            cri,
            new asn1.x509.AlgorithmIdentifier({ name: sigalg }),
            new asn1.DERBitString({ hex: "00" + sigHex }),
        ],
    });
    return pemFromHex(csr.tohex(), "CERTIFICATE REQUEST");
}

function jwkAlg(jwk, params) {
    if (params.jwt_alg) {
        return asString(params.jwt_alg, "params.jwt_alg");
    }
    if (jwk.alg) {
        return asString(jwk.alg, "params.provisioner_jwk.alg");
    }
    if (jwk.kty === "RSA") {
        return "RS256";
    }
    fail("params.jwt_alg is required for non-RSA local JWK signing");
}

function signingKey(params) {
    if (params.provisioner_encrypted_key || params.encryptedKey) {
        fail("step-ca provisioner encryptedKey JWE is not decrypted in this package; use params.token_endpoint, a pre-signed token, or decrypt it outside and provide provisioner_key_pem/provisioner_jwk");
    }

    if (params.provisioner_key_pem) {
        log("using local provisioner_key_pem for token signing");
        const pem = normalizePem(params.provisioner_key_pem, "params.provisioner_key_pem");
        const key = rs.KEYUTIL.getKey(pem, provisionerKeyPassphrase(params));
        requireRsaKey(key, "params.provisioner_key_pem");
        return { key, jwk: rs.KEYUTIL.getJWKFromKey(key) };
    }

    if (params.provisioner_jwk) {
        log("using local provisioner_jwk for token signing");
        const jwk = parseMaybeJson(params.provisioner_jwk, "params.provisioner_jwk");
        if (jwk.kty !== "RSA") {
            fail("params.provisioner_jwk must be an RSA private JWK for local signing. Use params.token_endpoint for the default step-ca EC JWK provisioner.");
        }
        const key = rs.KEYUTIL.getKey(jwk);
        requireRsaKey(key, "params.provisioner_jwk");
        return { key, jwk };
    }

    fail("one of params.token_endpoint, params.provisioner_jwk, or params.provisioner_key_pem is required");
}

function makeToken(domain, params, signUrl) {
    log("creating local OTT for domain=" + domain + " audience=" + safeUrl(params.audience || signUrl));
    const material = signingKey(params);
    const jwk = material.jwk;
    const now = Math.floor(Date.now() / 1000);
    const ttl = Number(params.token_ttl_seconds || 300);
    const sans = dnsSans(domain, params);
    const kid = params.kid || params.provisioner_kid || jwk.kid || rs.KJUR.jws.JWS.getJWKthumbprint(jwk);
    const issuer = params.issuer || params.provisioner || params.provisioner_name || kid;
    const fingerprint = asString(params.ca_fingerprint, "params.ca_fingerprint");
    const header = {
        alg: jwkAlg(jwk, params),
        kid,
        typ: "JWT",
    };
    const payload = {
        aud: params.audience || signUrl,
        exp: now + ttl,
        iat: now,
        iss: issuer,
        jti: String(now) + "-" + String(Math.random()).slice(2),
        nbf: now,
        sans,
        sha: fingerprint,
        sub: domain,
    };

    if (params.jwt_extra_claims && typeof params.jwt_extra_claims === "object") {
        Object.keys(params.jwt_extra_claims).forEach((key) => {
            payload[key] = params.jwt_extra_claims[key];
        });
    }

    const signingInput =
        rs.utf8tob64u(JSON.stringify(header)) +
        "." +
        rs.utf8tob64u(JSON.stringify(payload));
    const sigHex = rsaPkcs1SignHex(rs.utf8tohex(signingInput), material.key, header.alg);
    return signingInput + "." + rs.hextob64u(sigHex);
}

async function fetchToken(domain, params, signUrl, csr) {
    const token = staticToken(domain, params);
    if (token) {
        return token;
    }

    if (!params.token_endpoint) {
        log("no token_endpoint configured, using local token signing for domain=" + domain);
        return makeToken(domain, params, signUrl);
    }

    const tokenEndpoint = asString(params.token_endpoint, "params.token_endpoint");
    const body = {
        audience: params.audience || signUrl,
        ca_fingerprint: params.ca_fingerprint,
        csr,
        domain,
        sans: dnsSans(domain, params),
        sign_url: signUrl,
    };
    log("requesting token endpoint=" + safeUrl(tokenEndpoint) + " domain=" + domain);
    const res = await fetch(tokenEndpoint, {
        method: "POST",
        headers: Object.assign(
            { "content-type": "application/json" },
            params.token_headers || {}
        ),
        body: JSON.stringify(body),
    });
    const text = await res.text();
    log("token endpoint response status=" + res.status + " domain=" + domain);
    if (res.status < 200 || res.status >= 300) {
        fail("token endpoint returned HTTP " + res.status + ": " + text);
    }
    try {
        const json = JSON.parse(text);
        return asString(json.ott || json.token, "token endpoint response ott/token");
    } catch (e) {
        return asString(text, "token endpoint response");
    }
}

function buildSignBody(csr, ott, params) {
    const body = { csr, ott };
    if (params.not_before) {
        body.notBefore = params.not_before;
    }
    if (params.not_after) {
        body.notAfter = params.not_after;
    }
    if (params.template_data !== undefined) {
        body.templateData = params.template_data;
    }
    return body;
}

function appendPem(out, pem) {
    if (typeof pem === "string" && pem.trim() !== "") {
        out.push(pem.trim() + "\n");
    }
}

function responseCertChain(json, params) {
    const chain = [];
    appendPem(chain, json.crt);

    if (Array.isArray(json.certChain)) {
        json.certChain.forEach((pem) => {
            if (pem !== json.crt) {
                appendPem(chain, pem);
            }
        });
    } else if (params.append_ca === true) {
        appendPem(chain, json.ca);
    }

    if (chain.length === 0) {
        fail("step-ca sign response missing crt");
    }
    return chain.join("");
}

async function signCsr(csr, ott, params, signUrl) {
    log("requesting step-ca sign_url=" + safeUrl(signUrl));
    const res = await fetch(signUrl, {
        method: "POST",
        headers: Object.assign(
            { "content-type": "application/json" },
            params.sign_headers || {}
        ),
        body: JSON.stringify(buildSignBody(csr, ott, params)),
    });
    const text = await res.text();
    log("step-ca sign response status=" + res.status);
    if (res.status < 200 || res.status >= 300) {
        fail("step-ca sign returned HTTP " + res.status + ": " + text);
    }
    try {
        return JSON.parse(text);
    } catch (e) {
        fail("step-ca sign response is not JSON: " + e.message);
    }
}

export async function main(input) {
    try {
        const req = asObject(input, "input");
        const domain = asString(req.domain, "input.domain").toLowerCase();
        const params = asObject(req.params || {}, "input.params");
        const signUrl = (params.sign_url || (normalizeCaUrl(params.ca_url) + "/1.0/sign")).replace(/\/+$/, "");
        const tlsKeySource = params.tls_keys && params.tls_keys[domain] ? "tls_keys" : "tls_key_pem";
        const tlsKeyPem = normalizePem(
            (params.tls_keys && params.tls_keys[domain]) || params.tls_key_pem,
            "params.tls_key_pem"
        );

        const sans = dnsSans(domain, params);
        log(
            "start domain=" +
                domain +
                " sign_url=" +
                safeUrl(signUrl) +
                " sans=" +
                sans.join(",") +
                " tls_key_source=" +
                tlsKeySource
        );
        const csr = buildCsr(domain, params, tlsKeyPem);
        log("csr generated domain=" + domain);
        const ott = await fetchToken(domain, params, signUrl, csr);
        log("ott ready domain=" + domain);
        const signed = await signCsr(csr, ott, params, signUrl);
        const cert = responseCertChain(signed, params);
        const certCount = (cert.match(/BEGIN CERTIFICATE/g) || []).length;
        log("completed domain=" + domain + " cert_count=" + certCount);
        return {
            cert,
            key: tlsKeyPem,
        };
    } catch (error) {
        log("uncaught error: " + errorMessage(error));
        throw error;
    }
}
