import { Buffer } from "node:buffer";
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

import {
  enableDevVmBnsProxy,
  makeBnsDvSeedConfig,
  makeSnAuthSeedConfig,
  materializeSnDidWebDocuments,
  omitSnSelfBootstrapParams,
  patchLocalDnsBnsRecord,
} from "./make_sn_config.ts";

Deno.test("generated params omit optional SN self-DNS bootstrap material", () => {
  const params: Record<string, unknown> = {
    sn_host: "devtests.org",
    sn_ip: "192.0.2.10",
    sn_boot_jwt: "boot",
    sn_owner_pk: "owner",
    sn_device_jwt: "device",
    sn_cer: "fullchain.cert",
  };

  omitSnSelfBootstrapParams(params);

  for (const key of ["sn_boot_jwt", "sn_owner_pk", "sn_device_jwt"]) {
    if (key in params) {
      throw new Error(`legacy SN self bootstrap param was retained: ${key}`);
    }
  }
  if (params.sn_host !== "devtests.org" || params.sn_cer !== "fullchain.cert") {
    throw new Error("non-bootstrap params were modified");
  }
});

Deno.test("local DNS materializes SN and BNS infrastructure hosts idempotently", async () => {
  const root = await Deno.makeTempDir();
  const configPath = `${root}/local_dns.toml`;
  try {
    await Deno.writeTextFile(
      configPath,
      '["existing.example"]\nttl = 300\naddress = ["192.0.2.1"]\n',
    );

    patchLocalDnsBnsRecord(root, "devtests.org", "192.0.2.10");
    patchLocalDnsBnsRecord(root, "devtests.org", "192.0.2.10");

    const config = await Deno.readTextFile(configPath);
    for (const hostname of ["bns.devtests.org", "sn.devtests.org"]) {
      const table = `["${hostname}"]`;
      const expected = `${table}\nttl = 60\naddress = ["192.0.2.10"]`;
      if (
        config.split(table).length !== 2 ||
        !config.includes(expected)
      ) {
        throw new Error(`${hostname} was not materialized exactly once`);
      }
    }
    if (!config.includes('["existing.example"]')) {
      throw new Error("infrastructure records or existing records were lost");
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("production template omits self bootstrap and keeps RTCP stack identity", async () => {
  const template = await Deno.readTextFile(
    new URL("./web3-gateway/web3_gateway.yaml", import.meta.url),
  );
  for (
    const forbidden of [
      "boot_jwt:",
      "owner_pkx:",
      "device_jwt:",
      "{{sn_boot_jwt}}",
      "{{sn_owner_pk}}",
      "{{sn_device_jwt}}",
    ]
  ) {
    if (template.includes(forbidden)) {
      throw new Error(`production template retained ${forbidden}`);
    }
  }
  for (
    const expected of [
      "main_rtcp:",
      "protocol: rtcp",
      "key_path: ./sn_private_key.pem",
      "device_config_path: ./sn_device_config.json",
      "requirement: authority_current",
      "dns_txt_bootstrap: false",
      "named_min_relation: known_owner",
      "sn_did_web:",
      'eq ${REQ.path} "/.well-known/did.json"',
      "dns_tcp:",
      "local_relay_node:",
      'relay_id: "embedded-web3-gateway"',
    ]
  ) {
    if (!template.includes(expected)) {
      throw new Error(`production RTCP stack identity is missing ${expected}`);
    }
  }

  const paramsFile = JSON.parse(
    await Deno.readTextFile(
      new URL("./web3-gateway/params.json", import.meta.url),
    ),
  );
  const params = paramsFile.params as Record<string, unknown>;
  for (const key of ["sn_boot_jwt", "sn_owner_pk", "sn_device_jwt"]) {
    if (key in params) {
      throw new Error(`production params retained ${key}`);
    }
  }
});

Deno.test("SN did:web authority and canonical stack identity reuse one key", async () => {
  const root = await Deno.makeTempDir();
  try {
    await Deno.writeTextFile(
      `${root}/sn_device_config.json`,
      JSON.stringify({
        id: "did:web:sn.devtests.org",
        zone_did: "did:web:sn.devtests.org",
        owner: "did:bns:sn",
        device_type: "ood",
        name: "sn",
        verificationMethod: [{
          id: "did:web:sn.devtests.org#main_key",
          controller: "did:web:sn.devtests.org",
          publicKeyJwk: {
            kty: "OKP",
            crv: "Ed25519",
            x: "device-key-x",
          },
        }],
        authentication: ["did:web:sn.devtests.org#main_key"],
      }),
    );

    materializeSnDidWebDocuments(root, "example.test");
    for (const fileName of ["did.json", "device.json"]) {
      const document = JSON.parse(
        await Deno.readTextFile(
          `${root}/sn_did_web/.well-known/${fileName}`,
        ),
      );
      if (document.id !== "did:web:sn.example.test") {
        throw new Error(`unexpected authority id in ${fileName}`);
      }
      if (
        document.verificationMethod[0].publicKeyJwk.x !== "device-key-x"
      ) {
        throw new Error(`SN device key changed in ${fileName}`);
      }
      if (
        document.verificationMethod[0].controller !==
          "did:web:sn.example.test" ||
        document.authentication[0] !==
          "did:web:sn.example.test#main_key"
      ) {
        throw new Error(
          `controller references were not rewritten in ${fileName}`,
        );
      }
    }

    const stackDocument = JSON.parse(
      await Deno.readTextFile(`${root}/sn_device_config.json`),
    );
    if (
      stackDocument.id !== "did:dev:device-key-x" ||
      stackDocument.verificationMethod[0].controller !==
        "did:dev:device-key-x" ||
      stackDocument.authentication[0] !== "did:dev:device-key-x#main_key"
    ) {
      throw new Error("SN stack identity was not normalized to did:dev");
    }
    if (stackDocument.zone_did !== "did:web:sn.example.test") {
      throw new Error("SN stack zone alias does not match the deployment host");
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

function unsignedJwt(payload: Record<string, unknown>): string {
  const base64url = (value: string) =>
    btoa(value)
      .replaceAll("+", "-")
      .replaceAll("/", "_")
      .replaceAll("=", "");
  return `${base64url('{"alg":"EdDSA"}')}.${
    base64url(JSON.stringify(payload))
  }.signature`;
}

function signedJwt(
  payload: Record<string, unknown>,
  privateKeyPem: string,
): string {
  const header = Buffer.from('{"alg":"EdDSA"}', "utf8").toString("base64url");
  const claim = Buffer.from(JSON.stringify(payload), "utf8").toString(
    "base64url",
  );
  const signingInput = `${header}.${claim}`;
  const signature = cryptoSign(
    null,
    Buffer.from(signingInput, "utf8"),
    createPrivateKey(privateKeyPem),
  );
  return `${signingInput}.${signature.toString("base64url")}`;
}

const TEST_OWNER_PRIVATE_KEY_PEM = `-----BEGIN PRIVATE KEY-----
MC4CAQAwBQYDK2VwBCIEIJBRONAzbwpIOwm0ugIQNyZJrDXxZF7HoPWAZesMedOr
-----END PRIVATE KEY-----
`;
const TEST_OWNER_PUBLIC_KEY_X = "T4Quc1L6Ogu4N2tTKOvneV1yYnBcmhP89B_RsuFsJZ8";

function ownerDocument(username: string): Record<string, unknown> {
  const ownerDid = `did:bns:${username}`;
  return {
    "@context": [
      "https://www.w3.org/ns/did/v1",
      "https://buckyos.org/ns/owner/v1",
    ],
    id: ownerDid,
    verificationMethod: [{
      type: "Ed25519VerificationKey2020",
      id: "#main_key",
      controller: ownerDid,
      publicKeyJwk: {
        kty: "OKP",
        crv: "Ed25519",
        x: TEST_OWNER_PUBLIC_KEY_X,
      },
    }],
    authentication: ["#main_key"],
    assertion_method: ["#main_key"],
    capabilityInvocation: ["#main_key"],
    exp: 2_058_838_939,
    iat: 1_735_689_600,
    version_seq: 0,
    name: username,
    display_name: username,
  };
}

async function writeUserDidSeedMaterial(
  userDir: string,
  username: string,
  zoneDid: string,
): Promise<void> {
  const ownerDid = `did:bns:${username}`;
  await Deno.writeTextFile(
    `${userDir}/user_config.json`,
    JSON.stringify(ownerDocument(username)),
  );
  await Deno.writeTextFile(
    `${userDir}/user_private_key.pem`,
    TEST_OWNER_PRIVATE_KEY_PEM,
  );
  await Deno.writeTextFile(
    `${userDir}/zone_config.json`,
    JSON.stringify({
      "@context": [
        "https://www.w3.org/ns/did/v1",
        "https://buckyos.org/ns/zone/v1",
      ],
      id: zoneDid,
      verificationMethod: [{
        type: "Ed25519VerificationKey2020",
        id: "#main_key",
        controller: ownerDid,
        publicKeyJwk: {
          kty: "OKP",
          crv: "Ed25519",
          x: TEST_OWNER_PUBLIC_KEY_X,
        },
      }],
      authentication: ["#main_key"],
      assertionMethod: ["#main_key"],
      capabilityInvocation: ["#main_key"],
      exp: 2_058_838_939,
      iat: 1_901_158_939,
      version_seq: 0,
      hostname: zoneDid.startsWith("did:web:")
        ? zoneDid.slice("did:web:".length)
        : `${username}.bns.did`,
      owner: ownerDid,
      oods: ["ood1"],
      boot_jwt: "",
    }),
  );
}

function decodeAndVerifyJwt(
  jwt: string,
  publicKeyX: string,
): Record<string, unknown> {
  const parts = jwt.trim().split(".");
  if (parts.length !== 3) {
    throw new Error("signed DID document is not a compact JWT");
  }
  const header = JSON.parse(
    Buffer.from(parts[0], "base64url").toString("utf8"),
  );
  if (header.alg !== "EdDSA" || header.typ !== undefined) {
    throw new Error(`unexpected owner JWT header: ${JSON.stringify(header)}`);
  }
  const verified = cryptoVerify(
    null,
    Buffer.from(`${parts[0]}.${parts[1]}`, "utf8"),
    createPublicKey({
      key: { kty: "OKP", crv: "Ed25519", x: publicKeyX },
      format: "jwk",
    }),
    Buffer.from(parts[2], "base64url"),
  );
  if (!verified) {
    throw new Error("DID document JWT signature is invalid");
  }
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

Deno.test("BNS seed publishes full device documents separately from TXT mini JWTs", async () => {
  const root = await Deno.makeTempDir();
  const envRoot = `${root}/env`;
  const outputRoot = `${root}/out`;
  const userDir = `${envRoot}/alice.bns.did`;
  const identityDir = `${userDir}/ood1/local/identity/ood1.alice.bns.did`;
  const webUserDir = `${envRoot}/charlie.me`;
  const webIdentityDir = `${webUserDir}/ood1/local/identity/ood1.charlie.me`;
  const deviceDoc = {
    id: "did:bns:ood1.alice",
    owner: "did:bns:alice",
    zone_did: "did:bns:alice",
    device_type: "ood",
    name: "ood1",
    iat: 1_735_689_600,
    exp: 2_058_838_939,
    verificationMethod: [{
      id: "#main_key",
      controller: "did:bns:ood1.alice",
      publicKeyJwk: { kty: "OKP", crv: "Ed25519", x: "device-x" },
    }],
    authentication: ["#main_key"],
  };
  const deviceDocJwt = signedJwt(deviceDoc, TEST_OWNER_PRIVATE_KEY_PEM);
  const webDeviceDoc = {
    ...deviceDoc,
    id: "did:web:ood1.charlie.me",
    owner: "did:bns:charlie",
    zone_did: "did:web:charlie.me",
    verificationMethod: [{
      ...deviceDoc.verificationMethod[0],
      controller: "did:web:ood1.charlie.me",
    }],
  };
  const webDeviceDocJwt = signedJwt(
    webDeviceDoc,
    TEST_OWNER_PRIVATE_KEY_PEM,
  );
  const miniJwt = signedJwt(
    {
      n: "ood1",
      x: "device-x",
      exp: 2_058_838_939,
    },
    TEST_OWNER_PRIVATE_KEY_PEM,
  );
  const bootJwt = signedJwt(
    {
      id: "did:bns:alice",
      oods: ["ood1"],
      exp: 2_058_838_939,
    },
    TEST_OWNER_PRIVATE_KEY_PEM,
  );
  const webBootJwt = signedJwt(
    {
      id: "did:web:charlie.me",
      oods: ["ood1@portmap"],
      exp: 2_058_838_939,
    },
    TEST_OWNER_PRIVATE_KEY_PEM,
  );

  try {
    await Deno.mkdir(identityDir, { recursive: true });
    await Deno.mkdir(webIdentityDir, { recursive: true });
    await Deno.mkdir(outputRoot, { recursive: true });
    await writeUserDidSeedMaterial(
      userDir,
      "alice",
      "did:bns:alice",
    );
    await writeUserDidSeedMaterial(
      webUserDir,
      "charlie",
      "did:web:charlie.me",
    );
    await Deno.writeTextFile(
      `${userDir}/ood1/node_identity.json`,
      JSON.stringify({
        schema: "buckyos.node_identity.v2",
        device_did: "did:bns:ood1.alice",
      }),
    );
    await Deno.writeTextFile(
      `${identityDir}/device_doc.jwt`,
      deviceDocJwt,
    );
    await Deno.writeTextFile(
      `${webUserDir}/ood1/node_identity.json`,
      JSON.stringify({
        schema: "buckyos.node_identity.v2",
        device_did: "did:web:ood1.charlie.me",
      }),
    );
    await Deno.writeTextFile(
      `${webIdentityDir}/device_doc.jwt`,
      webDeviceDocJwt,
    );
    await Deno.writeTextFile(
      `${userDir}/zone_txt_record.json`,
      JSON.stringify({
        boot_config_jwt: bootJwt,
        device_mini_doc_jwt: miniJwt,
        pkx: TEST_OWNER_PUBLIC_KEY_X,
      }),
    );
    await Deno.writeTextFile(
      `${userDir}/alice.bns.did.zone.json`,
      JSON.stringify({
        oods: ["ood1"],
        sn: "sn.devtests.org",
        exp: 2_058_838_939,
      }),
    );
    await Deno.writeTextFile(
      `${webUserDir}/zone_txt_record.json`,
      JSON.stringify({
        boot_config_jwt: webBootJwt,
        device_mini_doc_jwt: miniJwt,
        pkx: TEST_OWNER_PUBLIC_KEY_X,
      }),
    );
    await Deno.writeTextFile(
      `${webUserDir}/charlie.me.zone.json`,
      JSON.stringify({
        oods: ["ood1@portmap"],
        sn: "sn.devtests.org",
        exp: 2_058_838_939,
      }),
    );

    await makeBnsDvSeedConfig(outputRoot, envRoot, [
      {
        groupName: "alice.ood1",
        username: "alice",
        email: "alice@buckyos.org",
        zoneId: "alice.bns.did",
        snAccount: true,
      },
      {
        groupName: "charlie.ood1",
        username: "charlie",
        email: "charlie@buckyos.org",
        zoneId: "charlie.me",
        userDomain: "charlie.me",
        snAccount: true,
      },
    ]);
    await makeSnAuthSeedConfig(outputRoot, envRoot, [{
      groupName: "charlie.ood1",
      username: "charlie",
      email: "charlie@buckyos.org",
      zoneId: "charlie.me",
      userDomain: "charlie.me",
      snAccount: true,
    }]);

    const seedYaml = await Deno.readTextFile(
      `${outputRoot}/bns_dv_seed.yaml`,
    );
    for (
      const reference of [
        "bns_seed_docs/alice/owner.jwt",
        "bns_seed_docs/charlie/owner.jwt",
      ]
    ) {
      if (!seedYaml.includes(`inline_text_file: "${reference}"`)) {
        throw new Error(`BNS seed does not publish signed ${reference}`);
      }
    }
    if (
      !seedYaml.includes(
        'inline_json_file: "bns_seed_docs/alice/zone.json"',
      )
    ) {
      throw new Error("BNS seed does not publish the complete ZoneDocument");
    }

    const storedOwner = JSON.parse(
      await Deno.readTextFile(
        `${outputRoot}/bns_seed_docs/alice/owner.json`,
      ),
    );
    const storedOwnerJwt = await Deno.readTextFile(
      `${outputRoot}/bns_seed_docs/alice/owner.jwt`,
    );
    const signedOwner = decodeAndVerifyJwt(
      storedOwnerJwt,
      TEST_OWNER_PUBLIC_KEY_X,
    );
    if (
      JSON.stringify(storedOwner) !== JSON.stringify(signedOwner) ||
      signedOwner.id !== "did:bns:alice" ||
      !Array.isArray(signedOwner.verificationMethod) ||
      !Array.isArray(signedOwner.authentication)
    ) {
      throw new Error("BNS owner document is not the complete signed document");
    }

    const storedZone = JSON.parse(
      await Deno.readTextFile(
        `${outputRoot}/bns_seed_docs/alice/zone.json`,
      ),
    );
    const storedZoneJwt = await Deno.readTextFile(
      `${outputRoot}/bns_seed_docs/alice/zone.jwt`,
    );
    const signedZone = decodeAndVerifyJwt(
      storedZoneJwt,
      TEST_OWNER_PUBLIC_KEY_X,
    );
    if (
      JSON.stringify(storedZone) !== JSON.stringify(signedZone) ||
      signedZone.id !== "did:bns:alice" ||
      signedZone.owner !== "did:bns:alice" ||
      signedZone.iat !== 1_901_158_939 ||
      (signedZone.devices as Record<string, unknown>).ood1 === undefined
    ) {
      throw new Error("BNS zone document is not complete or owner-signed");
    }

    const snSeed = await Deno.readTextFile(`${outputRoot}/sn_seed.yaml`);
    const userDomainJwtLine = snSeed.split("\n").find((line) =>
      line.trimStart().startsWith("zone_document_jwt:")
    );
    if (!userDomainJwtLine) {
      throw new Error("SN user-domain seed misses ZoneDocument JWT");
    }
    const userDomainJwt = JSON.parse(
      userDomainJwtLine.slice(userDomainJwtLine.indexOf(":") + 1).trim(),
    );
    const userDomainZone = decodeAndVerifyJwt(
      userDomainJwt,
      TEST_OWNER_PUBLIC_KEY_X,
    );
    if (
      userDomainZone.id !== "did:web:charlie.me" ||
      userDomainZone.owner !== "did:bns:charlie" ||
      (userDomainZone.devices as Record<string, unknown>).ood1 === undefined
    ) {
      throw new Error(
        "SN user-domain seed does not contain a signed ZoneDocument",
      );
    }

    const aggregate = JSON.parse(
      await Deno.readTextFile(
        `${outputRoot}/bns_seed_docs/alice/device_mini_doc.json`,
      ),
    );
    if (JSON.stringify(aggregate.devices.ood1) !== JSON.stringify(deviceDoc)) {
      throw new Error(
        "authority device payload differs from Hello JWT payload",
      );
    }
    if (aggregate.mini_device_jwts.ood1 !== miniJwt) {
      throw new Error("mini JWT compatibility map is missing");
    }
    if (aggregate.device_document_jwts.ood1 !== deviceDocJwt) {
      throw new Error("full device JWT archive map is missing");
    }
    const webAggregate = JSON.parse(
      await Deno.readTextFile(
        `${outputRoot}/bns_seed_docs/charlie/device_mini_doc.json`,
      ),
    );
    if (
      JSON.stringify(webAggregate.devices.ood1) !==
        JSON.stringify(webDeviceDoc) ||
      webAggregate.device_document_jwts.ood1 !== webDeviceDocJwt
    ) {
      throw new Error(
        "did:web device document was not seeded via canonical BNS",
      );
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("BNS seed refreshes legacy did:dev user environments", async () => {
  const root = await Deno.makeTempDir();
  const envRoot = `${root}/env`;
  const outputRoot = `${root}/out`;
  const nodeDir = `${envRoot}/bob.bns.did/ood1`;

  try {
    await Deno.mkdir(nodeDir, { recursive: true });
    await Deno.mkdir(outputRoot, { recursive: true });
    await Deno.writeTextFile(
      `${nodeDir}/node_identity.json`,
      JSON.stringify({
        device_doc_jwt: unsignedJwt({
          id: "did:dev:legacy-bob-device",
        }),
      }),
    );

    await makeBnsDvSeedConfig(outputRoot, envRoot, [{
      groupName: "bob.ood1",
      username: "bob",
      email: "bob@buckyos.org",
      zoneId: "bob.bns.did",
      snAccount: true,
    }]);

    const aggregate = JSON.parse(
      await Deno.readTextFile(
        `${outputRoot}/bns_seed_docs/bob/device_mini_doc.json`,
      ),
    );
    if (aggregate.devices.ood1.id !== "did:bns:ood1.bob") {
      throw new Error(
        `legacy device identity was not refreshed: ${aggregate.devices.ood1.id}`,
      );
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("dev-vm replaces the production BNS key source with controller list", async () => {
  const root = await Deno.makeTempDir();
  const configPath = `${root}/web3_gateway.yaml`;
  const baseConfig = `servers:
  web3_sn:
    id: web3_sn
    bns_server_url: "{{bns_server_url}}"
    bns_proxy:
      require_user_asset_owner: true
      controllers:
        - id: default
          private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY
`;

  try {
    await Deno.writeTextFile(configPath, baseConfig);
    enableDevVmBnsProxy(root);
    const configured = await Deno.readTextFile(configPath);
    if (configured.includes("BNS_SN_CONTROLLER_PRIVATE_KEY")) {
      throw new Error(`production key source was not removed:\n${configured}`);
    }
    for (
      const expected of [
        "allowed_operations:",
        "controllers:",
        "id: controller-a",
        "id: controller-b",
      ]
    ) {
      if (!configured.includes(expected)) {
        throw new Error(`missing ${expected}:\n${configured}`);
      }
    }

    enableDevVmBnsProxy(root);
    const replayed = await Deno.readTextFile(configPath);
    if (replayed !== configured) {
      throw new Error("dev-vm BNS proxy injection is not idempotent");
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("dev-vm BNS proxy injection also covers the split config files", async () => {
  const root = await Deno.makeTempDir();
  const baseConfig = `servers:
  web3_sn:
    id: web3_sn
    bns_server_url: "{{bns_server_url}}"
    bns_proxy:
      require_user_asset_owner: true
      controllers:
        - id: default
          private_key_env: BNS_SN_CONTROLLER_PRIVATE_KEY
`;
  // web3_sn_api.yaml 缺失：拆分文件是可选的，注入必须跳过而不是报错。
  const files = ["web3_gateway.yaml", "web3_dns.yaml", "web3_relay.yaml"];

  try {
    for (const file of files) {
      await Deno.writeTextFile(`${root}/${file}`, baseConfig);
    }
    enableDevVmBnsProxy(root);
    for (const file of files) {
      const configured = await Deno.readTextFile(`${root}/${file}`);
      if (configured.includes("BNS_SN_CONTROLLER_PRIVATE_KEY")) {
        throw new Error(
          `production key source was not removed from ${file}:\n${configured}`,
        );
      }
      if (!configured.includes("controllers:")) {
        throw new Error(`missing controllers in ${file}:\n${configured}`);
      }
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});
