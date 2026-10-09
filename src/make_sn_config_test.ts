import { Buffer } from "node:buffer";
import { fileURLToPath, pathToFileURL } from "node:url";
import {
  createPrivateKey,
  createPublicKey,
  sign as cryptoSign,
  verify as cryptoVerify,
} from "node:crypto";

import {
  enableDevVmBnsProxy,
  getSeedUserSpecs,
  makeBnsDvSeedConfig,
  makeSnAuthSeedConfig,
  materializeSnDidWebDocuments,
  omitSnSelfBootstrapParams,
  patchLocalDnsBnsRecord,
  prepareSeedIdentities,
  writeMachineConfig,
} from "./make_sn_config.ts";

Deno.test("machine config sets independent BNS resolver and bridge hosts", async () => {
  const root = await Deno.makeTempDir();
  try {
    writeMachineConfig(root, "devtests.org");
    const config = JSON.parse(await Deno.readTextFile(`${root}/machine.json`));
    if (config.bns_host !== "web3.devtests.org") {
      throw new Error("BNS resolver host was not generated");
    }
    if (config.web3_bridge?.bns !== "web3.devtests.org") {
      throw new Error("BNS bridge host was not generated");
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

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

function decodeAndVerifyJwt(jwt: string, publicKeyX: string): Record<string, unknown> {
  const parts = jwt.trim().split(".");
  const header = JSON.parse(Buffer.from(parts[0], "base64url").toString("utf8"));
  if (header.alg !== "EdDSA" || header.typ !== undefined || !cryptoVerify(
    null,
    Buffer.from(`${parts[0]}.${parts[1]}`),
    createPublicKey({ key: { kty: "OKP", crv: "Ed25519", x: publicKeyX }, format: "jwk" }),
    Buffer.from(parts[2], "base64url"),
  )) {
    throw new Error("invalid owner-signed JWT");
  }
  return JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
}

async function generateOodFixture(root: string, group: string) {
  const source = Deno.env.get("BUCKYOS_OOD_CONFIG_SOURCE");
  const sourceUrl = source
    ? pathToFileURL(source).href
    : new URL("../../buckyos/src/make_config.ts", import.meta.url).href;
  const { makeConfigByGroupName } = await import(sourceUrl);
  const rootfs = `${root}/${group}`;
  await makeConfigByGroupName(group, rootfs, `${root}/ca`, `${root}/env`);
  const start = JSON.parse(await Deno.readTextFile(`${rootfs}/etc/start_config.json`));
  return { rootfs, start };
}

async function runSnCli(root: string) {
  return await new Deno.Command(Deno.execPath(), {
    args: [
      "run", "-A", "--config", fileURLToPath(new URL("./deno.json", import.meta.url)),
      new URL("./make_sn_config.ts", import.meta.url).href,
      "--rootfs", `${root}/out`, "--env_root", `${root}/env`,
      "--ca", `${root}/ca`, "--sn_ip", "127.0.0.1",
    ],
    stdout: "piped",
    stderr: "piped",
  }).output();
}

async function expectSeedFailure(root: string, fragment: string) {
  try {
    await makeBnsDvSeedConfig(`${root}/out`, `${root}/env`, getSeedUserSpecs().slice(0, 1));
  } catch (error) {
    if (error instanceof Error && error.message.includes(fragment)) {
      return;
    }
    throw error;
  }
  throw new Error(`expected seed generation to reject: ${fragment}`);
}

Deno.test("BNS seed publishes full device documents separately from TXT mini JWTs", async () => {
  const root = await Deno.makeTempDir();
  const outputRoot = `${root}/out`;
  try {
    const users = getSeedUserSpecs();
    const fixtures = new Map<string, Awaited<ReturnType<typeof generateOodFixture>>>();
    for (const user of users) {
      fixtures.set(user.username, await generateOodFixture(root, user.groupName));
    }
    await Deno.mkdir(outputRoot, { recursive: true });
    const cli = await new Deno.Command(Deno.execPath(), {
      args: [
        "run", "-A", "--config", fileURLToPath(new URL("./deno.json", import.meta.url)),
        new URL("./make_sn_config.ts", import.meta.url).href,
        "--rootfs", outputRoot, "--env_root", `${root}/env`, "--ca", `${root}/ca`,
        "--sn_ip", "127.0.0.1",
      ],
      stdout: "piped",
      stderr: "piped",
    }).output();
    if (!cli.success) {
      throw new Error(`SN CLI failed: ${new TextDecoder().decode(cli.stderr)}`);
    }
    await makeBnsDvSeedConfig(outputRoot, `${root}/env`, users);
    await makeSnAuthSeedConfig(outputRoot, `${root}/env`, users);
    const seedYaml = await Deno.readTextFile(`${outputRoot}/bns_dv_seed.yaml`);
    const snSeed = await Deno.readTextFile(`${outputRoot}/sn_seed.yaml`);
    for (const user of users) {
      const { rootfs, start } = fixtures.get(user.username)!;
      const device = JSON.parse(Buffer.from(start.device_doc_jwt.split(".")[1], "base64url").toString("utf8"));
      const nodeIdentity = JSON.parse(await Deno.readTextFile(`${rootfs}/etc/node_identity.json`));
      const host = nodeIdentity.device_did.replace(/^did:(bns|web):/, "") +
        (nodeIdentity.device_did.startsWith("did:bns:") ? ".bns.did" : "");
      const installedJwt = (await Deno.readTextFile(`${rootfs}/local/identity/${host}/device_doc.jwt`)).trim();
      const seedJwt = (await Deno.readTextFile(`${outputRoot}/bns_seed_docs/${user.username}/ood1.jwt`)).trim();
      const owner = start.owner_document;
      const pkx = owner.verificationMethod[0].publicKeyJwk.x;
      decodeAndVerifyJwt(seedJwt, pkx);
      if (installedJwt !== seedJwt || start.device_doc_jwt !== seedJwt) {
        throw new Error(`installed and seeded JWT revisions differ for ${user.username}`);
      }
      if (!seedYaml.includes(`      - doc_type: "ood1"\n        inline_text_file: "bns_seed_docs/${user.username}/ood1.jwt"`)) {
        throw new Error(`missing independent device slot for ${user.username}`);
      }
      const originalJwt = (await Deno.readTextFile(
        `${root}/env/${user.zoneId}/ood1/local/identity/${host}/device_doc.jwt`,
      )).trim();
      if (originalJwt === seedJwt) {
        throw new Error("fixture failed to exercise OOD normalization");
      }
      const aggregate = JSON.parse(await Deno.readTextFile(
        `${outputRoot}/bns_seed_docs/${user.username}/device_mini_doc.json`,
      ));
      if (aggregate.device_document_jwts.ood1 !== seedJwt ||
        aggregate.mini_device_jwts.ood1 !== start.device_mini_doc_jwt ||
        JSON.stringify(aggregate.devices.ood1) !== JSON.stringify(device)) {
        throw new Error("aggregate seed differs from installed identity");
      }
      const ownerJwt = (await Deno.readTextFile(
        `${outputRoot}/bns_seed_docs/${user.username}/owner.jwt`,
      )).trim();
      if (JSON.stringify(decodeAndVerifyJwt(ownerJwt, pkx)) !== JSON.stringify(owner)) {
        throw new Error("owner seed differs from OOD OwnerDocument");
      }
      if (!user.userDomain) {
        for (const [name, expected] of [
          ["zone", start.zone_document_jwt], ["boot", start.boot_config_jwt],
        ]) {
          const token = (await Deno.readTextFile(
            `${outputRoot}/bns_seed_docs/${user.username}/${name}.jwt`,
          )).trim();
          if (token !== expected) {
            throw new Error(`${name} seed differs from installed identity`);
          }
          decodeAndVerifyJwt(token, pkx);
        }
      } else if (!snSeed.includes(JSON.stringify(start.zone_document_jwt))) {
        throw new Error("SN did:web authority differs from installed ZoneDocument");
      }
      const bundle = await Deno.readTextFile(
        `${root}/env/${user.zoneId}/ood1/sn_seed_identity.json`,
      );
      if (bundle.includes("PRIVATE KEY") || bundle.includes("admin_password")) {
        throw new Error("public identity handoff leaked a secret");
      }
    }
    const snapshot = seedYaml;
    await makeBnsDvSeedConfig(outputRoot, `${root}/env`, users);
    if ((await Deno.readTextFile(`${outputRoot}/bns_dv_seed.yaml`)) !== snapshot) {
      throw new Error("seed regeneration changed finalized identities");
    }
    const fixturePath = Deno.env.get("BUCKYOS_SN_SEED_FIXTURE");
    if (fixturePath) {
      const documents = [];
      for (const block of seedYaml.split("  - type: register_name\n").slice(1)) {
        const name = JSON.parse(block.match(/^    name: (".*")$/m)![1]);
        for (const match of block.matchAll(
          /^      - doc_type: (.+)\n        inline_(text|json)_file: (".*")$/gm,
        )) {
          const docType = match[1].startsWith('"') ? JSON.parse(match[1]) : match[1];
          const text = await Deno.readTextFile(`${outputRoot}/${JSON.parse(match[3])}`);
          documents.push({
            name,
            doc_type: docType,
            content: match[2] === "json" ? JSON.stringify(JSON.parse(text)) : text.trim(),
          });
        }
      }
      const { start } = fixtures.get("alice")!;
      await Deno.writeTextFile(fixturePath, JSON.stringify({
        owner: start.owner_document,
        zone_jwt: start.zone_document_jwt,
        device_jwt: start.device_doc_jwt,
        device: JSON.parse(Buffer.from(start.device_doc_jwt.split(".")[1], "base64url").toString("utf8")),
        documents,
      }));
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("low-level SN seed export does not initialize missing identities", async () => {
  const root = await Deno.makeTempDir();
  try {
    await expectSeedFailure(root, "missing finalized OOD identity");
    try {
      await Deno.stat(`${root}/env`);
    } catch (error) {
      if (error instanceof Deno.errors.NotFound) {
        return;
      }
      throw error;
    }
    throw new Error("seed export unexpectedly rebuilt the OOD environment");
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

for (const initialOodCount of [0, 1]) {
  Deno.test(`SN-first and mixed generation preserve final identities (initial OODs: ${initialOodCount})`, async () => {
    const root = await Deno.makeTempDir();
    try {
      const users = getSeedUserSpecs();
      let existingBundle: string | undefined;
      if (initialOodCount) {
        await generateOodFixture(root, users[0].groupName);
        existingBundle = await Deno.readTextFile(`${root}/env/${users[0].zoneId}/ood1/sn_seed_identity.json`);
      }
      const cli = await runSnCli(root);
      if (!cli.success) {
        throw new Error(`SN-first CLI failed: ${new TextDecoder().decode(cli.stderr)}`);
      }
      const bundles = new Map<string, string>();
      for (const user of users) {
        const text = await Deno.readTextFile(`${root}/env/${user.zoneId}/ood1/sn_seed_identity.json`);
        if (user === users[0] && existingBundle && text !== existingBundle) {
          throw new Error("SN preparation replaced an existing finalized identity");
        }
        bundles.set(user.username, text);
      }
      await new Promise((resolve) => setTimeout(resolve, 1200));
      for (const user of users) {
        for (let generation = 0; generation < 2; generation++) {
          const { start } = await generateOodFixture(root, user.groupName);
          const bundleText = bundles.get(user.username)!;
          const bundle = JSON.parse(bundleText);
          for (const field of [
            "zone_document_jwt", "boot_config_jwt", "device_doc_jwt", "device_mini_doc_jwt",
          ]) {
            if (start[field] !== bundle[field]) {
              throw new Error(`OOD regeneration revised ${user.username} ${field}`);
            }
          }
          const seeded = (await Deno.readTextFile(`${root}/out/bns_seed_docs/${user.username}/ood1.jwt`)).trim();
          if (seeded !== start.device_doc_jwt ||
              await Deno.readTextFile(`${root}/env/${user.zoneId}/ood1/sn_seed_identity.json`) !== bundleText) {
            throw new Error("SN-first seed no longer matches subsequent installed OOD identity");
          }
        }
      }
      const repeated = await runSnCli(root);
      if (!repeated.success) {
        throw new Error(`repeated SN CLI failed: ${new TextDecoder().decode(repeated.stderr)}`);
      }
      for (const user of users) {
        if ((await Deno.readTextFile(`${root}/out/bns_seed_docs/${user.username}/ood1.jwt`)).trim() !==
            JSON.parse(bundles.get(user.username)!).device_doc_jwt) {
          throw new Error("repeated SN CLI changed the seeded revision");
        }
      }
    } finally {
      await Deno.remove(root, { recursive: true });
    }
  });
}

Deno.test("SN-first preparation normalizes a pre-existing raw SDK environment", async () => {
  const root = await Deno.makeTempDir();
  try {
    const source = Deno.env.get("BUCKYOS_OOD_CONFIG_SOURCE");
    const sourceUrl = source
      ? pathToFileURL(source).href
      : new URL("../../buckyos/src/make_config.ts", import.meta.url).href;
    const { buildUserEnv } = await import(sourceUrl);
    const { getParamsFromGroupName } = await import(new URL("./devenv_config.ts", import.meta.url).href);
    const userDir = await buildUserEnv(getParamsFromGroupName("alice.ood1"), `${root}/env`);
    const rawJwt = (await Deno.readTextFile(`${userDir}/ood1/local/identity/ood1.alice.bns.did/device_doc.jwt`)).trim();
    await prepareSeedIdentities(`${root}/env`, getSeedUserSpecs().slice(0, 1));
    const bundle = JSON.parse(await Deno.readTextFile(`${userDir}/ood1/sn_seed_identity.json`));
    if (bundle.device_doc_jwt === rawJwt) {
      throw new Error("SN-first preparation reused the raw SDK JWT");
    }
    await makeBnsDvSeedConfig(`${root}/out`, `${root}/env`, getSeedUserSpecs().slice(0, 1));
    await new Promise((resolve) => setTimeout(resolve, 1200));
    const { start } = await generateOodFixture(root, "alice.ood1");
    if (start.device_doc_jwt !== bundle.device_doc_jwt ||
        (await Deno.readTextFile(`${root}/out/bns_seed_docs/alice/ood1.jwt`)).trim() !== start.device_doc_jwt) {
      throw new Error("later OOD generation changed the SN-first normalized identity");
    }
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("SN preparation fails before output or other users change when finalized identity is invalid", async () => {
  const root = await Deno.makeTempDir();
  try {
    await generateOodFixture(root, "alice.ood1");
    const bundlePath = `${root}/env/alice.bns.did/ood1/sn_seed_identity.json`;
    const text = await Deno.readTextFile(bundlePath);
    const bundle = JSON.parse(text);
    bundle.device_doc_jwt = "invalid";
    await Deno.writeTextFile(bundlePath, JSON.stringify(bundle));
    await Deno.mkdir(`${root}/out`);
    const paramsPath = `${root}/out/params.json`;
    await Deno.writeTextFile(paramsPath, "preserve existing config");
    const cli = await runSnCli(root);
    if (cli.success || await Deno.readTextFile(paramsPath) !== "preserve existing config") {
      throw new Error("SN CLI changed staged config before validating final identities");
    }
    if (await Deno.readTextFile(bundlePath) !== JSON.stringify(bundle)) {
      throw new Error("SN CLI repaired invalid identity instead of rejecting it");
    }
    try {
      await Deno.stat(`${root}/env/bob.bns.did`);
    } catch (error) {
      if (error instanceof Deno.errors.NotFound) {
        return;
      }
      throw error;
    }
    throw new Error("SN CLI initialized other users before rejecting invalid existing identity");
  } finally {
    await Deno.remove(root, { recursive: true });
  }
});

Deno.test("SN seed rejects stale, tampered and inconsistent final identities", async () => {
  const root = await Deno.makeTempDir();
  try {
    const { start } = await generateOodFixture(root, "alice.ood1");
    const bundlePath = `${root}/env/alice.bns.did/ood1/sn_seed_identity.json`;
    const bundle = JSON.parse(await Deno.readTextFile(bundlePath));
    const badSignature = structuredClone(bundle);
    const parts = start.device_doc_jwt.split(".");
    parts[2] = (parts[2][0] === "A" ? "B" : "A") + parts[2].slice(1);
    badSignature.device_doc_jwt = parts.join(".");
    await Deno.writeTextFile(bundlePath, JSON.stringify(badSignature));
    await expectSeedFailure(root, "signature does not match");

    const ownerKey = await Deno.readTextFile(`${root}/env/alice.bns.did/user_private_key.pem`);
    const wrongDevice = JSON.parse(Buffer.from(parts[1], "base64url").toString("utf8"));
    wrongDevice.name = "ood2";
    await Deno.writeTextFile(bundlePath, JSON.stringify({
      ...bundle, device_doc_jwt: signedJwt(wrongDevice, ownerKey),
    }));
    await expectSeedFailure(root, "identity binding");

    const wrongMini = JSON.parse(Buffer.from(start.device_mini_doc_jwt.split(".")[1], "base64url").toString("utf8"));
    wrongMini.p = 9999;
    await Deno.writeTextFile(bundlePath, JSON.stringify({
      ...bundle, device_mini_doc_jwt: signedJwt(wrongMini, ownerKey),
    }));
    await expectSeedFailure(root, "inconsistent signed documents");

    const rewriteDevice = (device: Record<string, unknown>) => {
      const mini = JSON.parse(Buffer.from(start.device_mini_doc_jwt.split(".")[1], "base64url").toString("utf8"));
      mini.p = device.rtcp_port;
      mini.iat = device.iat;
      const miniJwt = signedJwt(mini, ownerKey);
      const zone = JSON.parse(Buffer.from(start.zone_document_jwt.split(".")[1], "base64url").toString("utf8"));
      zone.devices.ood1 = device;
      zone.iat = device.iat;
      zone.mini_device_jwts.ood1 = miniJwt;
      return {
        ...bundle,
        device_doc_jwt: signedJwt(device, ownerKey),
        device_mini_doc_jwt: miniJwt,
        zone_document_jwt: signedJwt(zone, ownerKey),
      };
    };
    const originalDevice = JSON.parse(Buffer.from(start.device_doc_jwt.split(".")[1], "base64url").toString("utf8"));
    await Deno.writeTextFile(bundlePath, JSON.stringify(rewriteDevice({
      ...originalDevice, iat: Math.floor(Date.now() / 1000) + 3600,
    })));
    await expectSeedFailure(root, "invalid document validity times");
    await Deno.writeTextFile(bundlePath, JSON.stringify(rewriteDevice({
      ...originalDevice, rtcp_port: 9999,
    })));
    await expectSeedFailure(root, "network parameters");

    await Deno.writeTextFile(bundlePath, JSON.stringify(bundle));
    const zonePath = `${root}/env/alice.bns.did/zone_config.json`;
    const zone = JSON.parse(await Deno.readTextFile(zonePath));
    zone.iat += 1;
    await Deno.writeTextFile(zonePath, JSON.stringify(zone));
    await expectSeedFailure(root, "is stale");
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
