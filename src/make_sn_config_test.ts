import {
  enableDevVmBnsProxy,
  omitSnSelfBootstrapParams,
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
