#!/usr/bin/env -S deno run --allow-env --allow-net --allow-read --allow-write

import * as path from "node:path";
import { parseArgs } from "node:util";
import { domainToASCII } from "node:url";
import acme from "acme-client";

import { inspectExistingCertificate, obtainCertificate } from "./certificate.ts";
import { waitForAuthoritativeTxt } from "./dns_propagation.ts";
import { GoDaddyDnsProvider } from "./godaddy_provider.ts";

interface CliOptions {
  zone: string;
  domains: string[];
  email: string;
  outputDir: string;
  directoryUrl: string;
  acceptTerms: boolean;
  force: boolean;
  renewBeforeDays: number;
  propagationTimeoutMs: number;
  propagationIntervalMs: number;
  verbose: boolean;
}

export async function run(args: string[]): Promise<void> {
  const options = parseCli(args);
  const log = (message: string) => console.log(`[acme] ${message}`);

  const decision = await inspectExistingCertificate(
    options.outputDir,
    options.domains,
    options.directoryUrl,
    options.renewBeforeDays,
  );
  if (!options.force && !decision.renew) {
    log(
      `无需续期：${decision.reason}（到期时间 ${decision.notAfter?.toISOString()}，证书目录 ${options.outputDir}）`,
    );
    return;
  }
  log(`需要签发：${options.force ? "使用了 --force" : decision.reason}`);
  log(`ACME directory: ${options.directoryUrl}`);

  if (!options.acceptTerms) {
    throw new Error("签发前必须通过 --accept-terms 明确接受 ACME/Let's Encrypt 服务条款");
  }
  const token = Deno.env.get("GODADDY_PAT")?.trim();
  if (!token) {
    throw new Error("环境变量 GODADDY_PAT 未设置");
  }

  if (options.verbose) {
    acme.setLogger((message) => log(message));
  }
  const provider = new GoDaddyDnsProvider({ token, zone: options.zone });
  const result = await obtainCertificate({
    directoryUrl: options.directoryUrl,
    domains: options.domains,
    email: options.email,
    outputDir: options.outputDir,
    provider,
    waitForPropagation: (fqdn, value) =>
      waitForAuthoritativeTxt(fqdn, value, {
        zone: options.zone,
        timeoutMs: options.propagationTimeoutMs,
        intervalMs: options.propagationIntervalMs,
        log,
      }),
    log,
  });

  log(`证书签发成功，到期时间 ${result.notAfter.toISOString()}`);
  log(`证书已写入 ${options.outputDir}`);
  for (const warning of result.cleanupWarnings) {
    console.warn(`[acme] 警告：${warning}`);
  }
}

function parseCli(args: string[]): CliOptions {
  const parsed = parseArgs({
    args,
    strict: true,
    allowPositionals: false,
    options: {
      zone: { type: "string", short: "z" },
      domain: { type: "string", short: "d", multiple: true },
      email: { type: "string", short: "e" },
      output: { type: "string", short: "o", default: "./certs" },
      production: { type: "boolean", default: false },
      "directory-url": { type: "string" },
      "accept-terms": { type: "boolean", default: false },
      force: { type: "boolean", default: false },
      "renew-before-days": { type: "string", default: "30" },
      "propagation-timeout": { type: "string", default: "300" },
      "propagation-interval": { type: "string", default: "5" },
      verbose: { type: "boolean", short: "v", default: false },
      help: { type: "boolean", short: "h", default: false },
    },
  });

  if (parsed.values.help) {
    printHelp();
    Deno.exit(0);
  }

  const zone = normalizeDomain(requiredString(parsed.values.zone, "--zone"), false);
  const domains = (parsed.values.domain ?? []).map((domain) => normalizeDomain(domain, true));
  if (domains.length === 0) {
    throw new Error("至少需要一个 --domain");
  }
  for (const domain of domains) {
    const baseDomain = domain.replace(/^\*\./, "");
    if (baseDomain !== zone && !baseDomain.endsWith(`.${zone}`)) {
      throw new Error(`域名 ${domain} 不在 GoDaddy zone ${zone} 内`);
    }
  }

  const email = requiredString(parsed.values.email, "--email");
  if (!/^\S+@\S+\.\S+$/.test(email)) {
    throw new Error(`无效邮箱：${email}`);
  }
  if (parsed.values.production && parsed.values["directory-url"]) {
    throw new Error("--production 与 --directory-url 不能同时使用");
  }

  const directoryUrl = parsed.values["directory-url"] ?? (
    parsed.values.production
      ? acme.directory.letsencrypt.production
      : acme.directory.letsencrypt.staging
  );
  validateHttpsUrl(directoryUrl, "--directory-url");

  return {
    zone,
    domains: [...new Set(domains)],
    email,
    outputDir: path.resolve(parsed.values.output),
    directoryUrl,
    acceptTerms: parsed.values["accept-terms"],
    force: parsed.values.force,
    renewBeforeDays: positiveNumber(parsed.values["renew-before-days"], "--renew-before-days"),
    propagationTimeoutMs: positiveNumber(
      parsed.values["propagation-timeout"],
      "--propagation-timeout",
    ) * 1000,
    propagationIntervalMs: positiveNumber(
      parsed.values["propagation-interval"],
      "--propagation-interval",
    ) * 1000,
    verbose: parsed.values.verbose,
  };
}

function normalizeDomain(input: string, allowWildcard: boolean): string {
  const value = input.trim().toLowerCase().replace(/\.$/, "");
  const wildcard = value.startsWith("*.");
  if (wildcard && !allowWildcard) {
    throw new Error(`zone 不允许通配符：${input}`);
  }
  if (!wildcard && value.includes("*")) {
    throw new Error(`通配符只能出现在域名最左侧：${input}`);
  }

  const unicodeBase = wildcard ? value.slice(2) : value;
  const asciiBase = domainToASCII(unicodeBase);
  if (!asciiBase || asciiBase.length > 253) {
    throw new Error(`无效域名：${input}`);
  }
  for (const label of asciiBase.split(".")) {
    if (!/^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/.test(label)) {
      throw new Error(`无效域名标签：${input}`);
    }
  }
  return wildcard ? `*.${asciiBase}` : asciiBase;
}

function requiredString(value: string | undefined, option: string): string {
  const normalized = value?.trim();
  if (!normalized) {
    throw new Error(`缺少必填参数 ${option}`);
  }
  return normalized;
}

function positiveNumber(value: string, option: string): number {
  const number = Number(value);
  if (!Number.isFinite(number) || number <= 0) {
    throw new Error(`${option} 必须是大于 0 的数字`);
  }
  return number;
}

function validateHttpsUrl(value: string, option: string): void {
  let url: URL;
  try {
    url = new URL(value);
  } catch {
    throw new Error(`${option} 不是有效 URL`);
  }
  if (url.protocol !== "https:") {
    throw new Error(`${option} 必须使用 https`);
  }
}

function printHelp(): void {
  console.log(`GoDaddy DNS-01 / Let's Encrypt certificate demo

用法：
  deno task start --zone example.com --domain example.com \\
    --domain '*.example.com' --email admin@example.com --accept-terms [选项]

必填：
  -z, --zone <zone>                 GoDaddy 托管的权威 DNS zone
  -d, --domain <domain>             证书域名；可重复，支持最左侧通配符
  -e, --email <email>               ACME 账号联系邮箱
      --accept-terms                接受 ACME CA 的服务条款

选项：
  -o, --output <dir>                输出目录（默认 ./certs）
      --production                  使用 Let's Encrypt 生产环境（默认 staging）
      --directory-url <url>         自定义 ACME directory URL
      --renew-before-days <days>    提前续期天数（默认 30）
      --propagation-timeout <sec>   DNS 传播超时（默认 300）
      --propagation-interval <sec>  DNS 检查间隔（默认 5）
      --force                       忽略现有证书并重新签发
  -v, --verbose                     输出 acme-client 调试日志
  -h, --help                        显示帮助

凭据只从环境变量 GODADDY_PAT 读取。`);
}

if (import.meta.main) {
  try {
    await run(Deno.args);
  } catch (error) {
    console.error(`[acme] 失败：${error instanceof Error ? error.message : String(error)}`);
    Deno.exit(1);
  }
}
