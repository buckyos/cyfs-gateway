 /**
 * CYFS-Gateway Dashboard - kRPC API & 数据结构草案（TypeScript）
 * -----------------------------------------------------------------------------
 * 说明：
 * - 这是“接口/数据结构草案”，用于 PRD/研发对齐字段口径与方法命名。
 * 版本：v0.2-draft
 * 日期：2026-01-24
 */

/* eslint-disable @typescript-eslint/no-explicit-any */
/* eslint-disable @typescript-eslint/no-unused-vars */

///////////////////////////////
// 0) 依赖与运行时约定
///////////////////////////////

/**
 * buckyos.kRPCClient 由你们的 SDK 提供。
 * - 如果你们项目里是模块导入，请把这里改成： import * as buckyos from "xxx";
 * - 如果你们项目里是全局变量，则保留 declare 即可。
 */
declare const buckyos: {
  kRPCClient: new (url: string) => {
    call: (method: string, params: JsonValue) => Promise<Record<string, any>>;
  };
};

/** 网关 RPC 服务地址：按你的部署环境替换 */
export const GATEWAY_RPC_URL = "http://127.0.0.1:21000/kapi";

///////////////////////////////
// 1) 基础类型（与 UI/配置体系对齐）
///////////////////////////////

/** ISO8601 时间戳字符串，例如 "2026-01-24T10:00:00Z" */
export type ISO8601 = string;

/** 通用 ID */
export type ID = string;

/** 不透明品牌类型 */
export type Branded<T, B extends string> = T & { readonly __brand: B };

/** 任意 JSON 值 */
export type JsonValue =
  | null
  | boolean
  | number
  | string
  | JsonValue[]
  | { [k: string]: JsonValue };

/** JSON Object（便于 params["x"] 这种写法；兼容你们的 kRPC params 习惯） */
export type JsonObject = { [k: string]: JsonValue };

/**
 * “编码后的 JSON 文本”
 * - tunnel 新增、环境导入等均采用“本质 JSON + 编码承载”的形式（便于粘贴/二维码）
 * - 编码方式（base64url/压缩/加密）由实现决定；UI 只要求可解析预览与校验
 */
export type EncodedJsonPayload = Branded<string, "EncodedJsonPayload">;

/** 速率/用量单位 */
export type Bytes = number;
export type BitsPerSecond = number;
export type Milliseconds = number;

export type UiMode = "router" | "ops" | "developer";

///////////////////////////////
// 2) kRPC 通用返回与错误
///////////////////////////////

/**
 * 约定：所有 RPC 返回至少包含 code:number（0 表示成功）
 * 可能还包含 msg/message 以及 data/result 等字段
 */
export type KRpcRawResponse = Record<string, any> & {
  code: number;
  msg?: string;
  message?: string;
  data?: any;
  result?: any;
};

/** 将非 0 code 转成可捕获的 Error（前端可统一 toast/弹窗展示） */
export class KRpcError extends Error {
  public readonly method: string;
  public readonly code: number;
  public readonly raw: KRpcRawResponse;

  constructor(method: string, raw: KRpcRawResponse) {
    const code = typeof raw?.code === "number" ? raw.code : -1;
    const msg = (raw?.msg ?? raw?.message ?? "").toString();
    super(`kRPC call failed: ${method}, code=${code}${msg ? `, msg=${msg}` : ""}`);
    this.method = method;
    this.code = code;
    this.raw = raw;
  }
}

/** code!=0 直接抛错 */
function ensureOk(method: string, result: KRpcRawResponse): void {
  if (!result || typeof result.code !== "number") {
    throw new Error(`kRPC malformed response for ${method}: missing numeric code`);
  }
  if (result.code !== 0) {
    throw new KRpcError(method, result);
  }
}

/**
 * 兼容性取数：优先 data，其次 result，否则返回整包（极少数接口可能直接把 payload 平铺）
 * - 你们如果现网字段固定（比如都用 data），可以把这里收敛掉
 */
function pickData<T>(result: KRpcRawResponse): T {
  if ("data" in result) return result.data as T;
  if ("result" in result) return result.result as T;
  // fallback：有些接口可能把字段直接放在顶层
  return result as unknown as T;
}

///////////////////////////////
// 3) RPC method 名称（统一管理，便于后续对齐/改名）
///////////////////////////////

export const GW_RPC = {
  // --- System / Overview ---
  get_system_info: "get_system_info",
  get_overview_snapshot: "get_overview_snapshot",
  set_ui_mode: "set_ui_mode",

  // --- Security ---
  list_tokens: "list_tokens",
  create_token: "create_token",
  revoke_token: "revoke_token",
  set_login_password: "set_login_password",

  // --- Devices ---
  list_devices: "list_devices",
  get_device: "get_device",
  set_device_alias: "set_device_alias",
  set_device_tags: "set_device_tags",
  get_device_enrichment: "get_device_enrichment",
  set_device_enrichment: "set_device_enrichment",

  // --- Tunnels / Links ---
  list_tunnels: "list_tunnels",
  get_tunnel: "get_tunnel",
  import_tunnel: "import_tunnel", // 粘贴/扫码导入（EncodedJsonPayload）
  set_tunnel_enabled: "set_tunnel_enabled",
  run_predefined_tests: "run_predefined_tests", // 大网站测试 -> 返回 trace_id

  // --- Rules (process-chain post rules) ---
  list_rules: "list_rules",
  validate_rule: "validate_rule",
  create_post_rule: "create_post_rule",
  update_post_rule: "update_post_rule",
  set_rule_enabled: "set_rule_enabled",
  reorder_post_rules: "reorder_post_rules",
  delete_post_rule: "delete_post_rule",

  // --- Databases ---
  list_databases: "list_databases",
  query_ip_host: "query_ip_host",
  query_ip_geo: "query_ip_geo",
  query_hostname_tags: "query_hostname_tags",
  query_ip_tags: "query_ip_tags",
  upsert_custom_db_entry: "upsert_custom_db_entry",
  delete_custom_db_entry: "delete_custom_db_entry",

  // --- LAN Host/Zone env (mobile app test) ---
  list_lan_envs: "list_lan_envs",
  import_lan_env: "import_lan_env",
  set_lan_env_enabled: "set_lan_env_enabled",

  // --- TLS MITM ---
  get_tls_mitm_status: "get_tls_mitm_status",
  set_tls_mitm_enabled: "set_tls_mitm_enabled",
  set_tls_mitm_scope: "set_tls_mitm_scope",
  gen_ca: "gen_ca",
  rotate_ca: "rotate_ca",
  get_ca: "get_ca", // 下载/查看 CA（返回 PEM/base64 或下载 token）

  // --- Config ---
  show_effective_config: "show_effective_config",
  list_config_layers: "list_config_layers",
  get_config_draft: "get_config_draft",
  set_config_draft: "set_config_draft",
  validate_config_draft: "validate_config_draft",
  apply_config_draft: "apply_config_draft",
  list_config_versions: "list_config_versions",
  rollback_config: "rollback_config",
} as const;

export type GwRpcMethod = (typeof GW_RPC)[keyof typeof GW_RPC];

///////////////////////////////
// 4) 数据结构：System / Overview
///////////////////////////////

export type HealthStatus = "healthy" | "degraded" | "down" | "unknown";

export interface SystemInfo {
  version: string;
  build?: string;
  git_sha?: string;
  uptime_sec: number;

  ui_mode: UiMode;

  host: {
    hostname: string;
    os: string; // linux/windows/darwin...
    arch: string; // x64/arm64...
  };

  dashboard: {
    port: number;
    loopback_trusted: boolean; // 127.0.0.1 免授权
  };
}

export type ActionKind = "direct" | "proxy" | "blocked" | "failed" | "accepted";

export type DeviceId = Branded<ID, "DeviceId">;
export type TunnelId = Branded<ID, "TunnelId">;

export interface OverviewSnapshot {
  ts: ISO8601;

  health: {
    gateway: HealthStatus;

    last_config_applied_at?: ISO8601;

    // remote include 自动更新（每 30 分钟检查一次）
    last_remote_check_at?: ISO8601;
    last_remote_apply_at?: ISO8601;
    last_remote_error?: string;
  };

  traffic: {
    rx_bps: BitsPerSecond;
    tx_bps: BitsPerSecond;

    rx_bytes_window?: Bytes;
    tx_bytes_window?: Bytes;

    breakdown?: {
      by_action?: Partial<Record<ActionKind, Bytes>>;
      by_tunnel_id?: Partial<Record<string, Bytes>>;
      by_device_id?: Partial<Record<string, Bytes>>;
    };
  };

  tls_mitm: TlsMitmStatusSummary;
}

///////////////////////////////
// 5) 数据结构：Security / Token
///////////////////////////////

export type TokenId = Branded<ID, "TokenId">;

export interface ApiTokenInfo {
  id: TokenId;
  name: string;
  created_at: ISO8601;
  last_used_at?: ISO8601;
  scopes?: string[];
  /** 仅展示尾部（避免泄露） */
  token_tail?: string;
}

export interface CreateTokenResult {
  token_id: TokenId;
  /** 只在创建时返回一次，UI 必须提示用户保存 */
  token: string;
}

///////////////////////////////
// 6) 数据结构：Device
///////////////////////////////

export interface Device {
  id: DeviceId;

  /** 必有：设备名（无增强信息时可退化为 Device-xxxx） */
  name: string;

  /** 必有：当前 IP（旁路由透明栈必得） */
  ip: string;

  /** 必有：MAC（旁路由透明栈必得） */
  mac: string;

  /** 可扩展结构：由旁路由独立 Device API 提供的增强字段 */
  ext?: Record<string, JsonValue>;

  alias?: string;
  last_seen_at?: ISO8601;
  tags?: string[];
}

export interface DeviceEnrichmentStatus {
  enabled: boolean;
  provider: "none" | "device_api";
  endpoint?: string;
  last_sync_at?: ISO8601;
  last_error?: string;
}

///////////////////////////////
// 7) 数据结构：Tunnel / Link
///////////////////////////////

export type TunnelSchema = string; // e.g. "rtcp" | "socks" | "tcp" ...

export interface TunnelMetrics {
  latency_ms?: Milliseconds;
  bandwidth_bps?: BitsPerSecond;
  rx_bps?: BitsPerSecond;
  tx_bps?: BitsPerSecond;
  usage_bytes_window?: Bytes;
  exit_ip?: string;
}

export interface TunnelSummary {
  id: TunnelId;
  schema: TunnelSchema;

  enabled: boolean;

  metrics: TunnelMetrics;

  /** 计费/状态：若 tunnel 配置了查询 API，可展示 */
  billing_status?: Record<string, JsonValue>;

  updated_at?: ISO8601;
}

export interface TunnelDetail extends TunnelSummary {
  /** 原始配置（展示时建议脱敏） */
  config?: JsonValue;

  /** 最近测试记录（可选） */
  recent_tests?: Array<{
    ts: ISO8601;
    ok: boolean;
    trace_id?: TraceId;
    summary?: string;
  }>;
}

/** 预置测试站点 */
export type PredefinedTestSite =
  | "google"
  | "youtube"
  | "netflix"
  | "baidu"
  | "custom"; // 允许后续扩展

export type TraceId = Branded<string, "TraceId">;

export interface TestRunResult {
  trace_id: TraceId;
  started_at: ISO8601;
  sites: Array<{
    site: PredefinedTestSite;
    target?: string; // 当 site=custom 时可带 url
  }>;
}

///////////////////////////////
// 8) 数据结构：Rules（Post / Config Readonly）
///////////////////////////////

export type RuleId = Branded<ID, "RuleId">;
export type RuleSource = "post" | "config";

export interface Rule {
  id: RuleId;
  source: RuleSource;

  /** Post 规则可编辑；配置规则只读 */
  editable: boolean;

  /** 自然语言描述（用于列表展示与审计） */
  natural_language: string;

  /** 最终生效的规则脚本（process-chain block 代码片段） */
  script: string;

  enabled: boolean;

  /** 规则挂载点信息（用于解释/排障） */
  attach: {
    /**
     * 规范：用户规则默认挂到最高优先级 Post 节点上（由实现保证）
     * - hook_point/chain_id 的具体命名由网关定义
     */
    hook_point?: string;
    chain_id?: string;
    /** 在 Post 规则中的顺序（0 表示最高优先级） */
    post_order?: number;
  };

  /** 只读配置规则的来源 */
  config_origin?: {
    include_path?: string;
    layer_id?: string;
  };

  created_at?: ISO8601;
  updated_at?: ISO8601;
}

export interface RuleValidationResult {
  ok: boolean;
  errors?: Array<{
    code: string; // e.g. "SYNTAX_ERROR"
    message: string;
    line?: number;
    column?: number;
  }>;
  warnings?: Array<{
    code: string; // e.g. "UNREACHABLE"
    message: string;
  }>;
}

///////////////////////////////
// 9) 数据结构：Databases
///////////////////////////////

export type DatabaseId = Branded<ID, "DatabaseId">;

export type DatabaseKind =
  | "hostname_tag"
  | "ip_tag"
  | "ip_host"
  | "ip_geo"
  | "ip_dns" // 可与 ip_host 合并实现，但 UI 概念保留
  | "lan_zone";

export type DatabaseSource = "subscription" | "custom" | "probe";

export interface DatabaseInfo {
  id: DatabaseId;
  kind: DatabaseKind;
  source: DatabaseSource;

  /** 订阅库只读；自定义库可编辑 */
  read_only: boolean;

  updated_at?: ISO8601;
  size_bytes?: Bytes;

  /** 若来自订阅，可展示订阅 URL（可脱敏） */
  subscription_url?: string;
}

export interface IpHostRecord {
  ip: string;
  host: string;
  source: DatabaseSource;
  updated_at?: ISO8601;
}

export interface IpGeoRecord {
  ip: string;
  country?: string;
  region?: string;
  city?: string;
  isp?: string;
  lat?: number;
  lon?: number;
  source: DatabaseSource;
  updated_at?: ISO8601;
}

export interface TagRecord {
  key: string; // hostname 或 ip
  tags: string[];
  source: DatabaseSource;
  updated_at?: ISO8601;
}

///////////////////////////////
// 10) 数据结构：LAN Env（移动 App 测试）
///////////////////////////////

export type LanEnvId = Branded<ID, "LanEnvId">;

export interface LanEnv {
  id: LanEnvId;
  name: string;
  enabled: boolean;
  updated_at?: ISO8601;

  /** 原始环境配置（只读展示；编辑可走“替换导入”） */
  config?: JsonValue;
}

///////////////////////////////
// 11) 数据结构：TLS MITM
///////////////////////////////

export type TlsMitmScopeMode = "selected_devices" | "all_devices" | "by_rule";

export interface TlsMitmStatusSummary {
  enabled: boolean;

  scope: {
    mode: TlsMitmScopeMode;
    device_ids?: DeviceId[];
  };

  ca?: CaInfo;
}

export type CaId = Branded<ID, "CaId">;

export interface CaInfo {
  id: CaId;
  created_at: ISO8601;

  /** 可选：用于 UI 展示，便于对照 */
  fingerprint_sha256?: string;
  not_before?: ISO8601;
  not_after?: ISO8601;
}

export interface CaDownload {
  ca: CaInfo;
  /** PEM 内容（base64 编码，避免二进制传输问题） */
  pem_base64: string;
}

///////////////////////////////
// 12) 数据结构：Config
///////////////////////////////

export type ConfigLayerId = Branded<ID, "ConfigLayerId">;
export type ConfigFormat = "json" | "yaml" | "toml" | "unknown";

export type RemoteSyncMode = "manual" | "auto";

/** include 合成的每一层（用于 show_config / diff / 排障） */
export interface ConfigLayer {
  id: ConfigLayerId;
  path: string;

  format?: ConfigFormat;

  is_remote: boolean;
  remote_url?: string;

  sync_mode?: RemoteSyncMode;
  auto_apply?: boolean;

  last_sync_at?: ISO8601;
  last_error?: string;

  /** 只读/可写：例如 post overlay 可写，其它稳定层只读 */
  writable?: boolean;
}

/** 配置版本（用于回滚） */
export type ConfigVersionId = Branded<ID, "ConfigVersionId">;

export interface ConfigVersion {
  id: ConfigVersionId;
  created_at: ISO8601;
  note?: string;

  /** 应用来源：manual_apply / auto_apply(remote) 等 */
  applied_by?: "manual" | "auto_remote" | "unknown";
}

export interface ValidateConfigResult {
  ok: boolean;
  errors?: Array<{ code: string; message: string; path?: string }>;
  warnings?: Array<{ code: string; message: string; path?: string }>;
}

export interface ApplyConfigResult {
  ok: boolean;
  applied_at?: ISO8601;
  version_id?: ConfigVersionId;
  message?: string;
}

///////////////////////////////
// 13) RPC 封装函数（按你们 kRPC 规格写）
///////////////////////////////

// -----------------------------
// System / Overview
// -----------------------------

export async function get_system_info(): Promise<SystemInfo> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.get_system_info, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.get_system_info, result);
  return pickData<SystemInfo>(result);
}

export async function get_overview_snapshot(): Promise<OverviewSnapshot> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.get_overview_snapshot, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.get_overview_snapshot, result);
  return pickData<OverviewSnapshot>(result);
}

export async function set_ui_mode(mode: UiMode): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { mode };
  let result = (await rpc_client.call(GW_RPC.set_ui_mode, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

// -----------------------------
// Security
// -----------------------------

export async function list_tokens(): Promise<ApiTokenInfo[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.list_tokens, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.list_tokens, result);
  return pickData<ApiTokenInfo[]>(result);
}

export async function create_token(name: string, scopes: string[] | null = null): Promise<CreateTokenResult> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { name };
  if (scopes != null) {
    params["scopes"] = scopes;
  }
  let result = (await rpc_client.call(GW_RPC.create_token, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.create_token, result);
  return pickData<CreateTokenResult>(result);
}

export async function revoke_token(token_id: TokenId): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { token_id };
  let result = (await rpc_client.call(GW_RPC.revoke_token, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

/** 设置/修改登录密码（是否启用密码策略由实现决定；这里只给接口草案） */
export async function set_login_password(new_password: string): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { new_password };
  let result = (await rpc_client.call(GW_RPC.set_login_password, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

// -----------------------------
// Devices
// -----------------------------

export interface ListDevicesParams {
  /** 可选：按关键字过滤（设备名/IP） */
  q?: string;
  /** 可选：仅在线 */
  online_only?: boolean;
}

export async function list_devices(filter: ListDevicesParams | null = null): Promise<Device[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  if (filter != null) {
    params["filter"] = filter as unknown as JsonValue;
  }
  let result = (await rpc_client.call(GW_RPC.list_devices, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.list_devices, result);
  return pickData<Device[]>(result);
}

export async function get_device(device_id: DeviceId): Promise<Device> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { device_id };
  let result = (await rpc_client.call(GW_RPC.get_device, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.get_device, result);
  return pickData<Device>(result);
}

export async function set_device_alias(device_id: DeviceId, alias: string | null): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { device_id };
  if (alias != null) {
    params["alias"] = alias;
  }
  let result = (await rpc_client.call(GW_RPC.set_device_alias, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

export async function set_device_tags(device_id: DeviceId, tags: string[]): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { device_id, tags };
  let result = (await rpc_client.call(GW_RPC.set_device_tags, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

export async function get_device_enrichment(): Promise<DeviceEnrichmentStatus> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.get_device_enrichment, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.get_device_enrichment, result);
  return pickData<DeviceEnrichmentStatus>(result);
}

export async function set_device_enrichment(enabled: boolean, endpoint: string | null = null): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { enabled };
  if (endpoint != null) {
    params["endpoint"] = endpoint;
  }
  let result = (await rpc_client.call(GW_RPC.set_device_enrichment, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

// -----------------------------
// Tunnels / Links
// -----------------------------

export async function list_tunnels(): Promise<TunnelSummary[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.list_tunnels, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.list_tunnels, result);
  return pickData<TunnelSummary[]>(result);
}

export async function get_tunnel(tunnel_id: TunnelId): Promise<TunnelDetail> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { tunnel_id };
  let result = (await rpc_client.call(GW_RPC.get_tunnel, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.get_tunnel, result);
  return pickData<TunnelDetail>(result);
}

/**
 * 新增 tunnel（粘贴/扫码导入）
 * - payload 本质是 JSON，但会做编码承载（二维码/复制粘贴友好）
 */
export async function import_tunnel(payload: EncodedJsonPayload): Promise<TunnelId> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { payload };
  let result = (await rpc_client.call(GW_RPC.import_tunnel, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.import_tunnel, result);
  return pickData<TunnelId>(result);
}

export async function set_tunnel_enabled(tunnel_id: TunnelId, enabled: boolean): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { tunnel_id, enabled };
  let result = (await rpc_client.call(GW_RPC.set_tunnel_enabled, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

/**
 * 一键测试（预置大网站）
 * - 结果以日志/trace 为主：返回 trace_id，前端跳转日志页按 trace-id 过滤
 */
export async function run_predefined_tests(
  sites: Array<{ site: PredefinedTestSite; target?: string }> | null = null,
  tunnel_id: TunnelId | null = null
): Promise<TestRunResult> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  if (sites != null) {
    params["sites"] = sites as unknown as JsonValue;
  }
  if (tunnel_id != null) {
    params["tunnel_id"] = tunnel_id;
  }
  let result = (await rpc_client.call(GW_RPC.run_predefined_tests, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.run_predefined_tests, result);
  return pickData<TestRunResult>(result);
}

// -----------------------------
// Rules
// -----------------------------

export interface ListRulesParams {
  source?: "post" | "config" | "all";
}

export async function list_rules(params_in: ListRulesParams | null = null): Promise<Rule[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  if (params_in != null) {
    params["filter"] = params_in as unknown as JsonValue;
  }
  let result = (await rpc_client.call(GW_RPC.list_rules, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.list_rules, result);
  return pickData<Rule[]>(result);
}

export async function validate_rule(script: string): Promise<RuleValidationResult> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { script };
  let result = (await rpc_client.call(GW_RPC.validate_rule, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.validate_rule, result);
  return pickData<RuleValidationResult>(result);
}

/**
 * 创建 Post 规则（可编辑）
 * - 规范：默认挂在最高优先级 Post 节点（由后端规范保证）
 * - 前端要求：至少做语法校验通过后再允许“生效/应用”
 */
export async function create_post_rule(natural_language: string, script: string, enabled: boolean): Promise<RuleId> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { natural_language, script, enabled };
  let result = (await rpc_client.call(GW_RPC.create_post_rule, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.create_post_rule, result);
  return pickData<RuleId>(result);
}

export async function update_post_rule(rule_id: RuleId, natural_language: string, script: string): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { rule_id, natural_language, script };
  let result = (await rpc_client.call(GW_RPC.update_post_rule, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

export async function set_rule_enabled(rule_id: RuleId, enabled: boolean): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { rule_id, enabled };
  let result = (await rpc_client.call(GW_RPC.set_rule_enabled, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

/** 仅对 Post 规则排序；配置规则只读不参与拖拽 */
export async function reorder_post_rules(rule_ids_in_order: RuleId[]): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { rule_ids_in_order };
  let result = (await rpc_client.call(GW_RPC.reorder_post_rules, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

export async function delete_post_rule(rule_id: RuleId): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { rule_id };
  let result = (await rpc_client.call(GW_RPC.delete_post_rule, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

// -----------------------------
// Databases
// -----------------------------

export async function list_databases(): Promise<DatabaseInfo[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.list_databases, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.list_databases, result);
  return pickData<DatabaseInfo[]>(result);
}

/** IP -> Host 查询：只查 DB，不做在线反查 */
export async function query_ip_host(ip: string): Promise<IpHostRecord[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { ip };
  let result = (await rpc_client.call(GW_RPC.query_ip_host, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.query_ip_host, result);
  return pickData<IpHostRecord[]>(result);
}

export async function query_ip_geo(ip: string): Promise<IpGeoRecord> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { ip };
  let result = (await rpc_client.call(GW_RPC.query_ip_geo, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.query_ip_geo, result);
  return pickData<IpGeoRecord>(result);
}

export async function query_hostname_tags(hostname: string): Promise<TagRecord | null> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { hostname };
  let result = (await rpc_client.call(GW_RPC.query_hostname_tags, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.query_hostname_tags, result);
  return pickData<TagRecord | null>(result);
}

export async function query_ip_tags(ip: string): Promise<TagRecord | null> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { ip };
  let result = (await rpc_client.call(GW_RPC.query_ip_tags, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.query_ip_tags, result);
  return pickData<TagRecord | null>(result);
}

/**
 * 自定义库写入（订阅库只读）
 * - 通过 db_id + entry 的方式泛化：不同 kind 的 entry 结构由后端校验
 */
export async function upsert_custom_db_entry(db_id: DatabaseId, entry: JsonValue): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { db_id, entry };
  let result = (await rpc_client.call(GW_RPC.upsert_custom_db_entry, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

export async function delete_custom_db_entry(db_id: DatabaseId, key: string): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { db_id, key };
  let result = (await rpc_client.call(GW_RPC.delete_custom_db_entry, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

// -----------------------------
// LAN Env
// -----------------------------

export async function list_lan_envs(): Promise<LanEnv[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.list_lan_envs, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.list_lan_envs, result);
  return pickData<LanEnv[]>(result);
}

export async function import_lan_env(payload: EncodedJsonPayload): Promise<LanEnvId> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { payload };
  let result = (await rpc_client.call(GW_RPC.import_lan_env, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.import_lan_env, result);
  return pickData<LanEnvId>(result);
}

export async function set_lan_env_enabled(env_id: LanEnvId, enabled: boolean): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { env_id, enabled };
  let result = (await rpc_client.call(GW_RPC.set_lan_env_enabled, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

// -----------------------------
// TLS MITM
// -----------------------------

export async function get_tls_mitm_status(): Promise<TlsMitmStatusSummary> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.get_tls_mitm_status, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.get_tls_mitm_status, result);
  return pickData<TlsMitmStatusSummary>(result);
}

export async function set_tls_mitm_enabled(enabled: boolean): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { enabled };
  let result = (await rpc_client.call(GW_RPC.set_tls_mitm_enabled, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

export async function set_tls_mitm_scope(mode: TlsMitmScopeMode, device_ids: DeviceId[] | null = null): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { mode };
  if (device_ids != null) {
    params["device_ids"] = device_ids;
  }
  let result = (await rpc_client.call(GW_RPC.set_tls_mitm_scope, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

/** 生成 CA（首次启用 MITM 时调用） */
export async function gen_ca(name: string | null = null, info: string | null = null): Promise<CaInfo> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  if (name != null) params["name"] = name;
  if (info != null) params["info"] = info;
  let result = (await rpc_client.call(GW_RPC.gen_ca, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.gen_ca, result);
  return pickData<CaInfo>(result);
}

/** 重新生成 CA（会导致已安装设备失效；前端必须二次确认） */
export async function rotate_ca(): Promise<CaInfo> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.rotate_ca, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.rotate_ca, result);
  return pickData<CaInfo>(result);
}

/** 下载/查看 CA 内容 */
export async function get_ca(ca_id: CaId): Promise<CaDownload> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { ca_id };
  let result = (await rpc_client.call(GW_RPC.get_ca, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.get_ca, result);
  return pickData<CaDownload>(result);
}

// -----------------------------
// Config
// -----------------------------

/** show_config：返回最终合成的大配置（include 展开 + params 替换后） */
export async function show_effective_config(): Promise<JsonValue> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.show_effective_config, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.show_effective_config, result);
  return pickData<JsonValue>(result);
}

export async function list_config_layers(): Promise<ConfigLayer[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.list_config_layers, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.list_config_layers, result);
  return pickData<ConfigLayer[]>(result);
}

/**
 * 草稿获取/写入
 * - 你们可以把草稿存于 post overlay 或独立 draft 空间；PRD 只关心“有草稿、不自动生效”
 */
export async function get_config_draft(layer_id: ConfigLayerId): Promise<string> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { layer_id };
  let result = (await rpc_client.call(GW_RPC.get_config_draft, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.get_config_draft, result);
  return pickData<string>(result);
}

export async function set_config_draft(layer_id: ConfigLayerId, content: string): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { layer_id, content };
  let result = (await rpc_client.call(GW_RPC.set_config_draft, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

export async function validate_config_draft(layer_id: ConfigLayerId): Promise<ValidateConfigResult> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { layer_id };
  let result = (await rpc_client.call(GW_RPC.validate_config_draft, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.validate_config_draft, result);
  return pickData<ValidateConfigResult>(result);
}

/** 生效草稿（需要二次确认；并要求失败可回滚到上一版） */
export async function apply_config_draft(layer_id: ConfigLayerId, note: string | null = null): Promise<ApplyConfigResult> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { layer_id };
  if (note != null) params["note"] = note;
  let result = (await rpc_client.call(GW_RPC.apply_config_draft, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.apply_config_draft, result);
  return pickData<ApplyConfigResult>(result);
}

export async function list_config_versions(): Promise<ConfigVersion[]> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = {};
  let result = (await rpc_client.call(GW_RPC.list_config_versions, params)) as KRpcRawResponse;
  ensureOk(GW_RPC.list_config_versions, result);
  return pickData<ConfigVersion[]>(result);
}

export async function rollback_config(version_id: ConfigVersionId): Promise<boolean> {
  let rpc_client = new buckyos.kRPCClient(GATEWAY_RPC_URL);
  let params: JsonObject = { version_id };
  let result = (await rpc_client.call(GW_RPC.rollback_config, params)) as KRpcRawResponse;
  return result["code"] === 0;
}

///////////////////////////////
// 14) 备注：日志/连接/对象树
///////////////////////////////

/**
 * 你在 PRD 中明确：一键测试的结果“就是日志”，日志面板更像系统日志。
 * 这类能力在 kRPC 下通常有两种实现：
 * 1) 轮询 query_logs(trace_id/keyword/time_range)
 * 2) subscribe_logs（长连接/流）
 *
 */
