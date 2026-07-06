#!/usr/bin/env bash
# SN 开发环境冒烟。
#
#   sn-dev-smoke.sh [--local]
#   sn-dev-smoke.sh --vm
#
# --local（默认）读 sn-dev-up.sh 生成的 sn-dev-env.json，验证本机高位端口
# 环境。--vm 验证 buckyos-devtest 已按 src/dev_configs/sn_test 部署到
# multipass VM 的 web3-gateway，此时 SN 使用 VM/生产 profile 的特权端口
# （DNS :53 / HTTP :80），本机需已把 sn.devtests.org 配到该 VM IP。
#
# 验证 seed 确实生效（对应 doc/SN/SN-seed-config-TODO.md §3.3 的 curl/dig 面）：
#   S1 DNS A     alice.web3.devtests.org -> sn_ip（本机模式 127.0.0.1；VM 模式为 VM IP）
#   S2 DNS TXT   alice.web3.devtests.org 含 PKX= / BOOT= / DEV=
#   S3 链上种子  GET /1.0/identifiers/did:bns:alice 经 indexer 投影解析成功
#   S4 user_domain 种子  GET /1.0/identifiers/did:web:charlie.me 解析成功
#   S5 纯 Web3 位  did:bns:dave（无 sn_user 行）仍可经 BNS 路径解析
# 登录/激活码走 kRPC 协议，由 e2e_sn_seed 测试覆盖（T1）。
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
SRC_DIR="$(cd .. && pwd)"
VAR="${SN_DEV_VAR_DIR:-$APP_DIR/var/sn-dev}"
ENV_JSON="$VAR/sn-dev-env.json"
DEFAULT_VM_CONFIG_DIR="$SRC_DIR/dev_configs/sn_test"

usage() {
  cat <<EOF
Usage:
  scripts/sn-dev-smoke.sh [--local]
  scripts/sn-dev-smoke.sh --vm [--expected-a <vm-ip>] [--dns-server <ip>] [--http-origin <url>]

Options:
  --local              Test the local sn-dev-up.sh environment (default).
  --vm                 Test the buckyos-devtest/multipass VM environment.
  --sn-host <domain>   Base SN domain, default devtests.org.
  --expected-a <ip>    Expected A record for alice.web3.<domain>; defaults to sn.<domain> host resolution in VM mode.
  --dns-server <addr>  DNS server address; defaults to 127.0.0.1 locally and the VM IP in VM mode.
  --http-origin <url>  HTTP origin; defaults to local high port or http://sn.<domain> in VM mode.
  --config-dir <path>  VM devtest config dir; default $DEFAULT_VM_CONFIG_DIR.
EOF
}

require_tool() {
  command -v "$1" >/dev/null 2>&1 || { echo "missing required tool: $1" >&2; exit 1; }
}

json_get() {
  local v=""
  v="$(grep -o "\"$2\"[[:space:]]*:[[:space:]]*\"[^\"]*\"" "$1" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*"//;s/"$//')" || true
  printf '%s' "$v"
}
json_get_num() {
  local v=""
  v="$(grep -o "\"$2\"[[:space:]]*:[[:space:]]*[0-9][0-9]*" "$1" 2>/dev/null | head -1 | sed 's/.*:[[:space:]]*//')" || true
  printf '%s' "$v"
}

resolve_ipv4() {
  local host="$1"
  local ip=""
  if command -v getent >/dev/null 2>&1; then
    ip="$(getent ahostsv4 "$host" 2>/dev/null | awk '{print $1; exit}')" || true
  fi
  if [ -z "$ip" ] && command -v dscacheutil >/dev/null 2>&1; then
    ip="$(dscacheutil -q host -a name "$host" 2>/dev/null | awk '/ip_address:/ {print $2; exit}')" || true
  fi
  if [ -z "$ip" ] && command -v python3 >/dev/null 2>&1; then
    ip="$(python3 -c 'import socket, sys; print(socket.gethostbyname(sys.argv[1]))' "$host" 2>/dev/null)" || true
  fi
  if [ -z "$ip" ]; then
    ip="$(ping -c 1 "$host" 2>/dev/null | sed -n 's/^PING [^(]*(\([^)]*\)).*/\1/p' | head -1)" || true
  fi
  printf '%s' "$ip"
}

MODE="${SN_DEV_SMOKE_MODE:-local}"
SN_HOST_ARG="${SN_DEV_SN_HOST:-}"
EXPECTED_A="${SN_DEV_EXPECTED_A:-${SN_DEV_VM_IP:-}}"
DNS_SERVER_ARG="${SN_DEV_DNS_SERVER:-}"
HTTP_ORIGIN_ARG="${SN_DEV_HTTP_ORIGIN:-}"
VM_CONFIG_DIR="${SN_DEV_VM_CONFIG_DIR:-$DEFAULT_VM_CONFIG_DIR}"
SMOKE_RETRIES="${SN_DEV_SMOKE_RETRIES:-10}"
SMOKE_RETRY_DELAY="${SN_DEV_SMOKE_RETRY_DELAY:-2}"

while [ "$#" -gt 0 ]; do
  case "$1" in
    --local) MODE="local"; shift ;;
    --vm) MODE="vm"; shift ;;
    --sn-host)
      [ "$#" -ge 2 ] || { echo "--sn-host requires a value" >&2; exit 2; }
      SN_HOST_ARG="$2"; shift 2 ;;
    --expected-a|--vm-ip)
      [ "$#" -ge 2 ] || { echo "$1 requires a value" >&2; exit 2; }
      EXPECTED_A="$2"; shift 2 ;;
    --dns-server)
      [ "$#" -ge 2 ] || { echo "--dns-server requires a value" >&2; exit 2; }
      DNS_SERVER_ARG="$2"; shift 2 ;;
    --http-origin)
      [ "$#" -ge 2 ] || { echo "--http-origin requires a value" >&2; exit 2; }
      HTTP_ORIGIN_ARG="$2"; shift 2 ;;
    --config-dir)
      [ "$#" -ge 2 ] || { echo "--config-dir requires a value" >&2; exit 2; }
      VM_CONFIG_DIR="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown argument: $1" >&2; usage >&2; exit 2 ;;
  esac
done

require_tool curl
require_tool dig

case "$MODE" in
  local)
    [ -f "$ENV_JSON" ] || { echo "no sn-dev-env.json; run sn-dev-up.sh first" >&2; exit 1; }
    DNS_PORT="$(json_get_num "$ENV_JSON" gw_dns_port)"
    HTTP_PORT="$(json_get_num "$ENV_JSON" gw_http_port)"
    SN_HOST="$(json_get "$ENV_JSON" sn_host)"
    [ -n "$SN_HOST_ARG" ] && SN_HOST="$SN_HOST_ARG"
    [ -n "$SN_HOST" ] || SN_HOST="devtests.org"
    [ -n "$DNS_PORT" ] || { echo "missing gw_dns_port in $ENV_JSON" >&2; exit 1; }
    [ -n "$HTTP_PORT" ] || { echo "missing gw_http_port in $ENV_JSON" >&2; exit 1; }
    DNS_SERVER="${DNS_SERVER_ARG:-127.0.0.1}"
    HTTP_ORIGIN="${HTTP_ORIGIN_ARG:-http://127.0.0.1:${HTTP_PORT}}"
    EXPECTED_A="${EXPECTED_A:-127.0.0.1}"
    ;;
  vm)
    SN_HOST="${SN_HOST_ARG:-devtests.org}"
    DNS_PORT=53
    HTTP_PORT=80
    [ -d "$VM_CONFIG_DIR" ] || { echo "VM config dir not found: $VM_CONFIG_DIR" >&2; exit 1; }
    if [ -z "$EXPECTED_A" ]; then
      EXPECTED_A="$(resolve_ipv4 "sn.$SN_HOST")"
    fi
    [ -n "$EXPECTED_A" ] || {
      echo "could not resolve sn.$SN_HOST; configure hosts or pass --expected-a <vm-ip>" >&2
      exit 1
    }
    DNS_SERVER="${DNS_SERVER_ARG:-$EXPECTED_A}"
    HTTP_ORIGIN="${HTTP_ORIGIN_ARG:-http://sn.$SN_HOST}"
    ;;
  *)
    echo "unknown mode: $MODE" >&2
    usage >&2
    exit 2
    ;;
esac

SN_HTTP_HOST="sn.$SN_HOST"
ALICE_HOST="alice.web3.$SN_HOST"

PASS=0
FAIL=0
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  local attempt=1
  while [ "$attempt" -le "$SMOKE_RETRIES" ]; do
    if "$@" >/dev/null 2>&1; then
      echo "  PASS  $desc"
      PASS=$((PASS + 1))
      return
    fi
    if [ "$attempt" -lt "$SMOKE_RETRIES" ]; then
      sleep "$SMOKE_RETRY_DELAY"
    fi
    attempt=$((attempt + 1))
  done
  echo "  FAIL  $desc" >&2
  FAIL=$((FAIL + 1))
}

dns_a_matches_expected() {
  dig +short +time=3 +tries=1 @"$DNS_SERVER" -p "$DNS_PORT" "$ALICE_HOST" A | grep -Fxq "$EXPECTED_A"
}
dns_txt_has() { # dns_txt_has <marker>
  dig +short +time=3 +tries=1 @"$DNS_SERVER" -p "$DNS_PORT" "$ALICE_HOST" TXT | grep -Fq "$1"
}
identifiers_ok() { # identifiers_ok <did>
  # 当前兼容 API 顶层返回 boot/user_name；旧 DID 文档形态可能返回 id/oods。
  # 任一形态都说明 resolver 成功返回了可用文档。
  curl -fsS --connect-timeout 3 --max-time 10 -H "Host: $SN_HTTP_HOST" "$HTTP_ORIGIN/1.0/identifiers/$1" | grep -Eq '"(boot|user_name|id|oods)"'
}

echo "[sn-dev-smoke] mode: $MODE"
if [ "$MODE" = "vm" ]; then
  echo "[sn-dev-smoke] vm config: $VM_CONFIG_DIR"
fi
echo "[sn-dev-smoke] targets: dns $DNS_SERVER:$DNS_PORT, http $HTTP_ORIGIN (Host $SN_HTTP_HOST)"
echo "[sn-dev-smoke] expected SN A: $EXPECTED_A"
check "S1 DNS A $ALICE_HOST -> $EXPECTED_A" dns_a_matches_expected
check "S2 DNS TXT contains PKX=" dns_txt_has "PKX="
check "S2 DNS TXT contains BOOT=" dns_txt_has "BOOT="
check "S2 DNS TXT contains DEV=" dns_txt_has "DEV="
check "S3 resolve did:bns:alice via indexer projection" identifiers_ok "did:bns:alice"
check "S4 resolve did:web:charlie.me via user_domain seed" identifiers_ok "did:web:charlie.me"
check "S5 resolve did:bns:dave (pure Web3, no sn_user row)" identifiers_ok "did:bns:dave"

echo "[sn-dev-smoke] $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
