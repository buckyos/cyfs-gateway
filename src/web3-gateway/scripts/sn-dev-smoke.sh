#!/usr/bin/env bash
# SN 本机开发环境冒烟（读 sn-dev-up.sh 生成的 sn-dev-env.json）。
#
#   sn-dev-smoke.sh
#
# 验证 seed 确实生效（对应 doc/SN/SN-seed-config-TODO.md §3.3 的 curl/dig 面）：
#   S1 DNS A     alice.web3.devtests.org -> sn_ip(127.0.0.1)
#   S2 DNS TXT   alice.web3.devtests.org 含 PKX= / BOOT= / DEV=
#   S3 链上种子  GET /1.0/identifiers/did:bns:alice 经 indexer 投影解析成功
#   S4 user_domain 种子  GET /1.0/identifiers/did:web:charlie.me 解析成功
#   S5 纯 Web3 位  did:bns:dave（无 sn_user 行）仍可经 BNS 路径解析
# 登录/激活码走 kRPC 协议，由 e2e_sn_seed 测试覆盖（T1）。
set -euo pipefail

cd "$(dirname "$0")/.."
APP_DIR="$(pwd)"
VAR="${SN_DEV_VAR_DIR:-$APP_DIR/var/sn-dev}"
ENV_JSON="$VAR/sn-dev-env.json"
[ -f "$ENV_JSON" ] || { echo "no sn-dev-env.json; run sn-dev-up.sh first" >&2; exit 1; }

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

DNS_PORT="$(json_get_num "$ENV_JSON" gw_dns_port)"
HTTP_PORT="$(json_get_num "$ENV_JSON" gw_http_port)"
SN_HOST="$(json_get "$ENV_JSON" sn_host)"

PASS=0
FAIL=0
check() { # check <desc> <cmd...>
  local desc="$1"; shift
  if "$@" >/dev/null 2>&1; then
    echo "  PASS  $desc"
    PASS=$((PASS + 1))
  else
    echo "  FAIL  $desc" >&2
    FAIL=$((FAIL + 1))
  fi
}

dns_a_is_local() {
  dig +short +time=3 +tries=1 @127.0.0.1 -p "$DNS_PORT" "alice.web3.$SN_HOST" A | grep -q '^127\.0\.0\.1$'
}
dns_txt_has() { # dns_txt_has <marker>
  dig +short +time=3 +tries=1 @127.0.0.1 -p "$DNS_PORT" "alice.web3.$SN_HOST" TXT | grep -q "$1"
}
identifiers_ok() { # identifiers_ok <did>
  # did:bns 缺省返回 zone 文档（oods/...），did:web 返回带 id 的 boot 文档，
  # 两种形状都算解析成功。
  curl -fsS -H "Host: sn.$SN_HOST" "http://127.0.0.1:${HTTP_PORT}/1.0/identifiers/$1" | grep -Eq '"(id|oods)"'
}

echo "[sn-dev-smoke] targets: dns 127.0.0.1:$DNS_PORT, http 127.0.0.1:$HTTP_PORT (Host sn.$SN_HOST)"
check "S1 DNS A alice.web3.$SN_HOST -> 127.0.0.1" dns_a_is_local
check "S2 DNS TXT contains PKX=" dns_txt_has "PKX="
check "S2 DNS TXT contains BOOT=" dns_txt_has "BOOT="
check "S2 DNS TXT contains DEV=" dns_txt_has "DEV="
check "S3 resolve did:bns:alice via indexer projection" identifiers_ok "did:bns:alice"
check "S4 resolve did:web:charlie.me via user_domain seed" identifiers_ok "did:web:charlie.me"
check "S5 resolve did:bns:dave (pure Web3, no sn_user row)" identifiers_ok "did:bns:dave"

echo "[sn-dev-smoke] $PASS passed, $FAIL failed"
[ "$FAIL" -eq 0 ]
