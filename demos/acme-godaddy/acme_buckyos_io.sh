#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# 在这里填入 GoDaddy Personal Access Token（需要 domains.dns:update scope）。
# 警告：填入真实 PAT 后不要提交或分享这个文件。
GODADDY_PAT='XXXXX'

if [[ -z "${GODADDY_PAT}" || "${GODADDY_PAT}" == "REPLACE_WITH_YOUR_GODADDY_PAT" ]]; then
  echo "错误：请先编辑 ${BASH_SOURCE[0]}，填写 GODADDY_PAT。" >&2
  exit 1
fi

# 默认使用 Let's Encrypt production；需要再次测试 staging 时执行：
# ACME_PRODUCTION=0 ./acme_buckyos_io.sh
ACME_PRODUCTION="${ACME_PRODUCTION:-1}"
ACME_EMAIL="${ACME_EMAIL:-ops@buckyos.ai}"
ACME_OUTPUT_DIR="${ACME_OUTPUT_DIR:-}"
use_production=0

case "${ACME_PRODUCTION}" in
  1 | true | TRUE | yes | YES)
    use_production=1
    ACME_OUTPUT_DIR="${ACME_OUTPUT_DIR:-${SCRIPT_DIR}/certs/buckyos.io/production}"
    ;;
  0 | false | FALSE | no | NO)
    ACME_OUTPUT_DIR="${ACME_OUTPUT_DIR:-${SCRIPT_DIR}/certs/buckyos.io/staging}"
    ;;
  *)
    echo "错误：ACME_PRODUCTION 只能是 0/1、false/true 或 no/yes。" >&2
    exit 1
    ;;
esac

acme_args=(
  --zone "buckyos.io"
  --domain "*.buckyos.io"
  --email "${ACME_EMAIL}"
  --output "${ACME_OUTPUT_DIR}"
  --accept-terms
)
if [[ "${use_production}" == "1" ]]; then
  acme_args+=(--production)
fi

export GODADDY_PAT
cd -- "${SCRIPT_DIR}"
exec deno task start "${acme_args[@]}" "$@"
