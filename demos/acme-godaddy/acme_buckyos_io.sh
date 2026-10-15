#!/usr/bin/env bash

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

# 默认使用 Let's Encrypt production；需要再次测试 staging 时执行：
# ACME_PRODUCTION=0 ./acme_buckyos_io.sh
ACME_PRODUCTION="${ACME_PRODUCTION:-1}"
ACME_EMAIL="${ACME_EMAIL:-ops@buckyos.ai}"
use_production=0

case "${ACME_PRODUCTION}" in
  1 | true | TRUE | yes | YES)
    use_production=1
    ;;
  0 | false | FALSE | no | NO)
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
  --accept-terms
)
if [[ "${use_production}" == "1" ]]; then
  acme_args+=(--production)
fi

cd -- "${SCRIPT_DIR}"
exec deno task start "${acme_args[@]}" "$@"
