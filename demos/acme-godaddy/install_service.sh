#!/usr/bin/env bash

set -Eeuo pipefail
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/service_helpers.sh"

usage() {
  cat <<'EOF'
用法：sudo ./install_service.sh [安装选项] --zone example.com \
  --domain example.com --domain '*.example.com' --email admin@example.com \
  --accept-terms [--production] [其他 main.ts 选项]

安装选项：
  --deno <absolute/path>       Deno 可执行文件（默认从 PATH 查找）
  --buckyos-root <path>        BuckyOS 根目录（默认 BUCKYOS_ROOT 或 /opt/buckyos）
  --env-file <absolute/path>   凭据文件（默认 /etc/buckyos/acme-godaddy.env）
  --unit-name <name>           systemd 单元名称（默认 acme-godaddy）
  --unit-dir <absolute/path>   单元目录（默认 /etc/systemd/system）
  --no-enable                 仅部署文件，不运行 systemctl（用于打包或测试）

先运行 setup_godaddy_token.sh。安装器创建 root oneshot 服务及每 12 小时
检查的 timer，并 enable timer；不会启动服务或 timer。安装后手动启动：
  sudo systemctl start acme-godaddy.service
  sudo systemctl start acme-godaddy.timer
不指定 --production 时，证书写入隔离的 staging 目录。
EOF
}

buckyos_root="${BUCKYOS_ROOT:-/opt/buckyos}"
env_file=/etc/buckyos/acme-godaddy.env
unit_name=acme-godaddy
unit_dir=/etc/systemd/system
deno_bin=''
enable_timer=yes
have_zone=no
have_domain=no
have_email=no
have_terms=no
acme_args=()
configured_roots=()

while (($#)); do
  case "$1" in
    --deno | --buckyos-root | --env-file | --unit-name | --unit-dir)
      (($# >= 2)) || fail "$1 缺少值。"
      validate_text "$2"
      case "$1" in
        --deno) deno_bin="$2" ;;
        --buckyos-root) buckyos_root="$2" ;;
        --env-file) env_file="$2" ;;
        --unit-name) unit_name="$2" ;;
        --unit-dir) unit_dir="$2" ;;
      esac
      shift 2
      ;;
    --zone | -z | --domain | -d | --email | -e | --identity-root | --security-root | --state-root | \
      --directory-url | --renew-before-days | --propagation-timeout | --propagation-interval | \
      --propagation-delay)
      (($# >= 2)) || fail "$1 缺少值。"
      validate_text "$2"
      [[ "$2" != --* ]] || fail "$1 缺少值。"
      case "$1" in
        --zone | -z) have_zone=yes ;;
        --domain | -d) have_domain=yes ;;
        --email | -e) have_email=yes ;;
        --identity-root | --security-root | --state-root)
          validate_absolute_path "$2"
          configured_roots+=("$2")
          ;;
      esac
      acme_args+=("$1" "$2")
      shift 2
      ;;
    --accept-terms)
      have_terms=yes
      acme_args+=("$1")
      shift
      ;;
    --production | --verbose | -v)
      acme_args+=("$1")
      shift
      ;;
    --force) fail '定时服务不能配置 --force，以免每次运行都强制签发；请手动运行 main.ts。' ;;
    --no-enable) enable_timer=no; shift ;;
    -h | --help) usage; exit 0 ;;
    *) fail "未知参数：$1（请使用 --option value 格式）" ;;
  esac
done

require_root
[[ "$have_zone" == yes && "$have_domain" == yes && "$have_email" == yes && "$have_terms" == yes ]] ||
  fail '需要 --zone、至少一个 --domain、--email 和 --accept-terms。'
[[ "$unit_name" =~ ^[a-zA-Z0-9][a-zA-Z0-9_-]*$ ]] || fail '无效的 --unit-name。'
validate_absolute_path "$buckyos_root"
validate_absolute_path "$unit_dir"
require_private_env_file "$env_file"

if [[ -z "$deno_bin" ]]; then
  deno_bin="$(command -v deno)" || fail '找不到 deno；请通过 --deno 指定绝对路径。'
fi
deno_bin="$(readlink -f -- "$deno_bin")"
validate_absolute_path "$deno_bin"
[[ -f "$deno_bin" && -x "$deno_bin" ]] || fail 'Deno 必须是可执行的普通文件。'
secure_directory "${deno_bin%/*}" 0755 no
read -r deno_owner deno_mode < <(stat -c '%u %a' -- "$deno_bin")
[[ "$deno_owner" == 0 ]] && (( (8#$deno_mode & 0022) == 0 )) ||
  fail 'root 服务使用的 Deno 必须由 root 拥有且不能允许其他用户写入。'

source_dir="${buckyos_root}/libexec/acme-godaddy"
cache_dir="${buckyos_root}/var/cache/acme-godaddy"
secure_directory "$source_dir" 0755
secure_directory "$cache_dir" 0700
secure_directory "$unit_dir" 0755
for root in "${configured_roots[@]}"; do
  secure_directory "$root" 0755
done

# Deploy only runtime source files, never local certificate files, credentials,
# node_modules, or tests. Runtime dependencies use the frozen lock and DENO_DIR.
for file in "${SCRIPT_DIR}"/*.ts "${SCRIPT_DIR}/deno.json" "${SCRIPT_DIR}/deno.lock"; do
  [[ "$file" != *_test.ts ]] || continue
  destination="${source_dir}/${file##*/}"
  [[ ! -L "$destination" && ( ! -e "$destination" || -f "$destination" ) ]] ||
    fail "拒绝覆盖非普通文件：$destination"
  install -o root -g root -m 0644 -- "$file" "$destination"
done

acme_args+=(--buckyos-root "$buckyos_root")
temporary_service=''
temporary_timer=''
cleanup() {
  [[ -z "$temporary_service" ]] || rm -f -- "$temporary_service"
  [[ -z "$temporary_timer" ]] || rm -f -- "$temporary_timer"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
temporary_service="$(mktemp -- "${unit_dir}/.${unit_name}.service.XXXXXX")"
temporary_timer="$(mktemp -- "${unit_dir}/.${unit_name}.timer.XXXXXX")"

{
  printf '%s\n' '[Unit]' 'Description=GoDaddy ACME certificate renewal for BuckyOS' \
    'Wants=network-online.target' 'After=network-online.target' '' \
    '[Service]' 'Type=oneshot' 'User=root' 'Group=root' 'UMask=0022' 'NoNewPrivileges=true'
  # These directives take a single literal path, including any spaces or quotes.
  # Escape only % specifiers; word-list quoting makes EnvironmentFile non-absolute.
  printf 'WorkingDirectory=%s\n' "${source_dir//%/%%}"
  printf 'EnvironmentFile=%s\n' "${env_file//%/%%}"
  printf 'Environment=%s\n' "$(unit_quote "BUCKYOS_ROOT=$buckyos_root")" \
    "$(unit_quote "DENO_DIR=$cache_dir")"
  printf 'ExecStart=:%s run --no-prompt --frozen --node-modules-dir=none --allow-env --allow-net --allow-read --allow-write' \
    "$(unit_quote "$deno_bin")"
  printf ' %s' "$(unit_quote "${source_dir}/main.ts")"
  for arg in "${acme_args[@]}"; do
    printf ' %s' "$(unit_quote "$arg")"
  done
  printf '\nTimeoutStartSec=30min\n'
} > "$temporary_service"

{
  printf '%s\n' '[Unit]' 'Description=Check BuckyOS ACME certificates every 12 hours' '' \
    '[Timer]' 'OnCalendar=*-*-* 00,12:00:00' 'RandomizedDelaySec=30min' 'Persistent=true'
  printf 'Unit=%s.service\n' "$unit_name"
  printf '%s\n' '' '[Install]' 'WantedBy=timers.target'
} > "$temporary_timer"

for file in "$temporary_service" "$temporary_timer"; do
  chown root:root -- "$file"
  chmod 0644 -- "$file"
done
for target in "${unit_dir}/${unit_name}.service" "${unit_dir}/${unit_name}.timer"; do
  [[ ! -L "$target" && ( ! -e "$target" || -f "$target" ) ]] ||
    fail "拒绝覆盖非普通单元文件：$target"
done
mv -fT -- "$temporary_service" "${unit_dir}/${unit_name}.service"
temporary_service=''
mv -fT -- "$temporary_timer" "${unit_dir}/${unit_name}.timer"
temporary_timer=''

if [[ "$enable_timer" == yes ]]; then
  systemctl daemon-reload
  systemctl enable "${unit_dir}/${unit_name}.timer"
fi
printf '已部署 root 服务：%s.service；每 12 小时检查的 timer 已%s。\n' \
  "$unit_name" "$([[ "$enable_timer" == yes ]] && printf enable || printf '写入文件')"
printf '开始签发和定时续期：\n  sudo systemctl start %s.service\n  sudo systemctl start %s.timer\n' \
  "$unit_name" "$unit_name"
