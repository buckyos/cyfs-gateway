#!/usr/bin/env bash

set -Eeuo pipefail
# Never allow bash -x / inherited xtrace to disclose the token.
set +x
umask 077

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
source "${SCRIPT_DIR}/service_helpers.sh"

env_file=/etc/buckyos/acme-godaddy.env
while (($#)); do
  case "$1" in
    --env-file)
      (($# >= 2)) || fail '--env-file 缺少路径。'
      env_file="$2"
      shift 2
      ;;
    -h | --help)
      printf '%s\n' \
        '用法：sudo ./setup_godaddy_token.sh [--env-file /absolute/path]' \
        '从终端隐藏输入 GoDaddy PAT，写入 root:root 0600 的 systemd EnvironmentFile。' \
        '默认文件：/etc/buckyos/acme-godaddy.env；现有服务将在下次启动时读取新值。'
      exit 0
      ;;
    *) fail "未知参数：$1" ;;
  esac
done

require_root
validate_absolute_path "$env_file"
env_dir="${env_file%/*}"
secure_directory "$env_dir" 0755
if [[ -e "$env_file" || -L "$env_file" ]]; then
  require_private_env_file "$env_file"
fi

temporary_file=''
token=''
escaped_token=''
cleanup() {
  unset token escaped_token
  [[ -z "$temporary_file" ]] || rm -f -- "$temporary_file"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

exec 3<> /dev/tty || fail '需要交互式终端以隐藏输入 token。'
printf '请输入 GoDaddy API token (PAT)：' >&3
IFS= read -r -s token <&3 || fail '未能读取 token。'
printf '\n' >&3
exec 3>&-
[[ -n "${token//[[:space:]]/}" && ! "$token" =~ [[:cntrl:]] ]] ||
  fail 'token 不能为空或包含控制字符。'

# Quoting follows systemd.exec(5) EnvironmentFile= double-quoted values.
# Do not use printf %q, which emits shell syntax unsupported by systemd.
escaped_token="${token//\\/\\\\}"
escaped_token="${escaped_token//\"/\\\"}"
escaped_token="${escaped_token//\$/\\\$}"
escaped_token="${escaped_token//\`/\\\`}"
temporary_file="$(mktemp -- "${env_dir}/.acme-godaddy.env.XXXXXX")"
printf 'GODADDY_PAT="%s"\n' "$escaped_token" > "$temporary_file"
chown root:root -- "$temporary_file"
chmod 0600 -- "$temporary_file"
mv -fT -- "$temporary_file" "$env_file"
temporary_file=''
unset token escaped_token
printf '已保存凭据：%s (root:root, 0600)。服务下次启动时自动读取。\n' "$env_file"
