#!/usr/bin/env bash

# Shared by the root-only systemd installation scripts. Never source a token file:
# EnvironmentFile syntax belongs to systemd, not to a shell.

fail() {
  printf '错误：%s\n' "$*" >&2
  exit 1
}

require_root() {
  [[ "${EUID}" == 0 ]] || fail '请使用 sudo 或 root 运行此脚本。'
}

validate_text() {
  local value="$1"
  [[ -n "$value" && ! "$value" =~ [[:cntrl:]] ]] || fail '参数不能为空或包含控制字符。'
}

validate_absolute_path() {
  validate_text "$1"
  [[ "$1" == /* && "$1" != / && "$1" != */ && "$1" != *//* &&
    "$1" != */./* && "$1" != */../* && "$1" != */. && "$1" != */.. ]] ||
    fail "必须使用不含 .、.. 或尾部斜杠的绝对路径：$1"
}

# Refuse symlinked and untrusted parent directories before writing root-owned
# service files. Root-owned sticky directories (e.g. /tmp) can contain a private
# deployment/test directory; the final directory itself must not be writable by
# other users. Existing directory permissions are preserved.
secure_directory() {
  local directory="$1" mode="${2:-0755}" create="${3:-yes}"
  local current='' part owner bits create_mode
  local -a components
  validate_absolute_path "$directory"
  IFS=/ read -r -a components <<< "${directory#/}"
  for part in "${components[@]}"; do
    current+="/$part"
    [[ ! -L "$current" ]] || fail "目录不能是符号链接：$current"
    if [[ ! -e "$current" ]]; then
      [[ "$create" == yes ]] || fail "目录不存在：$current"
      create_mode=0755
      [[ "$current" != "$directory" ]] || create_mode="$mode"
      mkdir -m "$create_mode" -- "$current"
    fi
    [[ -d "$current" ]] || fail "不是目录：$current"
    read -r owner bits < <(stat -c '%u %a' -- "$current")
    [[ "$owner" == 0 ]] || fail "目录必须由 root 拥有：$current"
    if (( (8#$bits & 0022) != 0 )); then
      [[ "$current" != "$directory" ]] && (( (8#$bits & 01000) != 0 )) ||
        fail "目录不能允许其他用户写入：$current"
    fi
  done
}

require_private_env_file() {
  local file="$1" owner bits
  validate_absolute_path "$file"
  secure_directory "${file%/*}" 0755 no
  [[ -f "$file" && ! -L "$file" ]] || fail "凭据文件不存在或不是普通文件：$file"
  read -r owner bits < <(stat -c '%u %a' -- "$file")
  [[ "$owner" == 0 && "$bits" == 600 ]] ||
    fail "凭据文件必须由 root 拥有且权限为 0600：$file"
}

# systemd unit strings support C-style backslash escapes and % specifiers.
# The installer disables ExecStart variable expansion with the ':' prefix.
unit_quote() {
  local value="$1"
  validate_text "$value"
  value="${value//\\/\\\\}"
  value="${value//\"/\\\"}"
  value="${value//%/%%}"
  printf '"%s"' "$value"
}
