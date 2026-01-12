#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV_FILE="${ENV_FILE:-${SCRIPT_DIR}/.env}"

if [[ -f "$ENV_FILE" ]]; then
  # shellcheck disable=SC1090
  set -a
  . "$ENV_FILE"
  set +a
else
  echo "ERROR: .env file not found at ${ENV_FILE}" >&2
  exit 1
fi

# Repo and asset selection
REPO="${REPO:-buckyos/cyfs-gateway}"
ASSET_PATTERN="${ASSET_PATTERN:-^web3-gateway-.*\\.tar\\.gz$}"
ASSET_NAME="${ASSET_NAME:-}"

# Install target and optional service restart
INSTALL_PATH="${INSTALL_PATH:-}"
SERVICE_NAME="${SERVICE_NAME:-}"
CONFIG_NAME="${CONFIG_NAME:-web3_gateway.yaml}"

if [[ -z "$INSTALL_PATH" ]]; then
  echo "ERROR: INSTALL_PATH is required. Set it in ${ENV_FILE}." >&2
  exit 1
fi

CONFIG_PATH="${CONFIG_PATH:-$(dirname "$INSTALL_PATH")/${CONFIG_NAME}}"
BACKUP_DIR="${BACKUP_DIR:-$(dirname "$INSTALL_PATH")/bak}"

echo "Loaded env from ${ENV_FILE}:"
echo "  REPO=${REPO}"
echo "  ASSET_PATTERN=${ASSET_PATTERN}"
echo "  ASSET_NAME=${ASSET_NAME}"
echo "  INSTALL_PATH=${INSTALL_PATH}"
echo "  SERVICE_NAME=${SERVICE_NAME}"
echo "  CONFIG_NAME=${CONFIG_NAME}"
echo "  CONFIG_PATH=${CONFIG_PATH}"
echo "  BACKUP_DIR=${BACKUP_DIR}"
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  echo "  GITHUB_TOKEN=***"
else
  echo "  GITHUB_TOKEN="
fi

# Use a per-run temp directory so downloads/extraction never touch the live path.
# It is always removed on exit to avoid leaving partial files on failure.
tmp_dir="$(mktemp -d)"
cleanup() {
  rm -rf "$tmp_dir"
}
trap cleanup EXIT

# Use GitHub API to find latest release assets
api_url="https://api.github.com/repos/${REPO}/releases/latest"
headers=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  # Token is optional for public repos; required for private or rate limits.
  headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  headers+=(-H "X-GitHub-Api-Version: 2022-11-28")
fi

echo "Fetching latest release metadata from ${REPO}..."
release_json_path="${tmp_dir}/release.json"
api_status="$(curl -sS -w '%{http_code}' -o "$release_json_path" "${headers[@]}" "$api_url" || true)"
release_json="$(cat "$release_json_path" 2>/dev/null || true)"
if [[ "$api_status" != "200" ]]; then
  echo "ERROR: GitHub API request failed (HTTP ${api_status})." >&2
  echo "Response preview: $(printf '%s' "$release_json" | head -c 200)" >&2
  exit 1
fi
if [[ -z "$release_json" ]]; then
  echo "ERROR: Empty response from GitHub API." >&2
  exit 1
fi
if [[ "${release_json:0:1}" != "{" ]]; then
  echo "ERROR: Non-JSON response from GitHub API." >&2
  echo "Response preview: $(printf '%s' "$release_json" | head -c 200)" >&2
  exit 1
fi

# Select the asset from latest release metadata.
if [[ -n "$ASSET_NAME" ]]; then
  echo "Selecting asset by name: ${ASSET_NAME}"
else
  echo "Selecting asset by pattern: ${ASSET_PATTERN}"
fi

mapfile -t asset_info < <(ASSET_PATTERN="$ASSET_PATTERN" ASSET_NAME="$ASSET_NAME" python3 - "$release_json_path" <<'PY'
import json
import os
import re
import sys

asset_name = os.environ.get("ASSET_NAME", "")
pattern = os.environ.get("ASSET_PATTERN", "")
regex = re.compile(pattern) if pattern else None

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

selected = None
for asset in data.get("assets", []):
    name = asset.get("name", "")
    if asset_name:
        if name == asset_name:
            selected = asset
            break
    elif regex and regex.match(name):
        selected = asset
        break

if selected:
    print(selected.get("browser_download_url", ""))
    print(selected.get("url", ""))
    print(selected.get("name", ""))
PY
)

asset_url="${asset_info[0]:-}"
asset_api_url="${asset_info[1]:-}"
asset_name="${asset_info[2]:-}"

# If ASSET_NAME is set but not found in the API response, fall back to the
# stable latest/download URL (may still fail if the asset does not exist).
if [[ -n "$ASSET_NAME" && -z "$asset_url" ]]; then
  asset_url="https://github.com/${REPO}/releases/latest/download/${ASSET_NAME}"
fi

if [[ -z "$asset_url" ]]; then
  echo "ERROR: No matching asset found." >&2
  python3 - "$release_json_path" <<'PY' >&2
import json
import sys

path = sys.argv[1]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

tag = data.get("tag_name")
assets = data.get("assets", [])
print(f"Latest tag: {tag}")
print("Available assets:")
for asset in assets:
    print(f" - {asset.get('name', '')}")
PY
  exit 1
fi

archive_path="${tmp_dir}/asset.tar.gz"
extract_dir="${tmp_dir}/extract"
mkdir -p "$extract_dir"

if [[ -z "$asset_api_url" ]]; then
  echo "ERROR: Unable to download asset (no asset API URL)." >&2
  exit 1
fi

echo "Downloading via GitHub API: ${asset_api_url}"
api_download_headers=(-H "Accept: application/octet-stream" -H "User-Agent: sync.sh")
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
  api_download_headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
  api_download_headers+=(-H "X-GitHub-Api-Version: 2022-11-28")
fi
curl -fSL \
  "${api_download_headers[@]}" \
  -o "$archive_path" \
  "$asset_api_url"
echo "Extracting..."
tar -xzf "$archive_path" -C "$extract_dir"

# Locate the binary in the extracted tree.
bin_path=""
bin_path="$(find "$extract_dir" -type f \( -name 'web3_gateway' -o -name 'web3-gateway' \) -print -quit || true)"
if [[ -z "$bin_path" ]]; then
  # Fallback: first executable file if the name is different.
  bin_path="$(find "$extract_dir" -type f -perm -111 -print -quit || true)"
fi
config_path="$(find "$extract_dir" -type f -name "${CONFIG_NAME}" -print -quit || true)"

if [[ -z "$bin_path" ]]; then
  echo "ERROR: Unable to locate binary in archive." >&2
  exit 1
fi

echo "Found binary: ${bin_path}"
if [[ -f "$INSTALL_PATH" ]]; then
  # Back up existing binary for quick rollback.
  mkdir -p "$BACKUP_DIR"
  backup_path="${BACKUP_DIR}/web3_gateway.bak.$(date +%Y%m%d%H%M%S)"
  echo "Backing up existing binary to ${backup_path}"
  cp -f "$INSTALL_PATH" "$backup_path"
fi

echo "Installing to ${INSTALL_PATH}"
install -m 755 "$bin_path" "$INSTALL_PATH"

if [[ -n "$config_path" ]]; then
  if [[ -f "$CONFIG_PATH" ]]; then
    mkdir -p "$BACKUP_DIR"
    config_backup="${BACKUP_DIR}/${CONFIG_NAME}.bak.$(date +%Y%m%d%H%M%S)"
    echo "Backing up existing config to ${config_backup}"
    cp -f "$CONFIG_PATH" "$config_backup"
  fi
  echo "Installing config to ${CONFIG_PATH}"
  install -m 644 "$config_path" "$CONFIG_PATH"
else
  echo "WARN: ${CONFIG_NAME} not found in archive, skip config update." >&2
fi

if [[ -n "$SERVICE_NAME" ]]; then
  if command -v systemctl >/dev/null 2>&1; then
    # Service restart is optional and controlled via SERVICE_NAME.
    echo "Current service status: ${SERVICE_NAME}"
    systemctl status "$SERVICE_NAME" --no-pager || true
    read -r -p "Restart service ${SERVICE_NAME}? (y/N): " restart_answer
    if [[ "${restart_answer}" == "y" || "${restart_answer}" == "Y" ]]; then
      echo "Restarting service: ${SERVICE_NAME}"
      systemctl restart "$SERVICE_NAME"
      systemctl status "$SERVICE_NAME" --no-pager || true

      check_port_53() {
        if ! command -v lsof >/dev/null 2>&1; then
          echo "WARN: lsof not found, skip port check." >&2
          return 0
        fi
        lsof -i :53 -i :domain 2>/dev/null || true
      }

      echo "Checking port 53..."
      port_output="$(check_port_53)"
      if [[ -z "$port_output" ]]; then
        echo "Port 53 check failed after restart. Details:"
        lsof -i :53 -i :domain || true
        echo "Restarting service again: ${SERVICE_NAME}"
        systemctl restart "$SERVICE_NAME"
        systemctl status "$SERVICE_NAME" --no-pager || true
        echo "Re-checking port 53..."
        port_output="$(check_port_53)"
        if [[ -n "$port_output" ]]; then
          echo "Port 53 is now OK."
        else
          echo "ERROR: Port 53 still not listening after second restart." >&2
        fi
      else
        echo "Port 53 is OK."
      fi
    else
      echo "Restart skipped."
    fi
  else
    echo "WARN: systemctl not found, skip restart." >&2
  fi
else
  echo "SERVICE_NAME not set, skip restart."
fi

echo "Done."
