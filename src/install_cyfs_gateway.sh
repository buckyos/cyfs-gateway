#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'

REPO="${REPO:-buckyos/cyfs-gateway}"
API_URL="https://api.github.com/repos/${REPO}/releases/latest"
INSTALL_DIR="${INSTALL_DIR:-/opt/buckyos}"
CONFIG_PATH="${CONFIG_PATH:-${INSTALL_DIR}/etc/cyfs_gateway.yaml}"
SERVICE_NAME="${SERVICE_NAME:-cyfs_gateway}"
SYSTEMD_UNIT_PATH="/etc/systemd/system/${SERVICE_NAME}.service"
LAUNCHD_PLIST_PATH="/Library/LaunchDaemons/${SERVICE_NAME}.plist"
PROFILED_PATH="/etc/profile.d/cyfs_gateway.sh"
PATHS_D_PATH="/etc/paths.d/cyfs_gateway"

log() { printf '%s\n' "$*"; }
err() { printf 'ERROR: %s\n' "$*" >&2; }
warn() { printf 'WARN: %s\n' "$*" >&2; }

require_cmd() {
	if ! command -v "$1" >/dev/null 2>&1; then
		err "Missing required command: $1"
		exit 1
	fi
}

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
	err "Please run as root (use sudo)."
	exit 1
fi

require_cmd curl
require_cmd tar
require_cmd python3
require_cmd uname
require_cmd mktemp

os_name="$(uname -s)"
os_slug=""
needs_systemd=0
needs_launchd=0
if [[ "$os_name" == "Darwin" ]]; then
	os_slug="apple"
	needs_launchd=1
elif [[ "$os_name" == "Linux" ]]; then
	if [[ ! -f /etc/os-release ]]; then
		err "Cannot detect Linux distribution (missing /etc/os-release)."
		exit 1
	fi
	. /etc/os-release
	case "${ID:-}" in
	debian | ubuntu)
		needs_systemd=1
		;;
	*)
		err "Unsupported Linux distribution: ${ID:-unknown} (only debian/ubuntu supported)."
		exit 1
		;;
	esac
	os_slug="linux"
else
	err "Unsupported OS: $os_name"
	exit 1
fi

arch_raw="$(uname -m)"
case "$arch_raw" in
x86_64 | amd64)
	arch="amd64"
	;;
arm64 | aarch64)
	arch="aarch64"
	;;
*)
	err "Unsupported architecture: $arch_raw"
	exit 1
	;;
esac

asset_name="gateway-${os_slug}-${arch}.tar.gz"

tmp_dir="$(mktemp -d)"
cleanup() {
	rm -rf "$tmp_dir"
}
trap cleanup EXIT

release_json_path="${tmp_dir}/release.json"
headers=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
	headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
	headers+=(-H "X-GitHub-Api-Version: 2022-11-28")
fi

log "Fetching latest release metadata from ${REPO}..."
http_status="$(curl -sS -w '%{http_code}' -o "$release_json_path" "${headers[@]}" "$API_URL" || true)"
if [[ "$http_status" != "200" ]]; then
	err "GitHub API request failed (HTTP ${http_status})."
	exit 1
fi

mapfile -t release_info < <(
	python3 - "$release_json_path" "$asset_name" <<'PY'
import json
import sys

path = sys.argv[1]
target = sys.argv[2]
with open(path, "r", encoding="utf-8") as f:
    data = json.load(f)

tag = data.get("tag_name", "")
asset_url = ""
for asset in data.get("assets", []):
    if asset.get("name") == target:
        asset_url = asset.get("browser_download_url", "")
        break

print(tag)
print(asset_url)
PY
)

tag="${release_info[0]:-}"
asset_url="${release_info[1]:-}"

if [[ -z "$asset_url" ]]; then
	err "Release asset not found: ${asset_name}"
	exit 1
fi

if [[ -n "$tag" ]]; then
	log "Latest tag: ${tag}"
fi
log "Downloading asset: ${asset_name}"

archive_path="${tmp_dir}/${asset_name}"
download_headers=()
if [[ -n "${GITHUB_TOKEN:-}" ]]; then
	download_headers+=(-H "Authorization: Bearer ${GITHUB_TOKEN}")
fi
curl -fSL "${download_headers[@]}" -o "$archive_path" "$asset_url"

extract_dir="${tmp_dir}/extract"
mkdir -p "$extract_dir"
tar -xzf "$archive_path" -C "$extract_dir"

gateway_bin_src="$(find "$extract_dir" -type f -name "cyfs_gateway" -print -quit || true)"
if [[ -z "$gateway_bin_src" ]]; then
	err "Cannot locate cyfs_gateway binary in archive."
	exit 1
fi

gateway_bin_rel="${gateway_bin_src#"$extract_dir"/}"
gateway_bin_dest="${INSTALL_DIR}/${gateway_bin_rel}"

log "Installing to ${INSTALL_DIR}"
mkdir -p "$INSTALL_DIR"

preserve_config=0
config_backup=""
if [[ -f "$CONFIG_PATH" ]]; then
	preserve_config=1
	config_backup="${tmp_dir}/cyfs_gateway.yaml.bak"
	cp -f "$CONFIG_PATH" "$config_backup"
fi

cp -a "$extract_dir/." "$INSTALL_DIR/"

if [[ "$preserve_config" -eq 1 ]]; then
	mkdir -p "$(dirname "$CONFIG_PATH")"
	cp -f "$config_backup" "$CONFIG_PATH"
	log "Preserved existing config: ${CONFIG_PATH}"
fi

if [[ -f "$gateway_bin_dest" ]]; then
	chmod 755 "$gateway_bin_dest"
fi

if [[ "$os_name" == "Darwin" ]]; then
	log "Updating PATH file: ${PATHS_D_PATH}"
	mkdir -p "$(dirname "$PATHS_D_PATH")"
	printf '%s\n' "/opt/buckyos/bin/cyfs-gateway" >"$PATHS_D_PATH"
else
	log "Updating PATH profile: ${PROFILED_PATH}"
	mkdir -p "$(dirname "$PROFILED_PATH")"
	printf 'export PATH="/opt/buckyos/bin/cyfs-gateway:$PATH"\n' >"$PROFILED_PATH"
fi

if [[ "$needs_systemd" -eq 1 ]]; then
	if command -v systemctl >/dev/null 2>&1; then
		log "Writing systemd unit: ${SYSTEMD_UNIT_PATH}"
		cat >"$SYSTEMD_UNIT_PATH" <<EOF
[Unit]
Description=CYFS Gateway
After=network.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=${gateway_bin_dest}
WorkingDirectory=${INSTALL_DIR}
Restart=on-failure
RestartSec=5
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
EOF
		systemctl daemon-reload
		log "systemd unit installed (not enabled or started)."
	else
		warn "systemctl not found; skipping systemd unit setup."
	fi
fi

if [[ "$needs_launchd" -eq 1 ]]; then
	log "Writing launchd plist: ${LAUNCHD_PLIST_PATH}"
	cat >"$LAUNCHD_PLIST_PATH" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>${SERVICE_NAME}</string>
  <key>ProgramArguments</key>
  <array>
    <string>${gateway_bin_dest}</string>
  </array>
  <key>WorkingDirectory</key>
  <string>${INSTALL_DIR}</string>
  <key>RunAtLoad</key>
  <false/>
  <key>KeepAlive</key>
  <false/>
</dict>
</plist>
EOF
	chmod 644 "$LAUNCHD_PLIST_PATH"
	log "launchd plist installed (not loaded)."
fi

if [[ "$os_name" == "Darwin" ]]; then
	log "PATH updated via ${PATHS_D_PATH}. Open a new terminal or log out/in to apply."
else
	log "PATH updated via ${PROFILED_PATH}. Run: source /etc/profile (or open a new shell)."
fi

log "Done."
