# 下载并升级最新 GitHub Release 说明

本文档说明 `download_and_upgrade_latest_release.sh` 与 GitHub Release 的关系和使用方式。
如使用 `sync.sh`，配置与流程相同。

## 与 GitHub Release 的关系
- 通过 GitHub API `GET /repos/{owner}/{repo}/releases/latest` 获取最新 Release 元数据。
- 从最新 Release 的 assets 中选择一个匹配的压缩包：
  - 优先用 `ASSET_NAME` 精确匹配。
  - 否则用 `ASSET_PATTERN` 正则匹配（默认 `^web3-gateway-.*\\.tar\\.gz$`）。
- 使用 asset 的 API 下载地址下载压缩包（`Accept: application/octet-stream`）。

## 运行前准备
- 同目录下的 `.env` 为模板，字段内容留空，请在服务器上填写实际值。
- **必须**设置 `INSTALL_PATH`（避免在脚本里暴露目录结构）。
- 建议设置 `GITHUB_TOKEN`，以避免 API 限流或访问私有仓库失败。

## .env 字段说明
仓库里的 `.env` 仅作为模板文件，部署时请在服务器上填写真实配置。

必填：
- `INSTALL_PATH`：安装的二进制路径（例如 `/opt/web3_bridge/web3_gateway`）。
- `GITHUB_TOKEN`：GitHub PAT（可选但推荐；私有仓库必填）。

可选：
- `REPO`：仓库名（默认 `buckyos/cyfs-gateway`）。
- `ASSET_PATTERN`：Release 资产正则。
- `ASSET_NAME`：指定固定资产名。
- `SERVICE_NAME`：systemd 服务名（用于重启）。
- `CONFIG_NAME`：配置文件名（默认 `web3_gateway.yaml`）。
- `CONFIG_PATH`：配置文件安装路径。
- `BACKUP_DIR`：备份目录（默认 `$(dirname INSTALL_PATH)/bak`）。

## 执行流程摘要
1) 拉取最新 Release 元数据并选择资产。
2) 下载并解压压缩包到临时目录。
3) 替换二进制和 `web3_gateway.yaml`（如存在），并在 `BACKUP_DIR` 备份旧文件。
4) 可选：交互式重启服务并检查 53 端口占用情况。

## SN 服务器更新流程（从源码 Release 拉取）
适用于 SN 服务器仅拉取 Release 产物升级，不在服务器本地构建二进制。

步骤：
1) 在服务器上准备 `.env`，填写 `INSTALL_PATH`、`GITHUB_TOKEN`（推荐）等字段。
2) 运行 `download_and_upgrade_latest_release.sh`（或 `sync.sh`），脚本将：
   - 从 GitHub Release 拉取最新打包产物；
   - 解压并覆盖二进制与 `web3_gateway.yaml`；
   - 自动备份旧文件到 `BACKUP_DIR`；
   - 按需重启服务并检查 53 端口占用。
3) 验证服务状态与端口监听情况，确保 DNS 53/HTTP/TLS 端口恢复正常。

注意：
- 该流程避免在 SN 服务器执行 `cargo`/`buckyos-build`，减少环境依赖与构建时间。
- Release 产物由 CI 统一构建，确保版本一致性。

## 注意事项
- Release 中的压缩包需包含可执行文件 `web3_gateway` 和可选的 `web3_gateway.yaml`。
- `GITHUB_TOKEN` 不要提交到仓库，建议仅保存在服务器的 `.env` 中。
