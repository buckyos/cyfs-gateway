# cyfs-gateway

## Install with `install_cyfs_gateway.sh`

The installer supports Debian/Ubuntu Linux and macOS on x86_64 (amd64) and
ARM64 (aarch64). It requires Bash, `curl`, `tar`, `awk`, `uname`, and `mktemp`,
and must be run as root (for example, with `sudo`).

Install the latest GitHub release directly using the installer from the `main` branch:

```bash
curl -fsSL https://raw.githubusercontent.com/buckyos/cyfs-gateway/main/src/install_cyfs_gateway.sh | sudo bash
```

To install a specific release, pass its tag (replace `v1.2.3` with an existing release tag):

```bash
curl -fsSL https://raw.githubusercontent.com/buckyos/cyfs-gateway/main/src/install_cyfs_gateway.sh | sudo bash -s -- --version v1.2.3
```

Files are installed under `/opt/buckyos` by default. An existing
`/opt/buckyos/etc/cyfs_gateway.yaml` is preserved. If `cyfs_gateway` is already
running, the installer asks for confirmation in an interactive terminal before
stopping it.

The installer creates a service definition but does not start it. After reviewing
the configuration, start the service with the command for your platform:

```bash
# Debian/Ubuntu with systemd: enable at boot and start now
sudo systemctl enable --now cyfs_gateway

# macOS: load the launchd service
sudo launchctl bootstrap system /Library/LaunchDaemons/cyfs_gateway.plist
```

Open a new terminal to pick up the PATH change. On Linux, you can also run
`source /etc/profile` in the current shell.

## Development

Development Python scripts now follow the same `uv run` pattern as `buckyos`.

Examples:

```bash
cd src
uv run ./buckyos-build.py
uv run ./buckyos-install.py
```

## License

First-party code is licensed under [Apache-2.0](LICENSE). Third-party code and
dependencies retain their own licenses; see [NOTICE](NOTICE).
The independent [Adblock Plus test/example](src/components/cyfs-socks/pac/readme.md)
remains GPL-3.0-only. The vendored CryptoJS files remain MIT licensed.
