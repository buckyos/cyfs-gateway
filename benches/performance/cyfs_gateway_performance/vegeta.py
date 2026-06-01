from __future__ import annotations

import json
import os
import platform
import shutil
import stat
import tarfile
import tempfile
import urllib.request
from pathlib import Path


LATEST_RELEASE_URL = "https://api.github.com/repos/tsenart/vegeta/releases/latest"


class VegetaUnavailable(RuntimeError):
    pass


def ensure_vegeta() -> tuple[Path, dict]:
    configured = os.environ.get("CYFS_VEGETA_PATH")
    if configured:
        path = Path(configured)
        if path.exists():
            return path, {"source": "env", "path": str(path)}
        raise VegetaUnavailable(f"CYFS_VEGETA_PATH does not exist: {path}")

    existing = shutil.which("vegeta")
    if existing:
        return Path(existing), {"source": "path", "path": existing}

    cache_root = Path(os.environ.get("CYFS_VEGETA_CACHE", "/tmp/cyfs-gateway-performance/vegeta"))
    cached = cache_root / "vegeta"
    if cached.exists():
        return cached, {"source": "cache", "path": str(cached)}

    return _download_latest(cache_root)


def _download_latest(cache_root: Path) -> tuple[Path, dict]:
    system = _vegeta_os()
    arch = _vegeta_arch()
    with _urlopen(LATEST_RELEASE_URL, timeout=30) as response:
        release = json.loads(response.read().decode("utf-8"))
    tag = str(release.get("tag_name") or "")
    version = tag.removeprefix("v")
    asset = _select_asset(release, system, arch)
    url = asset.get("browser_download_url")
    if not isinstance(url, str) or not url:
        raise VegetaUnavailable(f"latest vegeta release has no {system}/{arch} download URL")

    cache_root.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="vegeta-download-") as temp_dir:
        archive = Path(temp_dir) / "vegeta.tar.gz"
        with _urlopen(url, timeout=120) as response:
            archive.write_bytes(response.read())
        extracted = Path(temp_dir) / "extract"
        extracted.mkdir()
        with tarfile.open(archive, "r:gz") as tar:
            _safe_extract(tar, extracted)
        binary = _find_vegeta_binary(extracted)
        target = cache_root / "vegeta"
        shutil.copy2(binary, target)
        target.chmod(target.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return target, {
        "source": "github-release",
        "path": str(target),
        "release": tag,
        "version": version,
        "asset": asset.get("name"),
        "download_url": url,
    }


def _urlopen(url: str, timeout: int):
    request = urllib.request.Request(url, headers={"User-Agent": "cyfs-gateway-performance"})
    return urllib.request.urlopen(request, timeout=timeout)


def _select_asset(release: dict, system: str, arch: str) -> dict:
    suffix = f"_{system}_{arch}.tar.gz"
    for asset in release.get("assets") or []:
        name = asset.get("name")
        if isinstance(name, str) and name.endswith(suffix):
            return asset
    raise VegetaUnavailable(f"latest vegeta release does not include asset matching *{suffix}")


def _vegeta_os() -> str:
    system = platform.system().lower()
    if system in {"linux", "darwin", "freebsd"}:
        return system
    raise VegetaUnavailable(f"unsupported vegeta platform: {platform.system()}")


def _vegeta_arch() -> str:
    machine = platform.machine().lower()
    if machine in {"x86_64", "amd64"}:
        return "amd64"
    if machine in {"aarch64", "arm64"}:
        return "arm64"
    if machine in {"i386", "i686", "x86"}:
        return "386"
    if machine.startswith("arm"):
        return "arm"
    raise VegetaUnavailable(f"unsupported vegeta architecture: {platform.machine()}")


def _safe_extract(tar: tarfile.TarFile, target: Path) -> None:
    root = target.resolve()
    for member in tar.getmembers():
        destination = (target / member.name).resolve()
        if not destination.is_relative_to(root):
            raise VegetaUnavailable(f"unsafe vegeta archive member: {member.name}")
    tar.extractall(target)


def _find_vegeta_binary(root: Path) -> Path:
    for path in root.rglob("vegeta"):
        if path.is_file():
            return path
    raise VegetaUnavailable("downloaded vegeta archive did not contain a vegeta binary")
