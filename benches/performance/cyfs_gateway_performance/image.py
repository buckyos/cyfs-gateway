from __future__ import annotations

from pathlib import Path

from .model import BenchmarkPlan, CommandPlan, ConfigError


FIXTURE_CARGO_TOML = """[package]
name = "cyfs-perf-reverse-proxy-fixture"
version = "0.1.0"
edition = "2021"

[workspace]

[dependencies]
"""


FIXTURE_MAIN_RS = r'''use std::env;
use std::io::{Read, Write};
use std::net::{Shutdown, TcpListener, TcpStream};
use std::thread;

fn main() -> std::io::Result<()> {
    let http_addr = listen_addr("HTTP_PORT", "0.0.0.0:8080");
    let stream_addr = listen_addr("STREAM_PORT", "0.0.0.0:9000");

    let http_thread = thread::spawn(move || serve_http(&http_addr));
    let stream_thread = thread::spawn(move || serve_stream(&stream_addr));

    http_thread.join().expect("http fixture thread panicked")?;
    stream_thread.join().expect("stream fixture thread panicked")?;
    Ok(())
}

fn listen_addr(port_var: &str, default_addr: &str) -> String {
    match env::var(port_var) {
        Ok(port) if port.contains(':') => port,
        Ok(port) if !port.is_empty() => format!("0.0.0.0:{port}"),
        _ => default_addr.to_owned(),
    }
}

fn serve_http(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle_http(stream);
                });
            }
            Err(err) => eprintln!("http accept failed: {err}"),
        }
    }
    Ok(())
}

fn handle_http(mut stream: TcpStream) -> std::io::Result<()> {
    let mut request = Vec::new();
    let mut buffer = [0_u8; 4096];
    let header_end;

    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            return Ok(());
        }
        request.extend_from_slice(&buffer[..read]);
        if let Some(pos) = find_header_end(&request) {
            header_end = pos;
            break;
        }
        if request.len() > 1024 * 1024 {
            header_end = request.len();
            break;
        }
    }

    let content_length = parse_content_length(&request[..header_end]).unwrap_or(0);
    while request.len() < header_end + content_length {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        request.extend_from_slice(&buffer[..read]);
    }

    let received_body = if request.len() > header_end {
        &request[header_end..]
    } else {
        &[]
    };
    let response_body = if received_body.is_empty() {
        request.as_slice()
    } else {
        received_body
    };
    write!(
        stream,
        "HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
        response_body.len()
    )?;
    stream.write_all(response_body)?;
    stream.flush()?;
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn serve_stream(addr: &str) -> std::io::Result<()> {
    let listener = TcpListener::bind(addr)?;
    for stream in listener.incoming() {
        match stream {
            Ok(stream) => {
                thread::spawn(move || {
                    let _ = handle_stream(stream);
                });
            }
            Err(err) => eprintln!("stream accept failed: {err}"),
        }
    }
    Ok(())
}

fn handle_stream(mut stream: TcpStream) -> std::io::Result<()> {
    let mut buffer = [0_u8; 16 * 1024];
    loop {
        let read = stream.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        stream.write_all(&buffer[..read])?;
    }
    let _ = stream.shutdown(Shutdown::Both);
    Ok(())
}

fn find_header_end(data: &[u8]) -> Option<usize> {
    data.windows(4).position(|window| window == b"\r\n\r\n").map(|pos| pos + 4)
}

fn parse_content_length(headers: &[u8]) -> Option<usize> {
    let text = std::str::from_utf8(headers).ok()?;
    for line in text.lines() {
        if let Some((name, value)) = line.split_once(':') {
            if name.eq_ignore_ascii_case("content-length") {
                return value.trim().parse().ok();
            }
        }
    }
    None
}
'''


def _write_candidate_configs(plan: BenchmarkPlan, image_key: str, config_dir: Path) -> None:
    http_port = int((plan.upstream.get("http_fixture") or {}).get("port") or 8080)
    stream_port = int((plan.upstream.get("stream_fixture") or {}).get("port") or 9000)
    proxy_path = str((plan.scenarios.get("http_reverse_proxy") or {}).get("path") or "/proxy/payload")
    proxy_prefix = proxy_path.rsplit("/", 1)[0] or "/"
    common_name = _tls_common_name(plan)
    if image_key == "nginx":
        (config_dir / "default.conf").write_text(
            f"""server {{
    listen 80;
    root /etc/cyfs-perf/static;

    location {proxy_prefix}/ {{
        proxy_pass http://127.0.0.1:{http_port};
    }}

    location / {{
        try_files $uri =404;
    }}
}}

server {{
    listen 443 ssl;
    server_name {common_name};
    root /etc/cyfs-perf/static;
    ssl_certificate /etc/cyfs-perf/tls.crt;
    ssl_certificate_key /etc/cyfs-perf/tls.key;

    location {proxy_prefix}/ {{
        proxy_pass http://127.0.0.1:{http_port};
    }}

    location / {{
        try_files $uri =404;
    }}
}}
""",
            encoding="utf-8",
        )
        (config_dir / "nginx.conf").write_text(
            f"""events {{
    worker_connections 4096;
}}

http {{
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    sendfile on;
    include /etc/nginx/conf.d/*.conf;
}}

stream {{
    server {{
        listen 9080;
        proxy_pass 127.0.0.1:{stream_port};
    }}

    server {{
        listen 9443 ssl;
        ssl_certificate /etc/cyfs-perf/tls.crt;
        ssl_certificate_key /etc/cyfs-perf/tls.key;
        proxy_pass 127.0.0.1:{stream_port};
    }}
}}
""",
            encoding="utf-8",
        )
    else:
        (config_dir / "gateway.yaml").write_text(
            f"""stacks:
  perf_http:
    bind: 0.0.0.0:80
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              http-probe && return "server perf_http_server";
              reject;
  perf_https:
    bind: 0.0.0.0:443
    protocol: tls
    certs:
      - domain: "*"
        cert_path: /etc/cyfs-perf/tls.crt
        key_path: /etc/cyfs-perf/tls.key
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "server perf_http_server";
  perf_stream_tcp:
    bind: 0.0.0.0:9080
    protocol: tcp
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward tcp:///127.0.0.1:{stream_port}";
  perf_stream_tls:
    bind: 0.0.0.0:9443
    protocol: tls
    certs:
      - domain: "*"
        cert_path: /etc/cyfs-perf/tls.crt
        key_path: /etc/cyfs-perf/tls.key
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "forward tcp:///127.0.0.1:{stream_port}";

servers:
  perf_http_server:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              starts-with ${{REQ.path}} "{proxy_prefix}/" && forward http://127.0.0.1:{http_port};
              call-server perf_static_files;
  perf_static_files:
    type: dir
    root_path: /etc/cyfs-perf/static
    index_file: index.html
    autoindex: false
    etag: true
""",
            encoding="utf-8",
        )


def _tls_common_name(plan: BenchmarkPlan) -> str:
    tls = (plan.generated_config.get("tls") or {}) if isinstance(plan.generated_config, dict) else {}
    return str(tls.get("common_name") or "perf.local")


def _static_file_specs(plan: BenchmarkPlan) -> list[dict]:
    static_cfg = (plan.generated_config.get("static_files") or {}) if isinstance(plan.generated_config, dict) else {}
    files = static_cfg.get("files")
    if not isinstance(files, list) or not files:
        return [{"path": "index.html", "size_bytes": 4096}]
    return [item for item in files if isinstance(item, dict)]


def write_static_files(plan: BenchmarkPlan, config_dir: Path) -> dict:
    static_dir = config_dir / "static"
    static_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for item in _static_file_specs(plan):
        rel_path = str(item.get("path") or "index.html").lstrip("/")
        size = int(item.get("size_bytes") or 0)
        if size <= 0:
            size = 4096
        target = static_dir / rel_path
        target.parent.mkdir(parents=True, exist_ok=True)
        seed = f"cyfs performance static file: {rel_path}\n".encode("utf-8")
        data = (seed * ((size // len(seed)) + 1))[:size]
        target.write_bytes(data)
        written.append({"path": rel_path, "size_bytes": size, "output": str(target)})
    return {"root": str(static_dir), "files": written}


def tls_certificate_commands(plan: BenchmarkPlan, context: Path) -> list[CommandPlan]:
    common_name = _tls_common_name(plan)
    generated = context / "generated"
    return [
        CommandPlan(
            "generate test tls certificate",
            (
                "openssl",
                "req",
                "-x509",
                "-nodes",
                "-newkey",
                "rsa:2048",
                "-keyout",
                str(generated / "tls.key"),
                "-out",
                str(generated / "tls.crt"),
                "-days",
                "7",
                "-subj",
                f"/CN={common_name}",
                "-addext",
                f"subjectAltName=DNS:{common_name},IP:127.0.0.1",
            ),
        )
    ]


def image_build_plan(plan: BenchmarkPlan, image_key: str, output: Path) -> tuple[Path, list[CommandPlan]]:
    if image_key not in plan.images:
        raise ConfigError(f"unknown image: {image_key}")
    context = output / "docker" / image_key
    dockerfile = context / "Dockerfile.generated"
    image = plan.images[image_key]
    command = ("docker", "build", "-t", image.image_ref, "-f", str(dockerfile), str(context))
    commands = [
        *fixture_build_commands(context),
        *fixture_package_commands(context),
        *tls_certificate_commands(plan, context),
    ]
    if image_key == "cyfs_gateway":
        commands.extend(cyfs_gateway_package_commands(plan, context))
    commands.append(CommandPlan(f"build {image_key} image", command))
    return dockerfile, commands


def fixture_build_commands(context: Path) -> list[CommandPlan]:
    fixture_dir = context / "reverse_proxy_fixture"
    return [
        CommandPlan(
            "build reverse_proxy_fixture binary",
            ("cargo", "build", "--release"),
            cwd=str(fixture_dir),
        )
    ]


def fixture_package_commands(context: Path) -> list[CommandPlan]:
    binary = fixture_build_binary(context)
    packaged = fixture_packaged_binary(context)
    return [
        CommandPlan(
            "package reverse_proxy_fixture binary",
            ("install", "-m", "0755", str(binary), str(packaged)),
        )
    ]


def cyfs_gateway_source(plan: BenchmarkPlan) -> dict:
    raw = {}
    # ImageConfig intentionally exposes only public image fields today; keep source
    # settings under generated profile data until the model grows a stable field.
    images_cfg = plan.generated_config.get("_raw_images") if isinstance(plan.generated_config, dict) else None
    if isinstance(images_cfg, dict):
        raw = dict((images_cfg.get("cyfs_gateway") or {}).get("source") or {})
    profile_dir = plan.profile_path.parent
    default_root = next((parent for parent in profile_dir.parents if (parent / "src" / "Cargo.toml").exists()), profile_dir)
    manifest = Path(raw.get("cargo_manifest") or str(default_root / "src" / "Cargo.toml"))
    repo_root = Path(raw.get("repo_root") or str(default_root))
    if not manifest.is_absolute():
        manifest = (profile_dir / manifest).resolve()
    if not repo_root.is_absolute():
        repo_root = (profile_dir / repo_root).resolve()
    package = str(raw.get("package") or "cyfs_gateway")
    build_profile = str(raw.get("build_profile") or "release")
    if build_profile not in {"debug", "release"}:
        raise ConfigError("images.cyfs_gateway.source.build_profile must be debug or release")
    target = raw.get("target", "x86_64-unknown-linux-musl")
    if target is not None and not isinstance(target, str):
        raise ConfigError("images.cyfs_gateway.source.target must be a string when provided")
    return {
        "repo_root": str(repo_root),
        "cargo_manifest": str(manifest),
        "package": package,
        "build_profile": build_profile,
        "target": target,
    }


def source_build_commands(plan: BenchmarkPlan, context: Path) -> list[CommandPlan]:
    source = cyfs_gateway_source(plan)
    target_dir = cyfs_gateway_cargo_target_dir(context)
    command = [
        "cargo",
        "build",
        "--manifest-path",
        source["cargo_manifest"],
        "--package",
        source["package"],
        "--target-dir",
        str(target_dir),
    ]
    if source["build_profile"] == "release":
        command.append("--release")
    if source["target"]:
        command.extend(["--target", source["target"]])
    return [
        CommandPlan(
            "build cyfs_gateway from current source",
            tuple(command),
            cwd=source["repo_root"],
        )
    ]


def cyfs_gateway_binary_paths(plan: BenchmarkPlan, context: Path) -> tuple[Path, Path]:
    source = cyfs_gateway_source(plan)
    target_dir = cyfs_gateway_cargo_target_dir(context)
    if source["target"]:
        target_dir = target_dir / source["target"]
    profile_dir = "release" if source["build_profile"] == "release" else "debug"
    target_dir = target_dir / profile_dir
    return target_dir / "cyfs_gateway", context / "generated" / "cyfs_gateway"


def cyfs_gateway_cargo_target_dir(context: Path) -> Path:
    return context.parent.parent / "cargo-target" / "cyfs_gateway"


def cyfs_gateway_package_commands(plan: BenchmarkPlan, context: Path) -> list[CommandPlan]:
    binary, packaged = cyfs_gateway_binary_paths(plan, context)
    return [
        CommandPlan(
            "package cyfs_gateway binary",
            ("install", "-m", "0755", str(binary), str(packaged)),
        )
    ]


def cyfs_gateway_binary_metadata(plan: BenchmarkPlan, context: Path) -> dict:
    source = cyfs_gateway_source(plan)
    binary, packaged = cyfs_gateway_binary_paths(plan, context)
    binary_size = binary.stat().st_size if binary.exists() else 0
    packaged_size = packaged.stat().st_size if packaged.exists() else 0
    return {
        **source,
        "target_dir": str(cyfs_gateway_cargo_target_dir(context)),
        "expected_binary": str(binary),
        "expected_binary_exists": binary.exists(),
        "expected_binary_size": binary_size,
        "packaged_binary": str(packaged),
        "packaged_binary_exists": packaged.exists(),
        "packaged_binary_size": packaged_size,
    }


def write_fixture_sources(context: Path) -> dict:
    fixture_dir = context / "reverse_proxy_fixture"
    src = fixture_dir / "src"
    src.mkdir(parents=True, exist_ok=True)
    (fixture_dir / "Cargo.toml").write_text(FIXTURE_CARGO_TOML, encoding="utf-8")
    (src / "main.rs").write_text(FIXTURE_MAIN_RS, encoding="utf-8")
    return {
        "cargo_toml": str(fixture_dir / "Cargo.toml"),
        "main_rs": str(src / "main.rs"),
        **fixture_binary_metadata(context),
    }


def fixture_binary_metadata(context: Path) -> dict:
    binary = fixture_build_binary(context)
    packaged = fixture_packaged_binary(context)
    return {
        "build_binary": str(binary),
        "build_binary_exists": binary.exists(),
        "packaged_binary": str(packaged),
        "packaged_binary_exists": packaged.exists(),
    }


def fixture_build_binary(context: Path) -> Path:
    return context / "reverse_proxy_fixture" / "target" / "release" / "cyfs-perf-reverse-proxy-fixture"


def fixture_packaged_binary(context: Path) -> Path:
    return context / "generated" / "cyfs-perf-reverse-proxy-fixture"


def write_image_context(plan: BenchmarkPlan, image_key: str, output: Path) -> dict:
    dockerfile, commands = image_build_plan(plan, image_key, output)
    dockerfile.parent.mkdir(parents=True, exist_ok=True)
    config_dir = dockerfile.parent / "generated"
    config_dir.mkdir(parents=True, exist_ok=True)
    (config_dir / "README.txt").write_text(
        f"Generated benchmark context for {image_key} from profile {plan.profile_path}\n",
        encoding="utf-8",
    )
    _write_candidate_configs(plan, image_key, config_dir)
    static_files = write_static_files(plan, config_dir)
    fixture = write_fixture_sources(dockerfile.parent)
    http_port = int((plan.upstream.get("http_fixture") or {}).get("port") or 8080)
    stream_port = int((plan.upstream.get("stream_fixture") or {}).get("port") or 9000)
    fixture_env = (
        "COPY generated/cyfs-perf-reverse-proxy-fixture /usr/local/bin/cyfs-perf-reverse-proxy-fixture\n"
        "RUN chmod +x /usr/local/bin/cyfs-perf-reverse-proxy-fixture\n"
        f"ENV HTTP_PORT={http_port}\n"
        f"ENV STREAM_PORT={stream_port}\n"
        f"EXPOSE 80 443 9080 9443 {http_port} {stream_port}\n"
    )
    source_build = None
    if image_key == "cyfs_gateway":
        source_build = cyfs_gateway_binary_metadata(plan, dockerfile.parent)

    if image_key == "nginx":
        body = (
            "FROM nginx:stable\nCOPY generated/ /etc/cyfs-perf/\n"
            + "COPY generated/default.conf /etc/nginx/conf.d/default.conf\n"
            + "COPY generated/nginx.conf /etc/nginx/nginx.conf\n"
            + fixture_env
            + 'CMD ["/bin/sh", "-c", "cyfs-perf-reverse-proxy-fixture & exec nginx -g \'daemon off;\'"]\n'
        )
    else:
        body = (
            "FROM ubuntu:22.04\nCOPY generated/ /etc/cyfs-perf/\n"
            + "COPY generated/cyfs_gateway /usr/local/bin/cyfs_gateway\n"
            + "RUN chmod +x /usr/local/bin/cyfs_gateway\n"
            + fixture_env
            + 'CMD ["/bin/sh", "-c", "cyfs-perf-reverse-proxy-fixture & exec cyfs_gateway --config_file /etc/cyfs-perf/gateway.yaml"]\n'
        )
    dockerfile.write_text(body, encoding="utf-8")
    return {
        "image": image_key,
        "dockerfile": str(dockerfile),
        "image_ref": plan.images[image_key].image_ref,
        "static_files": static_files,
        "tls": {
            "mode": "generated",
            "common_name": _tls_common_name(plan),
            "cert_path": str(config_dir / "tls.crt"),
            "key_path": str(config_dir / "tls.key"),
        },
        "packaged_reverse_proxy_fixture": {
            **fixture,
            "ports": {
                "http": http_port,
                "stream": stream_port,
            },
        },
        "commands": [list(command.command) for command in commands],
        "source_build": source_build,
    }


def push_plan(plan: BenchmarkPlan, image_key: str) -> list[CommandPlan]:
    if image_key not in plan.images:
        raise ConfigError(f"unknown image: {image_key}")
    image = plan.images[image_key]
    return [
        CommandPlan(f"push {image_key} image", ("docker", "push", image.image_ref)),
    ]
