export function main(argv) {
    const helpText = [
        "Usage:",
        "  http_server [--bind <ip:port|port>] [--path <dir>]",
        "",
        "Options:",
        "  --bind  Bind address, default 0.0.0.0:8080",
        "  --path  Root directory, default current dir",
        "  --help  Show this help",
    ].join("\n");

    let bindArg = "";
    let pathArg = "";
    let showHelp = false;
    for (let i = 0; i < argv.length; i += 1) {
        const arg = String(argv[i]);
        if (arg === "--help" || arg === "-h") {
            showHelp = true;
            break;
        }
        if (arg.startsWith("--bind=")) {
            bindArg = arg.slice("--bind=".length);
            continue;
        }
        if (arg === "--bind") {
            if (i + 1 < argv.length) {
                bindArg = String(argv[i + 1]);
                i += 1;
            }
            continue;
        }
        if (arg.startsWith("--path=")) {
            pathArg = arg.slice("--path=".length);
            continue;
        }
        if (arg === "--path") {
            if (i + 1 < argv.length) {
                pathArg = String(argv[i + 1]);
                i += 1;
            }
        }
    }
    if (showHelp) {
        console.log(helpText);
        return "";
    }

    const defaultBind = "0.0.0.0:8080";
    const bindInput = bindArg.trim();
    let bindIp = "0.0.0.0";
    let bindPort = "8080";

    if (bindInput.length === 0) {
        bindIp = "0.0.0.0";
        bindPort = "8080";
    } else if (/^\d+$/.test(bindInput)) {
        bindPort = bindInput;
    } else if (bindInput.includes(":")) {
        const parts = bindInput.split(":");
        bindIp = parts[0] ? parts[0] : "0.0.0.0";
        bindPort = parts[1] ? parts[1] : "8080";
    } else {
        bindIp = bindInput;
    }

    const bind = bindInput.length === 0 ? defaultBind : `${bindIp}:${bindPort}`;
    const idBindIp = bindIp.replace(/[^A-Za-z0-9_]/g, "_");

    const curDir = currentDir();
    let rootPath = pathArg.trim();
    if (rootPath.length === 0) {
        rootPath = curDir;
    } else {
        const isAbsolute = rootPath.startsWith("/") || /^[A-Za-z]:[\\/]/.test(rootPath);
        if (!isAbsolute) {
            const separator = curDir.endsWith("/") || curDir.endsWith("\\") ? "" : "/";
            rootPath = `${curDir}${separator}${rootPath}`;
        }
    }

    const stackId = `stack_tcp_${idBindIp}_${bindPort}`;
    const serverId = `server_tcp_${idBindIp}_${bindPort}`;
    const config = {
        stacks: {
            [stackId]: {
                bind,
                protocol: "tcp",
                hook_point: {
                    main: {
                        priority: 1,
                        blocks: {
                            default: {
                                priority: 1,
                                block: `call-server ${serverId};\n`,
                            },
                        },
                    },
                },
            },
        },
        servers: {
            [serverId]: {
                type: "dir",
                root_path: rootPath,
            },
        },
    };

    return JSON.stringify(config);
}

