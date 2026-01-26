// 命令行参数如下：
// --bind 0.0.0.0:8080 --target rtcp://127.0.0.1:8080 --username *** --password ***
// bind参数可以缺省，缺省时候使用默认值0.0.0.0:1080，还可以只输入端口，只有端口时默认使用0.0.0.0作为绑定地址
// target参数必须输入
// username和password参数可以缺省, 缺省时配置中不添加username和password字段
// 还要支持--help参数，使用console.log输出命令行帮助信息
/*
    生成配置格式：
    {
        "stacks": {
            "stack_socks5_${bind_ip}_${bind_port}": {
                "bind": "${bind}",
                "protocol": "tcp",
                "hook_point": {
                    "main": {
                        "priority": 1,
                        "blocks": {
                            "default": {
                                "priority": 1,
                                "block": "call-server server_socks5_${bind_ip}_${bind_port};\n"
                             }
                         }
                    }
                }
            }
        },
        "servers": {
            "server_socks5_${bind_ip}_${bind_port}": {
                "type": "socks",
                "target": "${target}",
                "username": "${username}",
                "password": "${password}",
                "hook_point": {
                    "main": {
                        "priority": 1,
                        "blocks": {
                            "default": {
                                "priority": 1,
                                "block": "return proxy;\n"
                             }
                         }
                    }
                }
            }
        }
    }
 */
export function main(argv) {
    const helpText = [
        "Usage:",
        "  socks_server --target <url> [--bind <ip:port|port>] [--username <name>] [--password <pass>]",
        "",
        "Options:",
        "  --bind      Bind address, default 0.0.0.0:1080",
        "  --target    Target proxy address (required)",
        "  --username  Username for auth",
        "  --password  Password for auth",
        "  --help      Show this help",
    ].join("\n");

    let bindArg = "";
    let targetArg = "";
    let usernameArg = "";
    let passwordArg = "";
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
        if (arg.startsWith("--target=")) {
            targetArg = arg.slice("--target=".length);
            continue;
        }
        if (arg === "--target") {
            if (i + 1 < argv.length) {
                targetArg = String(argv[i + 1]);
                i += 1;
            }
            continue;
        }
        if (arg.startsWith("--username=")) {
            usernameArg = arg.slice("--username=".length);
            continue;
        }
        if (arg === "--username") {
            if (i + 1 < argv.length) {
                usernameArg = String(argv[i + 1]);
                i += 1;
            }
            continue;
        }
        if (arg.startsWith("--password=")) {
            passwordArg = arg.slice("--password=".length);
            continue;
        }
        if (arg === "--password") {
            if (i + 1 < argv.length) {
                passwordArg = String(argv[i + 1]);
                i += 1;
            }
        }
    }

    if (showHelp) {
        console.log(helpText);
        return "";
    }

    const target = targetArg.trim();
    if (target.length === 0) {
        console.log(helpText);
        return "";
    }

    const defaultBind = "0.0.0.0:1080";
    const bindInput = bindArg.trim();
    let bindIp = "0.0.0.0";
    let bindPort = "1080";

    if (bindInput.length === 0) {
        bindIp = "0.0.0.0";
        bindPort = "1080";
    } else if (/^\d+$/.test(bindInput)) {
        bindPort = bindInput;
    } else if (bindInput.includes(":")) {
        const parts = bindInput.split(":");
        bindIp = parts[0] ? parts[0] : "0.0.0.0";
        bindPort = parts[1] ? parts[1] : "1080";
    } else {
        bindIp = bindInput;
    }

    const bind = bindInput.length === 0 ? defaultBind : `${bindIp}:${bindPort}`;
    const idBindIp = bindIp.replace(/[^A-Za-z0-9_]/g, "_");
    const stackId = `stack_socks5_${idBindIp}_${bindPort}`;
    const serverId = `server_socks5_${idBindIp}_${bindPort}`;

    const serverConfig = {
        type: "socks",
        target,
        hook_point: {
            main: {
                priority: 1,
                blocks: {
                    default: {
                        priority: 1,
                        block: "return proxy;\n",
                    },
                },
            },
        },
    };

    const username = usernameArg.trim();
    const password = passwordArg.trim();
    if (username.length > 0) {
        serverConfig.username = username;
    }
    if (password.length > 0) {
        serverConfig.password = password;
    }

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
            [serverId]: serverConfig,
        },
    };

    return JSON.stringify(config);
}
