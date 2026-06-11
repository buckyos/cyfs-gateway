# 仓库基线

## 仓库结构
- Rust 工作区根目录：`src/`
- 主服务应用：`src/apps/cyfs_gateway/`（`cyfs_gateway`）
- 核心运行时库：`src/components/cyfs-gateway-lib/`（`cyfs-gateway-lib`）
- 其他 Rust 组件：`src/components/*`
- Web 控制台：`src/apps/cyfs_gateway/web/`
- 运行时配置和模板：`src/rootfs/etc/` 与 `src/rootfs/etc/cyfs_gateway/server_templates/`
- 历史与探索性设计资料：`doc/`

## 构建与测试命令
Rust 相关命令默认从仓库根执行 `cd src` 后运行。

### 构建
```bash
cd src && cargo build --verbose
```

### 全量测试
```bash
cd src && cargo test -- --test-threads=1
```

### 单项测试模式
```bash
cd src && cargo test -p cyfs_gateway --test test_control_server
cd src && cargo test -p cyfs_gateway test_login -- --nocapture
cd src && cargo test --package cyfs-gateway-lib --lib server::dir_server
cd src && cargo test --package cyfs-gateway-lib ndn_server
cd src && cargo test --package cyfs-gateway-lib json_collection
```

### 可选本地工具
```bash
cd src && cargo fmt
cd src && cargo clippy
```

## Web 控制台命令
```bash
cd src/apps/cyfs_gateway/web
npm i
npm run dev
npm run build
```

## 交付约束
- CI 使用 `cargo build --verbose`。
- CI 使用单线程测试：`cargo test -- --test-threads=1`。
- 发布工作流在 `./src` 下通过 `buckyos-build` 打包。
- 很多测试和栈会绑定端口，因此新增测试时优先使用 `127.0.0.1:0` 或单线程执行。
- 在 Linux 上首次本地构建 Rust 依赖时，可能需要完整原生构建工具链以及 `perl`、`make`，因为 vendored OpenSSL 可能会从源码编译。

## Rust 约定
- 优先做小而局部的改动，不把修 bug 和重构混在一起。
- 遵循当前文件已有的 import 风格，常见顺序是 `std`、外部 crate、`crate::...`。
- 类型名使用 `PascalCase`，函数、模块、文件使用 `snake_case`。
- Tokio 是标准异步运行时。
- 应用层流程默认使用 `anyhow::Result<T>`，除非模块已经定义了自己的 typed result。
- 错误处理优先补充上下文，使用 `map_err(...)` 或现有辅助宏。
- 日志统一使用 `log` 宏，并遵循所在文件的导入风格。

## TypeScript / TSX 约定
- 控制台使用 Vite，别名 `@ -> ./src`。
- 类型严格度是混合状态；修改代码时可以补类型，但不要顺带重排无关文件。
- 除非任务明确要求改 UX，否则应保持当前控制台的视觉与组件风格。

## 运行时配置说明
- 监听地址通常由配置中的 `bind:` 字段驱动。
- 常见控制平面配置：`src/apps/cyfs_gateway/src/gateway_control_server.yaml`
- 常见运行时引导配置：`src/rootfs/etc/boot_gateway.yaml`
- 配置或默认值变更通常需要同步文档，并执行更高成本的验证，因为这类变化会影响部署行为。

## 参考优先级
- Harness 事实来源：`docs/` 与 `harness/`
- 运行时事实来源：`src/` 下的代码与 `src/rootfs/etc/` 下的配置
- 历史参考：`doc/`
