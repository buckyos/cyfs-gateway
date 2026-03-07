# cyfs-process-chain

`cyfs-process-chain` 是 `cyfs-gateway` 的流程脚本执行引擎，负责 DSL 解析、链接（link）、执行以及变量/集合管理。

## 功能概览

- 流程组织：`lib -> chain -> block -> line/statement`
- 执行模型：解析后 link，再进入运行时执行
- 变量作用域：`global / chain / block`
- 数据路径：支持 `.`、`[]`、可选访问 `?.` 与默认值 `??`
- 类型系统：支持 string/bool/number/null 及集合类型（set/map/multi-map/list）
- 控制流：`if/elif/else`、`invoke`、`exec`、`goto`（结构化语义）
- 扩展机制：Rust/JS external command

## 工程结构

- `src/`：核心实现（block/chain/cmd/collection/hook_point/js/...）
- `doc/`：最新设计与使用文档（以此目录为准）
- `Cargo.toml`：crate 定义（`cyfs-process-chain`）

## 快速开始

在 workspace 根目录执行：

```bash
cd src
cargo build -p cyfs-process-chain
```

运行 REPL（用于交互调试与命令帮助导出）：

```bash
cd src
cargo run -p cyfs-process-chain
```

运行测试：

```bash
cd src
cargo test -p cyfs-process-chain -- --test-threads=1
```

## 文档索引

- 总览：[doc/README.md](./doc/README.md)
- 架构：[doc/ARCHITECTURE.md](./doc/ARCHITECTURE.md)
- 命令参考：[doc/COMMAND_REFERENCE.md](./doc/COMMAND_REFERENCE.md)
- 严格语法规范草案：[doc/SYNTAX_STRICT_SPEC.md](./doc/SYNTAX_STRICT_SPEC.md)
- 轻量类型系统 RFC：[doc/RFC_LIGHTWEIGHT_TYPE_SYSTEM.md](./doc/RFC_LIGHTWEIGHT_TYPE_SYSTEM.md)
- 模块化 RFC：[doc/RFC_SCRIPT_MODULARIZATION.md](./doc/RFC_SCRIPT_MODULARIZATION.md)
- lint 规则：[doc/LINT.md](./doc/LINT.md)
- 模板脚本：[doc/templates/README.md](./doc/templates/README.md)

## 相关工程

- 静态检查器：`src/components/cyfs-process-chain-lint`
