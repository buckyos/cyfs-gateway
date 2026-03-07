# cyfs-process-chain-lint

`cyfs-process-chain-lint`（CLI 名称 `pc-lint`）是 `cyfs-process-chain` 的静态检查工具，用于在运行前发现脚本风险。

## 功能概览

- 扫描输入文件或目录（递归 `.xml` / `.json`）
- 输出格式：`text` / `json`
- 按严重级别控制退出码：`--fail-on error|warning|info`
- 支持注入已知变量：`--known-var <NAME>`

已实现规则详见：
- [../cyfs-process-chain/doc/LINT.md](../cyfs-process-chain/doc/LINT.md)

## 快速开始

```bash
cd src
cargo run -p cyfs-process-chain-lint -- check <file-or-dir>
```

示例：

```bash
cd src
cargo run -p cyfs-process-chain-lint -- \
  check components/cyfs-process-chain/doc/templates \
  --format text \
  --fail-on error
```

## 开发与测试

构建：

```bash
cd src
cargo build -p cyfs-process-chain-lint
```

测试：

```bash
cd src
cargo test -p cyfs-process-chain-lint -- --test-threads=1
```

## 工程结构

- `src/lib.rs`：lint 核心分析逻辑
- `src/main.rs`：CLI 入口（`pc-lint check`）
- `src/test/`：单元测试（按模块拆分）

## 依赖关系

- 依赖 `cyfs-process-chain` 的解析模型（AST/loader）进行静态分析
