# cyfs-process-chain 文档

本文档目录基于当前代码实现（`src/components/cyfs-process-chain`）整理，不依赖旧版 `doc/` 历史文档。

## 文档索引

- [ARCHITECTURE.md](./ARCHITECTURE.md)
  - 工程结构、执行模型、DSL 语法、变量与集合、扩展机制、已知限制。
- [COMMAND_REFERENCE.md](./COMMAND_REFERENCE.md)
  - 由 REPL `help doc` 自动导出的命令帮助（含内置命令和已注册外部命令）。
  - 注意：当前文件中的 external 命令来自 REPL 默认初始化（例如 `http-probe`、`https-sni-probe`），网关运行时可注册更多命令。
- [RFC_LIGHTWEIGHT_TYPE_SYSTEM.md](./RFC_LIGHTWEIGHT_TYPE_SYSTEM.md)
  - 轻量类型系统演进草案（兼容策略、policy 设计、分阶段落地方案）。
- [RFC_SCRIPT_MODULARIZATION.md](./RFC_SCRIPT_MODULARIZATION.md)
  - 脚本模块化能力草案（基于 `invoke` 的参数签名、调用边界与命名空间设计）。

## 版本与时间

- crate: `cyfs-process-chain`
- version: `0.5.1`
- generated at: `2026-03-02`

## 如何重新生成命令参考

当前实现依赖 `dirs_next::data_dir()` 初始化 REPL 数据目录；在受限环境下建议显式指定 `XDG_DATA_HOME`：

```bash
cd src
XDG_DATA_HOME=/tmp cargo run -p cyfs-process-chain <<'EOT'
help doc /tmp/cyfs-process-chain-command-ref.md
exit
EOT
```

然后将输出文件覆盖到：

```bash
src/components/cyfs-process-chain/doc/COMMAND_REFERENCE.md
```
