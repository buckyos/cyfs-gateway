# cyfs-process-chain 文档

本文档目录基于当前代码实现（`src/components/cyfs-process-chain`）整理，不依赖旧版 `doc/` 历史文档。

## 文档索引

- [ARCHITECTURE.md](./ARCHITECTURE.md)
  - 工程结构、执行模型、DSL 语法、变量与集合、扩展机制、已知限制。
- [COMMAND_REFERENCE.md](./COMMAND_REFERENCE.md)
  - 由 REPL `help doc` 自动导出的命令帮助（含内置命令和已注册外部命令）。
  - 注意：当前文件中的 external 命令来自 REPL 默认初始化（例如 `http-probe`、`https-sni-probe`），网关运行时可注册更多命令。
- [COMMAND_REFERENCE.zh-CN.md](./COMMAND_REFERENCE.zh-CN.md)
  - `COMMAND_REFERENCE.md` 的中文对照版，便于中文读者查阅。
  - 命令名、选项名与脚本关键字保持英文，说明文字提供中文化描述。
- [Gateway Runtime External Commands](../../../../doc/process_chain_gateway_external_commands.md)
  - `cyfs_gateway` 运行时默认注册的 external command 补充说明。
  - 当前包含 `verify-jwt`、`parse-cookie` 等网关命令，以及通过 `cyfs_gateway process_chain --all` 导出完整帮助的方式。
- [Gateway-Oriented Core Model Overview](../../../../doc/process_chain_core_model.md)
  - 从 gateway 场景出发整理 `process_chain` 的语言核心模型、宿主边界与设计原则。
- [RFC_LIGHTWEIGHT_TYPE_SYSTEM.md](./RFC_LIGHTWEIGHT_TYPE_SYSTEM.md)
  - 轻量类型系统演进草案（policy 设计、JSON 持久化策略、分阶段落地方案）。
- [RFC_SCRIPT_MODULARIZATION.md](./RFC_SCRIPT_MODULARIZATION.md)
  - 脚本模块化能力草案（基于 `invoke` 的参数签名、调用边界与命名空间设计）。
- [RFC_FOR_LOOP_STATEMENT.md](./RFC_FOR_LOOP_STATEMENT.md)
  - 结构化 `for ... in ...` 循环语句草案（容器遍历、break/continue、与 map-reduce 的关系）。
- [RFC_MATCH_RESULT_STATEMENT.md](./RFC_MATCH_RESULT_STATEMENT.md)
  - `match-result` 结果分支语句草案（按 `CommandResult` 分支、`Control` 透传规则、与 `capture` 的关系）。
- [COLLECTION_BACKEND_ASSESSMENT.md](./COLLECTION_BACKEND_ASSESSMENT.md)
  - collection 后端现状评估（memory/json/sqlite 边界、当前结论与未来演进方向）。
- [RFC_COLLECTION_SEMANTICS.md](./RFC_COLLECTION_SEMANTICS.md)
  - collection 语义与 backend 能力模型草案（引用、顺序、持久化、遍历约束与可移植性）。
- [RFC_TEMPLATE_LIBRARY.md](./RFC_TEMPLATE_LIBRARY.md)
  - 标准库与最佳实践模板草案（模板契约、错误码规范、分层落地路线）。
- [MIGRATION_TYPED_LITERAL_BREAKING.md](./MIGRATION_TYPED_LITERAL_BREAKING.md)
  - typed literal 无兼容迁移草案（破坏性清单 + 批量迁移规则 + 扫描流程）。
- [LINT.md](./LINT.md)
  - `pc-lint` 静态检查器（MVP）使用说明与当前规则清单。
- [SYNTAX_STRICT_SPEC.md](./SYNTAX_STRICT_SPEC.md)
  - 严格语法规范草案（上下文语义、`$` 规则、`$(...)` 约束、推荐写法）。
- [templates/README.md](./templates/README.md)
  - 官方模板脚本目录（`route_basic`、`auth_rewrite_fallback`）。

## 版本与时间

- crate: `cyfs-process-chain`
- version: `0.5.1`
- generated at: `2026-03-09`

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

中文版本当前为基于英文版整理的并行文档；当英文版命令参考更新后，应同步校准：

```bash
src/components/cyfs-process-chain/doc/COMMAND_REFERENCE.zh-CN.md
```

如果要导出包含 `cyfs_gateway` 默认 external command 的完整文档，可以执行：

```bash
cd src
cargo run -p cyfs_gateway -- process_chain --all --file /tmp/cyfs-gateway-process-chain-command-ref.md
```
