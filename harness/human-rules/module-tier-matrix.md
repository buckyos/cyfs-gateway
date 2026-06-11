# 模块分级矩阵

## 目标
- 让评审强度与模块耦合度、运行时风险保持匹配。

## 分级

| 等级 | 模块 | 常见路径 | 最低证据要求 |
|------|------|----------|--------------|
| A | 核心运行时与 process 执行 | `src/components/cyfs-gateway-lib/`、`src/components/cyfs-process-chain/`、`src/apps/cyfs_gateway/src/` 中的运行时组装 | design 同步、聚焦 unit 证据，契约变化时再加 dv 或 integration |
| B | 运行时配置与出厂默认值 | `src/rootfs/etc/`、gateway YAML、server template | 文档同步、配置敏感 dv 或 integration 证据、部署风险评审 |
| C | dashboard 与低耦合文档 | `src/apps/cyfs_gateway/web/`、低风险文档 | 本地 build 或定向验证；若后端字段变化则补契约审查 |

## 评审规则
- 一项任务跨越多个等级时，按最高等级处理。
- 不要把依赖 Tier A / Tier B 契约变更的 Tier C UI 工作误判为低风险。
