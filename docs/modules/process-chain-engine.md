# process-chain-engine

## 职责
负责 process-chain 语言、执行模型与 lint 能力，这些能力被 gateway runtime 用来表达可编排的请求处理逻辑。

## 主要路径
- `src/components/cyfs-process-chain/src/`
- `src/components/cyfs-process-chain-lint/src/`
- `doc/reference.md`

## 输入
- 来自运行时 stack 与 server 的请求和响应元数据
- 内建命令库与外部命令 hook

## 输出
- 被 gateway stack 与 server 使用的可执行 chain 行为
- process-chain 定义对应的校验与 lint 反馈

## 邻接边界
- 为 `gateway-runtime` 提供运行时逻辑
- 不负责网关打包，也不负责 dashboard UI

## 验证面
- 组件级 Rust 测试
- `doc/` 下的示例和参考文档
- 契约变更时通过 gateway 集成测试进行运行验证

## 风险等级
Tier A：语言或契约变更会级联影响运行时行为，需要针对性验证。
