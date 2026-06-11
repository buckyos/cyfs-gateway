# cyfs-tun 测试

## 元数据
- version: v0.6
- module: cyfs-tun
- stage: testing
- status: draft

## 测试文档索引
| 文档 | 主题 | 范围 |
|------|------|------|
| 无 | 暂无拆分测试文档 | 完整模块 |

## 统一测试入口
- 机器可读计划：`docs/versions/v0.6/modules/cyfs-tun/testplan.yaml`
- Unit：`python3 ./harness/scripts/test-run.py cyfs-tun unit`
- DV：`python3 ./harness/scripts/test-run.py cyfs-tun dv`
- Integration：`python3 ./harness/scripts/test-run.py cyfs-tun integration`

## 子模块测试
| 子模块 | 职责 | 详细测试文档 | 必须覆盖的行为 | 边界/失败场景 | 测试类型 | 测试文件 |
|--------|------|--------------|----------------|---------------|----------|----------|
| tun-stack-runtime | 创建 TUN 设备并运行 `ipstack` / hook_point | 无 | 当前至少要显式记录真实证据缺口 | 设备权限、平台差异、hook_point 漂移 | disabled | 暂无独立自动化 |
| tun-tunnel-adapter | 暴露 `tuntunnel` builder 与 endpoint 解析 | 无 | stack id 解析、TCP / UDP client 行为 | endpoint 不存在、多 tun stack 冲突 | unit | `src/components/cyfs-tun/src/tun_tunnel.rs` |
| gateway-assembly | 在 runtime 中注册 parser / factory / context | 无 | 当前至少要显式记录真实证据缺口 | parser 漂移、context 装配错误 | disabled | 暂无独立自动化 |
| tun-tests | 维护统一测试入口与缺口说明 | 无 | `testplan.yaml` 与文档一致 | level 漂移、误报覆盖 | 元验证 | `harness/scripts/test-run.py`、`testplan.yaml` |

## 模块级测试
| 测试项 | 覆盖边界 | 执行入口 | 预期结果 | 测试类型 | 测试文件/脚本 |
|--------|----------|----------|----------|----------|----------------|
| `tuntunnel` crate 单测 smoke | endpoint 注册、TCP / UDP client 最小行为 | `python3 ./harness/scripts/test-run.py cyfs-tun unit` | 选定单测通过 | unit | `src/components/cyfs-tun/src/tun_tunnel.rs` |
| tun stack 单模块可运行验证缺口 | 真实 TUN 设备、`ipstack` 与 hook_point 的单模块运行行为 | `python3 ./harness/scripts/test-run.py cyfs-tun dv` | 当前显式返回 disabled，不假装存在覆盖 | dv | `docs/versions/v0.6/modules/cyfs-tun/testplan.yaml` |
| tun 邻接模块集成验证缺口 | gateway runtime 对 tun stack 的装配与配置契约 | `python3 ./harness/scripts/test-run.py cyfs-tun integration` | 当前显式返回 disabled，不假装存在覆盖 | integration | `docs/versions/v0.6/modules/cyfs-tun/testplan.yaml` |

## 外部接口测试
| 接口 | 职责 | 成功场景 | 失败/边界场景 | 测试类型 | 测试文档/文件 |
|------|------|----------|---------------|----------|----------------|
| `tuntunnel` endpoint 解析 | 通过 stack id 或 bind IP 选择目标 tun endpoint | 已注册 stack id 可建立 TCP / UDP client | endpoint 缺失、多 stack 时未指定 target | unit | `src/components/cyfs-tun/src/tun_tunnel.rs` |
| `protocol: tun` 配置解析与运行时装配 | 把配置组装成可运行 tun stack | 当前无独立模块级成功证据 | parser 漂移、context 装配错误、设备条件缺失 | disabled | `docs/versions/v0.6/modules/cyfs-tun/testplan.yaml` |

## 单元测试
| 测试项 | 覆盖行为 | 测试文件 |
|--------|----------|----------|
| `test_tuntunnel_open_stream_by_stack_id` | `tuntunnel` 可按 stack id 建立 TCP stream | `src/components/cyfs-tun/src/tun_tunnel.rs` |
| `test_tuntunnel_create_datagram_client` | `tuntunnel` 可建立 UDP datagram client | `src/components/cyfs-tun/src/tun_tunnel.rs` |

## DV 测试
- 当前没有独立的 tun stack DV 自动化。
- 原因是仓库中尚无专门面向 `TunStack` 的单模块可运行测试入口，且真实 TUN 设备行为依赖权限与平台条件。
- 因此 `dv` 级别在 `testplan.yaml` 中显式标记为 `disabled`。

## 集成测试
- 当前没有独立的 `cyfs-tun` integration 自动化。
- 现有 `gateway-runtime` 集成测试并未为 tun 模块建立单独、可引用的证据路径。
- 因此 `integration` 级别在 `testplan.yaml` 中显式标记为 `disabled`，后续若新增 tun 场景，应先补 testing 文档与机器可读入口。

## 回归关注点
- `tuntunnel` 目标解析与多 tun stack 选择逻辑回归
- tun stack 真实设备行为与当前文档描述不一致
- gateway runtime 侧 parser / factory / context 接线漂移，但模块文档未同步

## 实现准入映射
| Proposal / Design 条目 ID | Testing 条目 / 章节 | 对应 testplan level / step | 显式缺口或补充要求 |
|---------------------------|---------------------|----------------------------|--------------------|
| `P-base-1` / `P-base-1` | `模块级测试`、`外部接口测试`、`DV 测试`、`集成测试` | `unit.cyfs-tun-unit`、`dv` disabled、`integration` disabled | 若当前任务改变 tun 行为、`tuntunnel` 契约、配置结构或真实运行时接线，必须先补 dedicated DV / integration 证据与 `testplan.yaml`，再进入 implementation |

## 完成定义
- [ ] 直接子模块都映射到现有证据或显式缺口
- [ ] `testplan.yaml` 与文中声明的 level 模式、命令和原因一致
- [ ] 当前自动化覆盖面与缺口没有被夸大
- [ ] 后续 tun 高风险行为变更可据此补充新的测试入口
