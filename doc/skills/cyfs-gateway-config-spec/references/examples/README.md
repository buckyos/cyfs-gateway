# 示例索引

本目录用于存放“按场景拆分”的代表性问答与分析模板。
不要把所有例子放到一个文件里。

## 怎么选示例

- 配置结构、includes、merge、路径归一化：看 [config-basics.md](config-basics.md)
- HTTP / TCP / UDP 路由与 process chain：看 [routing-and-process-chain.md](routing-and-process-chain.md)
- 数据转发、`call-server` / `forward` / 多上游选择：看 [../data-forwarding.md](../data-forwarding.md)
- `tun` 的 IP 级配置边界 / 显式地址互通分析：看 [overlay-networking.md](overlay-networking.md)
- `socks5` 型代理接入：看 [proxy-access.md](proxy-access.md)
- 边界判断题：看 [capability-boundaries.md](capability-boundaries.md)
- 排障题：看 [troubleshooting.md](troubleshooting.md)

## 使用原则

- 先按问题类型选文件，再从相近场景里抽答案结构。
- 示例用于稳定回答结构，不代表所有示例都可直接复制生产落地。
- 只要示例涉及“当前支持什么”，都要回到上级的 [implementation-checked.md](../implementation-checked.md) 做事实校验。
