# 能力边界示例

## 示例 1：可以承诺的结论

### 用户问题

当前 `cyfs_gateway` 正式支持哪些 stack 和 server？

### 可直接回答

根据当前实现校验，可直接回答：

- stack：`tcp`、`udp`、`tls`、`quic`、`rtcp`、`tun`
- server：`http`、`socks`、`dns`、`dir`、`control_server`、`local_dns`、`sn`、`acme_response`

## 示例 2：只能保守推断的结论

### 用户问题

`tun` 能不能拿来做异地虚拟私网？

### 推荐回答

当前只能直接确认 `tun` 的配置语义是 IP、mask、MTU、timeout、hook 这一类 IP 级接口参数。
如果要继续讨论异地互通，只能把它当成外部组网方案里的一个配置部件，同时补上 underlay、路由、防火墙、MTU 与验证步骤；不能把它直接表述成 `cyfs-gateway` 已原生提供的完整虚拟私网。

## 示例 3：不能直接承诺的结论

### 用户问题

`cyfs_gateway` 能不能像交换机一样把不同网段设备组成同一个广播域？

### 推荐回答

当前 skill 没有足够证据证明 `cyfs-gateway` 原生提供 L2 bridge / TAP / 广播域复现能力，所以不能直接承诺。
