# rtcp 协议

rtcp协议可以在A<->B 之间的网络连通受限的情况下，
rtcp的默认端口是2980，使用tcp协议。
- 在A<->B之间udp被封锁的情况下，可以互相使用对方提供的udp服务 
- 在A可以直连B的2980端口，而B无法直连A的2980端口时 (A在NAT后），支持B访问A提供的tcp服务
- B只开放了2980端口，通过rtcp协议，支持A访问B的全部服务

rtcp还强制实现了A<->B之间的通信加密，通过rtcp访问服务，即使服务协议本身是明文的(http),也可以保障在网络传输中是加密的
rtcp是强身份的，A和B之间都必须互相先信任对方的公钥

配置 `on_new_tunnel_hook_point` 控制 tunnel 来源的示例见：[rtcp_on_new_tunnel_hook_point_example.md](/Users/liuzhicong/project/cyfs-gateway/doc/rtcp_on_new_tunnel_hook_point_example.md)

## Tunnel Hello 认证

`Hello` 包现在包含以下字段：

- `from_id`
- `to_id`
- `my_port`
- `tunnel_token`
- `device_doc_jwt`（可选）

服务端处理 `Hello` 时有两条路径：

1. 如果 `device_doc_jwt` 存在：
   服务端先解析 JWT 中的 `owner`，再用 owner 的公钥验签 `device_doc_jwt`，随后从校验通过的设备文档里提取设备公钥，并优先用这个公钥验证 `tunnel_token`。这条路径适合跨 zone 首次接入，接收端还不知道该 device 公钥时也能完成准入判断。

2. 如果 `device_doc_jwt` 不存在：
   服务端保持原有行为，直接基于 `from_id` 解析设备公钥并验证 `tunnel_token`。这要求接收端已经能根据 `from_id` 找到该 device 的公钥信息。常见做法是 `from_id` 直接使用 `did:dev:<device_pubkey>`。

`on_new_tunnel_hook_point` 在 `device_doc_jwt` 验证成功后，可以拿到更完整的来源信息，详见 [process chain env.md](./process%20chain%20env.md)。

## 本地配置

RTCP stack 的 `device_config_path` 现在同时支持两种文件内容：

- 设备文档 JSON
- owner 已签名的设备文档 JWT（例如 `device.doc.jwt`）

只有在本地加载的是 JWT 文件时，发起跨 zone RTCP 连接的 `Hello` 才会自动携带 `device_doc_jwt`。如果本地只配置了 JSON，RTCP 会继续按旧行为工作，不会为你现场生成 owner 签名。

## 基本流程

### Step1 建立Tunnel 

A: Tcp.connect(B,2980)
A: Send Tunnel Hello
B: Send Tunnel HelloAck

只要Tunnel建立，那么这个Tunnel对B和A来说就是等效的,不同在于 主动发起连接成功的一方，can_direct = true, 总是用Open逻辑来连接对方的服务，而另一面的can_direct = false,总是用ROpen来连接对面的服务

### Step2 A连接B运行在3200端口上的服务
A: Send Stream Open(127.0.0.1, 3200, sessionid)
A': session_streamA = Tcp.connect(B,2980), Send StreamHello(sessionid)
B': session_stream_real = Tcp.connect(127.0.0.1,3200)
B': aes_copy_stream(session_stream_real,session_streamA,sessionid)
B: Send Stream OpenResp(sessionid)

### Step3 B连接A运行在3300端口上的服务
B: Send Stream ROpen(127.0.0.1,3300,sessionid)
A': session_steam_real = Tcp.connect(127.0.0.1,3300)
A': session_streamA = Tcp.connect(B,2980),Send StreamHello(sessionid)
A: Send Stream RopenResp(127.0.0.1,3300,sessionid)
A': aes_copy_stream(session_steam_real,session_streamA,sessionid)
B:  session_stream = accept from 2980 and first package is StreamHello(sessionid)

### Open和ROpen的区别
核心区别：加密的AesStream（这是一个TcpStream）是怎么建立的
如果是Open，则由发起Open的人建立
如果是ROpen，则由收到ROpen的人建立
