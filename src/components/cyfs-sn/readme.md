# cyfs-sn 的主要功能

1. 提供基于 HTTP JSON-RPC 的用户、设备、zone、dns、did 管理能力
2. 保留旧版 `/kapi/sn` JSON-RPC method 分发表，兼容现有客户端和前置代理
3. 新增 `/kapi/sn/v2/<module>` 管理面，支持 `register(name, pwd)`、`active(name, code)`、登录和服务端 JWT
4. 提供内部接口，cyfs-dns 打开时，可在查询 `$device_id.d.baseurl` 时返回设备 IP，并根据来源确定返回外网还是内网地址

## 文档

- v2 JSON-RPC 接口文档：[`doc/sn_v2_json_rpc.md`](/home/aa/app/base/cyfs-gateway/doc/sn_v2_json_rpc.md)
