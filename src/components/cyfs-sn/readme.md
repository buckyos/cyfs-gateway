# cyfs-sn 的主要功能

1. 提供基于 HTTP JSON-RPC 的用户、设备、zone、dns、did 管理能力
2. 保留固定入口 `/kapi/sn`，通过 namespaced `method` 兼容旧接口与新管理面
3. 新增 namespaced method 管理面，支持带 `active_code` 的 `auth.register`、`auth.login` 和服务端 JWT
4. 提供内部接口，cyfs-dns 打开时，可在查询 `$device_id.d.baseurl` 时返回设备 IP，并根据来源确定返回外网还是内网地址

## 文档

- JSON-RPC 接口文档：[`doc/sn_json_rpc.md`](/home/aa/app/base/cyfs-gateway/doc/sn_json_rpc.md)
