# cyfs-sn 的主要功能

1. 提供基于 HTTP JSON-RPC 的用户、设备、zone、dns、did 管理能力
2. 在 `/kapi` 下按路由需求拆分 SN 入口：`/kapi/sn`、`/kapi/sn/auth`、`/kapi/sn/bns`
3. 保留 namespaced `method` 和旧 method alias，兼容现有请求包体格式
4. 提供带 `active_code` 的 `auth.register`、`auth.login` 和服务端 JWT
5. 提供内部接口，cyfs-dns 打开时，可在查询 `$device_id.d.baseurl` 时返回设备 IP，并根据来源确定返回外网还是内网地址

## 文档

- JSON-RPC 接口文档：[`doc/sn_json_rpc.md`](/home/aa/app/base/cyfs-gateway/doc/sn_json_rpc.md)
