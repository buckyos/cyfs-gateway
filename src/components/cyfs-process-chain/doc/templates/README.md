# 官方模板脚本（草案）

本目录提供 process-chain 常见场景的官方模板脚本。

## 目录

- `route_basic.process_chain.xml`
  - 基础路由：host/path 匹配 + default fallback
- `auth_rewrite_fallback.process_chain.xml`
  - Bearer 鉴权 + path rewrite + fallback
- `canary_by_header.process_chain.xml`
  - 基于请求头灰度：`x-canary=1` 走 canary
- `geo_route_fallback.process_chain.xml`
  - 基于 IP 地域路由：查 geo map，缺失走默认
- `maintenance_guard.process_chain.xml`
  - 维护模式守卫：放行健康检查，其他请求拒绝

## 使用方式

1. 复制模板文件到你的业务配置目录。
2. 修改 `process_chain_lib id`，避免与已有库冲突。
3. 按模板头部注释补齐输入变量（`REQ.*`）。
4. 替换上游标识（如 `upstream_api`、`upstream_fallback`）。

## 推荐选型

1. 单站点基础分流：`route_basic`
2. 接口鉴权 + 升级兼容：`auth_rewrite_fallback`
3. 小流量灰度发布：`canary_by_header`
4. Geo 调度：`geo_route_fallback`
5. 运维维护窗口：`maintenance_guard`

## 输入输出契约

1. 输入变量默认从 `REQ.*` 读取。
2. 成功路径统一通过 `return --from lib <target>` 输出。
3. 失败路径建议通过 `error --from lib <error_code>` 输出。

## 错误码建议

- 格式：`PC-TPL-<DOMAIN>-<NNNN>`
- 示例：
  - `PC-TPL-AUTH-0001`
  - `PC-TPL-ROUTE-0001`

## 最佳实践

1. 建议在运行环境开启 strict missing var policy。
2. fallback 路径必须显式存在。
3. 先在测试环境验证成功/失败/fallback 三条路径再上线。
