# runtime-configs

## 职责
负责出厂运行时默认值、bind 地址、打包模板与配置组装输入，这些内容决定网关如何启动并暴露服务。

## 主要路径
- `src/rootfs/etc/`
- `src/rootfs/etc/cyfs_gateway/server_templates/`
- `src/apps/cyfs_gateway/src/*.yaml`

## 输入
- 产品默认值
- 打包工作流约束
- 来自 `gateway-runtime` 的模块契约

## 输出
- 启动期配置文件
- server 模板包
- 默认 bind 地址及部署级运行时行为

## 邻接边界
- 为 `gateway-runtime` 提供输入
- 必须与文档和打包部署预期保持一致

## 验证面
- 运行时测试中的配置加载行为
- 针对 bind、默认值与服务启动的集成 smoke 测试
- 对部署敏感变更的人审

## 风险等级
Tier B：配置变更影响运行时默认行为和部署结果，风险较高。
