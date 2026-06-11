# web-dashboard

## 职责
负责浏览器侧控制台、路由组织以及与网关运行时交互的 UI 控制流程。

## 主要路径
- `src/apps/cyfs_gateway/web/src/`
- `src/apps/cyfs_gateway/web/package.json`

## 输入
- 来自 `gateway-runtime` 的控制平面与数据模型契约
- 本地 UI 状态与路由定义

## 输出
- 浏览器 UI
- 由 Vite 产出的构建结果

## 邻接边界
- 消费运行时契约，但不定义后端契约
- 未同步运行时与文档前，不应私自新增后端字段假设

## 验证面
- `npm run build`
- 路由与状态模型审查
- 当 UI 所需数据发生变化时，对照运行时 API 做契约检查

## 风险等级
Tier C：纯 UI 变更可以局部处理，但只要涉及运行时契约，就必须回到对应运行时文档和测试链路。
