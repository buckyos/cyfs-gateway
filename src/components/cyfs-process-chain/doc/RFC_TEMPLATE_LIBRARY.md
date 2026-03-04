# 标准库与最佳实践模板 RFC（草案）

- status: Draft
- scope: `src/components/cyfs-process-chain`
- goal: 为常见路由、鉴权、rewrite、fallback 场景提供官方模板，降低脚本重复与接入成本。

## 1. 背景

当前 process-chain 已具备较强 DSL 能力，但业务脚本存在重复问题：

1. 相同控制流在多个项目重复拷贝，维护成本高。
2. 输入输出变量约定不统一，跨团队难复用。
3. 错误码和错误语义不统一，线上排障效率低。

## 2. 设计目标

1. 提供“复制即可运行”的官方模板脚本。
2. 为模板定义统一契约（输入、输出、错误、依赖）。
3. 保持与现有执行模型兼容，不引入额外运行时机制。
4. 为后续标准库化（可复用子流程）打基础。

## 3. 非目标

1. 第一阶段不实现远程模板仓库与自动版本解算。
2. 第一阶段不引入复杂编译期校验器。
3. 第一阶段不重写现有命令语义。

## 4. 两层架构

### 4.1 模板层（P0）

- 面向业务快速落地。
- 每个模板是完整 `process_chain_lib` 文件。
- 重点是可读性与可复制性。

### 4.2 标准库层（P1/P2）

- 从模板中抽取可复用子流程。
- 通过 `invoke` 形成组合式调用。
- 强化命名空间和版本控制。

## 5. 目录与文件规范

建议目录结构：

```text
src/components/cyfs-process-chain/doc/templates/
  README.md
  route_basic.process_chain.xml
  auth_rewrite_fallback.process_chain.xml
```

每个模板至少包含：

1. 模板脚本（`.process_chain.xml`）
2. 输入输出契约说明（写在模板头部注释 + `README.md`）
3. 错误码约定（如 `PC-TPL-AUTH-0001`）

## 6. 模板契约规范

### 6.1 输入变量

1. `REQ.*`: 外部请求输入（host/path/header/token 等）
2. `CTX.*`: 模板中间变量
3. 输入变量是否必填必须明确标注

### 6.2 输出约定

1. 默认通过 `return --from lib <target>` 输出目标链路/上游标识
2. 出错场景通过 `error --from lib <error_code>` 返回
3. 不依赖隐式全局副作用

### 6.3 错误码规范

- 推荐格式：`PC-TPL-<DOMAIN>-<NNNN>`
- 示例：
  - `PC-TPL-AUTH-0001`：缺少或非法认证头
  - `PC-TPL-ROUTE-0001`：路由参数缺失

## 7. 策略建议（Best Practice）

1. 默认启用严格策略：`missing_var=strict`。
2. 模板中尽量使用 typed value，避免字符串模拟布尔/数字。
3. fallback 路径必须显式，禁止隐式“掉默认”。
4. 模板必须包含最少 1 条失败路径与 1 条 fallback 路径。

## 8. 首批模板（P0）

1. `route_basic`
   - host/path 匹配
   - 明确 default fallback
2. `auth_rewrite_fallback`
   - Bearer 鉴权
   - path rewrite
   - fallback 到默认上游

## 9. 迭代计划

### P0（本 RFC 配套）

1. 发布模板样例与使用说明。
2. 建立模板命名、错误码、变量契约规范。

### P1

1. 从模板抽象 `std.route.* / std.auth.* / std.rewrite.*` 子流程。
2. 补充模板专项测试基线（成功/失败/fallback）。

### P2

1. 模板版本元数据与兼容声明。
2. 模板索引文档与自动校验脚本。

## 10. 开放问题

1. 模板参数是否统一通过 `CTX` 注入，还是保持 `REQ`/`CTX` 双通道？
2. `error` 与 `return` 在模板输出中的规范优先级是否需要强约束？
3. 是否引入模板级别的 `policy` 声明头，避免部署端遗漏策略配置？

## 11. 总结

先做“官方模板 + 契约规范”，再做“标准库化抽象”，能以最低风险提升脚本复用能力与可维护性。
