# 配置基础示例

## 示例 1：最小可运行配置

### 用户问题

我只想先起一个最小可运行的网关配置，应该怎么组织？

### 分析要点

- 顶层的 `stacks` / `servers` 是 map 定义源
- key 会被注入成 `id`
- `hook_point` / `blocks` 可以先用最小 map 写法

### 回答骨架

```yaml
stacks:
  tcp_listener:
    protocol: tcp
    bind: 0.0.0.0:8080
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return "server http_backend";

servers:
  http_backend:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              return ok;
```

### 结论

这是“配置承载结构”示例，不负责证明业务语义是否满足用户更复杂目标。

## 示例 2：includes 与 merge

### 用户问题

主配置和 include 文件合并后为什么结果与预期不同？

### 分析要点

- include 路径相对当前 include 源解析
- `path` / `*_path` 按主配置文件目录归一化
- object 递归 merge，array 去重追加，其他标量后者覆盖前者

### 回答结构

1. 先说明装载链
2. 再解释当前文件优先级高于它 include 的文件
3. 再区分“include 路径解析”和“配置值路径归一化”

## 示例 3：为什么 `id` 不需要手写

### 用户问题

`stacks.tcp1.id` 需要显式写吗？

### 结论

通常不需要。
`stacks.<key>`、`servers.<key>`、`timers.<key>`、`limiters.<key>`、`global_process_chains.<key>` 会注入成 `id`，`collections.<key>` 会注入成 `name`。
