# 路由与 Process Chain 示例

## 示例 1：HTTP 路由与 server 分发

### 用户问题

怎么按请求条件把流量分发到不同 server？

### 分析要点

- 路由决策应放在 `hook_point`
- 返回值通常决定 `server` / `forward` 等动作
- 响应后处理应放在 `post_hook_point`

### 回答结构

1. 指出“路由决策”和“响应后处理”要分开
2. 给出最小 `hook_point` 例子
3. 如果需要，再补 `post_hook_point`

## 示例 2：TCP / UDP 转发

### 用户问题

怎么把四层流量 forward 到上游？

### 分析要点

- 这属于流量转发，不是 HTTP 语义问题
- `forward` 适合描述目标上游
- 若还需要限速、统计、server 转发，按 chain 环境变量和动作补充

## 示例 3：Process Chain 结构化控制

### 用户问题

复杂规则应该写在一条命令里还是拆成结构化语句？

### 结论

只要涉及 `if/elif/else/end`、`for ... end`、`match-result ... end`，就要明确写成 statement 级结构，而不是把它们当普通命令。
