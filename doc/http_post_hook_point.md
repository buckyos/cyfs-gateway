# HTTP post_hook_point 配置说明

`post_hook_point` 是 HTTP server 的一个可选 process chain。

它的用途是：

- 在 HTTP server 已经拿到 `Response` 之后执行
- 在响应真正写回客户端之前，允许 process chain 修改响应头

它和普通 `hook_point` 的区别是：

- `hook_point` 决定请求如何路由，比如 `call-server`、`forward`、`reject`
- `post_hook_point` 不参与路由决策，只处理已经生成出来的响应

## 执行时机

当前时机是：

1. 普通 `hook_point` 先执行
2. 网关根据结果生成或拿到一个 `Response`
3. `post_hook_point` 执行，允许修改 `RESP`
4. 修改后的 `Response` 返回给 Hyper
5. Hyper 再把响应头和响应体发给客户端

这意味着：

- `post_hook_point` 可以改响应头
- 但它不是“响应已经开始发送后”的 hook
- 一旦响应头已经开始写到网络，HTTP 普通 header 就不能再改

## 配置格式

配置形式和普通 `hook_point` 一样，也是一个 chain map：

```yaml
servers:
  web_main:
    type: http
    hook_point:
      main:
        priority: 1
        blocks:
          default:
            priority: 1
            block: |
              call-server web_dir;

    post_hook_point:
      main:
        priority: 1
        blocks:
          add_header:
            priority: 1
            block: |
              map-add RESP x-test "1";

  web_dir:
    type: dir
    root_path: ./www
```

## 可用环境变量

`post_hook_point` 当前只暴露一个响应相关变量：

- `RESP`: `Map`

`RESP` 的 key 是响应 header 名称，value 是对应 header 值，类型都是字符串。

示例：

```txt
RESP["content-type"] = "text/html"
RESP["cache-control"] = "public, max-age=60"
```

可以做的操作通常包括：

- `map-add RESP <key> <value>`
- `map-set RESP <key> <value>`
- `map-remove RESP <key>`

## 当前限制

`post_hook_point` 目前有几个明确限制：

- 只能修改响应 header，不能修改 status code
- 不能修改 HTTP version
- process chain 的 `drop` / `reject` / `return` 等 control 结果会被忽略
- 只有在内部已经拿到 `Ok(Response)` 时才会执行
- 如果内部处理直接返回错误，外层生成的 500 响应不会再经过这个 `post_hook_point`

换句话说，`post_hook_point` 适合做“响应头补充/改写”，不适合做“二次路由”或“重新决定返回结果”。

## 常见用法

### 统一补充自定义 header

```yaml
post_hook_point:
  main:
    priority: 1
    blocks:
      default:
        priority: 1
        block: |
          map-add RESP x-gateway "cyfs";
```

### 覆盖上游返回的 header

```yaml
post_hook_point:
  main:
    priority: 1
    blocks:
      default:
        priority: 1
        block: |
          map-set RESP cache-control "no-store";
```

### 删除不希望暴露的 header

```yaml
post_hook_point:
  main:
    priority: 1
    blocks:
      default:
        priority: 1
        block: |
          map-remove RESP server;
```

## 建议

- 把 `post_hook_point` 用在统一补 header、改缓存头、补 CORS header 这类场景
- 不要依赖它去修改响应状态码或重新决定路由
- 如果你需要按请求内容决定走哪个 server，逻辑应放在普通 `hook_point`
- 如果你需要“响应发送后”再处理，那已经不是普通 HTTP header 能覆盖的能力范围

## 参考

- 环境变量说明：[process chain env.md](/Users/liuzhicong/project/cyfs-gateway/doc/process%20chain%20env.md)
- 配置样例：[cyfs_gateway_config.yaml](/Users/liuzhicong/project/cyfs-gateway/doc/cyfs_gateway_config.yaml)
- 测试样例：[test_cyfs_gateway.yaml](/Users/liuzhicong/project/cyfs-gateway/src/apps/cyfs_gateway/tests/test_cyfs_gateway.yaml)
