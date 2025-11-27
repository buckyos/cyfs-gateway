

1. 启动stack
2 获得新连接
3 调用process chain进行处理，得到 目标
- probe && forward (upstream) , 和另一个stream url绑定
- server server_id , 将stream交给另一个 server 处理
- parser && server server_id , 将quesiton发送一个QA server 处理


--- server 的类型
- QA server 
- stream server
1. main(new_stream) 进入 main_process_chain 处理

- http server
1. main(http_request) 进入 main_process_chain 处理
2. 

-- router 处理
1. router 处理 http request ， 得到 http response



## 问题
````
        let result = TcpStack::builder()
            .id("test")
            .bind("127.0.0.1:8085")
            .servers(server_manager)
            .hook_point(chains)
这里绑定hook_piont的时候，应该是  .hook_point("main",chains)? 
```

## http server的特殊性
 Server是否要独立出http server, 还是只要有stream server 和 datagram server 就可以？


## 从process chain使用的角度来看
```
let mut request = StreamRequest::new(Box::new(tls_stream), local_addr);
        request.source_addr = Some(remote_addr);
        request.dest_host = server_name;
        let (ret, stream) = execute_stream_chain(executor, request)
            .await
            .map_err(into_stack_err!(StackErrorCode::ProcessChainError))?;
        if ret.is_control() {
            if ret.is_drop() {
                return Ok(());
            } else if ret.is_reject() {
                return Ok(());
            }

            if let Some(CommandControl::Return(ret)) = ret.as_control() {
```

最终由调用者来处理Return，Return由定义一些标准的“错误“

## process chain的状态管理(env)

保存代码的executor和每次执行的context是否分离？ 
```  
        let executor = {
            self.executor.lock().unwrap().fork()
        };
```

## process chain扩展
```
 let request_map = StreamRequestMap::new(request);
    let chain_env = executor.chain_env();
    request_map.register(&chain_env)
        .await
        .map_err(|e| config_err!(ConfigErrorCode::ProcessChainError, "{}", e))?;
````
这里应该是 chain_env.register 比较合适。。 


## process chain的执行
首先需要有合适的benchmark 来衡量性能
主要命令的实现
对命令进行扩展

## cyfs-gateway的产品进程
1. 配置文件管理
2. 初始化全局对象（按需？）
3. 启动Server (按需启动？)
4. 启动stack 
为什么acme_mgr要特化实现？ 而不是一个标准扩展

## tunnel框架
rtcp协议文档
rtcp tunnel支持递归创建 （Tunnel->tunnel)

## socks tunnel

## 使用js(ts)
使用ts扩展process chain的复杂落哦
使用ts扩展server (更快的实现server)

## cmd server
这个名字有点奇怪， 是控制器服务
要考虑架构设计上是否存在潜在的安全问题