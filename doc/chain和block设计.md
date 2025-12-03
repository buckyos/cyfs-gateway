# chain和block的设计

基本设计理念:

block = function / sub , 一个chain的所有block在一个env中运行
chain = process (进程)，不同的chain之间状态是隔离的，通过全局环境变量和IPC(输入REQ和输出RESULT) 进行状态共享.
hook_point = chain list. 在一个hook_point上可以挂一组chain,一个hook point上的所有chain共享全局环境变量，但不共享chain内的变量。
Server可以有多个hook_pint（比如pre_req,main,post_resp),由server的开发者决定这些hook point的输入（通过全局变量），以及对result值的解读

## block (Code Block)
一个Chain由一个block列表组成，会按确定的顺序依次执行block.每个block在一个chain内都有一个唯一的id,不可以在一个chain内插入不同
任何block中调用return,则该chain的执行结束，得到返回结果
在block中可以调用另一个block. 有两种调用方法
- goto $blockid | $chainid，将当前执行顺序跳到目标block，相当于改变执行顺序。goto后的代码不会被执行。nginx里的`修改当前req后re-route`就比较适合这个场景
- exec $blockid, 在当前执行位置插入目标block, 执行完目标block的指令后，会回到call的下一行 (注意block没有返回值，大家相当于共享一个全局变量环境)

## chain (Process Chain)
Chain是一个完整的独立执行体，类似进程。每个Chain通过定义都会有一个全进程独立的id(系统实现的时候可能会通过前缀自动构造这个id)


## hook_point 
站在ProcessChainHttpServcer的角度理解HookPoint
- main 收到请求后，决定如何处理请求：直接返回RESP / 返回一个forward target 
- post 当系统确认好resp准备返回给client时，通过该hook_pint对resp进行再处理，得到最终的resp

## buckyos的实际例子
访问服务的逻辑有下面几个部分组成

### 核心(node-gatway主逻辑)
匹配http请求(通常是匹配host/url)，来决定将请求发送给哪个目标。
`整个node-gateway的主逻辑配置，都是调度器自动生成的`
这个匹配是有严格的优先级的（顺序敏感）
- 通过匹配Host得到明确的service_id(appid),
    - 快捷方式优先，看看host是否匹配系统快捷方式
    - 匹配默认用户
    - 子域名匹配
    - 前缀匹配

- 权限控制：判断该请求是否合法
根据 来源信息 + 目标app + 系统权限配置，判断是否需要拦截该请求
这里也包括一些传统的流量控制逻辑

- 特殊请求直接得到RESP
根据权限配置，自动响应一些浏览器发起的特殊请求

- 得到service-id可以访问的kernel service列表
优先匹配kernel service(通过url匹配)，这意味着如果service开发者在器内部实现了和kernel service一样的url,也会被覆盖掉

- 对req进行预处理（可能是第三方逻辑)
处于一些兼容需要，有的移植来的app需要对req进行一些预处理

- forward到当前appid的目标上去(buckyos-select && forward $ANSWER.target)
buckyos-select是一个buckyos扩展的命令，会在内部读取system_config的service_info,并构造合适的forward target(另一个思路时暴露读取service_info的指令，然后在process_chain里拼接最终target)
优化:当发现target service 就在本地时，会固化成foward 127.0.0.1:real_port

- 结论
从代码模块话的角度来看，上述逻辑应该是一组block call
```
call parse_appid_from_host
call permit_check
call dicrect_process
call forward_to_service
call app_pre_process_req //这里是call另一个chain?
call forward_to_app
```

### 后处理 （node-gateway辅助逻辑）
我们希望应用服务能专注于业务开发，一些和浏览器相关的权限控制细节由系统统一处理
该部分能力也是调度器自动构造的
下面的处理逻辑，应该挂在node-gateway-http的post逻辑上
- 根据resp确定service_id(appid)
- 按需增加正确的跨域请求头

### Zone Gateway
这里是zone-gatway的逻辑，这个逻辑一般基于系统配置使用固定模板(非调度器生成)
功能有
- 提供标准的http/https协议栈，转发给核心的gatweay-http-server （注意在REQ里添加适当的来源信息）    
- 提供对内核服务的访问支持（目前就是提供对system_config的访问支持）,解决调度器访问内核服务的问题


### 手工运维需求
站在运维的角度，每台设备上的cyfs-gatway的配置文件，由4部分组成,按顺序合并构造最终的配置文件
- user_gateway 运维可修改，只影响本机
- boot_gateway 不可手工修改，通常是系统配置的一部分，应通过管理软件修改
- node_gateway 不可修改，调度器高配自动修改
- post_gateway 运维可修改，只影响本机

#### 按上述设计，运维的常见任务的完成方法
- 对选定的node（可以是全部node)的cyfs-gatway配置文件，进行修改：通过系统管理软件，修改其boot_gateway配置
- 针对选定的node,添加不受buckyos (bug) 影响的配置：登录目标主机，手工修改 user_gateway 或 post_gateway
- 诊断具体问题：登录目标主机，通过cyfs-gateway命令行增加一些临时的规则进行诊断。诊断完成后调用reload就可以放弃所有的临时修改
