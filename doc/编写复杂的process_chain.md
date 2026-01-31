# 编写复杂的process_chain

本文主要讲解process_chain框架的模块化支持。

基本设计理念:

block = function / sub :一个chain的所有block在一个env中运行。意味着大家共享所有的环境变量，在一个block中定义的变量，可以再另一个block中直接访问。对变量的修改也是对所有block有效的
chain = process (进程) : 不同的chain之间状态是隔离的，通过全局环境变量和IPC(输入REQ和输出RESULT) 进行状态共享.
hook_point = chain_list :  在一个hook_point上可以挂一组chain,一个hook point上的所有chain共享全局环境变量，但不共享chain内的变量。

Server可以有多个hook_pint（比如pre_req,main,post_resp),由server的开发者决定这些hook point的输入（通过全局变量），以及对result值的解读

## block (Code Block)

一个Chain由一个block列表组成，会按确定的顺序依次执行block.每个block在一个chain内都有一个唯一的id,不可以在一个chain内插入不同

任何block中调用return,则该chain的执行结束，得到返回结果

在block中可以调用另一个block. 有两种调用方法

- goto $blockid | $chainid，将当前执行顺序跳到目标block，相当于改变执行顺序。goto后的代码不会被执行。nginx里的`修改当前req后re-route`就比较适合这个场景
- exec $blockid, 在当前执行位置插入目标block, 执行完目标block的指令后，会回到call的下一行 (注意block没有返回值，大家相当于共享一个全局变量环境)

## chain (Process Chain)

Chain是一个完整的独立执行体，类似进程。每个Chain通过定义都会有一个全进程独立的id(系统实现的时候可能会通过前缀自动构造这个id)

Chain包含一个map<block_id,block> ,按block的优先级排序后，从优先级最小的block执行到优先级最高的block


## code block的执行流程

- 准备环境变量
- 创建process-chain环境（创建进程）
- 按顺序执行code block
- 执行结束，环境变量被改变
- hook_point的调用者去使用这些环境便利。



在hook_point的使用者看来，其逻辑如下
```python
def on_req(request,context):
    hook_point_env = create_env()
    # 设置默认值
    hook_point_env.set("result","reject")
    init_env_values(request,context)
    process_env = hook_point_env.clone()
    run_process_chain_list(process_chain_list,process_env)
    do_resp(process_env,context)

def do_resp(process_env,context):
    # 这里不关心run_result，只关心env.result
    result = process_env.get("result")
    match result：
        # 默认drop
        case "drop" | "reject" | _ :
            error_info = process_env.get("error")
            context.set_error(error_info)
            context.close();
        case "accept":
            resp = process_env.get("resp")
            context.response(resp);
        case "forward*":
            context.forward(result);
        case "server*":
            context.serve(result);


def run_process(process_id,process_env):
    block_list = get_process_block_list(process_id)
    block_index = 0
    run_result = true
    while(block_index < block_list.len()):
        block = block_list[block_index]
        run_result = run_block(block,process_env)
        block_result = process_env.get("result"):
        if not run_result:
            break 
        
        # 流程里没有exec,这是在run_block内部处理的
        match block_result
            case "drop"|"reject":
                break
            case "accept":
                break
            case "goto*":
                # 为了防止死循环，这里会对goto计数
                block_index = get_block_index(block_result)
            case "exit":
                break
            case _:
                # run_result成功但没有终止result，说明继续下一个block
                block_index ++
                continue
    return run_result

def run_process_chain_list(process_chain_list,process_env):
    chain_index = 0
    run_result = true
    while(chain_index < process_chain_list.len()):
        process_chain = process_chain_list[block_index]
        run_result = run_process(process_chain,process_env.clone())
        process_result = process_env.get("result"):
        if not run_result:
            break 
        
        match process_result
            case "drop"|"reject":
                break
            case "accept":
                break
            case "goto*":
                # 为了防止死循环，这里会对goto计数
                chain_index = get_chain_index(process_result)
            case "exit":
                break
            case _:
                # run_result成功但没有终止result，说明继续下一个block
                chain_index ++
                continue    
        
    return run_result
            
```
可以看到，process-chain的运行容器非常关注run_block的运行结果(run_result)

下面列出所有的控制命令:

### exec : 调用一个block，核心模块化支持 
    `exec block_id1 && exec block_id2`

### return | error : 影响 `exec block_id1 && exec block_id2` 这种写法

- return $value. 成功结束当前block,并设置result = value
- error $value.失败结束当前block,并设施result = $value

另外5个终止命令，是对一些常用写法的简写 (run_block内部其实只认exit/return)   
accpet => return "accept"
reject => error "reject"
drop => error "drop"
forward xxx => return "forward xxxx"
server xxx => return "server xxxx"

### goto : jump到另一block执行，不会返回。
支持goto到另一个porcess_chain(通常被限制为同一个process_chain_list,或属于global_chain_list),是控制命令里唯一的跨process_chain指令
当goto到另一个process_chain时，使用fork模式:让新的process_chain集成当前的process_chain_env.

### exit：结束 process_chain_list
通常很少用,return/error 基本能达到相同目的
这里只适用于 “立刻结束当前process_chain_list，但不希望修改上一个process_chain构造的 result或error,run_result"


## 实际例子
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

能否只用process-chain,不用扩展命令实现真实的select的问题
```bash
exec select_node 
forward ${upstream_url}
```

```bash
#block select_node
choices service_info
echo "suffle result: ${nodeid}"
eq nodeid thisnode && upstream_url="tcp://_/${port}" && return
eq netid thisnetid && upstream_url="rtcp://${node_host}/:${port}" || upstream_url="rtcp://${gateway_host}/rtcp://${node_host}:${port}"
return
```



- 结论
从代码模块话的角度来看，上述逻辑应该是一组block exec
```bash
exec parse_appid
exec permit_check 
exec forward_to_service
exec forward_to_app
```

### 手工业务运维命令
- 柔性运维(随机让一些请求失败)


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
