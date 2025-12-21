## cyfs-gateway cli 主要产品目的

我们的核心设计理念

- AllInOne 
  - 无依赖的单可执行文件 + 单配置文件
  - 用同样的思路支持大量的常见服务器
  - 基于Rust的开源项目，可以很容易的将自己的server编译进cyfs-gateway,并轻松部署

- cyfs process-chain（核心）
  - 通过规则脚本，能动态的调整cyfs-gateway的各种规则。将符合条件的流量按规则路由到不同的目的地
  - bash的超精简子集，凭借bash经验就能维护和修改路由规则。
  - 内置js支持，可以直接用js编写规则脚本  

- 同时支持开发需求和运维需求
  - 对开发来说，是更好的nginx
  - 对运维来说，所有开发构造的配置都能原生支持 ”线上临时修改“，控制粒度更细，隔离边界更明确

- 配置文件提供include和params机制，以实现配置文件的模块切分，支持编写复杂的大型配置文件

## cyfs-gateway的安装

- apt, 未来通过apt install cyfs-gateway就能完成安装
- 在被常见的应用安装器收录以前，使用类似rustup的安装器 / bash 脚本来完成安装
- 在github cyfs-gateway repo的release里，也能找到合适的安装包
- cyfs-gateway是单可执行文件结构，下载单个可执行文件，也可以正常以最小集功能运行。
- 通过编译安装
- cyfs-gateway本身没有自动升级功能，需要手工升级，或被集成到更完整的产品(比如buckyos)里自动升级
- 通过 `cyfs upgrade` 命令自升级
- 如果设备上已经安装了的buckyos-desktop / buckyos-service套件，那么会自动安装cyfs-gateway

## 常见网络行为管理

这里需求类似iptables, 一行增加一个有意义的网络行为，从分类上来说，可以分成 网络行为控制（一般用在代理上）和 运维流量控制（一般用在反向代理上）。
我们先从网络行为控制开始。

### 启用socks代理服务器
1. 创建一个socks_server

```bash
cyfs start socks-server --bind 127.0.0.1:1080
```

该条命令启动一个socks_server,其默认行为是`将收到的请求通过本机发送出去`。

注意该socks_server没有任何的身份验证能力，因为其绑定的端口是环回地址，该server只有本机能使用。

如果是要运行一个正式的socks-server,我们强烈推荐使用cyfs-gateway的配置文件模式，可以对服务器的安全进行深入配置。

如果只是在VPS上临时运行一个socks服务，使用run代替start，此时只要命令结束，socks-server就会自动终止。

```bash
cyfs run socks-server --bind :1080
```

2. 给socks_server添加至少一条规则

当socks服务器是以start模式启动后，输入下面命令。

```bash
cyfs add_rule socks-server 'match ${REQ.dest_host} *github.com && forward "socks://target_server/${REQ.dest_host}:${REQ.dest_port}"' 
```
上述规则的含义是：如果请求的目标域名是以github.com结尾的，那么就把流量通过target_server这台socks服务器发送出去。注意使用add_rule创建的规则会放在所有规则的最前面。使用两条add_rule创建的规则，后创建的规则的匹配优先级更高。cyfs有3条命令来插入规则,1条命令用来删除规则,1条命令用来调整规则的优先级
  - add_rule 插入规则到最前面（优先级最高)
  - append_rule 插入规则到最后（优先级最低)
  - insert_rule $pos --file $file_name 插入规则到指定位置,并从指定的文件中读取规则的内容（可以是多行的）
  - move_rule $pos $new_pos
  - remove_rule $pos | $start_pos:$end_pos 删除一个区域的所有规则
  - set_rule $pos $new_rule_code


需要再次强调的是，上述命令所构造的都是一个临时的socks-server,会在cyfs进程重启或cyfs reload --all 命令后失效。如果希望创建永久规则
- 使用配置文件模式
- 使用 cyfs save $config_file 永久保存

`match ${REQ.host} *github.com && forward socks://target_server/${REQ.dest_host}:${REQ.dest_port}` 是一条典型的cyfs process-chain 规则。其逻辑语法与bash类似，简单的解析一下:

  - 执行 match命令，参数是${REQ.host} *github.com , REQ.host是一个环境变量，其值来自用户发起的socks代理请求
  - cmd1 && cmd2 如果cmd1执行成功则执行cmd2. 因此这一条的规则就是如果匹配成功就执行forward命令
  - forward命令是cyfs process-chain的常见终止命令之一。其终止返回值`socks://target_server/${REQ.dest_host}:${REQ.dest_port}`会被socks服务器解析并执行"流量重定向的效果".其中socks://这个URL看起来很好理解，我们称作cyfs stream url。

### 理解cyfs stream url: $协议名://$tunnelid/$streamid
stream(tcp): rtcp:// ， socks:// 
datagram(udp): rudp://

socks协议兼容性广，安全性差，我们推荐在安全的网络环境内使用。其主要目的是联通旧有系统。
rtcp协议是cyfs-gateway实现的开源tunnel协议， 有和TLS同等级别的安全性，基于密钥管理更简单，推荐在公网使用。
我们将会实现基于ssh的tunnel协议。


### 启用端口映射
类似ssh -D ,一行增加一个端口映射.

```bash
cyfs add_dispatch $port $target_url 
cyfs remove_dispatch $port
```
把一个本地端口，映射到一个stream url 或 datagram url上
这是一个helper函数，cyfs将其转换成了1条stack创建命令+1条 process-chain rule命令，相当于下面两条命令
```bash
cyfs start_stack dispatch_tcp_stack --bind 127.0.0.1:$port
cyfs add_rule dispatch_tcp_stack 'forward $target_url'
```

### 基于tag的大规模规则集 (TODO:需要根据实际情况完善)

在cyfs process chain中，match规则的顺序非常重要。一个请求到来后，总是按顺序从上到下执行match,直到遇见了终止指令。

尽管有match指令，可以在一条规则里匹配某种模式，但有的时候，规则的复杂度本身就很大，这会导致编写很多很多的match.

这不但让规则变得复杂，而且会降低运行的性能（毕竟cyfs-gateway）是一个高性能网络工具,此时应该考虑使用tag系统。

#### 查询tag
使用如下:当dest_host在HOST_DB中查询到含有tag-test时，流量通过rtcp协议转发到proxy_host
```bash
match-include HOST_DB ${REQ.dest_host} tag-test && forward 'rtcp://$proxy_host/${REQ.dest_host}:443' 
```

系统有两个自带的全局，只读Tag库，一个是BASE_HOST_DB,一个是BASE_IP_DB,所谓的只读是指这两个DB不会通过process-chain-rule改变。BASE_HOST_DB + 可变的USER_HOST_DB最终得到了全局的HOST_DB.

上述机制的底层设计基于process-chain基础的`collection`和`set`概念，其核心思想和ipset接近。
- HOST-DB支持使用通配符
- IP-DB 支持网段，支持地址范围
- 记录支持超时（常见用于防止DDoS攻击）
- 支持标准的sqlite3 db操作

#### 修改tag
```bash
db-add-tag HOST_DB tag-test "google.com"
```

## 通过cyfs show学习
```bash
cyfs show
```
查看cyfs-gateway的实时运行状态。
此时调用`cyfs save`,会把实时运行状态保存成配置文件

```bash
cyfs show config
```
查看cyfs-gateway当前生效的配置文件内容。注意不包含通过命令行添加的临时行为。

#### 常见的match规则整理
- match
- eq 

#### 常见终止指令
- forward
- reject
- accept
- call-server
- exit
- return 

## 旁路由

在网络行为管理中，如果有下面两种需求，应该考虑使用旁路由模式

1. 需要管理网络行为的软件不方便设置代理的
2. 需要针对设备进行全局网络行为管理的

比如测试一个iOS App, 需要在测试期间让部分请求走到测试服务器上，而iOS又缺乏对hosts文件的编辑能力。传统使用自建DNS的方法，环境搭建又比较重型。此时使用旁路由模式就可以很好的支持该测试需求。

旁路由的基本模式
流量捕获(系统相关)->执行规则->forward到目的地

流量捕获和执行规则的结构，应该用cyfs-gateway配置文件编写。在该结构存在后，可以用命令行

### 流量捕获（系统相关)

目前我们主要支持Linux系统，
iptables->TProxy
iptables->TUN

cyfs-gateway内部并没有操作iptables并让旁路由生效的功能，但自带了一些在典型环境下配置的bash脚本。你可以通过下面教程完成旁路由的设置
如果你旁路由上已经有了其它的iptables规则，请小心设置。

### 执行规则

规则写在哪？
  旁路由模式下可以不用启动代理服务器，而是直接使用协议栈+ProcessChain直接转发流量
  之前给代理服务器配置的process-chain,可以直接配置给透明协议栈使用
  如果需要启动代理服务器（业务需求），也可以很方便的通过forward socks://127.0.0.1/ 实现，就是多一次转发

如何得到source_device_id?
  通过source_mac标识？
  启用DHCP?
  从协议中嗅探

如何得到dest_host?
  从协议中嗅探
  通过dest_ip反查
    拦截dns查询？(DoH,DoT不一定拦截的到)

基于dest_ip tag的规则
  精确的ip匹配，通常面向精确的目标设备或目标网络，放在规则的最前面
  基于GeoIP的匹配，通常放在最后。一定要明确这个数据库不是百分百准确的，业务逻辑不能依赖这个匹配规则。

### 通过虚拟旁路由控制本机网络
以今天主流PC的性能，创建一个虚拟机来做旁路由可以更简单的对本机的网络行为进行全局控制。
我的习惯是使用一个随身的旁路由小盒子，好处是可以给手机用。

## 捕获(拦截)web内容

- 拦截感兴趣的内容到特定目录，并进行分析（需要客户端安装根证书）
- 基于内容来构造规则。
  - 通过TLS握手完成，推进客户端发送HTTP请求
  - 根据HTTP请求中的URL和cookie,构造更复杂的规则（不同的登录用户使用不同的远端代理服务器)

cyfs-gateway按照下面流程实现对https协议的拦截:
1. 构造CA证书，并让待拦截内容的设备安装证书
```bash
cyfs gen_ca $name $info
```
用命令下载自定义CA证书
```bash
cyfs show ca
```
2. 在cyfs-gateway的tls协议栈中，添加证书替换的规则
3. 替换证书的请求导向 smart_http_server,
4. http_server的process_chain中可以访问全部的http request信息，并对http resp进行改写。

通过配置文件建立好基础环境后，后续通过cyfs cli工具，可以对第2步和第4步的规则进行实时调整。

配置的一般规则如下
	1. Match来源设备
	2. Match目标域名
  3. 保存resp的方式

还可以使用js来实现复杂的process-chain rule，在保存前对resp进行一些必要的处理。


## 常见运维管理 
cyfs-gateway也是一个很好的3层反向代理工具。
这常用于集群运维。

基本结构是：开发创建server,运维创建stack

### 运维与开发分离
- 独立配置管理各种高安全级别的证书

### 对流量进行日常分析
开发通常有日志和统计，但对大组织来说，核心指标要至少有`双证据`
- 统计基础的访问量(请求总量)
- 统计性能(处理延迟)

日常统计用配置文件完成，数据量不大，细节不多
可以通过命令行，针对符合规则的特定流量，进行临时的详细统计和分析（比tcpdump好用)

### 对异常流量的管理
- 软降级（模拟抖动）
- 限流
- 拒绝
- 降频

### 灰度升级/平滑迁移


### 在特定的设备上启动高性能协议栈
因为cyfs-gateway的stack与server是分离的，而且server可以独立启动，所以可以透明地给server切换获得原始流量的stack

我们计划支持dpdk / netmap。 

需要在支持这类高性能协议栈的机器上启用相应的stack,来替换传统的tcp_stack/udp_stack就可以大幅度的提高性能。

### nginx配置文件转换工具

待开发.


## 快速构造服务器

基本格式 `cyfs run|start $server_template_id $params`

其原理是通过server_template_id,找到一个server_template,并根据params的值对server进行修改。随后启动server
run的语义是`临时运行`，会在命令行中捕获server的输出，control+c结束后，该server会立刻停止
start的语义是`临时启动服务`,启动成功后会输出server_id,后续可以通过cyfs命令控制该server. cyfs-gateway reload后该server会停止。

### 启动一个echo server,用来验证某个Endpoint是否可用
```bash
cyfs run echo_server --bind :10053
```


### 启动一个http server，产生一些临时可用的URL,或做常规速度测试，检查ssl证书是否有效
```bash
cyfs start http_server --bind :80
```

#### http_server的常见开发需求

给http_server添加一个router
```bash
cyfs add_router [$http_server_id] --target /home/lzc/www/
cyfs add_router [$http_server_id] --uri /abc/ --target /home/lzc/abc/ 
cyfs add_router [$http_server_id] --sub api --target tcp:///:8000 
```

add_router是一个help函数，实现会自动翻译成`add_rule` 命令。因此命令完成后除了输出router已经添加外，还会显示添加的rule的信息。

## cli的产品设计目标与配置文件的产品设计目标不同

配置文件的产品设计目的，是用于大规模的正式产品开发，是中高级用户的选择。对于cli产品面向的非开发用户来说，需要理解的概念如下:

- include机制
  最重要的基础机制。了解cyfs-gateway使用大配置文件，运行时的所有配置文件都会原子的合成一个。通过show_config可以看到当前cyfs-gateway加载的最终配置文件
  基于该最终配置文件的对象树基础上，再去进行命令行操作。并且理解每次reload后，未保存的修改会恢复到原状态。
- 基于include的remote sync机制
  每个include的文件，都可以选择配置不同的remote和sync机制。配置了remote的配置文件，有可能因为自动更新而修改。
  配置为auto sync的，会由系统负责定义同步
  配置为手工 sync的，通过 cyfs sync 命令触发更新
- params机制
  配置文件中的{{sn_host}}，是一种类似`环境变量`的字符串替换机制。
  理解一些定制的配置文件，是如何通过修改一个param就可以影响一组对象的。
  对这类配置的行为进行修改，最好是直接修改配置文件的params.yaml,而不是通过cli去进行修改。

## 保持当前状态到配置文件

有时，会希望通过cli构造的cyfs-gateway的行为可以永久生效，使用

`cyfs save [--config $RESULT]`  

将未保存的cli操作结果，保存到一个指定的配置文件中。

- 这利用配置文件的include机制，将所有命令行造成的修改，放到一个类似cli_result.yaml的结果里。
- 原始配置文件，不会被`cyfs save`命令影响

## cli的安全管理
- cyfs-gateway是管理员工具
- cyfs-gateway cli没有remote模式，用ssh登录到远程服务器上再用cyfs-gateway cli
- cyfs-gateway可以启用web control panel来方便远程管理。

1. 首次运行要求输入管理密码 
2. 登录成功后，每次cyfs指令都会操作上次login的cyfs-gateway
3. 通过执行 cyfs logout 命令，也可以要求重新输入管理密码
4. 有系统权限的用户，在删除权限配置文件后，可以重置管理密码


## cli 命令行设计的框架

命令行通用逻辑: 

```bash
cyfs $动词_对象类型 [$对象ID] [--$参数名1 参数值1 ...]
```

- 动词列表: gen,run,start,add,set,remove,insert,move,clean,list,show,save,sync,
- 对象类型: rule, stack, server。 为了减少操作，有一些动词允许省略对象类型。
- 对象ID的全名通常是 $rootobj:$child:$child_child ，为了减少输入，可以省略。不同类型的对象有其不同的获得默认id的逻辑


其核心意义，就是理解cyfs-gateway在运行时由一组stack/process-chain/server 对象组成。cli产品的核心就是通过命令对指定对象进行CRUD。

上述对象树可以通过`cyfs show`命令查看。并通过objid path定位。

高级的使用者，一定是先理解了这些对象，和这些对象的构造方法，再针对自己的需要正确的对这些对象进行操作。

### 辅助命令

在符合基础命令行语义的基础上，包装一些常用的行为变成一个逻辑命令。

- add_dispatch , remove_dispatch
- add_router, remove_router


## 参考1: cli的详细设计(持续补充完善)

### 管理config

### 管理server

### 管理stack

### 管理rule(code block)

### 管理limiter

## 参考2: process-chain的所有指令

## 参考3: 在process-chain中使用js



