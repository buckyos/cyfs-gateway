# **cyfs-gateway CLI 产品介绍（内部开发者版）**

文档状态：内部评审用 / 第一版草案（会持续迭代）  
目标读者：参与 cyfs-gateway / CLI / 配置体系 / process-chain 的开发者  
非目标：对外完整用户文档、全量运维手册（运维体系仅概要，详见另文档）

---

## **0\. 名称与组件约定**

* **项目名称**：`cyfs-gateway`  
* **进程/可执行文件名**：`cyfs-gateway`  
* **CLI 命令**：`cyfs`  
  （安装后提供 `cyfs`，用于控制本机的 `cyfs-gateway`，因为 `cyfs-gateway` 太长）

本文默认所有示例都在同一台机器上操作本机 `cyfs-gateway`。远程管理不在本篇展开（可通过 SSH 登录远端后执行 `cyfs`，或启用 Web 控制面板）。

---

## **1\. 产品定位与核心设计理念（内部共识版）**

cyfs-gateway 的核心定位不是单点“代理/反代”，而是一个 **本地优先（local-first）的网关工具箱**：

* **AllInOne**  
  * 单可执行文件 \+ 单配置体系（可拆分 include）  
  * RUST 开源，可把自己的 server 编译进 cyfs-gateway 并部署  
* **cyfs process-chain（核心差异）**  
  * 规则脚本动态调整路由/转发/阻断/改写等策略  
  * 语法贴近 bash 的超精简子集（强调：不是 bash 全集）  
  * 支持 JS 扩展（复杂逻辑可用 JS）  
* **同时服务开发 \+ 运维**  
  * 对开发：更好用的网关/代理实验场（可“现场改”）  
  * 对运维：能把“线上临时修改”纳入体系（可细粒度、可隔离、可沉淀）  
* **配置工程化**  
  * `include`：配置拆分、分层、可组合  
  * `params`（`{{param}}`）：把“可变项”显式暴露给用户/部署系统  
  * 运行态变更可 `cyfs save` 写入 overlay（不污染主配置）

---

## **2\. 两个经典任务：10 分钟上手闭环（内部开发者最小路径）**

目的：让读者先建立“怎么跑起来、怎么改策略、怎么确认生效、怎么撤销/保存”的闭环心智。  
注：以下示例聚焦 CLI 体验；正式生产建议以配置文件为主。

### **2.1 任务一：启动一个临时 socks 代理，并按域名分流**

#### **2.1.1 启动 socks server（本机环回，免鉴权）**

cyfs start socks-server \--bind 127.0.0.1:1080

语义：

* `start`：后台启动一个**临时服务**（reload 或进程重启后会消失）  
* 绑定在 `127.0.0.1`：仅本机可用，因此默认不做身份认证

如果是在 VPS 上临时跑（前台，Ctrl+C 结束即退出）：

cyfs run socks-server \--bind :1080

#### **2.1.2 添加一条规则：匹配 `*github.com` 的请求走远端 socks**

cyfs add\_rule socks-server \\  
  'match ${REQ.dest\_host} \*github.com && forward "socks://target\_server/${REQ.dest\_host}:${REQ.dest\_port}"'

要点：

* 规则从上到下执行，遇到终止指令（如 `forward/return/reject/accept`）停止  
* `add_rule` 会插入到最前面（优先级最高），同类规则后插入的优先级更高

规则相关常用操作（位置以 `$pos` 表示）：

* `add_rule`：插入到最前（最高优先级）  
* `append_rule`：插入到最后（最低优先级）  
* `insert_rule $pos --file $file`：插入到指定位置，从文件读取多行规则  
* `move_rule $pos $new_pos`：调整优先级  
* `remove_rule $pos` 或 `remove_rule $start:$end`：删除  
* `set_rule $pos $new_rule_code`：覆盖替换

#### **2.1.3 确认当前运行态**

cyfs show

查看对象树、server/stack/chain 的实时状态（开发调试时优先用它建立“我现在到底启动了什么”的信心）。

#### **2.1.4 保存为可持久化配置（可选）**

如果希望把 CLI 临时变更固化成配置层：

cyfs save

`cyfs save` 会把“运行态差量”写入一个 overlay 文件（具体写入哪一层与 include 顺序有关，后文详述）。

---

### **2.2 任务二：端口映射（dispatch）：把本地端口映射到一个 stream url**

目标：像 “ssh \-D/端口转发” 一样，一行命令建立“本地端口 \-\> 远端目标”的映射。

cyfs add\_dispatch 18080 'rtcp://proxy\_host/:443'

删除：

cyfs remove\_dispatch 18080

`add_dispatch` 是一个 helper：内部等价于“启动一个监听 stack \+ 给它挂一条 forward 规则”：

cyfs start\_stack dispatch\_tcp\_stack \--bind 127.0.0.1:18080  
cyfs add\_rule dispatch\_tcp\_stack 'forward rtcp://proxy\_host/:443'

这类 helper 的产品目标：把高频动作做成“少概念、少输入”的捷径，但内部仍落在 stack/process-chain 的统一模型上。

---

## **3\. 基础概念：看懂 cyfs-gateway 的对象与运行模型**

### **3.1 对象树：stack / server / process-chain（hook\_point \+ blocks）**

运行时可以把 cyfs-gateway 理解为一棵对象树，核心对象是：

* **stack**：网络入口（bind/捕获），协议栈（tcp/udp/tls/rtcp…）  
* **server**：应用层服务（socks/http/dns/自定义 server…）  
* **process-chain**：规则引擎（hook\_point → blocks → block 脚本）

典型路径有两类：

1. **server 模式（显式代理）**  
   client → server → process-chain → 终止指令（forward/return/…）  
2. **透明栈模式（旁路由/透明代理）**  
   traffic capture stack → process-chain → forward/accept/reject

---

### **3.2 process-chain 的最小语义（必须统一口径）**

这是整个产品的“语言层基建”。内部开发/写文档必须保持一致表述。

* 执行方式：**从上到下顺序执行**  
* 组合：`cmd1 && cmd2`（短路执行，类似 shell：cmd1 成功才执行 cmd2）  
* 变量：`${REQ.xxx}` 形式（环境变量来自输入 collections）  
* 终止：遇到终止指令后结束当前链执行（例如 `forward/return/reject/accept`）

常见匹配：

* `match`：模式匹配（glob/通配符语义以实现为准）  
* `eq`：严格相等

常见终止：

* `forward`：输出一个“转发目标”（通常是 stream url）  
* `reject`：拒绝  
* `accept`：接受（透明/栈场景常用）  
* `return`：返回一个结果给上层（例如 “server xxx” 或 “forward …”）  
* `exit`：结束（语义按实现）  
* `call-server` / `call`：调用（依赖外部 server 或内置能力）

**内部建议**：我们在文档里尽量用 “match/eq \+ forward/return/reject/accept” 这组最小闭环讲清楚，其它指令放到参考手册。

---

### **3.3 stream url：统一“转发目标”的表达**

统一格式（概念）：

$协议名://$tunnelid/$streamid

大类：

* stream(tcp)：`tcp://`、`socks://`、`rtcp://`  
* datagram(udp)：`udp://`、`rudp://`（按实现支持情况）

说明（内部口径）：

* socks：兼容性广但安全弱（适合内网/临时联通旧系统）  
* rtcp：cyfs-gateway 的 tunnel 协议，目标是公网可用、更简单的密钥管理（与 TLS 级别安全性对齐）  
* 未来规划：ssh tunnel 等

---

## **4\. 高级任务一：透明代理 / 旁路由（概要 \+ 最小落地）**

旁路由是强需求，但系统/内核/路由表/iptables 组合复杂，本篇只给“结构与最小落地路径”，详见《cyfs-gateway 运维与旁路由落地指南》（另文档）。

### **4.1 什么时候用旁路由**

* 需要管理网络行为的软件不方便配置代理（例如某些 App/设备）  
* 需要按设备做全局网络行为管理（按 source\_device 区分策略）

典型例子：iOS App 测试期间，把部分域名导到测试环境；iOS 不方便改 hosts，自建 DNS 又重。这时旁路由模式更合适。

### **4.2 旁路由的基本结构**

流量捕获（系统相关） \-\> 执行规则（process-chain） \-\> forward 到目的地

流量捕获我们当前主要支持 Linux：

* iptables → TPROXY  
* iptables → TUN

现状：cyfs-gateway 内部不直接操作 iptables；我们提供典型环境脚本帮助配置。多规则环境要谨慎（这部分属于运维文档范围）。

### **4.3 规则执行：透明栈与 server 的关系**

* 旁路由模式下可以不启动代理 server，直接 “协议栈 \+ process-chain” 转发  
* 之前写给代理 server 的 chain，多数可以复用于透明栈  
* 如果业务需要 server，也可以通过 `forward socks://127.0.0.1/…` 多一跳实现

### **4.4 关键难点（内部已知问题清单）**

这些点建议在运维文档详细展开；本文只把问题“显式化”。

* 如何得到 `source_device_id`：  
  * source\_mac？  
  * DHCP 结合？  
  * 协议嗅探？  
* 如何得到 `dest_host`：  
  * TLS SNI/HTTP Host 嗅探  
  * dest\_ip 反查  
  * DNS 拦截（但 DoH/DoT 不一定拦得到）  
* 基于 dest\_ip tag 的规则：  
  * 精确 IP/网段匹配一般放最前  
  * GeoIP 一般放最后，并强调“不保证 100% 准确，业务逻辑不能强依赖”

---

## **5\. 高级任务二：HTTPS 抓包/拦截（MITM）与内容处理（概要）**

该能力高价值也高风险。内部文档必须同时写清楚：用途、边界、证书生命周期与撤销方式。对外文档要更严格合规声明。

### **5.1 目标能力**

* 拦截感兴趣内容保存到目录，交给后续分析（需要客户端安装自定义根证书）  
* 基于内容构造规则（例如按 URL/cookie 分流到不同远端代理）

### **5.2 基本流程（概念）**

1. 生成 CA 证书，并在目标设备安装信任

cyfs gen\_ca \<name\> \<info\>  
cyfs show ca

2. 在 tls 协议栈中配置“证书替换规则”  
3. 将被替换证书的请求导向 `smart_http_server`  
4. 在 http\_server 的 process-chain 中访问请求信息，并可对响应改写/落盘

配置文件建立基础环境后，可通过 CLI 实时调整“证书替换规则”和“http 处理规则”。

### **5.3 规则组织建议（内部约定）**

常见规则顺序：

1. 匹配来源设备  
2. 匹配目标域名  
3. 定义保存/改写策略

复杂处理建议：

* 用 JS 扩展对响应做必要处理，再保存

---

## **6\. 高级概念：debug、严格校验、include/params 分层、save 写入策略**

### **6.1 `cyfs show_config`：查看最终合成配置（include 展开 \+ params 替换）**

我们把“最终生效配置可见”作为配置体系的基础能力。

* `cyfs show_config`：输出当前 cyfs-gateway 最终生效的大配置（合成结果）  
* 用途：  
  * 解释 include 覆盖顺序是否符合预期  
  * 检查 params 替换后最终值  
  * 现场排障：你以为加载了 A，实际上生效的是 B

内部注意：`show_config` 输出应尽量稳定（排序/默认值），便于 diff；并考虑敏感字段脱敏策略（JWT/私钥等）。

---

### **6.2 Debug 模式：脱离网络副作用的 chain 单元测试**

目标：规则像代码一样可测试；并为 CI/回归测试提供入口。

基本思路：

* cyfs-gateway 保持原 runtime 参数（config、include、params 都照常）  
* 提供 `--debug <debug-config>`，进入 debug 模式  
* debug 模式下：**不加载 stacks/servers**，只加载 process-chain  
* 构造 mock request（一组 collections），执行指定 chain，输出变量集合

运行示例：

cyfs-gateway \--config\_file cyfs\_gateway.yaml \--debug test\_req.json

`test_req.json`（示例）：

{  
  "input": {  
    "REQ": {  
      "target\_host": "www.buckyos.com",  
      "path": "/index.html"  
    }  
  },  
  "process\_chain\_id": "global\_chain",  
  "output": \["RESP"\]  
}

内部约定建议（后续可扩展）：

* Debug 输出至少包含：  
  * 最终输出集合（RESP/ANSWER 等）  
    \-（建议）执行 trace：命中哪条 block/哪条指令、短路情况、终止指令  
* 更进一步（规划）：支持对 `call` 类依赖提供 stub（确定性单测）

---

### **6.3 严格容错：尽可能在加载大配置时提前发现错误**

我们倾向于：

* **严格**的配置校验：能在加载阶段发现的错误，不要放到运行时才暴露  
* 支持单元测试与静态检查配合（debug \+ validate/严格加载）

内部实现建议方向：

* 未引用对象/重复 ID/非法字段/非法 stream url 立即报错  
* 规则层做基础质量检查（如明显 unreachable/引用缺失）

---

### **6.4 include \+ params：配置工程化的核心机制（结合实际例子）**

下面给一个更大的例子说明 include/param 的“工程化意义”。

#### **6.4.1 核心功能文件（开发写的 YAML）：`node_gateway.yaml`**

includes:  
  \- path: params.json  
  \- path: website.yaml

servers:  
  web3\_sn:  
    id: web3\_sn  
    type: sn  
    host: "{{sn\_host}}"  
    boot\_jwt: "REDACTED\_BOOT\_JWT"  
    owner\_pkx: "REDACTED\_OWNER\_PKX"  
    device\_jwt: \["REDACTED\_DEVICE\_JWT"\]  
    ip: "{{sn\_ip}}"

  main\_dns:  
    id: main\_dns  
    type: dns  
    hook\_point:  
      main:  
        id: main  
        priority: 1  
        blocks:  
          default:  
            id: default  
            priority: 1  
            block: |  
              call resolve ${REQ.name} ${REQ.record\_type} web3\_sn && return;

  main\_http:  
    type: http  
    hook\_point:  
      main:  
        id: main  
        priority: 1  
        blocks:  
          default:  
            id: default  
            priority: 1  
            block: |  
              eq ${REQ.host} "sn.{{sn\_host}}" && return "server web3\_sn";  
              map-add "REQ" "method" "query\_by\_hostname"  
              call qa "web3\_sn" "REQ" && eq ${ANSWER.state} "active" && return "forward rtcp://${ANSWER.did\_hostname}/:443";

  main\_tls:  
    bind: 0.0.0.0:3443  
    protocol: tls  
    certs:  
      \- domain: "sn.{{sn\_host}}"  
        cert\_path: ./fullchain.cert  
        key\_path: ./fullchain.pem  
      \- domain: "\*.web3.{{sn\_host}}"  
        cert\_path: ./fullchain.cert  
        key\_path: ./fullchain.pem  
    hook\_point:  
      main:  
        id: main  
        priority: 1  
        blocks:  
          default:  
            id: default  
            priority: 1  
            block: |  
              return "server main\_http";

  tls\_raw\_forward:  
    bind: 0.0.0.0:443  
    protocol: tcp  
    hook\_point:  
      main:  
        id: main  
        priority: 1  
        blocks:  
          default:  
            id: default  
            priority: 1  
            block: |  
              call https-sni-probe || reject;  
              match ${REQ.dest\_host} "sn.{{sn\_host}}" && return "forward tcp:///:3443";  
              match ${REQ.dest\_host} "www.{{sn\_host}}" && return "forward tcp:///:3443";  
              match ${REQ.dest\_host} "{{sn\_host}}" && return "forward tcp:///:3443";  
              map-create "QUESTION" && map-add "QUESTION" "dest\_host" "${REQ.dest\_host}" && map-add "QUESTION" "method" "query\_by\_hostname";  
              call qa "web3\_sn" "QUESTION" && eq ${ANSWER.self\_cert} "true" && return "forward rtcp://${ANSWER.did\_hostname}/:443";  
              reject;

#### **6.4.2 参数文件（机器/用户改 JSON）：`params.json`**

{  
  "params": {  
    "sn\_host": "devtests.org",  
    "sn\_ip": "192.168.100.64",  
    "sn\_boot\_jwt": "REDACTED",  
    "sn\_owner\_pkx": "REDACTED",  
    "sn\_device\_jwt": "REDACTED"  
  }  
}

意义：

* `{{sn_host}}` / `{{sn_ip}}` 等可变项被显式集中管理  
* 用户/部署系统只需要改 params，不必理解所有规则细节  
* 对内部开发：可以提供“模板化配置”，提升复用与交付效率

---

### **6.5 主配置文件（合成入口）：默认 `cyfs_gateway.json`**

用户使用的主配置文件（入口），默认命名为 `cyfs_gateway.json`：

{  
  "includes": \[  
    { "path": "user\_gateway.json" },  
    { "path": "boot\_gateway.yaml" },  
    { "path": "node\_gateway.yaml" },  
    { "path": "post\_gateway.json" }  
  \]  
}

约定（内部共识建议）：

* `.yaml`：人写的“稳定层”  
* `.json`：程序/CLI 构造的“可机器 diff 的层”  
* include 顺序决定覆盖顺序（后 include 覆盖前 include）

---

### **6.6 `cyfs save` 写入策略（与 include 顺序绑定）**

`cyfs save` 保存 CLI 造成的“运行态差量”时，会根据 include 的层次与顺序，选择写入某个 `.json` 层（例如 `post_gateway.json` 或 `user_gateway.json`）。

内部建议（工程化强烈推荐）：

* **默认写入专门的 overlay 层（建议是 `post_gateway.json`）**  
* 尽量避免默认覆盖“用户手写层”或“稳定层”  
* 这样可以做到：  
  * 主配置（boot/node/yaml）不被污染  
  * 临时策略可沉淀为“补丁层”，方便回滚/审计

---

## **7\. 运维能力（本篇仅概要）**

cyfs-gateway 也可作为三层反向代理/集群运维工具，但体系更专业，本篇只列能力边界：

* 运维与开发分离：证书/安全配置独立管理  
* 流量分析：请求量、延迟等指标（强调双证据）  
* 异常流量管理：软降级（抖动）、限流、拒绝、降频  
* 灰度升级/平滑迁移  
* 高性能协议栈规划：dpdk / netmap（需在特定机器启用对应 stack）

详见：《cyfs-gateway 运维与治理实践》（另文档，待补齐）

---

## **8\. CLI 参考手册（内部版：先覆盖核心命令框架）**

### **8.1 命令框架**

通用语义：

cyfs \<动词\>\_\<对象类型\> \[对象ID\] \[--参数名 参数值 ...\]

* 动词（示例）：`gen, run, start, add, set, remove, insert, move, clean, list, show, save, sync`  
* 对象类型：`rule, stack, server`  
  为减少输入，部分命令允许省略对象类型或提供 helper 命令。

对象 ID 的全名通常是 `$root:$child:$child_child`；CLI 支持省略（按类型有默认定位规则）。

---

### **8.2 常用命令速查**

#### **查看状态**

cyfs show  
cyfs show\_config

#### **启动/运行 server**

cyfs run  \<server\_template\_id\> \[--bind ...\]  
cyfs start \<server\_template\_id\> \[--bind ...\]

语义：

* `run`：前台临时运行（Ctrl+C 退出即停止）  
* `start`：后台临时启动（返回 server\_id，可后续控制；reload 后会停止）

#### **规则管理（process-chain blocks）**

cyfs add\_rule \<obj\_id\> '\<rule\>'  
cyfs append\_rule \<obj\_id\> '\<rule\>'  
cyfs insert\_rule \<pos\> \--file \<file\>  
cyfs move\_rule \<pos\> \<new\_pos\>  
cyfs remove\_rule \<pos\>|\<start:end\>  
cyfs set\_rule \<pos\> '\<rule\>'

#### **helper 命令**

cyfs add\_dispatch \<port\> \<target\_url\>  
cyfs remove\_dispatch \<port\>

cyfs add\_router \[server\_id\] \--target \<dir\_or\_upstream\> \[--uri ...\] \[--sub ...\]  
cyfs remove\_router ...

#### **保存与同步**

cyfs save \[--config \<RESULT\_FILE\>\]  
cyfs sync

---

## **9\. TODO（内部开发跟踪点）**

以下内容在对外发布前建议明确状态与边界：

* process-chain 语法边界（哪些 bash 语法支持/不支持）  
* debug 输出：trace / 变量 diff / call stub（至少设计到位）  
* show\_config 脱敏策略与稳定输出（排序、默认值补全）  
* 透明代理脚本与回滚机制（运维文档中给标准做法）  
* nginx 配置文件转换工具（规划）  
* ssh tunnel 支持（规划）  
* dpdk/netmap stack 支持（规划）

---

## **10\. 附：内部写文档/示例的统一规范建议**

为了减少“示例复制跑不通”和“概念口径不一致”，建议内部遵循：

1. 命名统一：`cyfs-gateway`（进程） \+ `cyfs`（CLI）  
2. 示例命令可复制可运行（尤其是 `forward` 拼写、REQ 字段名一致）  
3. 示例敏感信息一律 `REDACTED`  
4. 每个教程闭环至少包含：  
   * 做了什么（start/add\_rule）  
   * 如何确认（show/show\_config）  
   * 如何撤销（remove/clean/reload）  
   * 如何保存（save）

