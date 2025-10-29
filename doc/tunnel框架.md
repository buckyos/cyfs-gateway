## cyfs-gateway 的设计目的？


## tunnel框架
1. 在两个设备之间（设备用device did区分），有且仅有一条（默认）tunnel，tunnel协议可以被扩展。Tunnel是2层协议，默认适应ip协议
2. Tunnel一旦建立，就可以基于该Tunnel建立 应用层协议：Stream,Datagram
3. 可以用url来标识Tunnel,Stream,Datagram : 
- 标识Tunnel $协议名://Tunnel目标设备名/ 
- 标识Stream $协议名://$Tunnel目标设备名/$StreamId
  

- 标识Datagram $协议名://Tunnel目标设备名/$DatagramId

4. StreamId是递归的，可以是另一个 $协议名://$Tunnel目标设备名/$StreamId （但是需要符合url规范）

tcp://
5. 实现了任意的组合

## 使用用户态协议栈
- 为什么要用用户态协议栈？
- cyfs-gateway通过端口映射提供服务
- 开发者使用标准的tcp / udp 协议开发标准的app server

## rtcp协议简介
- 协议设计

##  基于cyfs-gateway构建任意远程桌面  (vs frp方案)
- 目标
- 准备 公网跳板机 + 内网跳板机
- 安装软件


------------------------------

## 扩展框架简介（相关代码结构讲解）




