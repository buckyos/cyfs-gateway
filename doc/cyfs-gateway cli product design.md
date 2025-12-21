## cyfs-gateway CLI Main Product Goals

Our Core Design Philosophy

- AllInOne 
  - Single executable file with no dependencies + single configuration file
  - Support a large number of common servers using the same approach
  - Open source project based on Rust, making it easy to compile your own server into cyfs-gateway and deploy it easily

- cyfs process-chain (Core)
  - Dynamically adjust various rules of cyfs-gateway through rule scripts. Route traffic that meets conditions to different destinations according to rules
  - Ultra-minimal subset of bash, maintain and modify routing rules with bash experience
  - Built-in JS support, can directly write rule scripts in JS

- Support both development and operations needs
  - For developers, it's a better nginx
  - For operations, all configurations constructed by developers natively support "online temporary modifications" with finer control granularity and clearer isolation boundaries

- Configuration files provide include and params mechanisms to achieve modular segmentation of configuration files, supporting the writing of complex large configuration files

## cyfs-gateway Installation

- apt, in the future installation can be completed through `apt install cyfs-gateway`
- Before being included in common application installers, use installers similar to rustup / bash scripts to complete installation
- Suitable installation packages can also be found in the releases of the github cyfs-gateway repo
- cyfs-gateway is a single executable file structure, downloading a single executable file can also run normally with minimal functionality
- Install through compilation
- cyfs-gateway itself has no auto-upgrade functionality, requires manual upgrade, or is integrated into more complete products (such as buckyos) for automatic upgrade
- Self-upgrade through `cyfs upgrade` command
- If buckyos-desktop / buckyos-service suite is already installed on the device, cyfs-gateway will be automatically installed

## Common Network Behavior Management

The requirements here are similar to iptables, adding a meaningful network behavior in one line. From a classification perspective, it can be divided into network behavior control (generally used on proxies) and operations traffic control (generally used on reverse proxies).
We start with network behavior control.

### Enable SOCKS Proxy Server
1. Create a socks_server

```bash
cyfs start socks-server --bind 127.0.0.1:1080
```

This command starts a socks_server, whose default behavior is `to send received requests through the local machine`.

Note that this socks_server has no authentication capability, because the port it binds to is a loopback address, and this server can only be used by the local machine.

If you want to run a formal socks-server, we strongly recommend using cyfs-gateway's configuration file mode, which allows in-depth security configuration of the server.

If you just want to temporarily run a socks service on a VPS, use run instead of start, and the socks-server will automatically terminate when the command ends.

```bash
cyfs run socks-server --bind :1080
```

2. Add at least one rule to socks_server

When the socks server is started in start mode, enter the following command.

```bash
cyfs add_rule socks-server 'match ${REQ.dest_host} *github.com && forward "socks://target_server/${REQ.dest_host}:${REQ.dest_port}"' 
```
The meaning of the above rule is: if the target domain name of the request ends with github.com, then send the traffic through the target_server socks server. Note that rules created with add_rule will be placed at the front of all rules. When two add_rule commands create rules, the rule created later has higher matching priority. cyfs has 3 commands to insert rules, 1 command to delete rules, and 1 command to adjust rule priority
  - add_rule Insert rule at the front (highest priority)
  - append_rule Insert rule at the end (lowest priority)
  - insert_rule $pos --file $file_name Insert rule at specified position, and read rule content from specified file (can be multi-line)
  - move_rule $pos $new_pos
  - remove_rule $pos | $start_pos:$end_pos Delete all rules in a region
  - set_rule $pos $new_rule_code


It should be emphasized again that all the commands above create a temporary socks-server, which will become invalid after cyfs process restart or `cyfs reload --all` command. If you want to create permanent rules
- Use configuration file mode
- Use `cyfs save $config_file` to save permanently

`match ${REQ.host} *github.com && forward socks://target_server/${REQ.dest_host}:${REQ.dest_port}` is a typical cyfs process-chain rule. Its logical syntax is similar to bash, let's parse it simply:

  - Execute the match command, parameters are ${REQ.host} *github.com, REQ.host is an environment variable whose value comes from the socks proxy request initiated by the user
  - cmd1 && cmd2 If cmd1 executes successfully, then execute cmd2. So this rule means if the match succeeds, execute the forward command
  - The forward command is one of the common termination commands of cyfs process-chain. Its termination return value `socks://target_server/${REQ.dest_host}:${REQ.dest_port}` will be parsed by the socks server and execute the "traffic redirection effect". The URL socks:// looks very understandable, we call it cyfs stream url.

### Understanding cyfs stream url: $protocol://$tunnelid/$streamid
stream(tcp): rtcp://, socks:// 
datagram(udp): rudp://

The socks protocol has wide compatibility but poor security. We recommend using it in secure network environments. Its main purpose is to connect legacy systems.
The rtcp protocol is an open source tunnel protocol implemented by cyfs-gateway, with security equivalent to TLS, simpler key management, recommended for use on public networks.
We will implement a tunnel protocol based on ssh.

### Enable Port Mapping
Similar to ssh -D, add a port mapping in one line.

```bash
cyfs add_dispatch $port $target_url 
cyfs remove_dispatch $port
```
Map a local port to a stream url or datagram url
This is a helper function, cyfs converts it into 1 stack creation command + 1 process-chain rule command, equivalent to the following two commands
```bash
cyfs start_stack dispatch_tcp_stack --bind 127.0.0.1:$port
cyfs add_rule dispatch_tcp_stack 'forward $target_url'
```

### Large-scale Rule Sets Based on Tags (TODO: needs to be improved based on actual situation)

In cyfs process chain, the order of match rules is very important. After a request arrives, matches are always executed in order from top to bottom until a termination instruction is encountered.

Although there is a match instruction that can match a certain pattern in one rule, sometimes the complexity of the rules themselves is very large, which will lead to writing many, many matches.

This not only makes the rules complex, but also reduces runtime performance (after all, cyfs-gateway is a high-performance network tool). At this time, you should consider using the tag system.

#### Query Tags
Usage: When dest_host is found to contain tag-test in HOST_DB query, traffic is forwarded to proxy_host via rtcp protocol
```bash
match-include HOST_DB ${REQ.dest_host} tag-test && forward 'rtcp://$proxy_host/${REQ.dest_host}:443' 
```

The system has two built-in global, read-only Tag libraries, one is BASE_HOST_DB, and one is BASE_IP_DB. The so-called read-only means these two DBs will not be changed through process-chain-rule. BASE_HOST_DB + variable USER_HOST_DB finally gets the global HOST_DB.

The underlying design of the above mechanism is based on the `collection` and `set` concepts of process-chain foundation, and its core idea is similar to ipset.
- HOST-DB supports using wildcards
- IP-DB supports network segments and address ranges
- Records support timeout (commonly used to prevent DDoS attacks)
- Supports standard sqlite3 db operations

#### Modify Tags
```bash
db-add-tag HOST_DB tag-test "google.com"
```

## Learning Through cyfs show
```bash
cyfs show
```
View the real-time running status of cyfs-gateway.
Calling `cyfs save` at this time will save the real-time running status as a configuration file

```bash
cyfs show config
```
View the content of the currently effective configuration file of cyfs-gateway. Note that it does not include temporary behaviors added through the command line.

#### Common Match Rules Summary
- match
- eq 

#### Common Termination Instructions
- forward
- reject
- accept
- call-server
- exit
- return 

## Transparent Gateway (Bypass Router)

In network behavior management, if you have the following two requirements, you should consider using transparent gateway mode

1. Software that needs to manage network behavior is inconvenient to set up a proxy
2. Need to perform global network behavior management for devices

For example, testing an iOS App, you need to make some requests go to the test server during testing, but iOS lacks the ability to edit the hosts file. The traditional method of using self-built DNS has a heavy environment setup. Using transparent gateway mode can well support this testing requirement.

Basic mode of transparent gateway
Traffic capture (system related) -> Execute rules -> forward to destination

The structure of traffic capture and rule execution should be written in cyfs-gateway configuration files. After this structure exists, command line can be used

### Traffic Capture (System Related)

Currently we mainly support Linux systems,
iptables->TProxy
iptables->TUN

cyfs-gateway internally does not have the functionality to operate iptables and make transparent gateway effective, but it comes with some bash scripts configured in typical environments. You can complete the transparent gateway setup through the following tutorial
If you already have other iptables rules on your transparent gateway, please set them carefully.

### Execute Rules

Where to write rules?
  In transparent gateway mode, you don't need to start a proxy server, but directly use protocol stack + ProcessChain to forward traffic directly
  The process-chain previously configured for the proxy server can be directly configured for the transparent protocol stack
  If you need to start a proxy server (business requirement), you can also easily achieve it through forward socks://127.0.0.1/, which is just one more forwarding

How to get source_device_id?
  Through source_mac identification?
  Enable DHCP?
  Sniff from protocol

How to get dest_host?
  Sniff from protocol
  Reverse lookup through dest_ip
    Intercept DNS queries? (DoH, DoT may not be interceptable)

Rules based on dest_ip tags
  Precise IP matching, usually targeting precise target devices or target networks, placed at the front of rules
  GeoIP-based matching, usually placed at the end. It must be clear that this database is not 100% accurate, and business logic cannot rely on this matching rule.

### Control Local Network Through Virtual Transparent Gateway
With today's mainstream PC performance, creating a virtual machine as a transparent gateway can more simply perform global control of the local machine's network behavior.
My habit is to use a portable transparent gateway box, which has the advantage of being usable for mobile phones.

## Capture (Intercept) Web Content

- Intercept content of interest to a specific directory and analyze it (requires client to install root certificate)
- Construct rules based on content.
  - Complete through TLS handshake, prompt client to send HTTP requests
  - Construct more complex rules based on URL and cookies in HTTP requests (different logged-in users use different remote proxy servers)

cyfs-gateway implements HTTPS protocol interception according to the following process:
1. Create CA certificate and let the device that needs to intercept content install the certificate
```bash
cyfs gen_ca $name $info
```
Download custom CA certificate with command
```bash
cyfs show ca
```
2. Add certificate replacement rules in cyfs-gateway's TLS protocol stack
3. Direct certificate replacement requests to smart_http_server,
4. The process_chain of http_server can access all http request information and rewrite http resp.

After establishing the basic environment through configuration files, the rules in steps 2 and 4 can be adjusted in real time through cyfs cli tools.

The general rules for configuration are as follows
	1. Match source device
	2. Match target domain name
  3. Method of saving resp

You can also use JS to implement complex process-chain rules, performing necessary processing on resp before saving.

## Common Operations Management 
cyfs-gateway is also a great Layer 3 reverse proxy tool.
This is commonly used in cluster operations.

The basic structure is: developers create servers, operations create stacks

### Separation of Operations and Development
- Independently configure and manage various high-security level certificates

### Daily Traffic Analysis
Developers usually have logs and statistics, but for large organizations, core metrics need to have at least `dual evidence`
- Statistics on basic access volume (total requests)
- Statistics on performance (processing latency)

Daily statistics are completed with configuration files, with small data volume and few details
You can use command line to perform temporary detailed statistics and analysis on specific traffic that meets rules (more useful than tcpdump)

### Management of Abnormal Traffic
- Soft degradation (simulate jitter)
- Rate limiting
- Reject
- Frequency reduction

### Gray Upgrade / Smooth Migration


### Start High-Performance Protocol Stack on Specific Devices
Because cyfs-gateway's stack and server are separated, and servers can be started independently, the stack that obtains original traffic can be transparently switched for the server

We plan to support dpdk / netmap. 

Enable the corresponding stack on machines that support such high-performance protocol stacks to replace traditional tcp_stack/udp_stack, which can greatly improve performance.

### nginx Configuration File Conversion Tool

To be developed.


## Quick Server Construction

Basic format `cyfs run|start $server_template_id $params`

The principle is to find a server_template through server_template_id, and modify the server according to the values of params. Then start the server
The semantics of run is `temporary run`, which will capture the server's output in the command line, and the server will stop immediately after control+c ends
The semantics of start is `temporary start service`, after successful startup it will output server_id, and the server can be controlled through cyfs commands afterwards. The server will stop after cyfs-gateway reload.

### Start an echo server to verify if an Endpoint is available
```bash
cyfs run echo_server --bind :10053
```


### Start an http server to generate some temporarily available URLs, or do regular speed tests, check if ssl certificates are valid
```bash
cyfs start http_server --bind :80
```

#### Common Development Requirements for http_server

Add a router to http_server
```bash
cyfs add_router [$http_server_id] --target /home/lzc/www/
cyfs add_router [$http_server_id] --uri /abc/ --target /home/lzc/abc/ 
cyfs add_router [$http_server_id] --sub api --target tcp:///:8000 
```

add_router is a helper function, the implementation will automatically translate into `add_rule` command. Therefore, after the command completes, in addition to outputting that the router has been added, it will also display information about the added rule.

## CLI Product Design Goals Differ from Configuration File Product Design Goals

The product design purpose of configuration files is for large-scale formal product development, and is a choice for intermediate and advanced users. For non-developer users targeted by CLI products, the concepts that need to be understood are as follows:

- include mechanism
  The most important basic mechanism. Understand that cyfs-gateway uses large configuration files, and all configuration files at runtime will be atomically synthesized into one. You can see the final configuration file currently loaded by cyfs-gateway through show_config
  Based on the object tree of this final configuration file, then perform command line operations. And understand that after each reload, unsaved modifications will be restored to the original state.
- Remote sync mechanism based on include
  Each included file can choose to configure different remote and sync mechanisms. Configuration files configured with remote may be modified due to automatic updates.
  Those configured as auto sync will be synchronized by the system
  Those configured as manual sync are triggered to update through the cyfs sync command
- params mechanism
  {{sn_host}} in configuration files is a string replacement mechanism similar to `environment variables`.
  Understand how some customized configuration files can affect a group of objects by modifying one param.
  To modify the behavior of such configurations, it's best to directly modify the params.yaml of the configuration file, rather than modifying through CLI.

## Save Current State to Configuration File

Sometimes, you may want the behavior of cyfs-gateway constructed through CLI to take effect permanently, use

`cyfs save [--config $RESULT]`  

Save the unsaved CLI operation results to a specified configuration file.

- This uses the include mechanism of configuration files to put all modifications caused by command lines into a result similar to cli_result.yaml.
- The original configuration file will not be affected by the `cyfs save` command

## CLI Security Management
- cyfs-gateway is an administrator tool
- cyfs-gateway CLI has no remote mode, use ssh to log in to the remote server and then use cyfs-gateway CLI
- cyfs-gateway can enable web control panel for convenient remote management.

1. First run requires entering admin password 
2. After successful login, each cyfs command will operate on the last logged-in cyfs-gateway
3. By executing the cyfs logout command, you can also require re-entering the admin password
4. Users with system permissions can reset the admin password after deleting the permission configuration file


## CLI Command Line Design Framework

General command line logic: 

```bash
cyfs $verb_object_type [$objectID] [--$param_name1 param_value1 ...]
```

- Verb list: gen,run,start,add,set,remove,insert,move,clean,list,show,save,sync,
- Object types: rule, stack, server. To reduce operations, some verbs allow omitting object types.
- The full name of object ID is usually $rootobj:$child:$child_child, which can be omitted to reduce input. Different types of objects have different logic for obtaining default ids


The core meaning is to understand that cyfs-gateway at runtime consists of a group of stack/process-chain/server objects. The core of CLI products is to perform CRUD on specified objects through commands.

The above object tree can be viewed through the `cyfs show` command. And locate through objid path.

Advanced users must first understand these objects and their construction methods, and then correctly operate on these objects according to their needs.

### Helper Commands

On the basis of conforming to basic command line semantics, wrap some common behaviors into a logical command.

- add_dispatch , remove_dispatch
- add_router, remove_router


## Reference 1: Detailed CLI Design (continuously improved)

### Manage config

### Manage server

### Manage stack

### Manage rule(code block)

### Manage limiter

## Reference 2: All Instructions in process-chain

## Reference 3: Using JS in process-chain




