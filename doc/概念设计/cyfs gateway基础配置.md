## 基础配置例子

```json
{
    "process_chain":{
        "chain1":{
            "code":""
        },
        "include":{
            "type":"dir",
            "path":"./process_chains"
        }
    },
    "inner_services" : {
        "main_sn": {
            "type":"sn",
            "config":{
                "main_host":"sn.buckyos.ai"
            }
        }
    },
    

    "server":{
        "test_dns":{
            "type":"dns",
            "config":{

            },
            "hook":{
                "on_req":"chain1",
                "post_resp":"chain1"
            }
        },
        "dispatch":{
        }
    },

    "stack":{
        "main_udp":{
            "protocol":udp,
            "bind":["127.0.0.1:53"],
            "on_req":[
                "chain1": {
                    "code":"
                        return test_dns
                    "
                }
            ]
            
        }
    }
}
```


分层逻辑



inner_services
---
http-server

---
http,https

----
rtcp,quic

---
tcp、udp