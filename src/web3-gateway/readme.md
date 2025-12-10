为什么web3-gateway不是buckyos的一个应用？
比如用户可以在应用商店里安装web3-gateway,然后自己的zone就变成了一个web3 bridge,可以给其它需要sn的zone提供服务。

答:目前web3_gateway的整体逻辑与基于zone的基础逻辑相差太大，一定是需要有运维的情况下才能做到和原有的buckyos逻辑共存。
让web3_gateway与buckyos强耦合，还会带来潜在的循环以来问题。

因此在这个阶段，web3-gateway是基于cyfs-gatway开发的应用，而不是基于buckyos开发的应用，是一个为了防止混乱的刻意设计。web3-gateway的妥善运行是需要有运维支持的。 

## web3-gatway的核心配置文件

- web3_gateway.yaml 核心配置文件，可以看成是代码的一部分
- website.yaml 被web3_gatweay引用，提供https://sn.$sn_base 的常规网页需求。这个根据运维手工填写。默认为 {}
- fullchain.cert,fullchain.pem 包含 sn.$sn_base, *.web3.$sn_base 的证书和对应的密钥。如果做全自拥有证书的逻辑就没有 *.web3的证书
- ca/ca_cert,ca_cert.pem 如果是测试环境，fullchain.cert是自签名的。这里保存用于于自签名的CA证书
- dns_zone 手工配置的，DNS Zone文件。web3_gateway是DNS Server,会根据该配置处理返回值
- zone_zone 自动生成的，包含有buckyos定制的DNS TXT记录的DNS Zone文件
- device.doc.jwt, device_private_key.pem rtcp协议栈用到的 DeviceConfig和对应的密钥文件
- node_idenity.json （包含device.doc.jwt)，兼容buckyos的设备identity文件，目前暂没用到

## web3-gatway的核心数据文件
- sn.db sqlite数据库文件，需要定期备份

## 日志文件
- /opt/buckyos
