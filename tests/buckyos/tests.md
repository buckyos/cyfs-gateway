# buckyos的真实配置测试

1.测试访问public app成功: `req_app_public_ok.json`
2.测试访问prviate app失败: `req_app_private_no_cookie_fail.json`
3.测试有正确的cookie 访问private app成功: `req_server_node_gateway.json`
4.测试有cooke,但jwt appid不匹配的失败: `req_app_private_cookie_wrong_appid_fail.json`

5.测试通过/kapi/访问service成功: `req_service_by_kapi_ok.json`
6.测试通过host-perfix访问service成功: `req_service_by_host_prefix_ok.json`
7.测试通过无前缀的的域名(appid="_")访问service成功: `req_service_by_root_host_ok.json`
8.测试service在app的block list中的情况，访问service失败: `req_service_blocked_by_app_fail.json`
9.测试 `/1.0/identifiers/*` 特例命中 `system_config`: `req_service_system_config_identifiers_ok.json`
10.测试 `/.well-known/*` 特例命中 `system_config`: `req_service_system_config_well_known_ok.json`
