# Buckyos Process Chain Debug Tests

Tests for real buckyos config (cyfs_gateway.yaml + includes). Uses the same pattern as `tests/process_chain_debug/`.

## Scripts

### run_debug_tests.py

Runs all `req_*.json` in this directory against `cyfs_gateway.yaml`.

```bash
python run_debug_tests.py
python run_debug_tests.py -v          # verbose: print full result JSON
python run_debug_tests.py --config path/to/config.yaml
```

### run_debug_single.py

Run one req file (manual / ad-hoc debugging).

```bash
python run_debug_single.py req_server_node_gateway.json
python run_debug_single.py req_stack_node_rtcp.json --id stack:node_rtcp:main
python run_debug_single.py req_stack_zone_gateway_http.json --repeat 3
```

## Test Cases

| req_file | target | assertion |
|----------|--------|-----------|
| req_app_public_ok.json | server:node_gateway:main | publicview app with valid cookie, forward to 127.0.0.1:10161 |
| req_app_private_no_cookie_fail.json | server:node_gateway:main | filebrowser without cookie, redirect to login |
| req_app_private_cookie_wrong_appid_fail.json | server:node_gateway:main | filebrowser with valid jwt but mismatched appid, redirect to login |
| req_server_node_gateway.json | server:node_gateway:main | filebrowser with verify-jwt success, forward to 127.0.0.1:10160 |
| req_service_by_kapi_ok.json | server:node_gateway:main | /kapi route success, forward to 127.0.0.1:10165 |
| req_service_by_host_prefix_ok.json | server:node_gateway:main | host prefix service success, forward to 127.0.0.1:10262 |
| req_service_by_root_host_ok.json | server:node_gateway:main | root host service success, forward to 127.0.0.1:10262 |
| req_service_blocked_by_app_fail.json | server:node_gateway:main | service blocked by app, reject |
| req_service_system_config_identifiers_ok.json | server:node_gateway:main | `/1.0/identifiers/*` special case, forward to 127.0.0.1:3200 |
| req_service_system_config_well_known_ok.json | server:node_gateway:main | `/.well-known/*` special case, forward to 127.0.0.1:3200 |
| req_app_static_dir_ok.json | server:node_gateway:main | static dir app success, return `server bob_testweb` |
| req_stack_node_rtcp.json | stack:node_rtcp:main | forward tcp:///host:port |
| req_stack_zone_gateway_http.json | stack:zone_gateway_http:main | return server node_gateway |
