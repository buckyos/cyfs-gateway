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
| req_server_node_gateway.json | server:node_gateway:main | forward to 127.0.0.1:3200 for /kapi/system_config |
| req_stack_node_rtcp.json | stack:node_rtcp:main | forward tcp:///host:port |
| req_stack_zone_gateway_http.json | stack:zone_gateway_http:main | return server node_gateway |
