use crate::*;
use simplelog::*;
use std::path::PathBuf;
use std::sync::Once;
use std::time::{SystemTime, UNIX_EPOCH};

static LOGGER_INIT: Once = Once::new();

fn init_test_logger() {
    LOGGER_INIT.call_once(|| {
        TermLogger::init(
            LevelFilter::Info,
            Config::default(),
            TerminalMode::Mixed,
            ColorChoice::Auto,
        )
        .unwrap_or_else(|_| {
            let _ = SimpleLogger::init(LevelFilter::Info, Config::default());
        });
    });
}

fn new_test_data_dir(scope: &str) -> Result<PathBuf, String> {
    let ts = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|e| format!("system time error: {}", e))?
        .as_nanos();
    let pid = std::process::id();
    let data_dir =
        std::env::temp_dir().join(format!("cyfs-process-chain-{}-{}-{}", scope, pid, ts));
    std::fs::create_dir_all(&data_dir)
        .map_err(|e| format!("create test data dir {:?} failed: {}", data_dir, e))?;
    Ok(data_dir)
}

const PROCESS_CHAIN_RANGE_BASIC: &str = r#"
<process_chain_lib id="range_basic_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                range 5 1 10 || return --from lib "range_literal_fail";
                range 20 1 10 && return --from lib "range_false_should_not_pass";
                range $port 1000 2000 || return --from lib "range_var_fail";
                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_RANGE_RUNTIME_ERROR: &str = r#"
<process_chain_lib id="range_runtime_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                range $raw_port 1000 2000;
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_RANGE_PARSE_ERROR: &str = r#"
<process_chain_lib id="range_parse_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                range 5 abc 10;
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRLEN_TYPED_NUMBER: &str = r#"
<process_chain_lib id="strlen_typed_number_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local len=$(strlen "hello");
                is-number $len || return --from lib "len_not_number";
                range $len 5 5 || return --from lib "len_value_fail";
                return --from lib $(type $len);
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRLEN_STRICT_ERROR: &str = r#"
<process_chain_lib id="strlen_strict_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                strlen true;
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STARTS_ENDS: &str = r#"
<process_chain_lib id="starts_ends_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                starts-with --ignore-case "HelloWorld" "hello" || return --from lib "starts_ignore_case_fail";
                ends-with --ignore-case "HelloWorld" "WORLD" || return --from lib "ends_ignore_case_fail";

                starts-with "HelloWorld" "world" && return --from lib "starts_should_fail";
                ends-with "HelloWorld" "HELLO" && return --from lib "ends_should_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_SLICE_SUCCESS: &str = r#"
<process_chain_lib id="slice_success_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                return --from lib $(slice "你好世界" 0:6);
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_SLICE_PARSE_ERROR: &str = r#"
<process_chain_lib id="slice_parse_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                slice "abc" bad;
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_PARSE_AUTHORITY_RETURN: &str = r#"
<process_chain_lib id="parse_authority_return_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                return --from lib $(parse-authority "user:pass@[::1]:8080");
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_PARSE_AUTHORITY_DEFAULT_PORT: &str = r#"
<process_chain_lib id="parse_authority_default_port_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local fallback_port=3180;

                capture --value auth $(parse-auth --default-port $fallback_port "service.internal");
                eq $auth.host "service.internal" || return --from lib "default_host_fail";
                eq $auth.port 3180 || return --from lib "default_port_fail";
                eq $auth.has_port false || return --from lib "default_has_port_fail";
                is-null $auth.userinfo || return --from lib "default_userinfo_fail";

                capture --value auth2 $(parse-authority --default-port 3180 "api.example.com:8443");
                eq $auth2.host "api.example.com" || return --from lib "explicit_host_fail";
                eq $auth2.port 8443 || return --from lib "explicit_port_fail";
                eq $auth2.has_port true || return --from lib "explicit_has_port_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_PARSE_AUTHORITY_ERROR: &str = r#"
<process_chain_lib id="parse_authority_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                parse-authority "https://example.com/path";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_PARSE_URI_RETURN: &str = r#"
<process_chain_lib id="parse_uri_return_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                return --from lib $(parse-uri "https://user:pass@example.com:8443/api/v1?q=1#frag");
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_PARSE_URI_EFFECTIVE_PORT: &str = r#"
<process_chain_lib id="parse_uri_effective_port_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                capture --value secure $(parse-uri "https://example.com");
                eq $secure.scheme "https" || return --from lib "scheme_fail";
                eq $secure.authority "example.com" || return --from lib "authority_fail";
                eq $secure.host "example.com" || return --from lib "host_fail";
                is-null $secure.port || return --from lib "port_fail";
                eq $secure.effective_port 443 || return --from lib "effective_port_fail";
                eq $secure.has_port false || return --from lib "has_port_fail";
                eq $secure.username "" || return --from lib "username_fail";
                is-null $secure.password || return --from lib "password_fail";
                eq $secure.path "/" || return --from lib "path_fail";
                is-null $secure.query || return --from lib "query_fail";
                is-null $secure.fragment || return --from lib "fragment_fail";

                capture --value hostless $(parse-uri "unix:/run/foo.socket");
                eq $hostless.scheme "unix" || return --from lib "hostless_scheme_fail";
                is-null $hostless.authority || return --from lib "hostless_authority_fail";
                is-null $hostless.host || return --from lib "hostless_host_fail";
                eq $hostless.path "/run/foo.socket" || return --from lib "hostless_path_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_BUILD_URI_SUCCESS: &str = r#"
<process_chain_lib id="build_uri_success_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local built=$(build-uri {
                    "scheme": "https",
                    "host": "example.com",
                    "username": "user",
                    "password": "pass",
                    "port": 8443,
                    "path": "/api/v1",
                    "query": "q=1",
                    "fragment": "frag"
                });
                eq $built "https://user:pass@example.com:8443/api/v1?q=1#frag" || return --from lib "build_fail";

                capture --value parsed $(parse-uri $built);
                local rebuilt=$(build-uri $parsed);
                eq $rebuilt $built || return --from lib "roundtrip_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_BUILD_URI_HOSTLESS: &str = r#"
<process_chain_lib id="build_uri_hostless_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local built=$(build-uri {
                    "scheme": "unix",
                    "path": "/run/foo.socket"
                });
                eq $built "unix:/run/foo.socket" || return --from lib "build_hostless_fail";

                capture --value parsed $(parse-uri $built);
                eq $parsed.path "/run/foo.socket" || return --from lib "parse_hostless_path_fail";
                is-null $parsed.host || return --from lib "parse_hostless_host_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_BUILD_URI_ERROR: &str = r#"
<process_chain_lib id="build_uri_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                build-uri {
                    "scheme": "https",
                    "path": "/api/v1"
                };
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_PARSE_QUERY_RETURN: &str = r#"
<process_chain_lib id="parse_query_return_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                return --from lib $(parse-query "?redirect_url=%2Fdashboard&tag=alpha&tag=beta&tag=alpha&empty=&space=hello+world");
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_BUILD_QUERY_SUCCESS: &str = r#"
<process_chain_lib id="build_query_success_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local simple=$(build-query {
                    "redirect_url": "/dashboard",
                    "page": 2,
                    "exact": true,
                    "note": "hello world"
                });
                eq $simple "redirect_url=%2Fdashboard&page=2&exact=true&note=hello+world" || return --from lib "build_query_map_fail";

                capture --value tags $(parse-query "tag=alpha&tag=beta");
                local repeated=$(build-query $tags);
                eq $repeated "tag=alpha&tag=beta" || return --from lib "build_query_multimap_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_QUERY_GET_SUCCESS: &str = r#"
<process_chain_lib id="query_get_success_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local redirect=$(query-get "?redirect_url=%2Fdashboard&tag=alpha" "redirect_url");
                eq $redirect "/dashboard" || return --from lib "query_get_raw_fail";

                capture --value params $(parse-query "tag=alpha&tag=beta&tag=alpha&space=hello+world");

                local first_tag=$(query-get $params "tag");
                eq $first_tag "alpha" || return --from lib "query_get_first_fail";

                capture --value tags $(query-get --all $params "tag");
                eq $tags[0] "alpha" || return --from lib "query_get_all_first_fail";
                eq $tags[1] "beta" || return --from lib "query_get_all_second_fail";

                local space=$(query-get $params "space");
                eq $space "hello world" || return --from lib "query_get_space_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_QUERY_GET_ERROR: &str = r#"
<process_chain_lib id="query_get_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local missing=$(query-get "tag=alpha" "missing");
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRIP_PREFIX_DYNAMIC: &str = r#"
<process_chain_lib id="strip_prefix_dynamic_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local route_prefix="/.cluster/klog";
                local path="/.cluster/klog/ood1/admin/cluster-state";
                local tail=$(strip-prefix $path $route_prefix);
                eq $tail "/ood1/admin/cluster-state" || return --from lib "strip_prefix_tail_fail";

                local exact=$(strip-prefix $route_prefix $route_prefix);
                eq $exact "" || return --from lib "strip_prefix_exact_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRIP_PREFIX_ERROR: &str = r#"
<process_chain_lib id="strip_prefix_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local route_prefix="/.cluster/klog";
                local path="/service/admin";

                match-result $(strip-prefix $path $route_prefix)
                ok(value)
                    return --from lib $(append "unexpected_ok:" $value);
                err(err_value)
                    eq $err_value "" || return --from lib "strip_prefix_err_value_fail";
                    return --from lib "handled_error";
                end
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRIP_PREFIX_IGNORE_CASE: &str = r#"
<process_chain_lib id="strip_prefix_ignore_case_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local route_prefix="/.cluster/klog";
                local path="/.Cluster/Klog/OOD1/admin";

                match-result $(strip-prefix $path $route_prefix)
                ok(value)
                    return --from lib $(append "unexpected_sensitive_ok:" $value);
                err(err_value)
                    eq $err_value "" || return --from lib "strip_prefix_sensitive_err_value_fail";
                end

                local tail=$(strip-prefix --ignore-case $path $route_prefix);
                eq $tail "/OOD1/admin" || return --from lib "strip_prefix_ignore_case_tail_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRIP_SUFFIX_DYNAMIC: &str = r#"
<process_chain_lib id="strip_suffix_dynamic_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local zone_suffix=".example.com";
                local host="api.example.com";
                local head=$(strip-suffix $host $zone_suffix);
                eq $head "api" || return --from lib "strip_suffix_head_fail";

                local exact=$(strip-suffix $zone_suffix $zone_suffix);
                eq $exact "" || return --from lib "strip_suffix_exact_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRIP_SUFFIX_ERROR: &str = r#"
<process_chain_lib id="strip_suffix_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local zone_suffix=".example.com";
                local host="api.internal";

                match-result $(strip-suffix $host $zone_suffix)
                ok(value)
                    return --from lib $(append "unexpected_ok:" $value);
                err(err_value)
                    eq $err_value "" || return --from lib "strip_suffix_err_value_fail";
                    return --from lib "handled_error";
                end
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRIP_SUFFIX_IGNORE_CASE: &str = r#"
<process_chain_lib id="strip_suffix_ignore_case_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local zone_suffix=".example.com";
                local host="Api.Example.Com";

                match-result $(strip-suffix $host $zone_suffix)
                ok(value)
                    return --from lib $(append "unexpected_sensitive_ok:" $value);
                err(err_value)
                    eq $err_value "" || return --from lib "strip_suffix_sensitive_err_value_fail";
                end

                local head=$(strip-suffix --ignore-case $host $zone_suffix);
                eq $head "Api" || return --from lib "strip_suffix_ignore_case_head_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_SPLIT_BASIC: &str = r#"
<process_chain_lib id="split_basic_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                capture --value raw $(split "/a/b/" "/");
                eq $(list-remove $raw 0) "" || return --from lib "split_keep_empty_0_fail";
                eq $(list-remove $raw 0) "a" || return --from lib "split_keep_empty_1_fail";
                eq $(list-remove $raw 0) "b" || return --from lib "split_keep_empty_2_fail";
                eq $(list-remove $raw 0) "" || return --from lib "split_keep_empty_3_fail";
                list-pop $raw && return --from lib "split_keep_empty_tail_should_be_empty";

                capture --value trimmed $(split --skip-empty "/a/b/" "/");
                eq $(list-remove $trimmed 0) "a" || return --from lib "split_skip_empty_0_fail";
                eq $(list-remove $trimmed 0) "b" || return --from lib "split_skip_empty_1_fail";
                list-pop $trimmed && return --from lib "split_skip_empty_tail_should_be_empty";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_SPLIT_CAPTURE: &str = r#"
<process_chain_lib id="split_capture_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local delimiter="/";
                split --capture parts --skip-empty "/.cluster/klog/ood1/admin/" $delimiter;
                eq $(list-remove $parts 0) ".cluster" || return --from lib "split_capture_0_fail";
                eq $(list-remove $parts 0) "klog" || return --from lib "split_capture_1_fail";
                eq $(list-remove $parts 0) "ood1" || return --from lib "split_capture_2_fail";
                eq $(list-remove $parts 0) "admin" || return --from lib "split_capture_3_fail";
                list-pop $parts && return --from lib "split_capture_tail_should_be_empty";

                split --capture parts "svc:9000" ":";
                eq $(list-remove $parts 0) "svc" || return --from lib "split_capture_overwrite_0_fail";
                eq $(list-remove $parts 0) "9000" || return --from lib "split_capture_overwrite_1_fail";
                list-pop $parts && return --from lib "split_capture_overwrite_tail_should_be_empty";

                local stale=${parts?.[2] ?? "missing"};
                eq $stale "missing" || return --from lib "split_capture_stale_index_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_SPLIT_EMPTY_DELIMITER_ERROR: &str = r#"
<process_chain_lib id="split_empty_delimiter_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local delimiter="";
                split "abc" $delimiter;
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_STRING_REGEX_PIPELINE: &str = r#"
<process_chain_lib id="string_regex_pipeline_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local path="/kapi/my-service/v1";

                rewrite $path "/kapi/my-service/*" "/kapi/*" || return --from lib "rewrite_fail";
                eq $path "/kapi/v1" || return --from lib "rewrite_value_fail";

                rewrite-reg $path "^/kapi/([A-Za-z0-9_]+)\$" "/new/\$1" || return --from lib "rewrite_reg_fail";
                eq $path "/new/v1" || return --from lib "rewrite_reg_value_fail";

                replace $path "/new/" "/api/" || return --from lib "replace_fail";
                eq $path "/api/v1" || return --from lib "replace_value_fail";

                replace $path "not_found" "x" && return --from lib "replace_should_fail";

                match-reg $path "^/api/[a-z0-9_]+\$" || return --from lib "match_reg_fail";
                match-reg --no-ignore-case $path "^/API/[A-Z0-9_]+\$" && return --from lib "match_reg_case_should_fail";
                match-reg $path "^/API/[A-Z0-9_]+\$" || return --from lib "match_reg_ignore_case_default_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_REWRITE_REGEX_PARSE_ERROR: &str = r#"
<process_chain_lib id="rewrite_regex_parse_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local path="/kapi/v1";
                rewrite-reg $path "(" "/x";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_URL_ENCODE_DECODE: &str = r#"
<process_chain_lib id="url_encode_decode_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local raw="https://sys.test.buckyos.io/oauth/login?redirect_url=/a/b?x=1&y=2";
                local encoded=$(url_encode $raw);
                eq $encoded "https%3A%2F%2Fsys.test.buckyos.io%2Foauth%2Flogin%3Fredirect_url%3D%2Fa%2Fb%3Fx%3D1%26y%3D2" || return --from lib "url_encode_value_fail";

                local redirect=$(append "https://control.example.com/oauth/login?redirect_url=" $(url_encode $raw));
                eq $redirect "https://control.example.com/oauth/login?redirect_url=https%3A%2F%2Fsys.test.buckyos.io%2Foauth%2Flogin%3Fredirect_url%3D%2Fa%2Fb%3Fx%3D1%26y%3D2" || return --from lib "redirect_append_fail";

                local decoded=$(url_decode $encoded);
                eq $decoded $raw || return --from lib "url_decode_roundtrip_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_URL_DECODE_PARSE_ERROR: &str = r#"
<process_chain_lib id="url_decode_parse_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                url_decode "https%2";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_MATCH_REGEX_CAPTURE_SUCCESS: &str = r#"
<process_chain_lib id="match_regex_capture_success_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local input="AbC-123";
                match-reg --capture cap --capture-named named $input "^(?P<kind>[a-z]+)-(?P<id>[0-9]+)\$" || return --from lib "capture_fail";
                eq $(list-remove $cap 0) "AbC-123" || return --from lib "capture_0_fail";
                eq $(list-remove $cap 0) "AbC" || return --from lib "capture_1_fail";
                eq $(list-remove $cap 0) "123" || return --from lib "capture_2_fail";
                list-pop $cap && return --from lib "capture_tail_should_be_empty";
                eq $named.kind "AbC" || return --from lib "named_capture_kind_fail";
                eq $named.id "123" || return --from lib "named_capture_id_fail";
                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_MATCH_REGEX_CAPTURE_FRESH_LIST: &str = r#"
<process_chain_lib id="match_regex_capture_fresh_list_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local extended="abc-123-def";
                match-reg --capture cap --capture-named named $extended "^(?P<service>[a-z]+)-(?P<port>[0-9]+)-(?P<env>[a-z]+)\$" || return --from lib "extended_capture_fail";
                eq $cap[0] "abc-123-def" || return --from lib "extended_capture_0_fail";
                eq $cap[1] "abc" || return --from lib "extended_capture_1_fail";
                eq $cap[2] "123" || return --from lib "extended_capture_2_fail";
                eq $cap[3] "def" || return --from lib "extended_capture_3_fail";
                eq $named.service "abc" || return --from lib "extended_named_service_fail";
                eq $named.port "123" || return --from lib "extended_named_port_fail";
                eq $named.env "def" || return --from lib "extended_named_env_fail";

                local optional="svc";
                match-reg --capture cap --capture-named named $optional "^(?P<service>[a-z]+)(?:-(?P<port>[0-9]+))?\$" || return --from lib "optional_capture_fail";
                eq $cap[0] "svc" || return --from lib "optional_capture_0_fail";
                eq $cap[1] "svc" || return --from lib "optional_capture_1_fail";
                is-null $cap[2] || return --from lib "optional_capture_2_should_be_null";
                eq $named.service "svc" || return --from lib "optional_named_service_fail";
                is-null $named.port || return --from lib "optional_named_port_should_be_null";

                local stale=${cap?.[3] ?? "missing"};
                eq $stale "missing" || return --from lib "capture_stale_index_fail";
                local named_stale=${named?.env ?? "missing"};
                eq $named_stale "missing" || return --from lib "named_capture_stale_key_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_MATCH_PATH_TEMPLATE: &str = r#"
<process_chain_lib id="match_path_template_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local route_prefix="/.cluster/klog";
                local path="/.cluster/klog/ood1/admin/cluster-state";
                match-path --capture cap --capture-named named $path "${route_prefix}/{node}/{plane}/**" || return --from lib "path_match_fail";
                eq $cap[0] "/.cluster/klog/ood1/admin/cluster-state" || return --from lib "path_capture_0_fail";
                eq $cap[1] "ood1" || return --from lib "path_capture_1_fail";
                eq $cap[2] "admin" || return --from lib "path_capture_2_fail";
                eq $named.node "ood1" || return --from lib "path_named_node_fail";
                eq $named.plane "admin" || return --from lib "path_named_plane_fail";
                local stale=${cap?.[3] ?? "missing"};
                eq $stale "missing" || return --from lib "path_capture_stale_index_fail";

                local exact="/kapi/system_config";
                match-path --capture cap --capture-named named $exact "/kapi/{service_id}" || return --from lib "path_exact_fail";
                eq $cap[0] "/kapi/system_config" || return --from lib "path_exact_capture_0_fail";
                eq $cap[1] "system_config" || return --from lib "path_exact_capture_1_fail";
                eq $named.service_id "system_config" || return --from lib "path_exact_named_service_fail";
                local overwritten=${cap?.[2] ?? "missing"};
                eq $overwritten "missing" || return --from lib "path_capture_overwrite_fail";
                local named_overwritten=${named?.plane ?? "missing"};
                eq $named_overwritten "missing" || return --from lib "path_named_capture_overwrite_fail";

                match-path "/API/Users" "/api/users" && return --from lib "path_case_sensitive_should_fail";
                match-path --ignore-case "/API/Users" "/api/users" || return --from lib "path_ignore_case_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_MATCH_HOST_TEMPLATE: &str = r#"
<process_chain_lib id="match_host_template_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local zone="app1.com";

                match-host --capture cap --capture-named named "buckyos-app1.com" "{app}-${zone}" || return --from lib "host_hyphen_match_fail";
                eq $cap[0] "buckyos-app1.com" || return --from lib "host_hyphen_capture_0_fail";
                eq $cap[1] "buckyos" || return --from lib "host_hyphen_capture_1_fail";
                eq $named.app "buckyos" || return --from lib "host_hyphen_named_app_fail";

                match-host "www.buckyos-app1.com" "{app}-${zone}" && return --from lib "host_hyphen_should_not_match_prefixed_host";

                match-host --capture cap --capture-named named "Api.App1.Com" "{app}.${zone}" || return --from lib "host_dot_match_fail";
                eq $cap[0] "Api.App1.Com" || return --from lib "host_dot_capture_0_fail";
                eq $cap[1] "Api" || return --from lib "host_dot_capture_1_fail";
                eq $named.app "Api" || return --from lib "host_dot_named_app_fail";

                match-host --no-ignore-case "Api.App1.Com" "{app}.${zone}" && return --from lib "host_case_sensitive_should_fail";

                match-host --capture cap --capture-named named "api-stage.app1.com" "{app}-{env}.${zone}" || return --from lib "host_multi_capture_fail";
                eq $cap[1] "api" || return --from lib "host_multi_capture_1_fail";
                eq $cap[2] "stage" || return --from lib "host_multi_capture_2_fail";
                eq $named.app "api" || return --from lib "host_multi_named_app_fail";
                eq $named.env "stage" || return --from lib "host_multi_named_env_fail";

                match-host --capture cap --capture-named named "svc.app1.com" "{app}.${zone}" || return --from lib "host_named_overwrite_fail";
                eq $named.app "svc" || return --from lib "host_named_overwrite_app_fail";
                local named_stale=${named?.env ?? "missing"};
                eq $named_stale "missing" || return --from lib "host_named_capture_overwrite_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_MATCH_CAPTURE_NAMED_CONFLICT: &str = r#"
<process_chain_lib id="match_capture_named_conflict_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                match-path --capture cap --capture-named cap "/kapi/system_config" "/kapi/{service_id}";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_REWRITE_PATH_TEMPLATE: &str = r#"
<process_chain_lib id="rewrite_path_template_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local route_prefix="/.cluster/klog";
                local path="/.cluster/klog/ood1/admin/cluster-state";
                rewrite-path $path "${route_prefix}/{node}/{plane}/**" "/klog/{node}/{plane}/**" || return --from lib "rewrite_path_tail_fail";
                eq $path "/klog/ood1/admin/cluster-state" || return --from lib "rewrite_path_tail_value_fail";

                local exact="/kapi/system_config";
                rewrite-path $exact "/kapi/{service}/**" "/internal/{service}/**" || return --from lib "rewrite_path_empty_rest_fail";
                eq $exact "/internal/system_config" || return --from lib "rewrite_path_empty_rest_value_fail";

                local case_path="/API/Users";
                rewrite-path --ignore-case $case_path "/api/{kind}" "/internal/{kind}" || return --from lib "rewrite_path_ignore_case_fail";
                eq $case_path "/internal/Users" || return --from lib "rewrite_path_ignore_case_value_fail";

                local untouched="/public/healthz";
                rewrite-path $untouched "/kapi/{service}/**" "/internal/{service}/**" && return --from lib "rewrite_path_should_not_match";
                eq $untouched "/public/healthz" || return --from lib "rewrite_path_non_match_mutated_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_REWRITE_HOST_TEMPLATE: &str = r#"
<process_chain_lib id="rewrite_host_template_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local zone="app1.com";

                local host="Api.App1.Com";
                rewrite-host $host "{app}.${zone}" "{app}-internal.${zone}" || return --from lib "rewrite_host_basic_fail";
                eq $host "Api-internal.app1.com" || return --from lib "rewrite_host_basic_value_fail";

                local wildcard="api.edge.internal.app1.com";
                rewrite-host $wildcard "{app}.**" "{app}.gateway.**" || return --from lib "rewrite_host_rest_fail";
                eq $wildcard "api.gateway.edge.internal.app1.com" || return --from lib "rewrite_host_rest_value_fail";

                local strict="Api.App1.Com";
                rewrite-host --no-ignore-case $strict "{app}.${zone}" "{app}-internal.${zone}" && return --from lib "rewrite_host_case_sensitive_should_fail";
                eq $strict "Api.App1.Com" || return --from lib "rewrite_host_case_sensitive_mutated_fail";

                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

const PROCESS_CHAIN_REWRITE_PATH_TEMPLATE_ERROR: &str = r#"
<process_chain_lib id="rewrite_path_template_error_lib" priority="100">
    <process_chain id="main">
        <block id="entry">
            <![CDATA[
                local path="/kapi/system_config";
                rewrite-path $path "/kapi/{service}" "/internal/{missing}";
                return --from lib "unexpected";
            ]]>
        </block>
    </process_chain>
</process_chain_lib>
"#;

#[tokio::test]
async fn test_range_command_basic_flow() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_range_basic");
    hook_point
        .load_process_chain_lib("range_basic_lib", 0, PROCESS_CHAIN_RANGE_BASIC)
        .await?;

    let data_dir = new_test_data_dir("test-range-basic")?;
    let hook_point_env = HookPointEnv::new("test-range-basic", data_dir);
    hook_point_env
        .hook_point_env()
        .create("port", CollectionValue::Number(NumberValue::Int(1500)))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("range_basic_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_range_command_runtime_rejects_non_numeric_value() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_range_runtime_error");
    hook_point
        .load_process_chain_lib(
            "range_runtime_error_lib",
            0,
            PROCESS_CHAIN_RANGE_RUNTIME_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-range-runtime-error")?;
    let hook_point_env = HookPointEnv::new("test-range-runtime-error", data_dir);
    hook_point_env
        .hook_point_env()
        .create("raw_port", CollectionValue::String("abc".to_owned()))
        .await?;

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("range_runtime_error_lib")
        .await
        .err()
        .ok_or_else(|| "range runtime error expected".to_string())?;
    assert!(
        err.contains("Cannot convert string 'abc' to number"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_range_command_parse_rejects_invalid_begin_literal() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_range_parse_error");
    hook_point
        .load_process_chain_lib("range_parse_error_lib", 0, PROCESS_CHAIN_RANGE_PARSE_ERROR)
        .await?;

    let data_dir = new_test_data_dir("test-range-parse-error")?;
    let hook_point_env = HookPointEnv::new("test-range-parse-error", data_dir);

    let err = hook_point_env
        .link_hook_point(&hook_point)
        .await
        .err()
        .ok_or_else(|| "link should fail on invalid range begin literal".to_string())?;
    assert!(
        err.contains("Invalid range command begin value"),
        "unexpected link error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_strlen_returns_typed_number() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_strlen_typed_number");
    hook_point
        .load_process_chain_lib(
            "strlen_typed_number_lib",
            0,
            PROCESS_CHAIN_STRLEN_TYPED_NUMBER,
        )
        .await?;

    let data_dir = new_test_data_dir("test-strlen-typed-number")?;
    let hook_point_env = HookPointEnv::new("test-strlen-typed-number", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("strlen_typed_number_lib").await?;
    assert_eq!(ret.value(), "Number");

    Ok(())
}

#[tokio::test]
async fn test_strlen_in_strict_mode_rejects_bool() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_strlen_strict_error");
    hook_point
        .load_process_chain_lib(
            "strlen_strict_error_lib",
            0,
            PROCESS_CHAIN_STRLEN_STRICT_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-strlen-strict-error")?;
    let hook_point_env = HookPointEnv::new("test-strlen-strict-error", data_dir);
    hook_point_env.set_coercion_policy(CoercionPolicy::Strict);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("strlen_strict_error_lib")
        .await
        .err()
        .ok_or_else(|| "strict strlen should fail on bool".to_string())?;
    assert!(
        err.contains("Expected string value, found Bool (strict coercion)"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_starts_with_and_ends_with_case_behaviors() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_starts_ends");
    hook_point
        .load_process_chain_lib("starts_ends_lib", 0, PROCESS_CHAIN_STARTS_ENDS)
        .await?;

    let data_dir = new_test_data_dir("test-starts-ends")?;
    let hook_point_env = HookPointEnv::new("test-starts-ends", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("starts_ends_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_slice_success_with_utf8_boundary() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_slice_success");
    hook_point
        .load_process_chain_lib("slice_success_lib", 0, PROCESS_CHAIN_SLICE_SUCCESS)
        .await?;

    let data_dir = new_test_data_dir("test-slice-success")?;
    let hook_point_env = HookPointEnv::new("test-slice-success", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("slice_success_lib").await?;
    assert_eq!(ret.value(), "你好");

    Ok(())
}

#[tokio::test]
async fn test_slice_rejects_invalid_range_format() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_slice_parse_error");
    hook_point
        .load_process_chain_lib("slice_parse_error_lib", 0, PROCESS_CHAIN_SLICE_PARSE_ERROR)
        .await?;

    let data_dir = new_test_data_dir("test-slice-parse-error")?;
    let hook_point_env = HookPointEnv::new("test-slice-parse-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("slice_parse_error_lib")
        .await
        .err()
        .ok_or_else(|| "slice invalid range should fail".to_string())?;
    assert!(
        err.contains("Invalid range format: bad"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_strip_prefix_supports_dynamic_prefix_and_exact_match() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_strip_prefix_dynamic");
    hook_point
        .load_process_chain_lib(
            "strip_prefix_dynamic_lib",
            0,
            PROCESS_CHAIN_STRIP_PREFIX_DYNAMIC,
        )
        .await?;

    let data_dir = new_test_data_dir("test-strip-prefix-dynamic")?;
    let hook_point_env = HookPointEnv::new("test-strip-prefix-dynamic", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("strip_prefix_dynamic_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_strip_prefix_returns_error_when_prefix_does_not_match() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_strip_prefix_error");
    hook_point
        .load_process_chain_lib(
            "strip_prefix_error_lib",
            0,
            PROCESS_CHAIN_STRIP_PREFIX_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-strip-prefix-error")?;
    let hook_point_env = HookPointEnv::new("test-strip-prefix-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("strip_prefix_error_lib").await?;
    assert_eq!(ret.value(), "handled_error");

    Ok(())
}

#[tokio::test]
async fn test_strip_prefix_ignore_case_is_opt_in() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_strip_prefix_ignore_case");
    hook_point
        .load_process_chain_lib(
            "strip_prefix_ignore_case_lib",
            0,
            PROCESS_CHAIN_STRIP_PREFIX_IGNORE_CASE,
        )
        .await?;

    let data_dir = new_test_data_dir("test-strip-prefix-ignore-case")?;
    let hook_point_env = HookPointEnv::new("test-strip-prefix-ignore-case", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("strip_prefix_ignore_case_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_strip_suffix_supports_dynamic_suffix_and_exact_match() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_strip_suffix_dynamic");
    hook_point
        .load_process_chain_lib(
            "strip_suffix_dynamic_lib",
            0,
            PROCESS_CHAIN_STRIP_SUFFIX_DYNAMIC,
        )
        .await?;

    let data_dir = new_test_data_dir("test-strip-suffix-dynamic")?;
    let hook_point_env = HookPointEnv::new("test-strip-suffix-dynamic", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("strip_suffix_dynamic_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_strip_suffix_returns_error_when_suffix_does_not_match() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_strip_suffix_error");
    hook_point
        .load_process_chain_lib(
            "strip_suffix_error_lib",
            0,
            PROCESS_CHAIN_STRIP_SUFFIX_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-strip-suffix-error")?;
    let hook_point_env = HookPointEnv::new("test-strip-suffix-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("strip_suffix_error_lib").await?;
    assert_eq!(ret.value(), "handled_error");

    Ok(())
}

#[tokio::test]
async fn test_strip_suffix_ignore_case_is_opt_in() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_strip_suffix_ignore_case");
    hook_point
        .load_process_chain_lib(
            "strip_suffix_ignore_case_lib",
            0,
            PROCESS_CHAIN_STRIP_SUFFIX_IGNORE_CASE,
        )
        .await?;

    let data_dir = new_test_data_dir("test-strip-suffix-ignore-case")?;
    let hook_point_env = HookPointEnv::new("test-strip-suffix-ignore-case", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("strip_suffix_ignore_case_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_split_returns_list_and_respects_skip_empty() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_split_basic");
    hook_point
        .load_process_chain_lib("split_basic_lib", 0, PROCESS_CHAIN_SPLIT_BASIC)
        .await?;

    let data_dir = new_test_data_dir("test-split-basic")?;
    let hook_point_env = HookPointEnv::new("test-split-basic", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("split_basic_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_split_capture_populates_fresh_list() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_split_capture");
    hook_point
        .load_process_chain_lib("split_capture_lib", 0, PROCESS_CHAIN_SPLIT_CAPTURE)
        .await?;

    let data_dir = new_test_data_dir("test-split-capture")?;
    let hook_point_env = HookPointEnv::new("test-split-capture", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("split_capture_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_split_rejects_empty_delimiter() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_split_empty_delimiter_error");
    hook_point
        .load_process_chain_lib(
            "split_empty_delimiter_error_lib",
            0,
            PROCESS_CHAIN_SPLIT_EMPTY_DELIMITER_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-split-empty-delimiter-error")?;
    let hook_point_env = HookPointEnv::new("test-split-empty-delimiter-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("split_empty_delimiter_error_lib")
        .await
        .err()
        .ok_or_else(|| "split with empty delimiter should fail".to_string())?;
    assert!(
        err.contains("Delimiter for split command cannot be empty"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_rewrite_replace_and_match_regex_pipeline() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_string_regex_pipeline");
    hook_point
        .load_process_chain_lib(
            "string_regex_pipeline_lib",
            0,
            PROCESS_CHAIN_STRING_REGEX_PIPELINE,
        )
        .await?;

    let data_dir = new_test_data_dir("test-string-regex-pipeline")?;
    let hook_point_env = HookPointEnv::new("test-string-regex-pipeline", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("string_regex_pipeline_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_rewrite_regex_rejects_invalid_pattern_at_link_time() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_rewrite_regex_parse_error");
    hook_point
        .load_process_chain_lib(
            "rewrite_regex_parse_error_lib",
            0,
            PROCESS_CHAIN_REWRITE_REGEX_PARSE_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-rewrite-regex-parse-error")?;
    let hook_point_env = HookPointEnv::new("test-rewrite-regex-parse-error", data_dir);

    let err = hook_point_env
        .link_hook_point(&hook_point)
        .await
        .err()
        .ok_or_else(|| "link should fail on invalid rewrite-reg regex".to_string())?;
    assert!(
        err.contains("Invalid regex pattern"),
        "unexpected link error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_url_encode_and_decode_support_nested_urls() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_url_encode_decode");
    hook_point
        .load_process_chain_lib("url_encode_decode_lib", 0, PROCESS_CHAIN_URL_ENCODE_DECODE)
        .await?;

    let data_dir = new_test_data_dir("test-url-encode-decode")?;
    let hook_point_env = HookPointEnv::new("test-url-encode-decode", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("url_encode_decode_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_url_decode_rejects_incomplete_escape_sequence() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_url_decode_parse_error");
    hook_point
        .load_process_chain_lib(
            "url_decode_parse_error_lib",
            0,
            PROCESS_CHAIN_URL_DECODE_PARSE_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-url-decode-parse-error")?;
    let hook_point_env = HookPointEnv::new("test-url-decode-parse-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("url_decode_parse_error_lib")
        .await
        .err()
        .ok_or_else(|| "url_decode invalid escape should fail".to_string())?;
    assert!(
        err.contains("Incomplete percent-encoded sequence"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_parse_authority_returns_typed_map_and_preserves_fields() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_parse_authority_return");
    hook_point
        .load_process_chain_lib(
            "parse_authority_return_lib",
            0,
            PROCESS_CHAIN_PARSE_AUTHORITY_RETURN,
        )
        .await?;

    let data_dir = new_test_data_dir("test-parse-authority-return")?;
    let hook_point_env = HookPointEnv::new("test-parse-authority-return", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("parse_authority_return_lib").await?;
    let map = ret.value_ref().try_as_map()?.clone();

    assert_eq!(map.get("host").await?.unwrap().as_str(), Some("[::1]"));
    assert!(matches!(
        map.get("port").await?.unwrap(),
        CollectionValue::Number(NumberValue::Int(8080))
    ));
    assert_eq!(map.get("has_port").await?.unwrap().as_bool(), Some(true));
    assert_eq!(
        map.get("userinfo").await?.unwrap().as_str(),
        Some("user:pass")
    );

    Ok(())
}

#[tokio::test]
async fn test_parse_authority_alias_and_default_port_support() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_parse_authority_default_port");
    hook_point
        .load_process_chain_lib(
            "parse_authority_default_port_lib",
            0,
            PROCESS_CHAIN_PARSE_AUTHORITY_DEFAULT_PORT,
        )
        .await?;

    let data_dir = new_test_data_dir("test-parse-authority-default-port")?;
    let hook_point_env = HookPointEnv::new("test-parse-authority-default-port", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("parse_authority_default_port_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_parse_authority_rejects_full_url_input() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_parse_authority_error");
    hook_point
        .load_process_chain_lib(
            "parse_authority_error_lib",
            0,
            PROCESS_CHAIN_PARSE_AUTHORITY_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-parse-authority-error")?;
    let hook_point_env = HookPointEnv::new("test-parse-authority-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("parse_authority_error_lib")
        .await
        .err()
        .ok_or_else(|| "parse-authority full URL should fail".to_string())?;
    assert!(
        err.contains("Invalid authority"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_parse_uri_returns_typed_map() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_parse_uri_return");
    hook_point
        .load_process_chain_lib("parse_uri_return_lib", 0, PROCESS_CHAIN_PARSE_URI_RETURN)
        .await?;

    let data_dir = new_test_data_dir("test-parse-uri-return")?;
    let hook_point_env = HookPointEnv::new("test-parse-uri-return", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("parse_uri_return_lib").await?;
    let map = ret.value_ref().try_as_map()?.clone();

    assert_eq!(map.get("scheme").await?.unwrap().as_str(), Some("https"));
    assert_eq!(
        map.get("authority").await?.unwrap().as_str(),
        Some("user:pass@example.com:8443")
    );
    assert_eq!(
        map.get("host").await?.unwrap().as_str(),
        Some("example.com")
    );
    assert!(matches!(
        map.get("port").await?.unwrap(),
        CollectionValue::Number(NumberValue::Int(8443))
    ));
    assert!(matches!(
        map.get("effective_port").await?.unwrap(),
        CollectionValue::Number(NumberValue::Int(8443))
    ));
    assert_eq!(map.get("has_port").await?.unwrap().as_bool(), Some(true));
    assert_eq!(map.get("username").await?.unwrap().as_str(), Some("user"));
    assert_eq!(map.get("password").await?.unwrap().as_str(), Some("pass"));
    assert_eq!(map.get("path").await?.unwrap().as_str(), Some("/api/v1"));
    assert_eq!(map.get("query").await?.unwrap().as_str(), Some("q=1"));
    assert_eq!(map.get("fragment").await?.unwrap().as_str(), Some("frag"));

    Ok(())
}

#[tokio::test]
async fn test_parse_uri_supports_effective_port_and_hostless_uri() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_parse_uri_effective_port");
    hook_point
        .load_process_chain_lib(
            "parse_uri_effective_port_lib",
            0,
            PROCESS_CHAIN_PARSE_URI_EFFECTIVE_PORT,
        )
        .await?;

    let data_dir = new_test_data_dir("test-parse-uri-effective-port")?;
    let hook_point_env = HookPointEnv::new("test-parse-uri-effective-port", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("parse_uri_effective_port_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_build_uri_supports_roundtrip_from_parse_uri_map() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_build_uri_success");
    hook_point
        .load_process_chain_lib("build_uri_success_lib", 0, PROCESS_CHAIN_BUILD_URI_SUCCESS)
        .await?;

    let data_dir = new_test_data_dir("test-build-uri-success")?;
    let hook_point_env = HookPointEnv::new("test-build-uri-success", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("build_uri_success_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_build_uri_supports_hostless_path_based_uri() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_build_uri_hostless");
    hook_point
        .load_process_chain_lib(
            "build_uri_hostless_lib",
            0,
            PROCESS_CHAIN_BUILD_URI_HOSTLESS,
        )
        .await?;

    let data_dir = new_test_data_dir("test-build-uri-hostless")?;
    let hook_point_env = HookPointEnv::new("test-build-uri-hostless", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("build_uri_hostless_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_build_uri_rejects_missing_authority_for_special_scheme() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_build_uri_error");
    hook_point
        .load_process_chain_lib("build_uri_error_lib", 0, PROCESS_CHAIN_BUILD_URI_ERROR)
        .await?;

    let data_dir = new_test_data_dir("test-build-uri-error")?;
    let hook_point_env = HookPointEnv::new("test-build-uri-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("build_uri_error_lib")
        .await
        .err()
        .ok_or_else(|| "build-uri without host on https should fail".to_string())?;
    assert!(
        err.contains("requires host or authority"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_parse_query_returns_typed_multimap() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_parse_query_return");
    hook_point
        .load_process_chain_lib(
            "parse_query_return_lib",
            0,
            PROCESS_CHAIN_PARSE_QUERY_RETURN,
        )
        .await?;

    let data_dir = new_test_data_dir("test-parse-query-return")?;
    let hook_point_env = HookPointEnv::new("test-parse-query-return", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("parse_query_return_lib").await?;
    let params = ret.value_ref().try_as_multi_map()?.clone();

    assert_eq!(
        params.get("redirect_url").await?,
        Some("/dashboard".to_string())
    );
    assert_eq!(params.get("empty").await?, Some(String::new()));
    assert_eq!(params.get("space").await?, Some("hello world".to_string()));

    let tags = params
        .get_many("tag")
        .await?
        .ok_or_else(|| "expected tag values".to_string())?;
    assert_eq!(
        tags.get_all().await?,
        vec!["alpha".to_string(), "beta".to_string()]
    );

    Ok(())
}

#[tokio::test]
async fn test_build_query_supports_map_and_multimap_inputs() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_build_query_success");
    hook_point
        .load_process_chain_lib(
            "build_query_success_lib",
            0,
            PROCESS_CHAIN_BUILD_QUERY_SUCCESS,
        )
        .await?;

    let data_dir = new_test_data_dir("test-build-query-success")?;
    let hook_point_env = HookPointEnv::new("test-build-query-success", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("build_query_success_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_query_get_supports_raw_query_and_multimap_reads() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_query_get_success");
    hook_point
        .load_process_chain_lib("query_get_success_lib", 0, PROCESS_CHAIN_QUERY_GET_SUCCESS)
        .await?;

    let data_dir = new_test_data_dir("test-query-get-success")?;
    let hook_point_env = HookPointEnv::new("test-query-get-success", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("query_get_success_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_query_get_reports_missing_key() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_query_get_error");
    hook_point
        .load_process_chain_lib("query_get_error_lib", 0, PROCESS_CHAIN_QUERY_GET_ERROR)
        .await?;

    let data_dir = new_test_data_dir("test-query-get-error")?;
    let hook_point_env = HookPointEnv::new("test-query-get-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("query_get_error_lib")
        .await
        .err()
        .ok_or_else(|| "query-get missing key should fail".to_string())?;
    assert!(
        err.contains("Query key 'missing' not found"),
        "unexpected error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_match_regex_capture_populates_fresh_list() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_match_regex_capture_success");
    hook_point
        .load_process_chain_lib(
            "match_regex_capture_success_lib",
            0,
            PROCESS_CHAIN_MATCH_REGEX_CAPTURE_SUCCESS,
        )
        .await?;

    let data_dir = new_test_data_dir("test-match-regex-capture-success")?;
    let hook_point_env = HookPointEnv::new("test-match-regex-capture-success", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("match_regex_capture_success_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_match_regex_capture_overwrites_with_fresh_list() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_match_regex_capture_fresh_list");
    hook_point
        .load_process_chain_lib(
            "match_regex_capture_fresh_list_lib",
            0,
            PROCESS_CHAIN_MATCH_REGEX_CAPTURE_FRESH_LIST,
        )
        .await?;

    let data_dir = new_test_data_dir("test-match-regex-capture-fresh-list")?;
    let hook_point_env = HookPointEnv::new("test-match-regex-capture-fresh-list", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec
        .execute_lib("match_regex_capture_fresh_list_lib")
        .await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_match_path_template_supports_dynamic_prefix_and_wildcard_tail() -> Result<(), String>
{
    init_test_logger();

    let hook_point = HookPoint::new("test_match_path_template");
    hook_point
        .load_process_chain_lib(
            "match_path_template_lib",
            0,
            PROCESS_CHAIN_MATCH_PATH_TEMPLATE,
        )
        .await?;

    let data_dir = new_test_data_dir("test-match-path-template")?;
    let hook_point_env = HookPointEnv::new("test-match-path-template", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("match_path_template_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_match_host_template_supports_hyphen_and_dot_forms() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_match_host_template");
    hook_point
        .load_process_chain_lib(
            "match_host_template_lib",
            0,
            PROCESS_CHAIN_MATCH_HOST_TEMPLATE,
        )
        .await?;

    let data_dir = new_test_data_dir("test-match-host-template")?;
    let hook_point_env = HookPointEnv::new("test-match-host-template", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("match_host_template_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_match_capture_named_rejects_same_variable_name() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_match_capture_named_conflict");
    hook_point
        .load_process_chain_lib(
            "match_capture_named_conflict_lib",
            0,
            PROCESS_CHAIN_MATCH_CAPTURE_NAMED_CONFLICT,
        )
        .await?;

    let data_dir = new_test_data_dir("test-match-capture-named-conflict")?;
    let hook_point_env = HookPointEnv::new("test-match-capture-named-conflict", data_dir);

    let err = hook_point_env
        .link_hook_point(&hook_point)
        .await
        .err()
        .ok_or_else(|| {
            "link should fail when capture and capture-named share a variable".to_string()
        })?;
    assert!(
        err.contains("capture and capture-named must use different variable names"),
        "unexpected link error: {}",
        err
    );

    Ok(())
}

#[tokio::test]
async fn test_rewrite_path_template_supports_named_capture_and_rest_splice() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_rewrite_path_template");
    hook_point
        .load_process_chain_lib(
            "rewrite_path_template_lib",
            0,
            PROCESS_CHAIN_REWRITE_PATH_TEMPLATE,
        )
        .await?;

    let data_dir = new_test_data_dir("test-rewrite-path-template")?;
    let hook_point_env = HookPointEnv::new("test-rewrite-path-template", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("rewrite_path_template_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_rewrite_host_template_supports_named_capture_and_rest_splice() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_rewrite_host_template");
    hook_point
        .load_process_chain_lib(
            "rewrite_host_template_lib",
            0,
            PROCESS_CHAIN_REWRITE_HOST_TEMPLATE,
        )
        .await?;

    let data_dir = new_test_data_dir("test-rewrite-host-template")?;
    let hook_point_env = HookPointEnv::new("test-rewrite-host-template", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let ret = exec.execute_lib("rewrite_host_template_lib").await?;
    assert_eq!(ret.value(), "ok");

    Ok(())
}

#[tokio::test]
async fn test_rewrite_path_template_rejects_unknown_capture_name() -> Result<(), String> {
    init_test_logger();

    let hook_point = HookPoint::new("test_rewrite_path_template_error");
    hook_point
        .load_process_chain_lib(
            "rewrite_path_template_error_lib",
            0,
            PROCESS_CHAIN_REWRITE_PATH_TEMPLATE_ERROR,
        )
        .await?;

    let data_dir = new_test_data_dir("test-rewrite-path-template-error")?;
    let hook_point_env = HookPointEnv::new("test-rewrite-path-template-error", data_dir);

    let exec = hook_point_env.link_hook_point(&hook_point).await?;
    let err = exec
        .execute_lib("rewrite_path_template_error_lib")
        .await
        .err()
        .ok_or_else(|| "rewrite-path with unknown capture should fail".to_string())?;
    assert!(
        err.contains("unknown capture name 'missing'"),
        "unexpected error: {}",
        err
    );

    Ok(())
}
