use criterion::black_box;
use cyfs_process_chain::{
    CollectionValue, CommandResult, HookPoint, HookPointEnv, HookPointExecutorRef,
    MemoryListCollection, MemoryMapCollection, ProcessChainLibExecutor, ProcessChainLibRef,
    ProcessChainXMLLoader,
};
use std::fs;
use std::path::PathBuf;

pub(crate) const SCALE_SMALL: &str = "S";
pub(crate) const SCALE_MEDIUM: &str = "M";
pub(crate) const SCALE_LARGE: &str = "L";
pub(crate) const EMPTY_RETURN_CASE: &str = "empty_return";
pub(crate) const VAR_READ_FLAT_CASE: &str = "var_read_flat";
pub(crate) const VAR_READ_PATH_CASE: &str = "var_read_path";
pub(crate) const LIST_PATH_READ_CASE: &str = "list_path_read";
pub(crate) const ROUTE_PREFIX_PIPELINE_CASE: &str = "route_prefix_pipeline";
pub(crate) const HOST_CLASSIFY_PIPELINE_CASE: &str = "host_classify_pipeline";
pub(crate) const URI_QUERY_PIPELINE_CASE: &str = "uri_query_pipeline";
pub(crate) const MATCH_CAPTURE_PIPELINE_CASE: &str = "match_capture_pipeline";
pub(crate) const FIRST_OK_FIRST_SUCCESS_CASE: &str = "first_ok_first_success";
pub(crate) const FIRST_OK_SUCCESS_CASE: &str = "first_ok_success";
pub(crate) const FIRST_OK_LAST_SUCCESS_CASE: &str = "first_ok_last_success";
pub(crate) const FIRST_OK_ALL_FAIL_CASE: &str = "first_ok_all_fail";
pub(crate) const CASE_WHEN_PIPELINE_CASE: &str = "case_when_pipeline";
pub(crate) const IF_ELIF_PIPELINE_CASE: &str = "if_elif_pipeline";
pub(crate) const MATCH_RESULT_FLOW_CASE: &str = "match_result_flow";
pub(crate) const LITERAL_AND_ACCESS_CASE: &str = "literal_and_access";
pub(crate) const INVOKE_HELPER_RETURN_CASE: &str = "invoke_helper_return";
pub(crate) const CAPTURE_STATUS_VALUE_CASE: &str = "capture_status_value";
pub(crate) const JS_REGISTER_BOOL_CASE: &str = "js_register_bool";
pub(crate) const JS_EXECUTE_BOOL_CASE: &str = "js_execute_bool";
pub(crate) const JS_EXECUTE_MAP_RESULT_CASE: &str = "js_execute_map_result";
pub(crate) const JS_EXECUTE_SET_RESULT_CASE: &str = "js_execute_set_result";
pub(crate) const EMPTY_RETURN_LIB_ID: &str = "empty_return_lib";

const VAR_READ_FLAT_LIB_ID: &str = "var_read_flat_lib";
const VAR_READ_PATH_LIB_ID: &str = "var_read_path_lib";
const LIST_PATH_READ_LIB_ID: &str = "list_path_read_lib";
const ROUTE_PREFIX_PIPELINE_LIB_ID: &str = "route_prefix_pipeline_lib";
const HOST_CLASSIFY_PIPELINE_LIB_ID: &str = "host_classify_pipeline_lib";
const URI_QUERY_PIPELINE_LIB_ID: &str = "uri_query_pipeline_lib";
const MATCH_CAPTURE_PIPELINE_LIB_ID: &str = "match_capture_pipeline_lib";
const FIRST_OK_FIRST_SUCCESS_LIB_ID: &str = "first_ok_first_success_lib";
const FIRST_OK_SUCCESS_LIB_ID: &str = "first_ok_success_lib";
const FIRST_OK_LAST_SUCCESS_LIB_ID: &str = "first_ok_last_success_lib";
const FIRST_OK_ALL_FAIL_LIB_ID: &str = "first_ok_all_fail_lib";
const CASE_WHEN_PIPELINE_LIB_ID: &str = "case_when_pipeline_lib";
const IF_ELIF_PIPELINE_LIB_ID: &str = "if_elif_pipeline_lib";
const MATCH_RESULT_FLOW_LIB_ID: &str = "match_result_flow_lib";
const LITERAL_AND_ACCESS_LIB_ID: &str = "literal_and_access_lib";
const INVOKE_HELPER_RETURN_LIB_ID: &str = "invoke_helper_return_lib";
const CAPTURE_STATUS_VALUE_LIB_ID: &str = "capture_status_value_lib";
const JS_EXECUTE_BOOL_LIB_ID: &str = "js_execute_bool_lib";
const JS_EXECUTE_MAP_RESULT_LIB_ID: &str = "js_execute_map_result_lib";
const JS_EXECUTE_SET_RESULT_LIB_ID: &str = "js_execute_set_result_lib";

const EMPTY_RETURN_XML: &str = r#"
<root>
    <process_chain id="main" priority="100">
        <block id="entry">
            <![CDATA[
                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</root>
"#;

const VAR_READ_FLAT_XML: &str = r#"
<root>
    <process_chain id="main" priority="100">
        <block id="entry">
            <![CDATA[
                return --from lib $(append $HOST $HOST);
            ]]>
        </block>
    </process_chain>
</root>
"#;

const VAR_READ_PATH_XML: &str = r#"
<root>
    <process_chain id="main" priority="100">
        <block id="entry">
            <![CDATA[
                return --from lib $(append $REQ.ext.url "|" $REQ.meta.route_prefix);
            ]]>
        </block>
    </process_chain>
</root>
"#;

const LIST_PATH_READ_XML: &str = r#"
<root>
    <process_chain id="main" priority="100">
        <block id="entry">
            <![CDATA[
                return --from lib $(append $RECORDS[0].key "|" $RECORDS[1].name "|" $RECORDS[2].key);
            ]]>
        </block>
    </process_chain>
</root>
"#;

const HOST_CLASSIFY_PIPELINE_XML: &str = r#"
<root>
    <process_chain id="main" priority="100">
        <block id="entry">
            <![CDATA[
                local authority="api.gateway.example.com:8443";
                capture --value auth $(parse-authority $authority);
                match-host --capture cap --capture-named named $auth.host "{service}.gateway.example.com" || return --from lib "host_miss";
                oneof $auth.port 443 8443 || return --from lib "port_miss";
                return --from lib $(append $named.service "|" $auth.port);
            ]]>
        </block>
    </process_chain>
</root>
"#;

const MATCH_RESULT_FLOW_XML: &str = r#"
<root>
    <process_chain id="main" priority="100">
        <block id="entry">
            <![CDATA[
                local outer="outer";
                local calls="";

                match-result $(capture --value calls $(append $calls "1"))
                ok(outer)
                    eq $outer "1" || return --from lib "bad_match_value";
                    eq $calls "1" || return --from lib "bad_calls_inside";
                err(err_value)
                    return --from lib $(append "unexpected_err:" $err_value);
                end

                eq $calls "1" || return --from lib "bad_calls_after";
                eq $outer "outer" || return --from lib "bad_shadow_restore";
                return --from lib "ok";
            ]]>
        </block>
    </process_chain>
</root>
"#;

const JS_EXECUTE_BOOL_XML: &str = r#"
<root>
    <process_chain id="main" priority="100">
        <block id="entry">
            <![CDATA[
                call check_host_bool "gateway.buckyos.com" && return --from lib "matched";
                return --from lib "unmatched";
            ]]>
        </block>
    </process_chain>
</root>
"#;

#[derive(Clone, Copy)]
pub(crate) struct BenchScale {
    pub(crate) label: &'static str,
    pub(crate) path_segments: usize,
    pub(crate) query_pairs: usize,
    pub(crate) first_ok_candidates: usize,
    pub(crate) case_branches: usize,
    pub(crate) structured_entries: usize,
}

pub(crate) const PHASE2_SMALL_SCALE: BenchScale = BenchScale {
    label: SCALE_SMALL,
    path_segments: 4,
    query_pairs: 4,
    first_ok_candidates: 3,
    case_branches: 3,
    structured_entries: 4,
};

pub(crate) const PHASE2_MEDIUM_SCALE: BenchScale = BenchScale {
    label: SCALE_MEDIUM,
    path_segments: 12,
    query_pairs: 16,
    first_ok_candidates: 8,
    case_branches: 8,
    structured_entries: 16,
};

pub(crate) const PHASE2_LARGE_SCALE: BenchScale = BenchScale {
    label: SCALE_LARGE,
    path_segments: 32,
    query_pairs: 64,
    first_ok_candidates: 16,
    case_branches: 16,
    structured_entries: 64,
};

pub(crate) const PHASE2_SCALES: [BenchScale; 3] =
    [PHASE2_SMALL_SCALE, PHASE2_MEDIUM_SCALE, PHASE2_LARGE_SCALE];

pub(crate) struct LinkFixture {
    pub(crate) lib_id: &'static str,
    pub(crate) hook_point: HookPoint,
    pub(crate) hook_point_env: HookPointEnv,
}

pub(crate) struct LinkedFixture {
    pub(crate) lib_id: &'static str,
    pub(crate) _hook_point: HookPoint,
    pub(crate) _hook_point_env: HookPointEnv,
    pub(crate) linked: HookPointExecutorRef,
}

enum FirstOkOutcome {
    FirstSuccess,
    MiddleSuccess,
    LastSuccess,
    AllFail,
}

pub(crate) fn disable_logging() {
    log::set_max_level(log::LevelFilter::Off);
}

pub(crate) fn load_empty_return_lib() -> Result<ProcessChainLibRef, String> {
    ProcessChainXMLLoader::load_process_chain_lib(EMPTY_RETURN_LIB_ID, 0, EMPTY_RETURN_XML)
}

pub(crate) async fn build_empty_return_link_fixture(
    case_name: &str,
) -> Result<LinkFixture, String> {
    build_link_fixture(case_name, EMPTY_RETURN_LIB_ID, EMPTY_RETURN_XML).await
}

pub(crate) async fn build_empty_return_linked_fixture(
    case_name: &str,
) -> Result<LinkedFixture, String> {
    let link_fixture = build_empty_return_link_fixture(case_name).await?;
    link_fixture_with_env(link_fixture).await
}

pub(crate) async fn build_route_prefix_pipeline_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_route_prefix_pipeline_xml(scale.path_segments);
    build_script_linked_fixture(case_name, ROUTE_PREFIX_PIPELINE_LIB_ID, &xml).await
}

pub(crate) async fn build_host_classify_pipeline_linked_fixture(
    case_name: &str,
) -> Result<LinkedFixture, String> {
    build_script_linked_fixture(
        case_name,
        HOST_CLASSIFY_PIPELINE_LIB_ID,
        HOST_CLASSIFY_PIPELINE_XML,
    )
    .await
}

pub(crate) async fn build_uri_query_pipeline_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_uri_query_pipeline_xml(scale.query_pairs);
    build_script_linked_fixture(case_name, URI_QUERY_PIPELINE_LIB_ID, &xml).await
}

pub(crate) async fn build_match_capture_pipeline_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_match_capture_pipeline_xml(scale.path_segments);
    build_script_linked_fixture(case_name, MATCH_CAPTURE_PIPELINE_LIB_ID, &xml).await
}

pub(crate) async fn build_first_ok_first_success_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_first_ok_xml(scale.first_ok_candidates, FirstOkOutcome::FirstSuccess);
    build_script_linked_fixture(case_name, FIRST_OK_FIRST_SUCCESS_LIB_ID, &xml).await
}

pub(crate) async fn build_first_ok_success_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_first_ok_xml(scale.first_ok_candidates, FirstOkOutcome::MiddleSuccess);
    build_script_linked_fixture(case_name, FIRST_OK_SUCCESS_LIB_ID, &xml).await
}

pub(crate) async fn build_first_ok_last_success_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_first_ok_xml(scale.first_ok_candidates, FirstOkOutcome::LastSuccess);
    build_script_linked_fixture(case_name, FIRST_OK_LAST_SUCCESS_LIB_ID, &xml).await
}

pub(crate) async fn build_first_ok_all_fail_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_first_ok_xml(scale.first_ok_candidates, FirstOkOutcome::AllFail);
    build_script_linked_fixture(case_name, FIRST_OK_ALL_FAIL_LIB_ID, &xml).await
}

pub(crate) async fn build_case_when_pipeline_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_case_when_pipeline_xml(scale.case_branches);
    build_script_linked_fixture(case_name, CASE_WHEN_PIPELINE_LIB_ID, &xml).await
}

pub(crate) async fn build_if_elif_pipeline_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_if_elif_pipeline_xml(scale.case_branches);
    build_script_linked_fixture(case_name, IF_ELIF_PIPELINE_LIB_ID, &xml).await
}

pub(crate) async fn build_match_result_flow_linked_fixture(
    case_name: &str,
) -> Result<LinkedFixture, String> {
    build_script_linked_fixture(case_name, MATCH_RESULT_FLOW_LIB_ID, MATCH_RESULT_FLOW_XML).await
}

pub(crate) async fn build_literal_and_access_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_literal_and_access_xml(scale.structured_entries);
    build_script_linked_fixture(case_name, LITERAL_AND_ACCESS_LIB_ID, &xml).await
}

pub(crate) async fn build_invoke_helper_return_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_invoke_helper_return_xml(scale.structured_entries);
    build_script_linked_fixture(case_name, INVOKE_HELPER_RETURN_LIB_ID, &xml).await
}

pub(crate) async fn build_capture_status_value_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_capture_status_value_xml(scale.structured_entries);
    build_script_linked_fixture(case_name, CAPTURE_STATUS_VALUE_LIB_ID, &xml).await
}

pub(crate) async fn build_js_execute_bool_linked_fixture(
    case_name: &str,
) -> Result<LinkedFixture, String> {
    build_js_external_linked_fixture(
        case_name,
        JS_EXECUTE_BOOL_LIB_ID,
        JS_EXECUTE_BOOL_XML,
        "check_host_bool",
        js_bool_command_source(),
    )
    .await
}

pub(crate) async fn build_js_execute_map_result_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_js_map_result_xml(scale.structured_entries);
    let source = build_js_map_result_command(scale.structured_entries);
    build_js_external_linked_fixture(
        case_name,
        JS_EXECUTE_MAP_RESULT_LIB_ID,
        &xml,
        "describe_host_map",
        source,
    )
    .await
}

pub(crate) async fn build_js_execute_set_result_linked_fixture(
    case_name: &str,
    scale: BenchScale,
) -> Result<LinkedFixture, String> {
    let xml = build_js_set_result_xml(scale.structured_entries);
    let source = build_js_set_result_command(scale.structured_entries);
    build_js_external_linked_fixture(
        case_name,
        JS_EXECUTE_SET_RESULT_LIB_ID,
        &xml,
        "classify_host_tags",
        source,
    )
    .await
}

pub(crate) async fn build_var_read_flat_linked_fixture(
    case_name: &str,
) -> Result<LinkedFixture, String> {
    let link_fixture =
        build_link_fixture(case_name, VAR_READ_FLAT_LIB_ID, VAR_READ_FLAT_XML).await?;
    link_fixture
        .hook_point_env
        .hook_point_env()
        .create(
            "HOST",
            CollectionValue::String("gateway.example.com".to_string()),
        )
        .await?;

    link_fixture_with_env(link_fixture).await
}

pub(crate) async fn build_var_read_path_linked_fixture(
    case_name: &str,
) -> Result<LinkedFixture, String> {
    let link_fixture =
        build_link_fixture(case_name, VAR_READ_PATH_LIB_ID, VAR_READ_PATH_XML).await?;
    let req = MemoryMapCollection::new_ref();
    let ext = MemoryMapCollection::new_ref();
    let meta = MemoryMapCollection::new_ref();

    ext.insert(
        "url",
        CollectionValue::String("https://gateway.example.com/service".to_string()),
    )
    .await?;
    meta.insert(
        "route_prefix",
        CollectionValue::String("/service".to_string()),
    )
    .await?;
    req.insert("ext", CollectionValue::Map(ext)).await?;
    req.insert("meta", CollectionValue::Map(meta)).await?;

    link_fixture
        .hook_point_env
        .hook_point_env()
        .create("REQ", CollectionValue::Map(req))
        .await?;

    link_fixture_with_env(link_fixture).await
}

pub(crate) async fn build_list_path_read_linked_fixture(
    case_name: &str,
) -> Result<LinkedFixture, String> {
    let link_fixture =
        build_link_fixture(case_name, LIST_PATH_READ_LIB_ID, LIST_PATH_READ_XML).await?;
    let records = MemoryListCollection::new_ref();

    records
        .push(CollectionValue::Map(
            build_record_entry("alpha", "first").await?,
        ))
        .await?;
    records
        .push(CollectionValue::Map(
            build_record_entry("beta", "second").await?,
        ))
        .await?;
    records
        .push(CollectionValue::Map(
            build_record_entry("gamma", "third").await?,
        ))
        .await?;

    link_fixture
        .hook_point_env
        .hook_point_env()
        .create("RECORDS", CollectionValue::List(records))
        .await?;

    link_fixture_with_env(link_fixture).await
}

pub(crate) fn prepare_exec(fixture: &LinkedFixture) -> Result<ProcessChainLibExecutor, String> {
    fixture.linked.prepare_exec_lib(fixture.lib_id)
}

pub(crate) fn black_box_result(result: CommandResult) {
    black_box(result.value());
}

pub(crate) fn build_bench_data_dir(case_name: &str) -> Result<PathBuf, String> {
    bench_data_dir(case_name)
}

pub(crate) fn js_bool_command_source() -> String {
    r#"
function check_host_bool(context, host) {
    return shExpMatch(host, "*.buckyos.com");
}
"#
    .trim()
    .to_string()
}

fn bench_data_dir(case_name: &str) -> Result<PathBuf, String> {
    let path = std::env::temp_dir()
        .join("cyfs-process-chain-benches")
        .join(case_name);

    fs::create_dir_all(&path).map_err(|e| {
        format!(
            "Failed to create benchmark data dir {}: {}",
            path.display(),
            e
        )
    })?;

    Ok(path)
}

async fn build_link_fixture(
    case_name: &str,
    lib_id: &'static str,
    xml: &str,
) -> Result<LinkFixture, String> {
    let hook_point = HookPoint::new(case_name);
    hook_point.load_process_chain_lib(lib_id, 0, xml).await?;

    let data_dir = bench_data_dir(case_name)?;
    let hook_point_env = HookPointEnv::new(case_name, data_dir);

    Ok(LinkFixture {
        lib_id,
        hook_point,
        hook_point_env,
    })
}

async fn link_fixture_with_env(link_fixture: LinkFixture) -> Result<LinkedFixture, String> {
    let linked = link_fixture
        .hook_point_env
        .link_hook_point(&link_fixture.hook_point)
        .await?;

    Ok(LinkedFixture {
        lib_id: link_fixture.lib_id,
        _hook_point: link_fixture.hook_point,
        _hook_point_env: link_fixture.hook_point_env,
        linked,
    })
}

async fn build_script_linked_fixture(
    case_name: &str,
    lib_id: &'static str,
    xml: &str,
) -> Result<LinkedFixture, String> {
    let fixture = build_link_fixture(case_name, lib_id, xml).await?;
    link_fixture_with_env(fixture).await
}

async fn build_js_external_linked_fixture(
    case_name: &str,
    lib_id: &'static str,
    xml: &str,
    command_name: &str,
    command_source: String,
) -> Result<LinkedFixture, String> {
    let fixture = build_link_fixture(case_name, lib_id, xml).await?;
    fixture
        .hook_point_env
        .register_js_external_command(command_name, command_source)
        .await?;
    link_fixture_with_env(fixture).await
}

fn build_route_prefix_pipeline_xml(path_segments: usize) -> String {
    let tail_segments = build_path_segments(path_segments);
    let middle_index = tail_segments.len() / 2;
    let last_index = tail_segments.len() - 1;
    let path = format!("/.cluster/klog/{}", tail_segments.join("/"));
    let entry_body = format!(
        r#"                local route_prefix="/.cluster/klog";
                local path="{path}";
                local tail=$(strip-prefix $path $route_prefix);
                capture --value parts $(split --skip-empty $tail "/");
                return --from lib $(append $parts[0] "|" $parts[{middle_index}] "|" $parts[{last_index}]);"#
    );

    build_process_chain_xml("", &entry_body)
}

fn build_uri_query_pipeline_xml(query_pairs: usize) -> String {
    let query = build_query_string(query_pairs);
    let entry_body = format!(
        r#"                local url="https://example.com/api/v1?{query}";
                capture --value parsed $(parse-uri $url);
                capture --value params $(parse-query $parsed.query);
                local redirect=$(query-get $params "redirect_url");
                local tag=$(query-get $params "tag");
                local query=$(build-query $params);
                local rebuilt=$(build-uri {{
                    scheme: $parsed.scheme,
                    host: $parsed.host,
                    path: $parsed.path,
                    query: $query
                }});
                return --from lib $(append $redirect "|" $tag "|" $rebuilt);"#
    );

    build_process_chain_xml("", &entry_body)
}

fn build_match_capture_pipeline_xml(path_segments: usize) -> String {
    let tail_segments = build_path_segments(path_segments);
    let path = format!("/.cluster/klog/{}", tail_segments.join("/"));
    let pattern = "${route_prefix}/{node}/{plane}/**";
    let entry_body = format!(
        r#"                local route_prefix="/.cluster/klog";
                local path="{path}";
                match-path --capture cap --capture-named named $path "{pattern}" || return --from lib "path_match_fail";
                return --from lib $(append $cap[1] "|" $named.plane);"#
    );

    build_process_chain_xml("", &entry_body)
}

fn build_first_ok_xml(candidate_count: usize, outcome: FirstOkOutcome) -> String {
    let candidate_count = candidate_count.max(3);
    let success_index = match outcome {
        FirstOkOutcome::FirstSuccess => Some(1),
        FirstOkOutcome::MiddleSuccess => Some(candidate_count / 2 + 1),
        FirstOkOutcome::LastSuccess => Some(candidate_count),
        FirstOkOutcome::AllFail => None,
    };

    let mut extra_blocks = String::new();
    let mut candidate_calls = String::new();

    for index in 1..=candidate_count {
        let path = format!("/candidate-{index:02}/payload-{index:02}");
        let prefix = if Some(index) == success_index {
            format!("/candidate-{index:02}")
        } else {
            format!("/missing-{index:02}")
        };

        extra_blocks.push_str(&format!(
            r#"        <block id="candidate{index:02}">
            <![CDATA[
                strip-prefix "{path}" "{prefix}";
            ]]>
        </block>
"#
        ));
        candidate_calls.push_str(&format!(
            "                  $(exec --block candidate{index:02})\n"
        ));
    }

    let entry_body = if let Some(success_index) = success_index {
        format!(
            r#"                local tail=$(first-ok
{candidate_calls}                );

                eq $tail "/payload-{success_index:02}" || return --from lib "bad_tail";
                return --from lib "ok";"#
        )
    } else {
        format!(
            r#"                match-result $(first-ok
{candidate_calls}                )
                ok(value)
                    return --from lib $(append "unexpected_ok:" $value);
                err(err_value)
                    eq $err_value "" || return --from lib "bad_last_error_value";
                    return --from lib "handled_error";
                end"#
        )
    };

    build_process_chain_xml(&extra_blocks, &entry_body)
}

fn build_case_when_pipeline_xml(branch_count: usize) -> String {
    let (target_path, branches) = build_branch_bodies(branch_count, true);
    let entry_body = format!(
        r#"                local host="user.example.com";
                local path="{target_path}";
                case then
{branches}                    end"#
    );

    build_process_chain_xml("", &entry_body)
}

fn build_if_elif_pipeline_xml(branch_count: usize) -> String {
    let (target_path, branches) = build_branch_bodies(branch_count, false);
    let entry_body = format!(
        r#"                local host="user.example.com";
                local path="{target_path}";
{branches}"#
    );

    build_process_chain_xml("", &entry_body)
}

fn build_literal_and_access_xml(entry_count: usize) -> String {
    let entry_count = entry_count.max(4);
    let last_index = entry_count - 1;
    let tags = build_string_entries("tag", entry_count, 24);
    let meta = build_map_entries("k", "v", entry_count, 24);
    let targets = build_target_entries(entry_count, 24);
    let entry_body = format!(
        r#"                local route={{
                    "kind": "service",
                    "service_id": "svc-main",
                    "tags": [
{tags}
                    ],
                    "meta": {{
                        "region_code": "CN_SZ",
{meta}
                    }},
                    "targets": [
{targets}
                    ]
                }};
                eq $route.kind "service" || return --from lib "route_kind_fail";
                eq $route.tags[{last_index}] "tag{last_index:02}" || return --from lib "route_tag_fail";
                eq $route.meta.k{last_index:02} "v{last_index:02}" || return --from lib "route_meta_fail";
                eq $route.targets[{last_index}].node_id "ood{last_index:02}" || return --from lib "route_target_fail";
                return --from lib $(append $route.kind "|" $route.tags[{last_index}] "|" $route.meta.k{last_index:02} "|" $route.targets[{last_index}].node_id);"#
    );

    build_process_chain_xml("", &entry_body)
}

fn build_invoke_helper_return_xml(entry_count: usize) -> String {
    let entry_count = entry_count.max(4);
    let last_index = entry_count - 1;
    let tags = build_string_entries("tag", entry_count, 24);
    let meta = build_map_entries("k", "v", entry_count, 24);
    let entry_body = format!(
        r#"                capture --value payload $(invoke --chain helper --arg service_id "svc-main");
                eq $payload.kind "service" || return --from lib "payload_kind_fail";
                eq $payload.service_id "svc-main" || return --from lib "payload_service_fail";
                eq $payload.tags[{last_index}] "tag{last_index:02}" || return --from lib "payload_tag_fail";
                eq $payload.meta.k{last_index:02} "v{last_index:02}" || return --from lib "payload_meta_fail";
                return --from lib $(append $payload.service_id "|" $payload.tags[{last_index}] "|" $payload.meta.k{last_index:02});"#
    );
    let helper_chain = format!(
        r#"    <process_chain id="helper" priority="100">
        <block id="worker">
            <![CDATA[
                return --from chain {{
                    "kind": "service",
                    "service_id": $__args.service_id,
                    "tags": [
{tags}
                    ],
                    "meta": {{
{meta}
                    }}
                }};
            ]]>
        </block>
    </process_chain>
"#
    );

    build_root_xml("", &entry_body, &helper_chain)
}

fn build_capture_status_value_xml(entry_count: usize) -> String {
    let entry_count = entry_count.max(4);
    let mut entry_body = String::new();

    for index in 0..entry_count {
        entry_body.push_str(&format!(
            "                capture --value value{index:02} --status status{index:02} --ok ok{index:02} $(append \"seg{index:02}\" \"\");\n"
        ));
        entry_body.push_str(&format!(
            "                eq $value{index:02} \"seg{index:02}\" || return --from lib \"value_{index:02}_fail\";\n"
        ));
        entry_body.push_str(&format!(
            "                eq $status{index:02} \"success\" || return --from lib \"status_{index:02}_fail\";\n"
        ));
        entry_body.push_str(&format!(
            "                eq $ok{index:02} true || return --from lib \"ok_{index:02}_fail\";\n"
        ));
    }

    let last_index = entry_count - 1;
    entry_body.push_str(&format!(
        "                return --from lib $(append $value{last_index:02} \"|\" $status{last_index:02} \"|\" $ok{last_index:02});"
    ));

    build_process_chain_xml("", &entry_body)
}

fn build_js_map_result_xml(entry_count: usize) -> String {
    let entry_count = entry_count.max(4);
    let last_index = entry_count - 1;
    let entry_body = format!(
        r#"                capture --value payload $(call describe_host_map "gateway.buckyos.com");
                eq $payload.host "gateway.buckyos.com" || return --from lib "host_fail";
                eq $payload.suffix "buckyos" || return --from lib "suffix_fail";
                eq $payload.k{last_index:02} "v{last_index:02}" || return --from lib "payload_key_fail";
                return --from lib $(append $payload.suffix "|" $payload.k{last_index:02});"#
    );

    build_process_chain_xml("", &entry_body)
}

fn build_js_set_result_xml(entry_count: usize) -> String {
    let entry_count = entry_count.max(4);
    let last_index = entry_count - 1;
    let entry_body = format!(
        r#"                match-result $(call classify_host_tags "gateway.buckyos.com")
                ok(tags)
                    match-include $tags "allow" || return --from lib "allow_missing";
                    match-include $tags "tag{last_index:02}" || return --from lib "payload_tag_missing";
                    return --from lib "ok:set";
                err(err_value)
                    return --from lib $(append "unexpected_err:" $err_value);
                end"#
    );

    build_process_chain_xml("", &entry_body)
}

fn build_js_map_result_command(entry_count: usize) -> String {
    let entry_count = entry_count.max(4);
    let mut inserts = String::new();

    for index in 0..entry_count {
        inserts.push_str(&format!(
            "    console.assert(payload.insert(\"k{index:02}\", \"v{index:02}\") == null, \"Expected k{index:02} insert to return null\");\n"
        ));
    }

    format!(
        r#"
function describe_host_map(context, host) {{
    const payload = new MapCollection();
    console.assert(payload.insert("host", host) == null, "Expected host insert to return null");
    console.assert(
        payload.insert("suffix", shExpMatch(host, "*.buckyos.com") ? "buckyos" : "other") == null,
        "Expected suffix insert to return null"
    );
{inserts}    return {{ state: true, result: payload }};
}}
"#
    )
    .trim()
    .to_string()
}

fn build_js_set_result_command(entry_count: usize) -> String {
    let entry_count = entry_count.max(4);
    let mut inserts = String::new();

    for index in 0..entry_count {
        inserts.push_str(&format!(
            "    console.assert(tags.insert(\"tag{index:02}\"), \"Expected tag{index:02} insert to succeed\");\n"
        ));
    }

    format!(
        r#"
function classify_host_tags(context, host) {{
    const tags = new SetCollection();
    console.assert(tags.insert("seen"), "Expected seen tag insert to succeed");
    console.assert(tags.insert("allow"), "Expected allow tag insert to succeed");
{inserts}    return {{ state: true, result: tags }};
}}
"#
    )
    .trim()
    .to_string()
}

fn build_process_chain_xml(extra_blocks: &str, entry_body: &str) -> String {
    build_root_xml(extra_blocks, entry_body, "")
}

fn build_root_xml(extra_blocks: &str, entry_body: &str, extra_chains: &str) -> String {
    format!(
        r#"
<root>
    <process_chain id="main" priority="100">
{extra_blocks}        <block id="entry">
            <![CDATA[
{entry_body}
            ]]>
        </block>
    </process_chain>
{extra_chains}
</root>
"#
    )
}

fn build_path_segments(path_segments: usize) -> Vec<String> {
    let path_segments = path_segments.max(4);
    let mut segments = Vec::with_capacity(path_segments);
    segments.push("ood1".to_string());
    segments.push("admin".to_string());

    for index in 2..path_segments {
        segments.push(format!("seg{index:02}"));
    }

    segments
}

fn build_query_string(query_pairs: usize) -> String {
    let query_pairs = query_pairs.max(4);
    let mut pairs = Vec::with_capacity(query_pairs);
    pairs.push("redirect_url=%2Fdashboard".to_string());
    pairs.push("tag=alpha00".to_string());
    pairs.push("tag=beta01".to_string());

    for index in 3..query_pairs {
        pairs.push(format!("k{index:02}=v{index:02}"));
    }

    pairs.join("&")
}

fn build_branch_bodies(branch_count: usize, case_when: bool) -> (String, String) {
    let branch_count = branch_count.max(3);
    let path_branch_count = branch_count - 1;
    let target_path = format!("/route-{path_branch_count:02}");

    let mut branches = String::new();

    if case_when {
        branches.push_str(
            "                    when match-reg $host \"^admin\\\\.\" then\n                        return --from lib \"host_admin\";\n",
        );

        for index in 1..=path_branch_count {
            branches.push_str(&format!(
                "                    when eq $path \"/route-{index:02}\" then\n                        return --from lib \"route_{index:02}\";\n"
            ));
        }

        branches.push_str(
            "                    else\n                        return --from lib \"default\";\n",
        );
    } else {
        branches.push_str(
            "                if match-reg $host \"^admin\\\\.\" then\n                    return --from lib \"host_admin\";\n",
        );

        for index in 1..=path_branch_count {
            branches.push_str(&format!(
                "                elif eq $path \"/route-{index:02}\" then\n                    return --from lib \"route_{index:02}\";\n"
            ));
        }

        branches.push_str(
            "                else\n                    return --from lib \"default\";\n                end",
        );
    }

    (target_path, branches)
}

fn build_string_entries(prefix: &str, count: usize, indent: usize) -> String {
    let padding = " ".repeat(indent);
    let mut entries = Vec::with_capacity(count);

    for index in 0..count {
        entries.push(format!("{padding}\"{prefix}{index:02}\""));
    }

    entries.join(",\n")
}

fn build_map_entries(key_prefix: &str, value_prefix: &str, count: usize, indent: usize) -> String {
    let padding = " ".repeat(indent);
    let mut entries = Vec::with_capacity(count);

    for index in 0..count {
        entries.push(format!(
            "{padding}\"{key_prefix}{index:02}\": \"{value_prefix}{index:02}\""
        ));
    }

    entries.join(",\n")
}

fn build_target_entries(count: usize, indent: usize) -> String {
    let padding = " ".repeat(indent);
    let mut entries = Vec::with_capacity(count);

    for index in 0..count {
        entries.push(format!(
            "{padding}{{ \"node_id\": \"ood{index:02}\", \"port\": {} }}",
            3100 + index
        ));
    }

    entries.join(",\n")
}

async fn build_record_entry(
    key: &str,
    name: &str,
) -> Result<cyfs_process_chain::MapCollectionRef, String> {
    let map = MemoryMapCollection::new_ref();
    map.insert("key", CollectionValue::String(key.to_string()))
        .await?;
    map.insert("name", CollectionValue::String(name.to_string()))
        .await?;
    Ok(map)
}
