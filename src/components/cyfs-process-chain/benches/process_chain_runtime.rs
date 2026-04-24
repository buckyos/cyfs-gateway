mod common;

use common::{
    CAPTURE_STATUS_VALUE_CASE, CASE_WHEN_PIPELINE_CASE, EMPTY_RETURN_CASE, FIRST_OK_ALL_FAIL_CASE,
    FIRST_OK_FIRST_SUCCESS_CASE, FIRST_OK_LAST_SUCCESS_CASE, FIRST_OK_SUCCESS_CASE,
    HOST_CLASSIFY_PIPELINE_CASE, IF_ELIF_PIPELINE_CASE, INVOKE_HELPER_RETURN_CASE,
    JS_EXECUTE_BOOL_CASE, JS_EXECUTE_MAP_RESULT_CASE, JS_EXECUTE_SET_RESULT_CASE,
    JS_REGISTER_BOOL_CASE, LIST_PATH_READ_CASE, LITERAL_AND_ACCESS_CASE,
    MAP_REDUCE_EXTERNAL_VARS_CASE, MATCH_CAPTURE_PIPELINE_CASE, MATCH_RESULT_FLOW_CASE,
    PHASE2_SCALES, PHASE2_SMALL_SCALE, ROUTE_PREFIX_PIPELINE_CASE, SCALE_SMALL,
    URI_QUERY_PIPELINE_CASE, VAR_READ_FLAT_CASE, VAR_READ_PATH_CASE, black_box_result,
    build_bench_data_dir, build_capture_status_value_linked_fixture,
    build_case_when_pipeline_linked_fixture, build_empty_return_link_fixture,
    build_empty_return_linked_fixture, build_first_ok_all_fail_linked_fixture,
    build_first_ok_first_success_linked_fixture, build_first_ok_last_success_linked_fixture,
    build_first_ok_success_linked_fixture, build_host_classify_pipeline_linked_fixture,
    build_if_elif_pipeline_linked_fixture, build_invoke_helper_return_linked_fixture,
    build_js_execute_bool_linked_fixture, build_js_execute_map_result_linked_fixture,
    build_js_execute_set_result_linked_fixture, build_list_path_read_linked_fixture,
    build_literal_and_access_linked_fixture, build_map_reduce_external_vars_linked_fixture,
    build_match_capture_pipeline_linked_fixture, build_match_result_flow_linked_fixture,
    build_route_prefix_pipeline_linked_fixture, build_uri_query_pipeline_linked_fixture,
    build_var_read_flat_linked_fixture, build_var_read_path_linked_fixture, disable_logging,
    js_bool_command_source, load_empty_return_lib, prepare_exec,
};
use criterion::measurement::WallTime;
use criterion::{BenchmarkGroup, BenchmarkId, Criterion, criterion_group, criterion_main};
use cyfs_process_chain::HookPointEnv;
use cyfs_process_chain::ProcessChainLibExecutor;
use std::time::Duration;
use tokio::runtime::Runtime;

fn cold_group<'a>(c: &'a mut Criterion, name: &str) -> BenchmarkGroup<'a, WallTime> {
    let mut group = c.benchmark_group(name);
    group.sample_size(20);
    group.warm_up_time(Duration::from_secs(1));
    group.measurement_time(Duration::from_secs(5));
    group
}

fn hot_group<'a>(c: &'a mut Criterion, name: &str) -> BenchmarkGroup<'a, WallTime> {
    let mut group = c.benchmark_group(name);
    group.sample_size(50);
    group.warm_up_time(Duration::from_secs(3));
    group.measurement_time(Duration::from_secs(8));
    group.noise_threshold(0.03);
    group
}

fn bench_fork_exec(
    group: &mut BenchmarkGroup<'_, WallTime>,
    rt: &Runtime,
    case: &str,
    scale: &str,
    exec: &ProcessChainLibExecutor,
    context: &str,
) {
    group.bench_function(BenchmarkId::new(case, scale), |b| {
        b.to_async(rt).iter(|| async {
            let result = exec.fork().execute_lib().await.expect(context);
            black_box_result(result);
        });
    });
}

fn phase2_scope(case: &str, scale: &str) -> String {
    format!(
        "bench-phase2-{}-{}",
        case.replace('_', "-"),
        scale.to_ascii_lowercase()
    )
}

fn bench_parse_empty_return(c: &mut Criterion) {
    let mut group = cold_group(c, "phase1/parse_only");
    group.bench_function(BenchmarkId::new(EMPTY_RETURN_CASE, SCALE_SMALL), |b| {
        b.iter(|| {
            let lib = load_empty_return_lib().expect("parse empty_return benchmark fixture");
            criterion::black_box(lib.get_len().expect("parsed lib length"));
        });
    });
    group.finish();
}

fn bench_link_empty_return(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime for link benchmark");
    let fixture = rt
        .block_on(build_empty_return_link_fixture("bench-link-empty-return"))
        .expect("build link fixture");

    let mut group = cold_group(c, "phase1/link_only");
    group.bench_function(BenchmarkId::new(EMPTY_RETURN_CASE, SCALE_SMALL), |b| {
        b.to_async(&rt).iter(|| async {
            let linked = fixture
                .hook_point_env
                .link_hook_point(&fixture.hook_point)
                .await
                .expect("link empty_return hook point");
            criterion::black_box(linked);
        });
    });
    group.finish();
}

fn bench_prepare_exec_empty_return(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime for prepare_exec benchmark");
    let fixture = rt
        .block_on(build_empty_return_linked_fixture(
            "bench-prepare-exec-empty-return",
        ))
        .expect("build linked fixture");

    let mut group = cold_group(c, "phase1/prepare_exec_only");
    group.bench_function(BenchmarkId::new(EMPTY_RETURN_CASE, SCALE_SMALL), |b| {
        b.to_async(&rt).iter(|| async {
            let exec = fixture
                .linked
                .prepare_exec_lib(common::EMPTY_RETURN_LIB_ID)
                .expect("prepare empty_return exec");
            criterion::black_box(exec);
        });
    });
    group.finish();
}

fn bench_execute_empty_return_api(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime for execute_api benchmark");
    let fixture = rt
        .block_on(build_empty_return_linked_fixture(
            "bench-execute-api-empty-return",
        ))
        .expect("build linked fixture");

    let mut group = hot_group(c, "phase1/execute_api_hot");
    group.bench_function(BenchmarkId::new(EMPTY_RETURN_CASE, SCALE_SMALL), |b| {
        b.to_async(&rt).iter(|| async {
            let result = fixture
                .linked
                .execute_lib(common::EMPTY_RETURN_LIB_ID)
                .await
                .expect("execute empty_return via public api");
            black_box_result(result);
        });
    });
    group.finish();
}

fn bench_execute_empty_return_fork(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime for execute_fork benchmark");
    let empty_fixture = rt
        .block_on(build_empty_return_linked_fixture(
            "bench-execute-fork-empty-return",
        ))
        .expect("build linked fixture");
    let empty_exec = prepare_exec(&empty_fixture).expect("prepare empty_return exec");
    let flat_fixture = rt
        .block_on(build_var_read_flat_linked_fixture(
            "bench-execute-fork-var-read-flat",
        ))
        .expect("build var_read_flat fixture");
    let flat_exec = prepare_exec(&flat_fixture).expect("prepare var_read_flat exec");
    let path_fixture = rt
        .block_on(build_var_read_path_linked_fixture(
            "bench-execute-fork-var-read-path",
        ))
        .expect("build var_read_path fixture");
    let path_exec = prepare_exec(&path_fixture).expect("prepare var_read_path exec");
    let list_fixture = rt
        .block_on(build_list_path_read_linked_fixture(
            "bench-execute-fork-list-path-read",
        ))
        .expect("build list_path_read fixture");
    let list_exec = prepare_exec(&list_fixture).expect("prepare list_path_read exec");

    let mut group = hot_group(c, "phase1/execute_fork_hot");
    bench_fork_exec(
        &mut group,
        &rt,
        EMPTY_RETURN_CASE,
        SCALE_SMALL,
        &empty_exec,
        "execute empty_return via forked executor",
    );
    bench_fork_exec(
        &mut group,
        &rt,
        VAR_READ_FLAT_CASE,
        SCALE_SMALL,
        &flat_exec,
        "execute var_read_flat via forked executor",
    );
    bench_fork_exec(
        &mut group,
        &rt,
        VAR_READ_PATH_CASE,
        SCALE_SMALL,
        &path_exec,
        "execute var_read_path via forked executor",
    );
    bench_fork_exec(
        &mut group,
        &rt,
        LIST_PATH_READ_CASE,
        SCALE_SMALL,
        &list_exec,
        "execute list_path_read via forked executor",
    );
    group.finish();
}

fn bench_execute_phase2_pipelines(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime for phase2 execute_fork benchmark");

    let mut group = hot_group(c, "phase2/execute_fork_hot");

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(ROUTE_PREFIX_PIPELINE_CASE, scale.label);
        let fixture = rt
            .block_on(build_route_prefix_pipeline_linked_fixture(&scope, scale))
            .expect("build route_prefix_pipeline fixture");
        let exec = prepare_exec(&fixture).expect("prepare route_prefix exec");
        bench_fork_exec(
            &mut group,
            &rt,
            ROUTE_PREFIX_PIPELINE_CASE,
            scale.label,
            &exec,
            "execute route_prefix_pipeline via forked executor",
        );
    }

    let host_classify_scope = phase2_scope(HOST_CLASSIFY_PIPELINE_CASE, SCALE_SMALL);
    let host_classify_fixture = rt
        .block_on(build_host_classify_pipeline_linked_fixture(
            &host_classify_scope,
        ))
        .expect("build host_classify_pipeline fixture");
    let host_classify_exec =
        prepare_exec(&host_classify_fixture).expect("prepare host_classify exec");
    bench_fork_exec(
        &mut group,
        &rt,
        HOST_CLASSIFY_PIPELINE_CASE,
        SCALE_SMALL,
        &host_classify_exec,
        "execute host_classify_pipeline via forked executor",
    );

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(URI_QUERY_PIPELINE_CASE, scale.label);
        let fixture = rt
            .block_on(build_uri_query_pipeline_linked_fixture(&scope, scale))
            .expect("build uri_query_pipeline fixture");
        let exec = prepare_exec(&fixture).expect("prepare uri_query exec");
        bench_fork_exec(
            &mut group,
            &rt,
            URI_QUERY_PIPELINE_CASE,
            scale.label,
            &exec,
            "execute uri_query_pipeline via forked executor",
        );
    }

    let match_capture_scope = phase2_scope(MATCH_CAPTURE_PIPELINE_CASE, SCALE_SMALL);
    let match_capture_fixture = rt
        .block_on(build_match_capture_pipeline_linked_fixture(
            &match_capture_scope,
            PHASE2_SMALL_SCALE,
        ))
        .expect("build match_capture_pipeline fixture");
    let match_capture_exec =
        prepare_exec(&match_capture_fixture).expect("prepare match_capture exec");
    bench_fork_exec(
        &mut group,
        &rt,
        MATCH_CAPTURE_PIPELINE_CASE,
        SCALE_SMALL,
        &match_capture_exec,
        "execute match_capture_pipeline via forked executor",
    );

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(FIRST_OK_FIRST_SUCCESS_CASE, scale.label);
        let fixture = rt
            .block_on(build_first_ok_first_success_linked_fixture(&scope, scale))
            .expect("build first_ok_first_success fixture");
        let exec = prepare_exec(&fixture).expect("prepare first_ok_first_success exec");
        bench_fork_exec(
            &mut group,
            &rt,
            FIRST_OK_FIRST_SUCCESS_CASE,
            scale.label,
            &exec,
            "execute first_ok_first_success via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(FIRST_OK_SUCCESS_CASE, scale.label);
        let fixture = rt
            .block_on(build_first_ok_success_linked_fixture(&scope, scale))
            .expect("build first_ok_success fixture");
        let exec = prepare_exec(&fixture).expect("prepare first_ok_success exec");
        bench_fork_exec(
            &mut group,
            &rt,
            FIRST_OK_SUCCESS_CASE,
            scale.label,
            &exec,
            "execute first_ok_success via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(FIRST_OK_LAST_SUCCESS_CASE, scale.label);
        let fixture = rt
            .block_on(build_first_ok_last_success_linked_fixture(&scope, scale))
            .expect("build first_ok_last_success fixture");
        let exec = prepare_exec(&fixture).expect("prepare first_ok_last_success exec");
        bench_fork_exec(
            &mut group,
            &rt,
            FIRST_OK_LAST_SUCCESS_CASE,
            scale.label,
            &exec,
            "execute first_ok_last_success via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(FIRST_OK_ALL_FAIL_CASE, scale.label);
        let fixture = rt
            .block_on(build_first_ok_all_fail_linked_fixture(&scope, scale))
            .expect("build first_ok_all_fail fixture");
        let exec = prepare_exec(&fixture).expect("prepare first_ok_all_fail exec");
        bench_fork_exec(
            &mut group,
            &rt,
            FIRST_OK_ALL_FAIL_CASE,
            scale.label,
            &exec,
            "execute first_ok_all_fail via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(CASE_WHEN_PIPELINE_CASE, scale.label);
        let fixture = rt
            .block_on(build_case_when_pipeline_linked_fixture(&scope, scale))
            .expect("build case_when_pipeline fixture");
        let exec = prepare_exec(&fixture).expect("prepare case_when exec");
        bench_fork_exec(
            &mut group,
            &rt,
            CASE_WHEN_PIPELINE_CASE,
            scale.label,
            &exec,
            "execute case_when_pipeline via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(IF_ELIF_PIPELINE_CASE, scale.label);
        let fixture = rt
            .block_on(build_if_elif_pipeline_linked_fixture(&scope, scale))
            .expect("build if_elif_pipeline fixture");
        let exec = prepare_exec(&fixture).expect("prepare if_elif exec");
        bench_fork_exec(
            &mut group,
            &rt,
            IF_ELIF_PIPELINE_CASE,
            scale.label,
            &exec,
            "execute if_elif_pipeline via forked executor",
        );
    }

    let match_result_scope = phase2_scope(MATCH_RESULT_FLOW_CASE, SCALE_SMALL);
    let match_result_fixture = rt
        .block_on(build_match_result_flow_linked_fixture(&match_result_scope))
        .expect("build match_result_flow fixture");
    let match_result_exec =
        prepare_exec(&match_result_fixture).expect("prepare match_result_flow exec");
    bench_fork_exec(
        &mut group,
        &rt,
        MATCH_RESULT_FLOW_CASE,
        SCALE_SMALL,
        &match_result_exec,
        "execute match_result_flow via forked executor",
    );

    group.finish();
}

fn bench_execute_phase3_structured_values(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime for phase3 structured value benchmark");

    let mut group = hot_group(c, "phase3/execute_fork_hot");

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(LITERAL_AND_ACCESS_CASE, scale.label);
        let fixture = rt
            .block_on(build_literal_and_access_linked_fixture(&scope, scale))
            .expect("build literal_and_access fixture");
        let exec = prepare_exec(&fixture).expect("prepare literal_and_access exec");
        bench_fork_exec(
            &mut group,
            &rt,
            LITERAL_AND_ACCESS_CASE,
            scale.label,
            &exec,
            "execute literal_and_access via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(INVOKE_HELPER_RETURN_CASE, scale.label);
        let fixture = rt
            .block_on(build_invoke_helper_return_linked_fixture(&scope, scale))
            .expect("build invoke_helper_return fixture");
        let exec = prepare_exec(&fixture).expect("prepare invoke_helper_return exec");
        bench_fork_exec(
            &mut group,
            &rt,
            INVOKE_HELPER_RETURN_CASE,
            scale.label,
            &exec,
            "execute invoke_helper_return via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(CAPTURE_STATUS_VALUE_CASE, scale.label);
        let fixture = rt
            .block_on(build_capture_status_value_linked_fixture(&scope, scale))
            .expect("build capture_status_value fixture");
        let exec = prepare_exec(&fixture).expect("prepare capture_status_value exec");
        bench_fork_exec(
            &mut group,
            &rt,
            CAPTURE_STATUS_VALUE_CASE,
            scale.label,
            &exec,
            "execute capture_status_value via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(MAP_REDUCE_EXTERNAL_VARS_CASE, scale.label);
        let fixture = rt
            .block_on(build_map_reduce_external_vars_linked_fixture(&scope, scale))
            .expect("build map_reduce_external_vars fixture");
        let exec = prepare_exec(&fixture).expect("prepare map_reduce_external_vars exec");
        bench_fork_exec(
            &mut group,
            &rt,
            MAP_REDUCE_EXTERNAL_VARS_CASE,
            scale.label,
            &exec,
            "execute map_reduce_external_vars via forked executor",
        );
    }

    group.finish();
}

fn bench_js_register_only(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime for phase3 js register benchmark");
    let data_dir =
        build_bench_data_dir("bench-phase3-js-register-bool").expect("create js register data dir");

    let mut group = cold_group(c, "phase3/js_register_only");
    group.bench_function(BenchmarkId::new(JS_REGISTER_BOOL_CASE, SCALE_SMALL), |b| {
        b.to_async(&rt).iter(|| {
            let data_dir = data_dir.clone();
            async move {
                let env = HookPointEnv::new("bench-phase3-js-register-bool", data_dir);
                env.register_js_external_command("check_host_bool", js_bool_command_source())
                    .await
                    .expect("register js bool command");
                criterion::black_box(env.get_external_command("check_host_bool").is_some());
            }
        });
    });
    group.finish();
}

fn bench_js_execute_phase3(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime for phase3 js execute benchmark");

    let bool_scope = phase2_scope(JS_EXECUTE_BOOL_CASE, SCALE_SMALL);
    let bool_fixture = rt
        .block_on(build_js_execute_bool_linked_fixture(&bool_scope))
        .expect("build js_execute_bool fixture");
    let bool_exec = prepare_exec(&bool_fixture).expect("prepare js_execute_bool exec");

    let mut group = hot_group(c, "phase3/js_execute_hot");
    bench_fork_exec(
        &mut group,
        &rt,
        JS_EXECUTE_BOOL_CASE,
        SCALE_SMALL,
        &bool_exec,
        "execute js_execute_bool via forked executor",
    );

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(JS_EXECUTE_MAP_RESULT_CASE, scale.label);
        let fixture = rt
            .block_on(build_js_execute_map_result_linked_fixture(&scope, scale))
            .expect("build js_execute_map_result fixture");
        let exec = prepare_exec(&fixture).expect("prepare js_execute_map_result exec");
        bench_fork_exec(
            &mut group,
            &rt,
            JS_EXECUTE_MAP_RESULT_CASE,
            scale.label,
            &exec,
            "execute js_execute_map_result via forked executor",
        );
    }

    for scale in PHASE2_SCALES {
        let scope = phase2_scope(JS_EXECUTE_SET_RESULT_CASE, scale.label);
        let fixture = rt
            .block_on(build_js_execute_set_result_linked_fixture(&scope, scale))
            .expect("build js_execute_set_result fixture");
        let exec = prepare_exec(&fixture).expect("prepare js_execute_set_result exec");
        bench_fork_exec(
            &mut group,
            &rt,
            JS_EXECUTE_SET_RESULT_CASE,
            scale.label,
            &exec,
            "execute js_execute_set_result via forked executor",
        );
    }

    group.finish();
}

fn criterion_benchmark(c: &mut Criterion) {
    disable_logging();
    bench_parse_empty_return(c);
    bench_link_empty_return(c);
    bench_prepare_exec_empty_return(c);
    bench_execute_empty_return_api(c);
    bench_execute_empty_return_fork(c);
    bench_execute_phase2_pipelines(c);
    bench_execute_phase3_structured_values(c);
    bench_js_register_only(c);
    bench_js_execute_phase3(c);
}

criterion_group!(process_chain_runtime, criterion_benchmark);
criterion_main!(process_chain_runtime);
