# cyfs-process-chain 性能测试设计与执行计划

本文档用于规划 `cyfs-process-chain` 的性能测试方法、基准矩阵、执行节奏与报告输出方式。

这不是一份“先跑几个 benchmark 看看”的临时笔记，而是面向后续长期演进的性能基线方案。目标是让新命令、新控制流能力和 JS external 扩展都能被稳定纳入回归分析，而不是每次只凭感觉判断是否变慢。

- crate: `cyfs-process-chain`
- status: draft, implementation-ready
- updated: `2026-04-23`

## 1. 文档目标

本计划要解决的不是单一命令快不快，而是以下几个工程问题：

1. 把 `process-chain` 的真实执行成本拆开测清楚：
   - parse
   - link
   - request hot path execute
2. 为当前项目里已经存在的典型脚本形态建立稳定 baseline，而不是只做脱离上下文的 micro-benchmark。
3. 为后续优化提供统一的判断口径：
   - 慢在冷启动还是热执行
   - 慢在变量解析还是命令组合
   - 慢在 built-in 还是 JS external
4. 让 benchmark 用例尽量复用现有测试中已经稳定的脚本形态，避免文档和实现脱节。

## 2. 基于当前实现的性能分层

从当前代码路径看，`cyfs-process-chain` 的性能必须至少拆成以下几层。

### 2.1 Parse 层

这层对应脚本从文本进入内部结构的成本，核心路径包括：

- `ProcessChainXMLLoader::load_process_chain_lib(...)`
- `ProcessChainJSONLoader::load_process_chain_lib(...)`
- `BlockParser::parse(...)`

这层主要覆盖：

- XML/JSON 解析
- block 文本拆行
- typed literal 识别
- `if/case/for/match-result` 语法树构建
- `ListLiteral` / `MapLiteral` 结构化字面量解析

### 2.2 Link 层

这层对应“已经 parse 完成的脚本”进入可执行态的成本，核心路径包括：

- `ProcessChainManager::link(...)`
- `ProcessChain::link(...)`
- `BlockCommandLinker::link(...)`
- `CommandParserFactory` 查找 parser
- external command 自动重写为 `call <name> ...`

这层主要覆盖：

- 命令 parser 解析
- executor 绑定
- 正则、模板、路径 matcher 等 link-time 校验和预处理
- 链式 script clone + link 的固定成本

### 2.3 Execute 层

这层对应请求热路径上的重复执行成本，核心路径包括：

- `HookPointExecutor::execute_lib(...)`
- `HookPointExecutor::prepare_exec_lib(...)`
- `ProcessChainLibExecutor::execute_lib(...)`
- `ProcessChainExecutor::execute_chain(...)`
- `BlockExecuter::execute_block(...)`
- `BlockExecuter::execute_expression_chain(...)`
- `CommandArgEvaluator::evaluate(...)`

这层主要覆盖：

- env lookup / path traversal
- command arg 求值
- expression chain 短路
- control flow 分支
- `capture` / `match-result` / `first-ok` 等结果编排
- helper / exec / invoke 的跨 block 或跨 chain 调用

### 2.4 JS External 层

这层需要单独看，不应和纯 built-in case 直接混在一个基线里。核心路径包括：

- `HookPointEnv::register_js_external_command(...)`
- `BlockCommandLinker` 对 external command 的 `call` 重写
- `src/js/exec.rs` 中的 JS 执行与结果封装

这层需要至少区分：

- JS command register/load 成本
- JS external hot execute 成本
- typed result wrapper 转换成本

## 3. 设计原则

### 3.1 冷启动和热路径必须分开

以下三类数字绝不能混在一个 benchmark 里：

1. parse
2. link
3. execute

如果把它们混在一起，最终只能得到一个“总耗时”，无法指导优化。

### 3.2 第一阶段优先测真实脚本组合

`process-chain` 的开销热点通常不在孤立命令本身，而在命令组合与数据流转：

- `strip-prefix + split + append`
- `parse-uri + parse-query + query-get + build-uri`
- `case when`
- `first-ok`
- `match-result`

所以第一阶段要优先建立组合基线；单条命令 micro-bench 只在必要时补充。

### 3.3 benchmark fixture 必须贴近现有项目脚本

优先从已有测试脚本演化基准，而不是重新发明一套“实验室脚本”。当前最适合复用的来源是：

- `src/test/test_string_match_commands.rs`
- `src/test/test_first_ok.rs`
- `src/test/test_match_result.rs`
- `src/test/test_case.rs`
- `src/test/test_invoke.rs`
- `src/test/test_collection_literal.rs`
- `src/test/test_js_external.rs`

### 3.4 热执行 benchmark 必须做到 link once, execute many

对热路径 benchmark：

- parse/link 必须在 benchmark iteration 外完成
- iteration 内只保留真正要测的 execute 路径

否则热路径数字会被冷启动成本污染。

### 3.5 stateful 场景必须显式隔离迭代

当前执行器里：

- `ProcessChainLibExecutor::execute_lib(self)` 会消费 executor
- `ProcessChainLibExecutor::fork()` 会创建新的执行上下文
- `Context::fork_block()` / `fork_chain()` 会复用或派生不同层级 env

因此任何会写 env 或 collection 的 benchmark，都必须在每轮迭代里重新拿到隔离态，推荐做法是：

- 基于一个预先准备好的 `ProcessChainLibExecutor`
- 每轮调用 `fork()`
- 然后执行 `execute_lib()`

## 4. 第一阶段测试边界

### 4.1 纳入第一阶段

第一阶段优先覆盖以下内容：

- 语言层：
  - 变量读取
  - path 访问
  - command arg 求值
  - `if/case/match-result/first-ok`
  - List/Map literal 与字段访问
- 运行时层：
  - `link_hook_point(...)`
  - `prepare_exec_lib(...)`
  - `execute_lib(...)`
  - `execute_chain(...)`
- 扩展层：
  - JS external 最小调用
  - JS external typed map/set result

### 4.2 暂不作为第一阶段核心目标

以下内容不放入第一阶段 baseline：

- 网关 HTTP/TCP 收发本身的开销
- DNS/TLS/网络 I/O
- file/json backend 持久化吞吐
- 大规模 collection 持久化读写
- REPL 交互性能
- 整个网关服务的端到端 QPS

这些内容可以后续做补充场景，但不应污染 `process-chain core runtime` 的基线。

## 5. 基准类型定义

建议把 benchmark 明确拆成以下类型。

### 5.1 T0: `parse_only`

目标：

- 只测脚本文本到 `ProcessChainLibRef` 的成本

建议实现：

- 直接调用 `ProcessChainXMLLoader::load_process_chain_lib(...)`
- 不把 `HookPoint::add_process_chain_lib(...)` 混进去

适用场景：

- 大脚本 parse 成本
- 复杂 block 语法成本
- typed literal / collection literal 密集场景

### 5.2 T1: `link_only`

目标：

- 只测已 parse 脚本的 link 成本

建议实现：

- 先创建 `HookPoint`
- 先完成 `load_process_chain_lib(...)`
- iteration 内只测 `hook_point_env.link_hook_point(&hook_point)`

适用场景：

- rewrite/match/template/regex 预处理成本
- external command 绑定成本
- 大脚本多 block link 成本

### 5.3 T2: `prepare_exec_only`

目标：

- 单独测请求级执行前准备成本

建议实现：

- 先完成 link，拿到 `HookPointExecutor`
- iteration 内只测 `prepare_exec_lib(lib_id)`

适用场景：

- 评估“每次请求重新准备执行器”的固定开销

### 5.4 T3: `execute_api_hot`

目标：

- 测用户最直接会走到的公开执行路径

建议实现：

- 先完成 link
- iteration 内调用 `HookPointExecutor::execute_lib(lib_id)` 或 `execute_chain(lib_id, chain_id)`

特点：

- 包含 `prepare_exec_lib(...)`
- 更贴近公开 API 视角

### 5.5 T4: `execute_fork_hot`

目标：

- 测尽可能接近纯 runtime 的热执行成本

建议实现：

- benchmark 外先创建 `base_exec = linked.prepare_exec_lib(lib_id)?`
- iteration 内执行 `base_exec.fork().execute_lib().await`

特点：

- 不再重复 lib 查找
- 不重复 link
- 只保留每轮请求必要的上下文隔离和脚本执行

### 5.6 T5: `js_register_and_execute`

目标：

- 把 JS external 的 register/load 和 hot execute 分开测

建议拆成两个 benchmark：

- `js_register_only`
- `js_execute_hot`

## 6. 推荐 benchmark 框架与组织方式

### 6.1 第一阶段采用 Criterion

建议在 crate 下新增：

```text
src/components/cyfs-process-chain/benches/
  process_chain_runtime.rs
  common/
    mod.rs
```

推荐原因：

- 统计结果稳定，适合做长期回归
- 支持 warm-up / sample size / baseline compare
- 适合输出 change %
- 比手写 `Instant::now()` 循环更可靠

### 6.2 Cargo 配置建议

建议在 `src/components/cyfs-process-chain/Cargo.toml` 中增加 benchmark 入口：

```toml
[dev-dependencies]
criterion = { version = "0.5", features = ["async_tokio"] }

[[bench]]
name = "process_chain_runtime"
harness = false
```

说明：

- 如果 workspace 已经引入 Criterion，可按 workspace 版本统一
- 这里不强制写死版本，以上仅作为推荐起点

### 6.3 Tokio runtime 建议

对于当前第一阶段 benchmark，建议使用：

- `tokio::runtime::Builder::new_current_thread()`

原因：

- 减少 runtime 调度噪音
- 当前基准主要测脚本执行，不需要额外并发吞吐

如果后续要测真正依赖并发 I/O 的 external 场景，再单独切到 multi-thread runtime。

## 7. 目录与 helper 设计

建议把 bench helper 显式做成小型夹具层，不要直接在 benchmark body 里堆初始化代码。

### 7.1 推荐 helper

建议至少抽出以下 helper：

- `build_hook_point_from_xml(lib_id, xml) -> HookPoint`
- `build_hook_point_env(case_name) -> HookPointEnv`
- `register_js_commands(env, commands) -> Result<(), String>`
- `link_executor(env, hook_point) -> HookPointExecutorRef`
- `prepare_base_exec(linked, lib_id) -> ProcessChainLibExecutor`
- `black_box_result(ret)`

### 7.2 helper 的约束

- 不要在 helper 里初始化 `simplelog`
- 不要在 helper 里创建每轮唯一的临时目录
- 不要在 helper 里隐式修改全局 logger 级别
- 所有输入都要固定

### 7.3 数据目录策略

`HookPointEnv::new(...)` 需要 `data_dir`，但第一阶段大部分 benchmark 不需要真实文件 I/O。

因此建议：

- 每个 benchmark case 创建一个固定目录
- 在整个 benchmark 进程生命周期内复用
- 不在 iteration 内做 `create_dir_all`

否则会把文件系统噪音带进结果。

## 8. benchmark 环境规范

所有正式 benchmark 都应满足以下要求。

### 8.1 编译配置

- 只看 `release`
- 建议运行前设置 `CARGO_INCREMENTAL=0`
- benchmark 报告中必须写明 commit 和 build profile

### 8.2 日志

当前项目里的测试通常会初始化 `simplelog`，但 benchmark 不应该这样做。

建议：

- benchmark 进程不初始化 logger
- 并显式设置 `log::set_max_level(log::LevelFilter::Off)` 或至少保持 `Error`

否则 `BlockExecuter`、`ProcessChainExecutor` 等路径上的 `log!` 会明显污染结果。

### 8.3 机器环境

建议报告中至少记录：

- CPU 型号
- 核数 / 线程数
- 内存大小
- OS / kernel
- governor / power mode
- 是否在物理机还是虚拟机

正式对比时建议：

- 同一台机器
- 同一电源模式
- 关闭明显后台任务
- 不与其他高负载 benchmark 并行

### 8.4 重复执行

每轮正式报告建议：

- 同一套 benchmark 连续跑 3 次
- 以 Criterion 结果为主
- 人工报告里记录 3 次中的中位表现，而不是只截一次最好的数字

## 9. 输入规模分层

只做一个输入规模通常不够，因为很多命令是非线性扩展的。第一阶段建议统一使用 `S/M/L` 三档。

| 维度 | S | M | L |
| --- | --- | --- | --- |
| path segments | 4 | 12 | 32 |
| query pairs | 4 | 16 | 64 |
| `first-ok` candidates | 3 | 8 | 16 |
| `case when` branches | 3 | 8 | 16 |
| list/map literal entries | 4 | 16 | 64 |
| JS typed map keys | 4 | 16 | 64 |
| JS typed set items | 4 | 16 | 64 |

补充约束：

- `S` 要贴近典型网关请求
- `M` 用于观察常规扩容趋势
- `L` 用于找出明显非线性热点

并不是每个 case 都必须做满三档，但每类热点至少要有一个支持规模放大的 case。

## 10. 第一阶段 benchmark 矩阵

下面的矩阵按优先级排序，并尽量映射到当前已有测试语义。

### 10.1 P0: 基础基线

| case | 类型 | 主要测量路径 | 参考来源 | 说明 |
| --- | --- | --- | --- | --- |
| `parse_empty_return_xml` | T0 | XML parse + `BlockParser::parse` | 新增最小脚本 | parse 下限 |
| `link_empty_return_lib` | T1 | `ProcessChainManager::link` | 新增最小脚本 | link 下限 |
| `prepare_exec_empty_return` | T2 | `prepare_exec_lib` | 新增最小脚本 | 每次执行准备成本 |
| `execute_empty_return_api` | T3 | `HookPointExecutor::execute_lib` | 新增最小脚本 | 公开 API 热路径下限 |
| `execute_empty_return_fork` | T4 | `fork + execute_lib` | 新增最小脚本 | 尽量接近纯 runtime 下限 |
| `var_read_flat` | T4 | `CommandArgEvaluator::evaluate_var_expression` | 参考 `test_var.rs` | 单层变量读取 |
| `var_read_path` | T4 | env path traversal | 参考 `test_var.rs` | 嵌套 map path |
| `list_path_read` | T4 | list index path traversal | 参考 `test_list.rs` / `test_var.rs` | List path 成本 |

### 10.2 P1: 与网关脚本最相关的组合

| case | 类型 | 参考来源 | 核心组合 | 优先级 |
| --- | --- | --- | --- | --- |
| `route_prefix_pipeline` | T4 | `test_string_match_commands.rs` | `strip-prefix + split --skip-empty + append` | P1 |
| `host_classify_pipeline` | T4 | `test_string_match_commands.rs` | `parse-authority + oneof/match-host` | P1 |
| `uri_query_pipeline` | T4 | `test_string_match_commands.rs` | `parse-uri + parse-query + query-get + build-uri` | P1 |
| `match_capture_pipeline` | T4 | `test_string_match_commands.rs` | `match-path --capture + --capture-named + path read` | P1 |
| `first_ok_success` | T4 | `test_first_ok.rs` | `first-ok` 第 2 个候选成功 | P1 |
| `first_ok_all_fail` | T4 | `test_first_ok.rs` | `first-ok` 全失败 | P1 |
| `case_when_pipeline` | T4 | `test_case.rs` | `case when` 多分支判定 | P1 |
| `match_result_flow` | T4 | `test_match_result.rs` | `match-result + branch scope restore` | P1 |

### 10.3 P1: 结构化值与调用

| case | 类型 | 参考来源 | 核心组合 | 优先级 |
| --- | --- | --- | --- | --- |
| `literal_and_access` | T4 | `test_collection_literal.rs` | map/list literal + path access | P1 |
| `invoke_helper_return` | T4 | `test_invoke.rs` | helper/invoke + typed payload read | P1 |
| `capture_status_value` | T4 | `capture.rs` 与相关测试模式 | `capture --value --status --ok` | P1 |
| `map_reduce_external_vars` | T4 | `map.rs` / `test_collection.rs` | `map` 遍历中读取 `__key/__value` external env | P1 |

### 10.4 P2: JS external

| case | 类型 | 参考来源 | 核心组合 | 说明 |
| --- | --- | --- | --- | --- |
| `js_register_bool` | T5 | `test_js_external.rs` | `register_js_external_command` | 冷路径，不与 built-in 混比 |
| `js_execute_bool` | T4/T5 | `test_js_external.rs` | 最小 JS bool/classify | 最小 external hot call |
| `js_execute_map_result` | T4/T5 | `test_js_external.rs` | JS typed map result | 关注 wrapper 转换 |
| `js_execute_set_result` | T4/T5 | `test_js_external.rs` | JS typed set result | 关注 wrapper 转换 |

## 11. case 设计细则

### 11.1 `route_prefix_pipeline`

建议脚本形态：

- 输入 `REQ.path`
- 执行 `strip-prefix`
- 执行 `split --skip-empty`
- 读取 `$parts[0]` / `$parts[1]`
- `append` 输出结果

原因：

- 这是最接近路由前缀解析的组合
- 同时覆盖字符串处理、list 生成、list path 读取

### 11.2 `host_classify_pipeline`

建议脚本形态：

- `parse-authority` 或 `parse-uri`
- 再做 `match-host` 或 `oneof`
- 最终输出一个短字符串结果

原因：

- 这类脚本经常出现在网关 host 路由与站点分类场景

### 11.3 `uri_query_pipeline`

建议脚本形态：

- `parse-uri`
- `parse-query`
- `query-get`
- `build-uri`

原因：

- 覆盖 typed map / multimap 构造
- 覆盖 URI parser 和 query parser
- 覆盖结构化值回写为字符串

### 11.4 `first_ok_*`

至少保留三种子场景：

- 第一个候选成功
- 最后一个候选成功
- 全部失败

原因：

- `first-ok` 的成本和短路位置强相关
- 只测一种场景会误导结论

### 11.5 `case_when_pipeline`

建议为同一语义保留两套脚本：

- `case when`
- 等价的 `if / elif`

原因：

- 这样才能判断 `case when` 的实现是否带来额外分支开销

### 11.6 JS external case

JS external 至少要有两类输出：

- 标量/布尔结果
- typed map/set 结果

不要只测布尔结果；否则看不到 wrapper 转换成本。

## 12. benchmark 实现建议

### 12.1 推荐的最小代码骨架

```rust
use criterion::{black_box, criterion_group, criterion_main, Criterion};

fn bench_execute_empty_return(c: &mut Criterion) {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap();

    let fixture = rt.block_on(async { build_empty_return_fixture().await });
    let base_exec = fixture.linked.prepare_exec_lib("empty_return_lib").unwrap();

    let mut group = c.benchmark_group("execute_fork_hot");
    group.bench_function("empty_return/S", |b| {
        b.to_async(&rt).iter(|| {
            let exec = base_exec.fork();
            async move {
                let ret = exec.execute_lib().await.unwrap();
                black_box(ret.value_ref().clone());
            }
        });
    });
    group.finish();
}
```

### 12.2 结果消费

必须确保 benchmark 真的消费结果，避免优化器把执行体裁掉：

- `black_box(ret.value_ref().clone())`
- 必要时校验返回值类型或固定字段

### 12.3 不要在 iteration 内做的事情

以下内容默认都应该在 iteration 外：

- 创建 `HookPoint`
- 创建 `HookPointEnv`
- 注册 parser context / JS command
- `load_process_chain_lib(...)`
- `link_hook_point(...)`，除非该 case 本身就是 T1
- 创建目录
- 构造超大输入字符串

## 13. Criterion 参数建议

第一阶段建议按 benchmark 类型设置不同参数。

### 13.1 热路径组

建议：

- `warm_up_time = 3s`
- `measurement_time = 8s`
- `sample_size = 50`
- `noise_threshold = 0.03`

适用：

- T3 / T4

### 13.2 冷路径组

建议：

- `warm_up_time = 1s`
- `measurement_time = 5s`
- `sample_size = 20`

适用：

- T0 / T1 / T2

原因：

- 冷路径本身更慢，不需要过大 sample
- 重点是稳定比较，不是追求超高采样数

## 14. 结果指标与回归门槛

### 14.1 正式报告必须包含

- `median ns/op`
- `ops/sec`
- 相对 baseline 的 change %
- 输入规模档位
- benchmark 类型 `T0/T1/T2/T3/T4/T5`

### 14.2 推荐回归门槛

第一阶段建议使用如下工程口径：

| 级别 | 建议处理 |
| --- | --- |
| `< 5%` | 视为正常波动，除非重复出现 |
| `5% ~ 10%` | 需要检查是否由输入、环境或实现变化引起 |
| `> 10%` | P0/P1 case 必须解释原因 |
| `> 15%` | 若为热路径 P0/P1，默认视为需要阻断或回滚优化前确认 |

补充说明：

- 对 JS external 可以稍微放宽，但也不建议长期接受双位数退化
- 冷路径与热路径不要用同一门槛做机械判断，热路径更重要

## 15. 建议的 benchmark 命令

### 15.1 跑单个 bench 文件

```bash
cd src
cargo bench -p cyfs-process-chain --bench process_chain_runtime
```

### 15.2 只跑某个 case

```bash
cd src
cargo bench -p cyfs-process-chain --bench process_chain_runtime -- route_prefix_pipeline
```

### 15.3 保存 baseline

```bash
cd src
cargo bench -p cyfs-process-chain --bench process_chain_runtime -- --save-baseline main-local
```

### 15.4 与 baseline 对比

```bash
cd src
cargo bench -p cyfs-process-chain --bench process_chain_runtime -- --baseline main-local
```

说明：

- 是否使用 `cargo bench` 还是 `cargo criterion`，可以按本地工具链决定
- 但 baseline 名称和报告格式需要统一

## 16. 报告格式建议

每一轮正式 benchmark 建议输出一份独立报告，并把 Markdown 报告和机器可读快照都放在：

```text
src/components/cyfs-process-chain/benches/reports/
```

建议目录结构：

```text
src/components/cyfs-process-chain/benches/reports/
  README.md
  INDEX.md
  manifest.json
  generate_report.py
  records/
    20260423T053000-0700__main-local__32cff73.md
    20260423T053000-0700__main-local__32cff73.json
```

说明：

- `records/*.md` 负责人工 review 和时间线浏览
- `records/*.json` 负责后续自动对照和脚本分析
- `INDEX.md` 维护报告时间线入口
- `manifest.json` 维护结构化元数据索引

建议在每次正式 benchmark 后，立即把 `target/criterion` 结果固化成一份报告，而不是只保留本机临时输出。

### 16.1 报告头

- date
- git commit
- benchmark branch
- machine info
- rustc version
- benchmark command
- baseline name

### 16.2 结果表

| case | type | scale | median ns/op | change % | notes |
| --- | --- | --- | --- | --- | --- |
| `execute_empty_return_fork` | T4 | S | TBD | baseline | runtime floor |
| `route_prefix_pipeline` | T4 | S | TBD | TBD | gateway-like path parsing |
| `uri_query_pipeline` | T4 | M | TBD | TBD | parser + typed value conversion |

### 16.3 结论

- 最慢的 3 个热路径 case
- 最可疑的 3 个热点模块
- 是否存在明显非线性扩展
- 是否出现回归
- 下一轮优化建议

### 16.4 报告生成命令

保存 baseline 后生成报告：

```bash
cd /home/bucky/work/cyfs-gateway
python3 src/components/cyfs-process-chain/benches/reports/generate_report.py \
  --baseline-name main-local \
  --benchmark-command 'CARGO_INCREMENTAL=0 cargo bench -p cyfs-process-chain --bench process_chain_runtime -- --save-baseline main-local'
```

与 baseline 对比后生成报告：

```bash
cd /home/bucky/work/cyfs-gateway
python3 src/components/cyfs-process-chain/benches/reports/generate_report.py \
  --baseline-name main-local \
  --compare-to main-local \
  --benchmark-command 'CARGO_INCREMENTAL=0 cargo bench -p cyfs-process-chain --bench process_chain_runtime -- --baseline main-local'
```

## 17. 第一轮落地顺序

### Phase 1: 建立 harness

交付：

- `criterion` bench 入口
- `common` helper
- `parse_empty_return_xml`
- `link_empty_return_lib`
- `execute_empty_return_api`
- `execute_empty_return_fork`

### Phase 2: 覆盖核心脚本组合

交付：

- `route_prefix_pipeline`
- `host_classify_pipeline`
- `uri_query_pipeline`
- `match_capture_pipeline`
- `first_ok_success`
- `first_ok_all_fail`
- `case_when_pipeline`
- `match_result_flow`

### Phase 3: 覆盖结构化值与 JS external

交付：

- `literal_and_access`
- `invoke_helper_return`
- `js_register_bool`
- `js_execute_bool`
- `js_execute_map_result`
- `js_execute_set_result`

### Phase 4: profiling 与优化

在有 baseline 之后，再进入：

- `cargo flamegraph`
- `perf record`
- allocation profiling

profiling 的角色是解释 benchmark 结果，不是替代 benchmark。

## 18. 第一轮优化关注点

在正式数据出来前不做结论，但当前实现上最值得优先关注的区域是：

- `CommandArgEvaluator::evaluate(...)`
- env path 解析与遍历
- `execute_expression_chain(...)` 的短路与包装逻辑
- `capture` / `match-result` 的分支变量快照与恢复
- `ProcessChainManager::link(...)` 中的 clone + link 成本
- `parse-uri` / `parse-query` / `build-uri` 的结构化值构造
- JS external wrapper 到 `CollectionValue` 的转换

## 19. 常见误区

以下做法会直接让结果失真，应明确避免：

1. 把 parse、link、execute 放在同一个 benchmark 里。
2. 在 iteration 内创建目录、写文件、初始化 logger。
3. 热路径 benchmark 使用会污染全局状态的脚本，却不做 `fork()` 隔离。
4. 只测 success path，不测短路位置变化后的成本。
5. 把 JS external 和 built-in case 放到同一个结论表里横向比较。
6. 只截取一次最好看的数字，不保留完整 benchmark 输出。

## 20. 本计划的结论

对于 `cyfs-process-chain`，第一阶段最有价值的不是“大而全”的 benchmark 数量，而是先把下面三件事做扎实：

1. 建立 parse / link / execute 的分层基线。
2. 用现有测试语义沉淀出几组稳定的真实脚本组合 case。
3. 把 JS external 作为独立扩展层持续跟踪，而不是混入 core runtime baseline。

只要这三点做对，后续无论是优化 `CommandArgEvaluator`、`case when`、`match-result`，还是继续扩展 URI/query/JS 能力，都会有清晰的回归判断依据。
