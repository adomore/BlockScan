# BlockScan — 架构与开发设计总览（Architecture & Project Design）

> 本文是项目的**顶层开发设计文档**:逻辑结构、分层依赖、模块盘点、代码量统计、功能状态矩阵(✅ 已完成 / 🔜 下一步 / 📋 TODO)。各功能域的详细设计见末尾的[设计文档索引](#设计文档索引)。
>
> 维护方式:每新增一个功能模块,先更新对应域设计文档,再回到本文同步「模块盘点」与「功能状态矩阵」。

BlockScan 是一个 Rust CLI:**发现以太坊智能合约 → 下载已验证源码 + 字节码 + 详情 → 静态分析 + 安全审计 → 过滤 → 落盘 → 机器/人类输出**;并提供一条独立的**防御监控/告警**支线(代理升级/所有权变更事件 + 新部署风险评分 + 跨轮去重,支持区间 `monitor` 与跟链头 `watch`)。

---

## 架构与逻辑结构

运行路径分为两条主干:**扫描主流水线**(下载 → 构建 → 分析审计 → 过滤 → 落盘 → 输出)与**独立的监控/watch 告警流**(事件解码 + 风险部署审计 + 基线去重)。

### 扫描主流水线（`range` / `addresses` / `discover` / `audit`）

```
  CLI 进程
  ┌──────────────────────────────────────────────────────────────────────┐
  │ main.rs::main()                                                        │
  │   dotenvy::dotenv() → Cli::parse() (cli.rs) → init_tracing()           │
  │   → lib::run(cli, ctrl_c_future)                                       │
  └───────────────────────────────┬──────────────────────────────────────┘
                                   ▼
  lib.rs::run()  [控制平面 / 分发]
    1. 展平 GlobalArgs;chains 为空 → [chain_id];单链提升为 primary
    2. 跨标志校验(--no-audit 与 --min-risk/--only-vulnerable 互斥;
       watch 与 --chains 互斥);min_risk 读取时 .min(100) 钳制
    3. match Command → 每链 prepare_chain():
         build_chain_config() → config_from_cli() (GlobalArgs→Config)
         → Config::validate()  [要求非空 rpc_url + etherscan_key,数值≥1]
         → build_scanner()  [构造 RpcClient/EtherscanClient/Blockscout/
                             Sourcify/Scanner]
                                   │   (discover 子命令额外先做地址发现,见下)
                                   ▼
  lib.rs::pin_to_block(cfg, rpc, scanner)     ← 每次扫描仅一次
    cfg.pin_block(--at-block) 或 rpc.block_number();再取该块 hash
    → rpc/scanner 双双 pinned_at(block, hash);此后全部状态读走同一 BlockId
    (解析不到 head 时告警降级为不固定,记录写出 block_number: null)

  scanner.rs::Scanner::process_addresses(Vec<Address>)
    buffer_unordered(cfg.concurrency) 流式逐地址:
      process_one(addr):
        storage::already_saved? (非 overwrite 则 Skipped)
        → fetch_and_save(addr):
           ┌ FETCH(固定顺序)
           │  rpc.get_code   @pinned block (空 → NotAContract)
           │  rpc.get_balance @pinned block
           │  etherscan.get_source_code  → SourceCodeResult
           │  etherscan.get_contract_creation
           │    Ok(Some)=有记录 / Ok(None)=确无记录 / Err=请求未成功（三态区分）
           │    失败不致命：写入 details.incomplete=["creation"]，RunStats.degraded += 1
           ├ BUILD
           │  build_details() → BuiltContract:
           │    storage::parse_sources()  拆 SourceCode 为 Vec<SourceFile>
           │    派生 is_verified/abi;detect_minimal_proxy()(EIP-1167)
           │    analysis::analyze(runtime bytecode) → model::Analysis
           ├ ENRICH
           │  rpc.resolve_storage_proxy()（无 impl 时回退）
           │    四个槽依次：EIP-1967 → beacon → EIP-1822 → zeppelinos 旧槽
           │  rpc.resolve_diamond()（仍无 impl **且** 字节码含 DELEGATECALL 时）
           │    facetAddresses() eth_call → 严格解码 address[] → EIP-2535
           │  sourcify.fetch_sources()(仅 !is_verified && cfg.sourcify)
           │  audit::audit_with(details, sources, &suppressions)
           │    → model::Audit(在 source/proxy/sourcify 落定后才审计)
           ├ FILTER
           │  passes_filters(): only_verified/only_proxy/min_balance/
           │                    min_risk/only_vulnerable → 否则 Filtered
           └ PERSIST
              storage::save_contract(): bytecode.hex → abi.json →
              source/ 树 → metadata.json(最后写,作 resume 标记)
                                   │
              收集 SaveOutcome → fold_outcomes() → RunStats
                                   ▼
  输出(由 OutputFormat 路由,lib.rs::emit_run_output / print_summary)
    human  : scanner 直接向 stdout 渲染 report::render_contract_table;摘要走 stderr
    ndjson : 每合约一行 JSON 到 stdout(内存平坦,run-scoped Vec 为空)
    json   : 单个 {run, stats, contracts} 文档(填充 run-scoped Vec)
    sarif  : sarif::build_sarif(contracts) → SARIF 2.1.0 文档
    (可选)write_manifest_if_set() → export::write_manifest(.json/.csv);
           analysis::cluster_by_code() → clusters.json
```

**`discover` 的地址发现前置**:进入 `process_addresses` 前 fan-out 到各独立来源,每个返回小写 `Vec<String>`(出错即空),调用方 union/dedup 后再 parse 回 `alloy::Address`:

```
  github::discover_repo(spec, token)        ─┐
  WebsiteScraper::discover(start, depth)     │  各源返回 Vec<String>
  Google::search_addresses(query)            ├─ union/dedup
  Defillama::fetch_addresses(slug)           │  → Vec<alloy::Address>
  TokenList::fetch(url, chain_id)            │  → 喂入 process_addresses
  Blockscout::search_contracts(name)        ─┘
  (显式地址另走 discovery::load_addresses,CLI 参数 + 文件)
  共享校验:github::valid_address(42 字符 0x+40hex,非零,小写)
```

**事件扫描发现(`discover --topic`)**:`rpc.fetch_logs` / `logs_addresses` 按 topic 收集发射事件的合约地址,同样喂入主流水线。

### 监控/watch 告警流（`monitor` / `watch --alert-*`）

与扫描主线**分离**的流程,两个入口都在 `lib.rs`:`run_monitor`(一次性区间 `[--from,--to]`)与 `watch_alerts_with_shutdown`(实时跟链头)。monitor / 纯事件 watch 仅构 `RpcClient`(`prepare_chain_rpc`,**不要求 Etherscan key、不调 validate()**);风险审计模式才用完整 `Scanner`。

```
  run_monitor / watch_alerts_with_shutdown:
    build_topics(events::default_alert_topics + 解析 --alert-topic,去无效/重复)
    load watchlist(可选)→ 构 1 个 alert::AlertSink(alerts 文件 + webhook)
    → 加载 1 个 baseline::AlertBaseline(--baseline)→ 钳制 min_risk
    组装 AlertCtx{ sink, baseline, throttle, grouper, watchlist, chain, min_transfer }
                                   │
      ┌────────────────────────────┴─────────────────────────────┐
      ▼                                                            ▼
  scan_events_range                              scan_risky_deployments_range
    rpc.fetch_logs(from,to,topics,…)               for block in from..=to:
      → (Vec<LogHit>, failed)                        rpc.contract_creations_in_block
    每条 log:                                        (watchlist 过滤 addr)
      (watchlist 过滤 log.address)                   scanner.scan_and_audit(addr)
      events::parse_alert(log)                         → 仅留 risk_score>0
        (未知 topic → unknown_alert)                       && >= min_risk
      alert.chain_id = ctx.chain                       构 RiskyDeployment Alert
      deliver_alert(…)                                 deliver_alert(…)
    failed → AlertCounts.incomplete                  receipts 失败 → counts.incomplete
                                   │
                                   ▼
  deliver_alert(单一漏斗,多级闸门):
    baseline.is_new(&alert)?  ── 否(重复)→ counts.suppressed++ 并返回
       │是(并 record 进 baseline)
       ▼
    grouper.enabled()? ── 是 → grouper.add(alert);counts.grouped++ 并返回(不即时 emit)
       │否
       ▼
    throttle.allow(alert)? ── 否 → counts.throttled++ 并返回
       │是
       ▼
    sink.emit(alert)  [JSONL append + webhook POST,best-effort,失败仅 warn!]
    emit_alert_line(alert)  [紧凑 JSON 到 stdout];counts.emitted++
                                   │
                                   ▼
  flush_groups(…) 收尾:每个分组发 1 条 digest(计入 emitted)
  AlertCounts.add 聚合 → report_alert_total(incomplete 时附"部分扫描"提示)
```

**watch 背压(`poll_alert_tick`)**:读 head,`confirmed = head - confirmations`,`next > confirmed` 提前返回;`--alert-events` 跑 `scan_events_range`,`--alert-on-risk` 跑 `scan_risky_deployments_range`;**仅当整段干净扫完才把 `next` 推进到 `confirmed+1`**,任何硬错误或 `incomplete`(部分 log/receipt 抓取失败)都让 `next` 原地不动、下个 tick 重扫——重发的告警仅在设了 `--baseline` 时去重。

---

## 分层依赖

模块按职责分 9 层,依赖方向自上而下(上层依赖下层);叶子层(`model`/`error`/`chains`)无 crate 内依赖。

| 层 | 模块 | 依赖方向说明 |
|---|---|---|
| **1. 入口 / 接口** | `main.rs`, `cli.rs`, `mcp.rs` | `main.rs` → `cli.rs`(`Cli::parse`)+ lib 根。`cli.rs` 仅依赖 clap/std。`mcp.rs` 是**第二入口**(agent 可调用):由 `lib::run` 的 `Command::Mcp` 分发,起 stdio/本地 HTTP 的 JSON-RPC 服务器,工具薄层复用 `audit`/`scanner`/`storage`/`sarif`/`analysis` |
| **2. 编排(控制平面)** | `lib.rs` | 顶层枢纽,依赖几乎所有下层。承载 `run()` 分发、Config 构建、watch/monitor 循环、`run_audit` |
| **3. 发现源** | `discovery.rs`, `github.rs`, `website.rs`, `websearch.rs`, `defillama.rs`, `tokenlist.rs`, `coingecko.rs`, `chains.rs` | 由 `lib.rs`(discover 分发)调用。内部:website/websearch/defillama/tokenlist/coingecko → `github::valid_address`;`github` → `website::extract_addresses`(互依)。`chains`/`discovery` 近叶子 |
| **4. 网络客户端(读侧)** | `rpc.rs`, `etherscan.rs`, `sourcify.rs`, `enrich.rs` | 由 `scanner.rs` 与 `lib.rs` 消费。均强制 HTTP/1.1 + 30s 超时;sourcify/blockscout 严格 best-effort(错误塌缩为空) |
| **5. 流水线 / 存储** | `scanner.rs`, `storage.rs`, `model.rs` | `scanner` 是流水线核心,依赖 config/model/storage/各客户端/audit/analysis/report。`model.rs` 是**纯数据层,零 crate 依赖**,被几乎所有层共享 |
| **6. 分析 / 审计(纯)** | `analysis.rs`, `audit.rs`, `ast.rs`, `suppress.rs`, `sarif.rs`, `report.rs` | 全部**纯**(无网络/IO,唯一例外是 suppress 读配置文件)。指纹在 `sarif` 定义、被 `suppress` 复用(**单向** `suppress → sarif::fingerprint`,非闭环);`audit` 与 `ast` **互依**(`audit → ast::detect`/`AST_RULES`;`ast` 反向复用 `audit::is_privileged_name` 做特权名判定);`ast`(slang_solidity 解析器)在源码可解析时精化 tx-origin/unchecked-call/reentrancy/access-control/weak-randomness/ecrecover/transfer-send-参数计数/收窄-downcast + 新增 arbitrary-delegatecall,失败降级回 `audit` 启发式;`report` → model + enrich |
| **7. 输出 / 导出** | `export.rs`(+ `sarif.rs`/`report.rs` 兼属审计层) | `export.rs` → model + error,按扩展名出 JSON/CSV manifest;由 `lib.rs` 在配置 manifest 路径时调用 |
| **8. 监控 / 告警** | `events.rs`, `alert.rs`, `baseline.rs`, `throttle.rs`, `group.rs` | 由 `lib.rs` 的 monitor/watch 循环消费。`events`(纯解码,chain_id 留 0 待覆盖)、`alert`(side-effecting sink,best-effort)、`baseline`(指纹去重,纯 + 可选文件 I/O)、`throttle`(同类突发封顶)、`group`(折叠成 digest,纯内存)。`deliver_alert` 唯一出口:seen→(group 则折叠 / 否则 throttle)→record→emit;`flush_groups` 收尾发 digest |
| **9. 支撑(基础类型)** | `config.rs`, `error.rs` | `error` 是**真叶子**(零 crate 依赖,被几乎所有 fallible 路径返回)。`config` 是**装配型**:虽列于此,但**向上依赖** cli(`OutputFormat`)+ suppress(`Suppressions`)——是分层"自上而下"规则的**显式例外**(由 `lib.rs` 从 CLI 装配而成),非纯叶子 |

**纯/IO 隔离要点**:第 6 层完全确定性、可无网络单测;`model.rs` 纯数据无依赖;网络副作用集中在第 4 层(读)与 alert/baseline 的文件/webhook 写;sourcify/enrich/各 discover 源/alert/baseline 均 best-effort,错误不上抛——确保扫描/监控循环**永不被外部失败阻断**。

---

## 模块与子模块盘点

全部 **33 个 `src/*.rs` 模块**(Phase 15 `throttle.rs`、Phase 16 `mcp.rs`、Phase 17 `group.rs`、Phase 14-audit `ast.rs`、第三批发现源 `coingecko.rs`)。

| 模块 | 职责 | 关键函数/类型(含 crate 内私有) |
|---|---|---|
| **入口 / CLI** | | |
| `src/main.rs` | 二进制入口:加载 .env、解析 CLI、初始化 tracing、接 Ctrl-C shutdown、调 `lib::run()` | `async fn main()`(`#[tokio::main]`) |
| `src/cli.rs` | clap 命令行表面:全局参数、输出格式枚举、子命令集与各参数结构 | `Cli`, `GlobalArgs`, `Command{Range,Watch,Addresses,Discover,Monitor,Audit,Mcp}`, `OutputFormat{Human,Json,Ndjson,Sarif}`, `RangeArgs/WatchArgs/AddressesArgs/AuditArgs/MonitorArgs/DiscoverArgs/McpArgs`, `WatchArgs::alert_mode()` |
| **编排** | | |
| `src/lib.rs` | crate 根:声明所有模块;承载 `run()` 分发(含 `Mcp`)、`GlobalArgs→Config`、watch/monitor 循环、`run_audit`/`audit_corpus` | `run<S:Future>`, `config_from_cli`, `prepare_chain/prepare_chain_rpc/build_scanner`, `run_monitor`, `run_audit`, `audit_corpus`, `watch_with_shutdown/watch_alerts_with_shutdown/poll_tick/poll_alert_tick`, `scan_events_range/scan_risky_deployments_range`, `process_block/discover_addresses`, `AlertCounts`, `AlertCtx<'a>`, `merge/print_summary/init_tracing/emit_run_output` |
| **发现源** | | |
| `src/discovery.rs` | 从 CLI 参数和/或文件(每行一个,`#`/空行跳过)加载显式地址,解析并保序去重 | `load_addresses(&[String], Option<&Path>) -> Result<Vec<Address>>` |
| `src/github.rs` | 从 GitHub 部署产物(hardhat-deploy / Foundry broadcasts)与审计 scope markdown 发现地址;并定义共享地址校验器 | `Artifact{Hardhat,Foundry,Markdown}`, `classify_path`, `valid_address`, `parse_hardhat`, `parse_foundry`, `discover_repo` |
| `src/website.rs` | 项目网站/文档的有界爬虫:抓页、收割内联 + explorer 链接地址、浅爬同域可疑链接 | `WebsiteScraper`, `WebsiteScraper::new/discover`, `extract_addresses`, `extract_links`, `is_interesting` |
| `src/websearch.rs` | 可选 Google Programmable Search:搜项目名,从结果 `/address/0x…` 链接收割地址 | `Google`, `Google::new/with_base/search_addresses`, `parse_google_addresses`, `extract_address_from_url` |
| `src/defillama.rs` | DefiLlama 发现:经 `/protocol/{slug}` 的 `address` 字段取协议锚点合约 | `Defillama`, `Defillama::new/with_base/fetch_addresses`, `parse_protocol_addresses`, `encode_slug` |
| `src/tokenlist.rs` | Token List 发现:抓标准 Token List JSON(`tokens[]`),按当前 chain id 过滤取 `address` | `TokenList`, `TokenList::new/fetch(url, chain_id)`, `parse_token_list(v, chain_id)` |
| `src/coingecko.rs` | CoinGecko 发现:`/api/v3/coins/{id}` 的 `platforms` 映射,按当前 chain id 映射 platform key 取合约地址 | `CoinGecko`, `CoinGecko::new/with_base/fetch_addresses(id, chain_id)`, `coingecko_platform`, `parse_platforms`, `encode_id` |
| `src/chains.rs` | 静态链注册表:chain id → Blockscout v2 base + 短链名(硬编码 1/10/8453/42161/137) | `blockscout_base(u64) -> Option<&'static str>`, `chain_name(u64) -> String` |
| **网络客户端** | | |
| `src/rpc.rs` | alloy RootProvider/HTTP 的薄异步封装:链状态、创建发现、代理解析、分块并发事件日志扫描 | `RpcClient`(block_number/block_hash/pinned_at/pinned_block/contract_creations_in_block/trace_creations_in_block/get_code/get_balance/resolve_storage_proxy/resolve_diamond/diamond_facets/logs_addresses/fetch_logs), `ProxyInfo`, `LogHit{block,address,topics,data,tx_hash,log_index}`, `slot_word_to_address`, `parse_facet_addresses`, `parse_trace_creations` |
| `src/etherscan.rs` | Etherscan V2 客户端:取已验证源码 + 编译器/代理元数据 + 创建信息,带限流与限流重试 | `EtherscanClient`(get_source_code/get_contract_creation), `SourceCodeResult`, `CreationResult`, `is_rate_limited`, `means_absent`（仅枚举“确无记录”一侧，其余 status!=1 一律为失败） |
| `src/sourcify.rs` | Sourcify v2 源码回退(Etherscan 无已验证源时):`GET /v2/contract/{chainId}/{address}?fields=sources` | `Sourcify`(new/fetch_sources), `parse_sourcify_sources(&Value) -> Vec<SourceFile>` |
| `src/enrich.rs` | 经免费 Blockscout v2 的 best-effort 富化 + 发现:name tag、project URL、USD top 持仓(`--table`)、按 name/tag 搜合约 | `Blockscout`(fetch/search_contracts), `Enrichment{name_tag,project_url,holdings}`, `parse_search/parse_holdings/fmt_usd` |
| **流水线 / 存储** | | |
| `src/scanner.rs` | 编排逐地址流水线:抓数据、构 `ContractDetails`、富化(代理/审计)、过滤、落盘、渲染输出;暴露日志/Blockscout 发现助手 | `Scanner`(Clone), `BuiltContract`, `RunStats`, `Scanner::process_addresses/scan_and_audit/find_by_logs/blockscout_search`, `passes_filters`, `build_details`, `fold_outcomes`, `detect_minimal_proxy` |
| `src/model.rs` | 流水线中流动并持久化的 serde 数据结构(**纯数据层,零依赖**) | `ContractDetails`(+`minimal`), `SourceFile`, `Analysis`, `SecurityFinding`, `AuditSummary`, `Audit`, `Alert`, `SaveOutcome{Saved,Skipped,NotAContract,Filtered,Failed}` |
| `src/storage.rs` | 磁盘语料布局:算每合约目录、写所有产物、回读(单个 + 递归)、解析 Etherscan SourceCode 为独立文件 | `contract_dir`, `already_saved`, `load_metadata`, `load_all_metadata_with_dirs`, `load_sources/load_sources_from_dir`, `parse_sources`, `save_contract` |
| **分析 / 审计** | | |
| `src/analysis.rs` | 运行时字节码静态分析(无网络):PUSH 感知扫描出危险 opcode、函数选择器(ERC 接口检测)、keccak 指纹(全量 + 去元数据)、克隆聚类 | `analyze(&[u8]) -> Analysis`, `cluster_by_code(&[ContractDetails]) -> Vec<CloneCluster>`, `CloneCluster` |
| `src/audit.rs` | 标准化安全审计引擎(SecurityFinding v2):源码 + 字节码纯启发式检测器,映射 OWASP SC Top10 → SWC → rule_id,多因子风险模型(triage 辅助,非验证器);源码可解析时由 `ast` 精化 8 条规则 + 新增 `DELEGATECALL_ARBITRARY_TARGET` | `audit(d, sources) -> Audit`, `audit_with(d, sources, &Suppressions) -> Audit`(36 检测器) |
| `src/ast.rs` | AST 精化层(`slang_solidity`):`tx-origin`/`unchecked-call`(+ 绑定布尔**函数内数据流**)/`reentrancy`(调用后写**状态变量**)/`access-control`(特权 public 无守卫)/`weak-randomness`(区块源进取模/keccak)/`ecrecover`(恢复地址无零校验)/`arbitrary-delegatecall`(目标为形参)解析级检测,消除子串启发式误报;`catch_unwind` 容 panic + 深嵌套守护防栈溢出,失败降级回启发式 | `detect(content) -> Option<Vec<AstHit>>`, `AST_RULES`, `classify_occurrence`/`FnControls`, `detect_reentrancy`/`detect_access_control`/`detect_block_randomness`/`detect_ecrecover_zero_check`, `binding_name`/`enclosing_function`/`definition_name`, `too_deeply_nested` |
| `src/import.rs` | 外部分析器结果导入：SARIF 2.1.0 / Slither JSON → `SecurityFinding`；按地址段或唯一源文件后缀归属；**不执行进程** | `Import{tool,findings}`, `ForeignFinding{path,finding}`, `MergeStats{tool,total,attributed,ambiguous,unmatched}`, `parse`/`load`/`merge` |
| `src/bundle.rs` | 可验证结果包：in-toto Statement v1 + SLSA Provenance v1 清单、双摘要（sha256 + keccak256）、外部工具的分离签名 | `Pin`, `Digests`, `Signer`, `digests`, `collect_pins`, `build_statement`, `now_rfc3339`, `invocation_id`, `sign_blob`, `signing_command`, `write_bundle`, `BundleReport` |
| `src/sarif.rs` | 审计发现的 SARIF 2.1.0 导出(GitHub Code Scanning/CI/IDE),纯;并拥有规范发现指纹 | `build_sarif(&[ContractDetails]) -> Value`, `fingerprint(&SecurityFinding) -> String` |
| `src/suppress.rs` | 审计发现抑制配置(`--suppress`):JSON 匹配规则,评分前丢弃已分诊误报;朝可见方向 fail-safe | `Suppressions{suppress:Vec<SuppressEntry>}`, `SuppressEntry{rule,contract,swc,category,fingerprint,reason}`, `load_or_warn`, `is_suppressed` |
| `src/report.rs` | 单合约详情的人类可读、CJK 宽度感知对齐表格(中文标签),含 wei→ETH 与审计摘要单元格 | `render_contract_table(&ContractDetails, &Enrichment) -> String`, `format_eth(&str) -> String` |
| **导出 / Sink(扫描侧)** | | |
| `src/export.rs` | 已保存 `ContractDetails` 的摘要 manifest 导出为 pretty JSON 或 CSV(按扩展名);独立于实时告警路径 | `write_manifest(&Path, &[ContractDetails]) -> Result<()>`, `render_json/render_csv`(固定 25 列) |
| **监控 / 告警** | | |
| `src/events.rs` | 纯、无网络的安全事件 topic 注册表与解码器:把 `LogHit` 解码为结构化 `Alert`(代理升级/所有权/管理员/角色授予撤销/暂停恢复;大额转账经 `--min-transfer` 选入) | `default_alert_topics() -> Vec<B256>`(8 项), `transfer_topic() -> B256`, `parse_alert(&LogHit) -> Option<Alert>`, `unknown_alert(&LogHit) -> Alert` |
| `src/alert.rs` | monitor/watch 的告警投递 sink:append-only JSONL 文件和/或 best-effort JSON webhook POST(失败仅 warn!,循环不崩) | `AlertSink{path,webhook,http}`(Clone), `AlertSink::new`, `async AlertSink::emit(&Alert)` |
| `src/baseline.rs` | 经持久化指纹文件的跨轮告警去重:给每个 alert 算运行无关指纹(含 `log_index`),非变更 `seen()` 探测 + `record()` 提交分离 | `alert_fingerprint(&Alert) -> String`(keccak256 前 8 字节→16 hex), `AlertBaseline`, `seen(&Alert)/record(&mut,&Alert)/is_new`, `len/is_empty/enabled` |
| `src/throttle.rs` | 同类突发节流:`(chain, contract, kind)` 每运行最多 N 条(`--throttle`),超出丢弃(计 throttled) | `Throttle{cap,counts}`, `Throttle::new(Option<usize>)`, `allow(chain,contract,kind) -> bool`, `enabled` |
| `src/group.rs` | 告警分组/摘要(`--group`):折叠同 `(chain, contract, event)` 为一条 end-of-run digest(保留 kind + 最高 risk/grade) | `Grouper{enabled,groups}`, `Grouper::new(bool)`, `add(&Alert)`, `drain() -> Vec<Alert>`, `enabled/len/is_empty` |
| **MCP 接口** | | |
| `src/mcp.rs` | `blockscan mcp` stdio MCP 服务器:手写 JSON-RPC 2.0,把审计/SARIF/存储/扫描暴露为 agent 可调用 **工具 + 资源**;stdout 仅 MCP 消息、日志走 stderr;地址参数经 `Address` 校验防路径穿越 | `ServerCtx{out}`, `serve_stdio(out)`, `serve<R,W>(ctx,…)`, `pub async fn handle(&ServerCtx,&Value)->Option<Value>`(可进程内测),**9 工具**(audit_source/audit_corpus/get_contract/list_contracts/export_sarif/cluster_corpus/scan_addresses/**scan_block_range**/**monitor_range**)+ `resources/list`+`resources/read` |
| **支撑(基础类型)** | | |
| `src/config.rs` | 由 CLI + env 组装的运行时 Config,`validate()` 强制必填字段与数值下限 | `Config`(含 `blockscout_rate` / `sourcify_base` / `min_risk` / `only_vulnerable` / `suppressions` 等), `Config::validate() -> Result<()>` |
| `src/error.rs` | crate 级错误类型与 Result 别名,被每条 fallible 路径使用 | `AppError{Config,Rpc,Etherscan,Http(#[from]),Io(#[from]),Json(#[from]),Address}`, `type Result<T>` |

---

## 代码量统计

> 精确统计(`#[cfg(test)]` 前为生产代码,之后为内联单测;截至 T-17 + 文档锁步事实层)。CI 每次推送自动复核测试/clippy/覆盖率三道门禁。

| 类别 | 行数 | 备注 |
|---|---|---|
| **生产代码**(35 个 src 模块) | **12,594** | Top:`ast.rs` 2,036 · `audit.rs` 1,519 · `lib.rs` 1,476 · `mcp.rs` 1,070 · `export.rs` 715 · `rpc.rs` 634 · `scanner.rs` 503 · `cli.rs` 453 · `import.rs` 365 · `bundle.rs` 358 |
| **单元测试**(src 内联 `mod tests`) | **8,650** | 667 个用例,分布于各模块;Top:`ast.rs` 1,948 · `audit.rs` 951 · `mcp.rs` 612 · `lib.rs` 540 · `rpc.rs` 472 · `export.rs` 371 |
| **集成测试**(`tests/` 三个文件) | **4,445** | 131 个用例,分三个测试二进制 —— 见下表 |
| examples(链上小工具) | 96 | `analyze` 39 · `log_scan` 37 · `resolve_proxy` 20 |
| 文档(docs/*.md + README) | **4,500** | 8 份域设计文档 + 任务清单 + 维护记录 + 中/英用户手册 + 中/英新手指南 + 本文;见下索引 |

集成测试按二进制拆分(每个文件是一个独立的 test binary,失败互不掩盖):

| 文件 | 行数 | 用例 | 覆盖 |
|---|---|---|---|
| `tests/integration.rs` | 3,547 | 112 | wiremock mock RPC/Etherscan/Blockscout/Sourcify/GitHub/Google/website/DefiLlama/TokenList/CoinGecko + 真二进制断言,含 MCP stdio + 本地 HTTP 往返 |
| `tests/mcp_hardening.rs` | 383 | 11 | MCP 的安全边界:HTTP 模式凭据强制(未给则自签)、错误 token 拒绝、`out` 参数的父级穿越与越界拒绝、RPC URL allow-list 在开 socket 前拒绝、Origin/body 守卫存活、传输失败对调用方不可区分 |
| `tests/docs_lockstep.rs` | 515 | 8 | 三对镜像文档的**结构**(标题层级序列 + 围栏数)与**事实**(命令+flag 面、列表条目数、表格行×列、链接数);每层都有一个"制造漂移必须被抓到"的自检 |

- **生产 : 测试 ≈ 12,594 : 13,095**(单元 8,650 + 集成 4,445)≈ **1 : 1.04**。
- **测试 798 个**(667 单元 + 131 集成),`cargo clippy --all-targets` 零告警;**全工作区行覆盖 97.25%**(区域 96.83%、函数 98.52%)——由 CI 的 `coverage` job **每次推送实测**、门禁设在 97%,非手工维护。此处只记百分比:精确行数每次提交都会微动,以最近一次 job 日志为准;下列逐模块数字同理,它们每次提交都在动,写在这里只为给出量级。
  - 10 个模块行覆盖 100%(`model`/`events`/`group`/`suppress`/`baseline`/`report`/`sarif`/`config`/`chains`/`throttle`);`audit.rs` 99.84%、`ast.rs` 96.76%、`mcp.rs` 96.64%。
  - 最大缺口是 **`lib.rs` 90.17%**(383 个未覆盖行里占 141,约四成)——watch/monitor 循环与多链 fan-out 的错误路径需真实链才能触达;其余为防御性 `?`/不可达的游标 API 守卫。

---

## 功能状态矩阵

### ✅ 已完成功能模块

| 模块 | 内容 | 设计文档 / 状态 |
|---|---|---|
| 扫描三模式 | `addresses` / `range` / `watch`(下载模式,Ctrl-C 优雅退出)· `--trace` 工厂(CREATE/CREATE2)发现 · `--chains` 多链 | 初版方案 ✅ |
| 项目发现 `discover` | Blockscout 搜索 · GitHub 部署产物 · 官网/文档浅爬 · Google 搜索 · DefiLlama · Token List · 事件 topic 扫描 | DISCOVERY_DESIGN ✅ |
| 详情下载 | RPC(code/balance/创建/存储槽代理 EIP-1167/1967/1822)+ Etherscan V2(源码/ABI/元数据/创建)+ Sourcify 回退 → per-contract 目录 + resume/去重 | 初版方案 ✅ |
| 静态分析 `analysis` | 危险 opcode · ERC-20/721/1155/165 接口识别 · 双 keccak 指纹(全量 + 去元数据)· 克隆聚类 `clusters.json` | ANALYSIS_DESIGN(批量1)✅ |
| 机器/人类输出 | `--format human/json/ndjson/sarif` · `--manifest` json/csv · `--table` 中文宽度感知表格 + Blockscout 富化 | OUTPUT_DESIGN(批量2)✅ |
| 安全审计引擎 | 标准化 SecurityFinding v2(OWASP→SWC→rule_id)· **36 检测器**〔计数口径:不同 `RuleSpec` 去重——字节码别名 `*_SELFDESTRUCT`/`*_DELEGATECALL` 与源码同义规则合并计 1;底层 41 个 rule_id / 39 个非 fallback `spec()` 臂〕· 多因子评分(impact×likelihood×confidence×exposure)→ 0–100 / A–F / P0–P3 · 报告矩阵 · `audit` 离线子命令 | AUDIT_DESIGN Phase 8/9/11 ✅ |
| 审计 AST 精化 | `slang_solidity` 解析器:`tx-origin`(仅鉴权上下文)/`unchecked-call`(结果未消费)在源码可解析时走 AST 精除误报,detection=`ast`;panic + 深嵌套(栈溢出)守护,失败降级回启发式;评分/指纹不变 | AUDIT_DESIGN Phase 14 ✅ |
| 审计 函数内数据流 | `unchecked-call` 绑定形态:per-occurrence 控制流(`classify_occurrence` 入边标签区分条件/体)+ 每函数缓存判"绑定布尔调用后是否被 gate 检查",消除 `(bool ok,)=call();require(ok);` 主导误报、不漏未检查;名字复用/shadow 经 Rebind 排序处理 | AUDIT_DESIGN Phase 15 ✅ |
| 审计 AST reentrancy | `REENTRANCY_*`(CEI 违反):低层外部调用(`.call`/`.delegatecall`/`.transfer`/`.send`)后写**状态变量**(赋值/`++`/`delete`/元组/`push`-`pop`,基标识符 ∈ 文件级状态变量集,`Name` 边取名)、无 `nonReentrant` 守卫、语句序精确;排除写局部、CEI 安全 | AUDIT_DESIGN Phase 16 ✅ |
| 审计 AST access-control | `ACCESS_MISSING_GUARD_PRIVILEGED_FN`:特权名(`is_privileged_name`)+ public/external + 有 `Block` 实现 + 非 view/pure + 无守卫(结构化 only*/auth/restrict 修饰符、或 require/if/比较里的 `msg.sender`、或 `_checkOwner`/`_checkRole` 调用);跳过接口/抽象声明;`function` 行发,指纹稳定 | AUDIT_DESIGN Phase 17 ✅ |
| 审计 AST weak-randomness | `WEAK_BLOCK_RANDOMNESS`:区块源(`block.timestamp`/`number`/`difficulty`/`prevrandao`、`blockhash(..)`)仅在**随机数上下文**(`% 取模` 的 `MultiplicativeExpression`、或 `keccak256`/`sha256`/`ripemd160` 种子)才报,按行去重;消除 deadline/记账等合法用途的海量误报 | AUDIT_DESIGN Phase 18 ✅ |
| 审计 AST ecrecover | `ECRECOVER_NO_ZERO_CHECK`:`ecrecover(..)` 恢复地址未与 `address(0)`/`0` 比较(内联或经绑定变量,扫 `EqualityExpression` 零标记)才报;消除写得好的签名验证(`require(s!=address(0))`,EIP-2612 permit/meta-tx)误报 | AUDIT_DESIGN Phase 19 ✅ |
| 审计 AST 任意 delegatecall | **新增** `DELEGATECALL_ARBITRARY_TARGET`(Critical,SWC-112,检测器 35→36):delegatecall 到**形参可控地址**(Parity 级接管)才报;复用 `enclosing_function` + `function_param_names`;AST-only,与泛化 `DELEGATECALL_USAGE` 同 swc 去重 | AUDIT_DESIGN Phase 20 ✅ |
| 审计 AST transfer/send + 收窄 cast | `HARDCODED_GAS_TRANSFER_SEND`:按**实参个数**判别——1 参 `addr.transfer/send(x)` = ETH stipend send(报)、≥2 参 = ERC-20 转账(不报),消除 `dai.transfer(to,amt)` 误报;`UNSAFE_DOWNCAST_TRUNCATION`:收窄 `uintN/intN(N<256)` 仅当实参非字面量、非同族等宽/更窄嵌套转换才报。`AST_RULES` 6→8;新 `to_child(Variant)` 按边导航跳过 slang **trivia** | AUDIT_DESIGN Phase 21 ✅ |
| 审计 绑定图(scope-aware 名字/类型解析) | `detect_unit` 合约级一次建 slang `BindingGraph`(公开 `CompilationBuilder`+`MemFiles`,相对路径归一化 + 路径段边界匹配),把标识符解析到定义+**声明类型**;消除类型相关 FP(`uint160(addrVar)`/`uint8(enumVar)`/`endpoint.send(payload)` 接收者类型)。三级 graceful degradation(`detect_unit`→`detect`→启发式);深度守卫扩到扁平链 | AUDIT_DESIGN Phase 22 ✅ |
| 审计 绑定图 alias 回溯 | `DELEGATECALL_ARBITRARY_TARGET` 的接收者经绑定图解析到定义:`Parameter` 报、`VariableDeclarationStatement` 沿**裸别名**回溯(上限 4 跳)、状态变量/未初始化不报。补上「一次局部赋值即漏报」的接管漏报,并消除 `function_param_names` 过度收集(函数类型形参的内部参数名)导致的误报;无绑定图时逐行退回 Phase 20 行为 | AUDIT_DESIGN Phase 23 ✅ |
| 审计 绑定图 reentrancy 跨文件 | `REENTRANCY_*` 的「是否状态写入」由**当前文件名字集合**升级为**绑定图定义解析**:继承自其他文件的状态变量可见(教科书 `withdraw()` 此前完全漏报)、局部遮蔽同名状态的误报消除、有图时解除 `state.is_empty()` 提前返回;左值按**边标签**导航(`LeftOperand`/`Operand`)而非取首标识符;`.push/.pop` 的合约类型接收者不计作状态写入 | AUDIT_DESIGN Phase 24 ✅ |
| 审计 绑定图 access-control | `ACCESS_MISSING_GUARD_PRIVILEGED_FN` 的特权判定由「26 名字精确匹配」扩为**名字 ∪ 写入守卫变量**:守卫变量 = 单元内与 `msg.sender` 比较的**裸**状态变量(跨文件收集),写它却无守卫即无鉴权改变权限,与函数名无关;结构体/映射字段守卫不入集合(否则 diamond 布局下每个 public 函数都会被报) | AUDIT_DESIGN Phase 25 ✅ |
| 审计 调用者间接层 | `is_caller_expression` 同时识别 `msg.sender` 与 OpenZeppelin `Context._msgSender()`(ERC-2771 元交易间接层,语料 10/42 单元、97 次):守卫识别不再把 `require(_msgSender() == owner)` 判为无守卫(**对正确代码的误报**),守卫变量收集同样受益。语料 ACCESS 发现 31 → 30 | AUDIT_DESIGN Phase 26 ✅ |
| 审计 重入的任意外部调用面 | `REENTRANCY_*` 的外部调用面从 4 个文本后缀(`.call`/`.delegatecall`/`.transfer`/`.send`)扩为**合约类型接收者上的非 view 方法调用**(`vault.deposit(n)`):两道闸门均为实测所必需——view 过滤器(否则 Uniswap V3 的 `pool.positions(key)` 被当成重入点)、`resolve_decl_type` 只分类**值声明**(否则 `Lib.fn()` / `Error.selector` 按定义体内首个类型名被误判为合约实例)。语料 reentrancy 2 → 3 | AUDIT_DESIGN Phase 27 ✅ |
| 审计 转换接收者 | 重入面纳入 `IThing(addr).m()`——语料 271 次 / 23 个单元的标准写法,此前 `receiver_identifier` 只认裸标识符而完全看不见。转换与普通调用**语法树完全相同**(`IERC20(a)` vs `pick(a)`),故经绑定图判定被调者是否为 `ContractDefinition`/`InterfaceDefinition`;并要求成员访问处于**调用位**,否则 `.selector`/`.address`/`encodeCall` 这类不产生调用的成员读取会抢走锚点 | AUDIT_DESIGN Phase 28 ✅ |
| 审计 初始化器精度 | `PROXY_UNPROTECTED_INITIALIZER` 语料 **17 → 1**:接口声明(16 条中的绝大多数——`initializer_guarded` 从不在 `;` 处停止,扫过声明撞上下一个函数的 `{` 即判无守卫)、`internal pure` 库函数、以及 `require(msg.sender == factory)` 这类非 OZ 修饰符守卫,三类误报全部消除。判据对齐 Phase 17:可外部调用 + 能写状态 + 无守卫 | AUDIT_DESIGN Phase 29 ✅ |
| 审计 常量操作数精度 | 编译期常量不再触发运行时规则:`WEAK_BLOCK_RANDOMNESS` **13 → 0**(`uint32(block.timestamp % 2**32)` 是 UniswapV2 TWAP 的位掩码,非取随机)、`UNSAFE_DOWNCAST_TRUNCATION` **138 → 107**(`uint112(-1)` 是 0.8 前的 `type().max`;既有字面量豁免只认裸数字节点)。取模边界判据经审查改为**结构化**——必须是实参自身的顶层 `%`,否则 `uint32(a + b % 2**32)` 这类会静默漏报 | AUDIT_DESIGN Phase 30 ✅ |
| 审计 窗口启发式作用域 | `CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK` 与 `PROXY_UNPROTECTED_INITIALIZER` 从固定行数看前改为 `scan_functions` 的**函数体**作用域。新鲜度判据从“附近有 require”改为“该调用解构出的**非价格槽**名字是否参与比较”，于是 `(, int p, , ,) = feed.latestRoundData()` 因**未绑定任何新鲜度变量**而必然未校验；`initializer_has_body` 整个删除（作用域自身就排掉无体声明）。语料 172 发现 / 773 出现**逐行不变**，Phase 29 的 17 → 1 保持 | AUDIT_DESIGN T-06 ✅ |
| 代理家族补齐 | 新增**标准前 zeppelinos 槽**（`keccak256("org.zeppelinos.proxy.implementation")`，无 EIP-1967 的“减一”推导）与 **EIP-2535 钻石**（无实现槽，只能问：`facetAddresses()` loupe 调用）。钻石探测每合约多一次 `eth_call`，故以**字节码是否含 DELEGATECALL** 为闸（复用已有的操作码扫描，零成本）；返回值严格解码（头偏移、长度与载荷一致、每词高 12 字节为零），因为被问的合约本就不知是否钻石、带 fallback 的合约会回答**某个东西** | TASKS T-07 ✅ |
| 报告文档输出 | `--manifest` 按扩展名分发新增 `.md` / `.html`：总览 + 严重度（**出现次数**）+ 每合约发现（位置/证据/修复）。HTML 为单一自包含文件（样式内联、零脚本、零外部请求，由“文档内标签集必须是白名单子集”而非字串探针断言）。所有链上/浏览器来源的文本均视为敌对：HTML 全量转义，Markdown 用**自适应宽度的代码跨度**一次性中和全部构造。`.pdf` 显式拒绝并指向外部管道——不向二进制里加 PDF 写器 | TASKS T-14 ✅ |
| 外部分析器结果导入 | `audit --import <file>`（可重复）读 SARIF 2.1.0 或 Slither JSON，**按形状识别**，归一化进现有 `SecurityFinding` 不扩字段（新增的只有 `source`）。**只读文件，从不执行任何进程**（由一个扫描本模块源码的测试看守）。归属先看路径里的地址段，再看整路径分量后缀唯一匹配；**多个合约都拥有的路径不猜**（记 ambiguous 并告警）。`overall_risk` / `summarize` / `build_sarif` 均只取 `source == blockscan`，因此导入无法移动评分、不会被 blockscan 的 SARIF 冒领；报告文档里两者**分列统计** | TASKS T-12 ✅ |
| 双语文档锁步（结构 + 事实） | `tests/docs_lockstep.rs` 对三对镜像文档（README / USER_MANUAL / GETTING_STARTED）比对两层。**结构层**：标题层级序列 + 代码围栏数，文字自由；围栏内容不参与解析，故 shell 示例里的 `# comment` 不会被当成标题。**事实层**（结构层通过后仍漏掉的那类漂移）：围栏内 `blockscan`/`cargo` 调用归约成的**命令 + 长 flag 面**、列表条目数、表格**行×列**、链接数。刻意不比：段落数（中文断句不同）、链接**目标**（锚点是翻译，各版本指向自己的镜像）、围栏内数字（示例输出本就该不同）。放在 `tests/` 而非 CI 脚本：在引入漂移的那台机器上就红，而 CI 无 `paths:` 过滤，纯文档变更同样跑 | TASKS T-15 ✅ |
| 编译器下限 + 评分自描述 | `rust-version = "1.97.1"`（由 `slang_solidity` 1.3.8 及 metaslang 系列决定，非选择），CI 新增 `msrv` job **从 Cargo.toml 读取**该版本构建（不硬编码，否则第二份真相会静默漂移）。另：`AuditSummary.suppressed` 记录被抑制规则剔除的发现数——剔除发生在**评分之前**，所以分数是抑制文件的函数，不报出剔了多少就是不可审计的数。JSON（serde）、SARIF（`runs[0].properties.suppressedFindings`）、`--table` 单元格、`audit` 人类行、以及 T-14 报告文档均会显示；为零时不显示 | TASKS T-16 ✅ |
| 错误中的响应体有界 | `etherscan.rs` 三处解析错误曾直接插入整个响应体。保留诊断价值（意外信封只能靠它看出来），但长度与字节都是**对方选的**：`clip_body` 限制到 512 字节并**显式标出截断与原始字节数**，控制字符转义（否则 body 里的换行会向日志写出一行伪造记录）。预算管的是**输出**而非输入：一个控制字节转义后最长 7 字符，管输入等于对恰好是恶意构造的 body 失去界 | TASKS T-17 ✅ |
| 可验证结果包 | `blockscan bundle --into <dir> <产物>...`：把**已产出**的产物、一份清单、一份分离签名放进一个目录。三件事刻意不自己发明：**格式**用 in-toto Statement v1 + SLSA Provenance v1；**签名**外包给 `cosign sign-blob`（本 crate 不碰密钥，自制信任链比没有更糟，因为它看起来像）；**快照**必须来自 T-04 的区块固定——任一记录无 pin 则拒绝打包且**不创建目录**。摘要同时给 `sha256`（生态工具能核，实测与 `sha256sum` 逐字匹配）与 `keccak256`（本项目 idiom），时间戳为**运行时** RFC 3339（无编译期常量） | TASKS T-13 ✅ |
| SARIF 输出 | SARIF 2.1.0 + `partialFingerprints`(GitHub Code Scanning 基线/去重) | AUDIT_DESIGN Phase 10 ✅ |
| 审计抑制 | `--suppress` JSON 配置(rule/contract/swc/category/fingerprint 匹配,评分前剔除,fail-safe) | AUDIT_DESIGN Phase 12 ✅ |
| 防御监控 `monitor` | 区间 `eth_getLogs` 解码安全事件(代理升级/所有权/管理员,`--alert-topic` 扩展)→ `Alert` 落 alerts.jsonl/webhook/stdout · `--watchlist` 限定 | MONITOR_DESIGN 批量3 ✅ |
| 新部署风险评分 | `monitor --audit-deployments`:审计区间新部署、`risk≥--min-risk` 发 `risky-deployment` 告警 | MONITOR_DESIGN Phase 12 ✅ |
| 跨轮告警去重 | `--baseline` 稳定指纹(含 `log_index`)+ 持久基线,抑制重复 | MONITOR_DESIGN Phase 13 ✅ |
| 跟链头实时告警 | `watch --alert-on-risk` / `--alert-events`:每确认块跑告警管线,部分失败不推进(背压) | MONITOR_DESIGN Phase 14 ✅ |
| 事件扩展 + 告警节流 | 默认集扩到 8(+RoleGranted/RoleRevoked/Paused/Unpaused);`--min-transfer` 大额转账(opt-in,排除 ERC-721);`--throttle` 同类突发封顶 | MONITOR_DESIGN Phase 15 ✅ |
| **MCP server** | `blockscan mcp` JSON-RPC 2.0(手写);Phase 16 起 7 工具(audit_source/audit_corpus/get_contract/list_contracts/export_sarif/cluster_corpus/scan_addresses),Phase 18 扩到 **9 工具**(+scan_block_range/monitor_range)把审计/SARIF/扫描暴露给 agent | MCP_DESIGN Phase 16/18 ✅ |
| 告警分组/摘要 | `--group` 折叠同 `(链, 合约, event)` 高频告警为一条 end-of-run digest(vs `--throttle` 硬丢弃) | MONITOR_DESIGN Phase 17 ✅ |
| MCP 资源 + 有界区间工具 | `resources/list`+`read`(语料)、`scan_block_range`/`monitor_range`(≤500 块,有界);地址参数防路径穿越 | MCP_DESIGN Phase 18 ✅ |
| watch 周期 digest + 多链并行 | `--digest-interval` 周期摘要;alert 模式 `--chains` 并行 watch(无锁,chain 维度键 + 行原子)| MONITOR_DESIGN Phase 19 ✅ |
| 审计 SCWE/EthTrust 映射 | `SecurityFinding` 补 `scwe`/`ethtrust`(高置信度精确匹配,29/40 规则);SARIF tag/property;纯元数据 | AUDIT_DESIGN Phase 13 ✅ |
| MCP 本地 HTTP 传输 | `mcp --http <addr>` Streamable HTTP(单 `/mcp`,POST JSON-RPC;`hyper` 1.x);复用纯 `handle`/9 工具;仅绑回环 + `Origin` 精确校验 + body 有界读 + 可选 Bearer | MCP_DESIGN Phase 20 ✅ |

### 🔜 下一步

| 模块 | 内容 | 依据 |
|---|---|---|
| **绑定图后续(Phase 31+)** | `resolve_decl_type` 的其余接收者形态(`arr[i].m()` 语料 90 次 / `a.b.m()` 107 次 / `payable(x).m()`;`IThing(addr).m()` 已由 Phase 28 完成);守卫按**完整访问路径**记录;`ACCESS_MISSING_GUARD_PRIVILEGED_FN` 剩余 17 条(需「是否只写调用者自身状态」判据);SafeCast「先转换后 require 校验」惯用法;同文件三元左值的既有不精确;修饰符调用解析(语料实测 0 次,优先级低) | AUDIT_DESIGN Phase 30「后续」 |
| **语料与检测质量门禁** | 依赖链 **T-08 →(T-09、T-10)**,根在 T-08(`corpus/manifest.json`:把 42 单元语料发布成可复现清单)而非 known_good。T-09 在 CI 里算逐规则精确率/召回率并对期望文件断言;T-10 是误报预算,`corpus/known_good.json` 目前 **8 槽填 1**(WETH9,`pinned_block` 仍为 `PIN_ME` 占位)、**未接入 CI 或任何测试**,断言只是文件里的声明。填槽流程见 [../corpus/KNOWN_GOOD_HOWTO.md](../corpus/KNOWN_GOOD_HOWTO.md) | [TASKS.md](TASKS.md) T-08/09/10 🚧 硬阻断 |
| **协议级分析** | `src/protocol.rs` 与五条 `PROTO_*` 规则(共享实现 / 共享部署者 / 悬空依赖 / 未验证依赖 / 价值集中)。**技术上今天就能做**——失败测试规格随外部审计包提供,26 个用例,`depends_on: []`。拦住它的是排序判断:五条新检测规则背后若无误报闸门,正是「规则把蓝筹合约判成 critical 而无人察觉」的成因。**决定权属项目所有者,不属实现者**;三条 known_good 种子(约一小时)即可开闸 | [TASKS.md](TASKS.md) T-11 ⏸ 政策阻断 |
| 更多发现源 | CoinGecko/CMC · ethereum-lists · Sourcify 全量 · 4byte 聚类 · 工厂展开 · Dune | 见 📋 TODO |
| WS `subscribe` 替代轮询;watch 下载模式多链 | 监控后续 | MONITOR_DESIGN「后续」 |

### 📋 TODO / 未来(超出当前批次)

| 方向 | 内容 |
|---|---|
| 监控 | WS `subscribe` 替代轮询;**下载模式**多链并行(alert 模式已并行,见 Phase 19) |
| 审计深度 | **跨函数 / 跨合约 scope-aware 数据流**(Phase 22 起以绑定图打底:消除跨合约同名、跨文件继承状态残留);更多 AST 检测器(oracle 上下文 / 算术边界);更多深度规则族 |
| 发现源 | CoinGecko/CMC `platforms` · ethereum-lists/contracts 归属反查 · Sourcify 全量枚举 · 字节码指纹/4byte 选择器聚类发现 · 工厂展开(factory→children)· Dune |

> 说明:审计 AST 化已推进至 Phase 22(精化 8 条规则 + 1 条 AST-only + 绑定图 scope-aware 名字/类型解析,均见上「✅」表);**绑定图扩面(reentrancy / access-control / delegatecall alias)属 Phase 23+**,见上「🔜」表。此处仅列尚未实现项。

---

## 设计文档索引

| 文档 | 覆盖 | 状态 |
|---|---|---|
| [GETTING_STARTED.md](GETTING_STARTED.md) · [.en](GETTING_STARTED.en.md) | 新手指南(中/英):~10 分钟安装 → 配置 → 第一次扫描 → 常见任务 | ✅ |
| [USER_MANUAL.md](USER_MANUAL.md) · [.en](USER_MANUAL.en.md) | 用户手册(中/英):安装/配置/逐子命令/审计/监控/MCP/输出/FAQ | ✅ |
| [ANALYSIS_DESIGN.md](ANALYSIS_DESIGN.md) | 字节码静态分析 + 克隆聚类(批量1) | ✅ |
| [OUTPUT_DESIGN.md](OUTPUT_DESIGN.md) | `--format` 机器输出 + manifest(批量2) | ✅ |
| [DISCOVERY_DESIGN.md](DISCOVERY_DESIGN.md) | `discover` 多源发现 + 源选型 | ✅(部分源标 📋 待办) |
| [AUDIT_DESIGN.md](AUDIT_DESIGN.md) | 安全审计引擎 Phase 8–30 + T-06 ✅(标准化/深度规则/SARIF/抑制/SCWE-EthTrust/AST 精化/数据流/reentrancy/access-control/weak-randomness/ecrecover/arbitrary-delegatecall/transfer-send/收窄-cast/**绑定图 scope-aware 类型解析**/**delegatecall alias 回溯**) | ✅ |
| [MONITOR_DESIGN.md](MONITOR_DESIGN.md) | 防御监控 批量3 + Phase 12–19(部署风险/去重/watch 实时/事件扩展+节流/分组 digest/周期 + 多链并行) | ✅ |
| [MCP_DESIGN.md](MCP_DESIGN.md) | MCP 服务器 Phase 16/18/20(协议/工具集/resources/选型/stdio + 本地 HTTP 传输);安全边界的看守见 `tests/mcp_hardening.rs` | ✅ |
| [TASKS.md](TASKS.md) | 外部审计任务清单 T-01…T-17(安全边界/可复现与可验证/检测精度/输出与工程约束) —— 状态矩阵里 `TASKS T-xx` 各行的出处 | ✅ 13/17 |
| [MAINTENANCE_LOG.md](MAINTENANCE_LOG.md) | 维护批次记录:文档审查、缺陷清理、发布流程改造 —— 不新增功能、但改变「会不会再次出错」的那类工作 | ✅ 按次追加 |
| [../corpus/KNOWN_GOOD_HOWTO.md](../corpus/KNOWN_GOOD_HOWTO.md) | 误报预算语料 `corpus/known_good.json` 的填槽实操指南(T-09/T-10 的前置) | 🚧 8 槽填 1,门禁未接线 |

> 流程约定(来自项目记忆):每加新功能 → 先更新对应域设计文档(此时阶段标题标 🔜/🚧 = 本期计划)→ 开发 → 功能 + 性能测试 100% 覆盖(不足须说明)→ 对抗式审查 → **把域设计文档的阶段标题标记翻成 ✅ 并更新其文首「状态:」行** → 回填本文「模块盘点」与「功能状态矩阵」。
>
> 最后两步缺一不可:域文档的 🔜 若不回填,单看该文档会严重低估完成度(2026-08 的一次全局评估发现 11 处此类滞后标记)。
