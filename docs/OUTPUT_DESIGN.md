# BlockScan — 输出模式设计（Output formats）

让 `blockscan` 可被脚本 / `jq` / agent 管道消费。原则:**stdout 只放结构化数据,所有人类可读文本(日志、进度条、汇总、表格)一律走 stderr**。这是后续 MCP server 的前置。

状态:✅ 批量 2 完成(`--format human/json/ndjson/sarif` + `--manifest`)。总览见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## `--format human|json|ndjson`（默认 human)

新增全局参数 `--format`(clap `ValueEnum`),写入 `Config.format`。

| 模式 | stdout | stderr |
|---|---|---|
| `human`(默认) | 现状:`--table` 表格、`print_summary` 汇总 | 日志、进度条 |
| `json` | 运行结束输出**一个** `{ run, stats, contracts }` JSON 文档 | 日志、进度条、汇总(转 stderr) |
| `ndjson` | **流式**:每保存/跳过一个合约,输出一行紧凑 JSON(`ContractDetails`) | 日志、汇总 |

### 行为细则
- **日志走 stderr**:`init_tracing` 加 `.with_writer(std::io::stderr)`(此前 `tracing_subscriber::fmt()` 默认写 stdout,会污染 JSON)。这是普遍正确的改动,human 模式也受益。
- **进度条**:`indicatif` 默认就画在 stderr;非 human 模式额外不创建进度条(免噪声)。
- **表格**:`--table` 的 `println!` 仅在 `human` 下执行(`--table --format json` 时表格被抑制)。
- **汇总**:`print_summary` 改为按 format 路由 —— human → stdout;json/ndjson → stderr(信息性,不污染数据)。
- **json 文档**:`{ "run": {mode, chains, out}, "stats": RunStats, "contracts": [ContractDetails...] }`;`contracts` 为**本轮运行实际处理**的合约(`process_addresses` 返回的 `Saved` + `Skipped(Some)` 详情累计),与 `stats` 同尺度 —— **不是**全盘 `load_all_metadata`,避免与 `stats` 口径不一致、以及共享 `--out` 时的跨轮/跨链串档。`RunStats` 加 `Serialize`。
- **ndjson 流式**:在 `scanner::process_addresses` 内,format==ndjson 时对每个 `Saved` / `Skipped(Some)` 打印一行 `serde_json::to_string(details)`。range/watch 逐块调用 → 天然流式。**续跑跳过(`Skipped`)的合约也要补出**:`process_one` 在 `--table` 或任意机器格式下都加载已存 metadata,故 `Skipped(Some)` 在 ndjson/json 下不丢。
- **断管安全**:所有 stdout 写入用 `writeln!` 并忽略错误(如 `| head` 触发的 `BrokenPipe`),不再用会 panic 的 `println!`。
- `--table` 与 `--format json|ndjson` 同时给出时,表格被忽略并 `warn!` 提示(不静默)。
- **ndjson 是流**:`--overwrite` 重扫或重叠区间下,同一地址可能跨块/跨轮多次出现一行;消费方如需唯一化按 `address` 去重。
- `watch` + json:文档在收到 shutdown 后输出一次(`watch_with_shutdown` 返回 `(RunStats, Vec<ContractDetails>)` 供 run() 汇总)。

### 不变量 / 边界
- 没有任何合约时:json 输出 `contracts: []`、stats 全 0(仍是合法 JSON);ndjson 无输出行(干净)。
- json 文档用 `to_string_pretty`;ndjson 每行用紧凑 `to_string`,保证逐行可解析。
- 与 `--manifest` 正交:可同时用(manifest 落文件,stdout 出 JSON)。

### 测试与性能(目标 100% 覆盖)
- **功能**(集成,wiremock,不走真网):
  - `--format json`:stdout 解析为对象,含 `run/stats/contracts`,`contracts[0].analysis.code_hash` 非空;**stdout 不含日志行**(首字符为 `{`)。
  - `--format ndjson`:stdout 每行均可 `serde_json` 解析为含 `address` 的对象;行数 == 保存数。
  - human 模式回归:汇总仍在 stdout。
- **单元**:`OutputFormat` 默认 human、`print_summary` 路由(human vs json 的目标流)、空集 json 文档。
- **性能**:输出为 O(n) 序列化,无新增网络;json 仅在结束时一次性序列化,ndjson 边扫边写、内存恒定(不缓存全量)。

### 对抗式审查(开发后)
12-agent 对抗式审查(3 lens × find → 9 verify)确认并修复:
1. **(high)** ndjson 在续跑时丢弃 `Skipped(None)` —— 旧实现仅在 `--table` 下加载已存详情。**修**:机器格式也加载,`Skipped(Some)` 补出。
2. **(high)** stdout 用 `println!` 在 `| head` 下 `BrokenPipe` panic。**修**:`writeln!` 忽略写错误。
3. **(medium)** json `contracts` 取全盘 `load_all_metadata`,与 run 级 `stats` 口径不一致、共享 `--out` 串档。**修**:改为本轮运行实际处理的合约(run-scoped)。
4. **(low)** `--table` 在机器格式下被静默忽略。**修**:`warn!` 提示。

**验证**:`run_addresses_{ndjson,json}_in_process` + `binary_format_{json,ndjson}_*`(真实子进程断言 stdout 纯净)+ `binary_ndjson_still_emits_skipped_contract_on_rerun`(续跑补出)+ `binary_json_contracts_are_run_scoped_not_whole_disk`(预置外来合约不进 run 文档)。

> 状态:✅ 批量 2 完成(全量 **237 测试** 通过、clippy 零告警、库行覆盖 ~98%)。

## 后续

- **批量 3:防御闭环**(代理升级/管理员变更监控 + 告警出口)将复用 ndjson/alerts 的 stderr/stdout 约定。
- MCP server(战略项)将复用 json 模式的 run-scoped `{run,stats,contracts}` 结构。
