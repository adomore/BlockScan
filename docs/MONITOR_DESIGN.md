# BlockScan — 防御监控与告警设计（Monitor + Alerts）

把已有的 `eth_getLogs` 扫描 + 槽/topic 解码 + 输出约定缝成一个**防御性威胁情报闭环**:扫描安全相关事件 → 解码 → 产出结构化 `Alert` → 落 `alerts.jsonl` / 推 webhook / stdout 流。

状态:✅ 批量 3 + Phase 12(部署风险监控)+ 13(去重/基线)+ 14(watch 实时告警)+ 15(事件扩展+节流)+ 17(分组/摘要)+ 19(周期 digest + 多链并行)

## `monitor` 子命令（区间扫描安全事件）

```
blockscan monitor --from <N> --to <M> [--watchlist file] [--alert-topic 0x..]…
                  [--alerts alerts.jsonl] [--webhook-url URL]
                  [--log-chunk 2000] [--log-concurrency 4]
```

对 `[from,to]` 区间用 `eth_getLogs` 拉取**安全相关事件**的完整日志,解码出关键字段,产出 `Alert`,写入各 sink。多链(`--chains`)按链循环。

### 监控的事件(默认 topic 集)
| 事件 | topic0 | 解码 | kind |
|---|---|---|---|
| `Upgraded(address)` | `0xbc7cd75a…2d3b` | topics[1] = 新实现 | proxy-upgrade |
| `BeaconUpgraded(address)` | `0x1cf3b03a…3d50` | topics[1] = 新 beacon | proxy-upgrade |
| `OwnershipTransferred(address,address)` | `0x8be0079c…57e0` | topics[1]=旧 owner,topics[2]=新 owner | ownership |
| `AdminChanged(address,address)` | `0x7e644d79…798f` | data 字 0=旧 admin,字 1=新 admin | admin |

`--alert-topic 0x..`(可重复)在默认集之外追加自定义 topic0(无专用解码器的仅记录 contract+event=`unknown`)。索引地址取 32 字节 topic 的低 20 字节;非索引取 data 的 32 字节字低 20 字节。

### Alert 结构(`model::Alert`,serde)
```
{ block, contract(发出事件的合约), event, kind, new_value, previous, tx_hash }
```

### 输出与 sink
- **stdout**:每个 alert 一行紧凑 JSON(断管安全 `writeln!`,与 ndjson 约定一致)—— monitor 的主数据流,可直接 `| jq`。
- **`--alerts <path>`**:**追加**(append)一行 JSON 到文件(`alerts.jsonl`);写错误仅 `warn!`,绝不让监控崩。
- **`--webhook-url <url>`**:best-effort `POST`(http1、超时、`content-type: application/json`);失败仅 `warn!`,不阻断。
- **`--watchlist <file>`**(每行一地址,`#` 注释):只保留 `contract` 命中清单的 alert(限定监控范围、压缩噪声/成本)。未给则全量。
- **汇总**:`N alert(s)` 到 stderr。

### 设计要点 / 不变量
- 复用 `rpc::fetch_logs`(新增):分块 + 并发 + 单窗失败二分(同 `logs_addresses`),返回完整日志 `LogHit{block,address,topics,data,tx_hash}`(解耦 alloy `Log`,便于纯函数测试)。
- `events::parse_alert(&LogHit) -> Option<Alert>`:纯函数,按 topic0 分派解码;未知 topic → `None`(默认集)或 `unknown`(显式 `--alert-topic`)。
- 要求 `--from <= --to`;空 topic 不可能(默认集非空)。
- AlertSink 的所有失败路径都降级为 `warn!`,**监控循环永不 panic/中断**。

### 测试与性能(目标 100% 覆盖)
- **单元**:`events` 对每个事件的解码(索引/非索引地址、缺字段、未知 topic);`AlertSink` 文件追加(tempfile)、webhook(wiremock)、双 sink、禁用;`rpc::fetch_logs`(wiremock:单块/分块/空)。
- **集成(end-to-end,wiremock)**:`run()` 跑 `monitor`,mock `eth_getLogs` 返回各类事件日志 → 断言 `alerts.jsonl` 行数/内容、webhook 命中、stdout JSON 流、`--watchlist` 过滤、`--from>--to` 报错。
- **性能**:`fetch_logs` 为 O(日志数),网络受限,分块并发(对标 `logs_addresses` 的 ~5× 并发加速);解码为纯 CPU、每条 O(1)。

### 对抗式审查(开发后)
15-agent 对抗式审查(3 lens × find → 12 verify)。topic0 四个常量经独立 keccak256 重算**确认正确**、解码器**无 panic 路径**。确认并修复:
1. **(high)** `monitor` 误要求 Etherscan key —— 它只用 `eth_getLogs`。**修**:新增 `prepare_chain_rpc`(仅建 RPC、不校验 etherscan key),`monitor` 改用之。
2. **(medium)** 多链告警无链标识。**修**:`Alert` 加 `chain_id`,`run_monitor` 按链回填。
3. **(medium)** JSONL 追加非原子(`writeln!` 分两次 write,跨进程可能撕行)。**修**:`write_all` 一次写入 `line\n`。
4. **(low)** 空/纯注释 `--watchlist` 静默吞掉全部告警。**修**:解析为 0 地址时 `warn!`。
- 其余为 nit/by-design:`monitor` stdout 恒为 JSONL 流(无 human 表格变体);缺块号→0(已确认区间日志均带块号)。

**真链验证**:对主网近 ~80 块区间 `monitor` 实测解码 **42 条告警**(Upgraded 22 / OwnershipTransferred 16 / BeaconUpgraded 4),`new_value`/`tx_hash` 均正确。

> 状态:✅ 批量 3 完成(全量 **256 测试** 通过、clippy 零告警、库行覆盖 ~98%)。

## Phase 12:新部署风险监控（`monitor --audit-deployments`）✅

把**安全审计引擎接入 monitor**,对区间内的**新部署合约**实时风险评分并告警 —— 不仅监控链上事件,还监控"谁刚部署了高危合约"。

```
blockscan monitor --from N --to M --audit-deployments --min-risk 50 \
                  [--watchlist file] [--alerts alerts.jsonl] [--webhook-url URL]
```

- **机制**:对 `[from,to]` 每块取 `contract_creations_in_block`(顶层部署;复用 `range` 的发现),对每个新合约跑**完整审计**(取字节码 + Etherscan 源码 → `audit::audit`),`risk_score > 0 且 ≥ --min-risk` 时发一条 `Alert{ event:"RiskyDeployment", kind:"risky-deployment", risk_score, grade, ... }` 到既有 sink(`alerts.jsonl` / webhook / stdout)。`--watchlist` 仍可限定地址。
- **客户端依赖**:`--audit-deployments` 需要 Etherscan key(要拉源码做源码级检测);纯事件监控仍是 rpc-only(无 key)。故 monitor 按是否 `--audit-deployments` 选 `prepare_chain`(全 scanner)/`prepare_chain_rpc`。两种监控可同次进行(事件 + 部署)。
- **复用**:`Alert` 加可选 `risk_score`/`grade`(事件告警留空);新增 `Scanner::scan_and_audit(addr) -> Option<ContractDetails>`(走 `process_one`:取码+源码+审计+落盘,返回含 `audit` 的详情);事件扫描逻辑抽成 `scan_events` 复用。
- **实时性**:monitor 是区间式,cron 周期化跑近 N 块即"准实时";真正跟链头的 `watch --alert-on-risk` 列为后续(复用本批 `scan_and_audit`+sink)。

**测试**:`scan_and_audit` 返回含审计的详情;集成(mock rpc `eth_getBlockReceipts`/creations + etherscan 含漏洞源码)→ `monitor --audit-deployments --min-risk` 产出 `risky-deployment` 告警含 `risk_score`/`grade`,低于阈值/clean 不报,`--watchlist` 过滤;`--audit-deployments` 需 key/审计(无 key、`--no-audit` 报错)。

### 对抗式审查记录(Phase 12,7-agent)
确认并修复 2 项(余 1 项 partial:跨轮重叠区间重复告警 —— 文档已声明 dedup 为后续,by-design):
1. **(high)** `--audit-deployments --no-audit` 静默零告警(cfg.audit=false → 部署从不审计)。**修**:run_monitor 拒绝该组合(报错)。
2. **(high/med)** 风险评分用磁盘上**陈旧/缺失**的 audit(`process_one` 命中 `already_saved` 短路 → 返回旧详情、从不重审;跨轮重叠/曾用 `--no-audit` 落盘时漏报)。**修**:`scan_and_audit` 直接走 `fetch_and_save` **每次重审**(绕过 resume 短路)。
均补回归测试。**真链验证**:近 8 块区间 `monitor --audit-deployments --min-risk 1` → 3 条 risky-deployment(含一验证合约 grade C/risk 39 "Privileged function without access control" + 2 未验证),plumbing 端到端工作。

> 状态:✅ Phase 12 完成(审计接入 monitor;`scanner.rs` 98.7%、库总 ~98.2%;全量 310 测试)。

## Phase 13:跨轮告警去重 / 基线(`monitor --baseline`）✅

重叠区间或周期化重跑会重复发同一条告警。引入**稳定指纹 + 持久基线**:每条告警算一个与运行无关的指纹,已见过的指纹直接抑制(不落 sink、不计数为新),新指纹发出并追加进基线文件,供后续运行参照。

```
blockscan monitor --from N --to M --baseline seen.fp [--alerts alerts.jsonl] …
blockscan watch --alert-on-risk --baseline seen.fp …      # Phase 14 复用
```

### 告警指纹(`baseline::alert_fingerprint`)
- 身份串 = `chain_id|block|contract|event|kind|tx_hash|previous|new_value` → `keccak256` 取前 8 字节 16 位十六进制(与 SARIF `partialFingerprints` 同构)。
- 选字段理由:链上同一事件的这些字段跨运行恒定;`tx_hash` 已使每条事件唯一,`block` 兜底无 tx_hash 的自定义 topic;`previous`/`new_value` 区分同一 tx 内的多次同名事件。`risky-deployment` 用创建 tx + 创建块,稳定。

### 基线存储(`baseline::AlertBaseline`)
- 文件:每行一个指纹(`#` 注释/空行忽略),**追加写**(crash-safe,与 `alerts.jsonl` 同哲学)。
- `load(Option<PathBuf>)`:无路径→去重禁用(透传,everything new);路径不存在→空集(首跑);**读失败→warn + 空集**(降级为不抑制 = 安全方向,绝不因基线 I/O 中断监控)。
- `is_new(&mut self, &Alert) -> bool`:算指纹;命中内存集→`false`(抑制);否则插入内存集 + 追加到文件(写失败仅 warn),返回 `true`。同一运行内的去重与跨运行去重共用这一个内存集。
- **不变量**:`--baseline` 未给 → 行为与现状完全一致(全量发);给了 → 去重 + 持久化。抑制方向只会**少发重复**,不会漏发新告警。

### 接线(`run_monitor` 重构)
把 `scan_events` / `scan_risky_deployments` 重构为**区间共享 helper**,接收一个 `AlertCtx`(topics/watchlist/sink/`&mut baseline`/chain/min_risk/log 参数),发 sink 前先 `baseline.is_new(&alert)` 过滤。Phase 14 的 `watch` 复用同一对 helper(`from==to==块`)。汇总行加抑制计数:`N alert(s) (M suppressed)`。

**测试**:`alert_fingerprint` 稳定性/区分性(改 block/tx/value→变,重复→同);`AlertBaseline` 无路径透传、空文件、读回已存指纹后抑制、追加落盘、读失败降级;集成:`monitor` 同区间跑两次,第二次 0 新告警、基线文件行数不增;`--watchlist`+`--baseline` 叠加。

### 对抗式审查记录(Phase 13)
确认并修复 1 个真实缺陷,持久化/计数/并发/借用均确认无误:
1. **(high)** 告警指纹漏 `log_index` → 同一 tx 内两条同签名事件(同 block/contract/event/tx_hash/value)指纹相同 → 第二条被当重复**误抑制**(对安全告警工具是真实漏报)。`tx_hash` 单独不是日志唯一标识。**修**:`LogHit`/`Alert` 加 `log_index`(rpc 从 `l.log_index` 取),指纹纳入 `log_index`;`tx_hash=None` 的自定义 topic 同样受益。补回归测试 `two_logs_same_tx_different_index_do_not_collide`。
- 其余确认正确:`--baseline` 未给 = 行为不变(透传不记录);文件追加 crash-safe、读/写失败仅 warn 不中断;跨链计数正确;`AlertCtx` 持 `&mut baseline` 严格顺序使用无数据竞争;watchlist 过滤在昂贵审计之前。分隔符 `|` 注入不可达(所有字段为数字或 `0x` 十六进制)。

> 状态:✅ Phase 13 完成(`baseline.rs` 行覆盖 100%)。

## Phase 14:跟链头实时告警(`watch --alert-on-risk` / `--alert-events`)✅

把区间式 `monitor` 的告警闭环接到 `watch` 的轮询循环上 —— 真正"跟着链头"实时发告警,而不是手动给区间。复用 Phase 12 的 `scan_and_audit`、Phase 13 的基线、既有 `AlertSink`/`events`/`fetch_logs`。

```
blockscan watch --alert-on-risk [--alert-events] --min-risk 50 \
                --alerts alerts.jsonl [--webhook-url URL] [--baseline seen.fp] \
                [--watchlist file] [--alert-topic 0x..] [--confirmations 2] [--poll-ms 4000]
```

- **两个开关**:`--alert-on-risk`(审计每个新部署、`risk≥--min-risk` 发 `risky-deployment`)、`--alert-events`(解码安全事件发告警)。可单开或同开。
- **模式切换**:任一告警开关置位 → `watch` 进入**告警模式**(每个确认块跑告警管线,不再批量下载所有新合约;risky 的由 `scan_and_audit` 顺带落盘)。都不置位 → 维持原**下载模式**(行为不变,既有测试不动)。
- **复用循环**:沿用 `watch` 的 head/confirmations/poll 机制;每个 tick 对 `[next..=confirmed]` 调共享 helper(`--alert-events`→`scan_events_range`,`--alert-on-risk`→`scan_risky_deployments_range`),`AlertCtx` 同上(含 `&mut baseline`,跨 tick 自然去重重叠/重组重扫)。错误仅 warn、循环不中断;Ctrl-C 优雅退出后按 `--format` 收尾。
- **依赖**:`watch` 本就需 Etherscan key(`prepare_chain`),`--alert-on-risk` 需源码审计正好满足;`--alert-events` 纯 RPC 但搭车现有 scanner。
- **实现**:新增 `watch_alerts_with_shutdown`(与下载版 `watch_with_shutdown` 并存,`run()` 按开关分派),共用 `poll` 内核读 head→推进 `next`→调 helper。

**测试**:`watch_alerts` 单 tick(注入可控 shutdown + mock rpc)→ 事件 + risky 部署各发一条;`--baseline` 跨 tick 去重;`--alert-on-risk` 与 `--no-audit` 互斥报错;低于 `--min-risk` 不发;event-only / risk-only / 两者同开三种组合。

### 对抗式审查记录(Phase 14)
确认并修复 2 个真实缺陷(区块推进/重组/分派/shutdown 等确认正确):
1. **(high)** 部分 `eth_getLogs`/回执失败仍推进 `next` → 永久跳过该窗口的区块(`fetch_logs` 把失败窗口折进计数并返回 `Ok(部分结果)`,旧 `poll_alert_tick` 视 `Ok` 为"已扫完"就推进)。**修**:`fetch_logs` 返回 `(hits, failed)`;`AlertCounts` 加 `incomplete`;事件/部署任一窗口失败 → 不推进 `next`、下个 tick 重扫(配 `--baseline` 去重)。补回归测试 `poll_alert_tick_does_not_advance_on_partial_log_fetch`。
2. **(low)** 纯 `--alert-events`(无 `--alert-on-risk`)仍要 Etherscan key —— 它只用 `eth_getLogs`。**修**:event-only 走 `prepare_chain_rpc`(免 key,与 `monitor` 一致),`watch_alerts` 的 `scanner` 改 `Option<&Scanner>`。补测试 `watch_alert_events_needs_no_etherscan_key`。
- 余 2 项为已知权衡/by-design:无 `--baseline` 时重扫会重发(已在帮助/文档声明推荐 `--baseline`);`scan_and_audit` 每次重审(绕过 `already_saved` 是 Phase 12 修陈旧审计的有意为之)。watch 每 tick 区间很小(贴着链头),持久失败块会响亮地反复 warn 而非静默跳过 —— 对安全工具是更安全的方向。

> 状态:✅ Phase 14 完成。

## Phase 15:事件扩展 + 告警节流 ✅

把监控的安全事件集扩到访问控制/暂停/大额转账,并加一层**同类突发节流**,避免单合约刷屏。

### 新增事件解码(`events.rs`)
全部经 `keccak256(签名)` 重算自校验(`topic0_hashes_match_signatures` 测试),错的字面量会让测试失败并报正确值。

| 事件 | 签名 | 解码 | kind | 默认集 |
|---|---|---|---|---|
| `RoleGranted` | `RoleGranted(bytes32,address,address)` | topics[2]=account(新授角色者),topics[3]=sender | `role-granted` | ✅ 加入 |
| `RoleRevoked` | `RoleRevoked(bytes32,address,address)` | topics[2]=account,topics[3]=sender | `role-revoked` | ✅ 加入 |
| `Paused` | `Paused(address)` | data 字 0=account(非索引) | `paused` | ✅ 加入 |
| `Unpaused` | `Unpaused(address)` | data 字 0=account | `unpaused` | ✅ 加入 |
| `Transfer`(大额) | `Transfer(address,address,uint256)` | topics[1]=from,topics[2]=to,data 字 0=value | `large-transfer` | **仅 `--min-transfer` 时**加入 |

- 默认安全事件集从 4 → **8**(代理升级 ×2 + 所有权 + 管理员 + 角色授予/撤销 + 暂停/恢复)。
- **大额转账**高频,**不进默认集**:仅当用户给 `--min-transfer <amount>`(原始最小单位 uint256 十进制)时才把 ERC-20 Transfer topic 加入扫描,并在投递前过滤 `value >= --min-transfer`。ERC-721 的 `Transfer` 同 topic0 但 tokenId 索引、data 为空 → `value=None` → 自然被阈值滤掉。`Alert` 加可选字段 `amount: Option<String>`(serde default,事件以外为空)。

### 告警节流(`throttle.rs`)
新模块 `Throttle{ cap: Option<usize>, counts: HashMap<(contract,kind),usize> }`:`--throttle <N>` 设每 `(合约, kind)` 在**本次运行**内最多发 N 条,超出计入 `throttled`(不发 sink)。`allow(contract,kind)` 命中上限返回 false。`cap=None` 即禁用(行为不变)。

### 接线
- `AlertCtx` 加 `throttle: &mut Throttle` 与 `min_transfer: Option<U256>`;`AlertCounts` 加 `throttled: usize`(`add` 累加,`report_alert_total` 报 `(M throttled)`)。
- `deliver_alert` 漏斗顺序:**baseline 去重(精确重复)→ throttle(同类封顶)→ emit**;`scan_events_range` 在 `parse_alert` 后对 `large-transfer` 做 `value >= min_transfer` 阈值过滤。
- CLI:`monitor`/`watch` 均加 `--throttle`、`--min-transfer`;`run_monitor`/`watch_alerts` 据 `--min-transfer` 决定是否把 `events::transfer_topic()` 加入扫描集。

**测试**:各新事件解码(索引/非索引/缺字段);Transfer 有值/ERC-721 空 data;`Throttle` 封顶/禁用/分键独立;集成:`--throttle` 封顶后多余计 throttled、`--min-transfer` 滤掉小额留下大额、新事件类型端到端解码。

### 对抗式审查记录(Phase 15,2-agent)
事件 topic0 经 keccak 自校验确认全部正确;确认并修复 3 个真实缺陷 + 2 个一致性项:
1. **(high)** `--alert-topic <Transfer 哈希>` 不配 `--min-transfer` → 绕过阈值 → 转账刷屏。**修**:large-transfer 改为**仅当阈值已设且值可解码且 ≥ 阈值才发**(`matches!((min_transfer, value), (Some(t),Some(v)) if v>=t)`),否则丢弃。
2. **(med)** `--min-transfer=0` 让 ERC-721/零值漏过(`amount None → 0`,`0<0` 为假未丢)。**修**:同上 —— 要求 `amount` 可解码,ERC-721(无 data 值)无论阈值一律丢弃。
3. **(med)** 节流但"新"的告警其指纹被 `is_new` 副作用写入基线 → 跨轮永久抑制、静默丢失。**修**:`AlertBaseline` 拆出非变更的 `seen()` 与提交用 `record()`;`deliver_alert` 改为 **peek(seen)→ throttle → record → emit**,只有真正发出的告警才写指纹(被节流者下轮可凭新预算重发)。补回归测试 `run_monitor_throttled_alert_not_lost_across_runs`。
4. **(一致性)** 节流键原为 `(contract,kind)`,与 baseline 指纹的链感知不一致。**修**:节流键纳入 `chain_id`,同址跨链各自预算。
5. **(UX)** `watch --min-transfer` 无 `--alert-events` 时静默无效。**修**:warn 提示并不加无用 topic。
- 确认正确:节流 `Some(0)`=禁用、无 off-by-one、键独立;`deliver_alert` 是唯一出口(事件 + 风险部署 + 大额转账统一过 throttle);AlertCtx 单实例跨 tick/跨链共享 baseline+throttle 借用无冲突。

> 状态:✅ Phase 15 完成(`events.rs`/`throttle.rs`/`baseline.rs`/`model.rs` 行覆盖 100%,库总 ~98%;全量 361 测试)。

## Phase 17:告警分组 / 摘要(`--group`)✅

`--throttle` 是**硬丢弃**(超额不发)。高频同类事件(尤其大额转账)更想要的是**聚合成一条摘要**而非丢失。`--group` 引入**摘要模式**:把同 `(chain, contract, kind)` 的多条告警折叠成**运行结束时的一条 digest**。

### 机制(`group.rs::Grouper`)
- `Grouper{ enabled, groups: BTreeMap<(chain,contract,event), Agg> }`,`Agg{ count, first_block, last_block, kind, max_risk, grade }`(BTreeMap → digest 顺序确定,可测)。**键用 `event` 而非 `kind`**:`Upgraded`/`BeaconUpgraded` 同属 `proxy-upgrade` kind,但应分别成摘要 —— 否则不同事件被合并、`new_value` 丢失。risky-deployment 组保留**最高** `risk_score` + 其 grade,摘要不丢严重度。
- `--group` 置位时,`deliver_alert` 在 baseline 去重后**不发个体告警**,而是 `grouper.add(&alert)`(累加 count、min/max block)并 `baseline.record`(跨轮去重仍生效)、`counts.grouped += 1`;**throttle 在 group 模式下被旁路**(分组本身即降噪)。
- 运行结束(`run_monitor` 链循环后 / `watch` shutdown 时)`flush_groups` 把每个 group 抽成**一条** digest:`Alert{ event:"Grouped", kind:<原kind>, contract, chain_id, block:last_block, new_value:Some("<N> <kind> event(s)"), previous:Some("blocks <first>..<last>"), amount:Some("<N>") }`,直接经 sink 发出(不再过 grouper/throttle)、`counts.emitted += 1`。
- 与 `--baseline` 正交(去重照常);与 `--throttle` 互斥取 group(同给则 group 生效)。digest 自身**不进** baseline 指纹(它是衍生摘要,非链上事件)。

### 接线
- `AlertCtx` 加 `grouper: &mut Grouper`;`AlertCounts` 加 `grouped: usize`;`report_alert_total` 报 `(G grouped)`。
- CLI:`monitor`/`watch` 加 `--group`;`run_monitor`/`watch_alerts` 末尾调 `flush_groups`。

**测试**:`Grouper` add/drain(计数、first/last block、分键、空)、digest 形状;集成:`monitor --group` 多条同类 → 1 条 digest(amount=count),不同 kind/合约各自一条;`--group` 与 `--baseline` 叠加跨轮不重复。

### 对抗式审查记录(Phase 17,1-agent)
确认 1 个 med + 2 个 low,顺序/计数/借用/块跨度/关闭即 no-op 等均确认正确:
1. **(med)** digest 键为 `kind`,使 `Upgraded`/`BeaconUpgraded`(同 `proxy-upgrade`)被合并、丢失 `new_value` 区分。**修**:键改 `event`(`Agg` 存 `kind` 供摘要);补测 `distinct_events_with_same_kind_stay_separate`。
2. **(low)** risky-deployment 折叠后摘要丢 `risk_score`/`grade`。**修**:`Agg` 保留最高 `risk_score` + 其 grade;补测 `risky_deployment_digest_keeps_max_risk_and_grade`。
3. **(low)** `--group`+`--throttle` 静默忽略 throttle。**修**:两入口加 warn;补测 monitor/watch 两路。
- 补回归测试覆盖审查指出的空白:group+baseline 跨轮去重、group+throttle 优先级、watch/poll group 路径折叠、grouped 计数/摘要行。确认正确:group 后 `baseline.record` 个体指纹(跨轮去重生效)、digest 直发 sink 不再过 dedup/throttle/group 且不入基线、块跨度 min/max、关闭即字节级 no-op。

> 状态:✅ Phase 17 完成(`group.rs` 行覆盖 100%,库总 ~98%;全量 387 测试)。

## Phase 19:watch 周期化 digest + 多链并行 ✅

两个 watch 增强,均贴合现有架构。

### A. 周期化 digest(`--digest-interval <secs>`)
`--group` 的 digest 原仅在 shutdown 时 flush;长跑 watch 希望**按时间窗周期性**出摘要。`watch_alerts_with_shutdown` 的 `select!` 加第三臂 `tokio::time::interval(digest_interval).tick()` → 调 `flush_groups`(经 ctx 排空 grouper、发 digest、计 emitted),loop 结束再 flush 一次收尾。仅 `--group` + `--digest-interval` 同设时启用;未设即维持"仅 shutdown flush"。

### B. 多链并行 watch(alert 模式)
放开 watch 的 `--chains` 限制(**仅 alert 模式**;下载模式仍单链)。**无需 `Arc<Mutex>`**:baseline 指纹与 throttle/grouper 键都含 `chain_id`,故每条链用**各自独立**的 `AlertBaseline`/`Throttle`/`Grouper` 实例即可(不同链永不产生相同指纹/键,无需跨链共享内存);共享仅限 `alerts.jsonl` 文件(`append_line` 单次 `write_all` 行原子,多任务追加不撕行)与 baseline 文件(同样行原子;各链只查自己 chain_id 的指纹)。
- 实现:`run()` 的 watch arm 在 `alert_mode() && multichain` 时,逐链 `prepare_chain`(risk)/`prepare_chain_rpc`(event-only)建客户端,`shutdown` 用 `futures::FutureExt::shared()` 克隆给每条链,`futures::future::join_all` 并发跑 N 个 `watch_alerts_with_shutdown`,聚合各链返回的 `AlertCounts` 后**统一报一行**。
- 重构:`watch_alerts_with_shutdown` 不再自行 `report_alert_total`,改为返回 `AlertCounts`,由 `run()` 单链/多链各自汇报(单链行为不变)。

### 接线
- CLI:`WatchArgs` 加 `--digest-interval <secs>`(`Option<u64>`)。
- `Cargo.toml`:无新依赖(`futures` 已在用;`tokio` 已含 `time`)。

**测试**:periodic flush(注入短 interval + 可控 shutdown,断言中途 digest 发出、grouper 清空);多链并行(两链 mock,各出告警,聚合计数;同址跨链不串)。`watch_alerts` 返回值/聚合报告。

### 对抗式审查记录(Phase 19,1-agent)
确认并修复 **1 个 HIGH**;select 借用健全性、多链无锁声明、Shared shutdown、报告重构等均确认正确:
1. **(high)轮询饥饿**:poll 用每轮重建的 `sleep(poll)`,而 digest 是持久 interval;当 `--digest-interval`(秒×1000)< `--poll-ms` 时,digest 每次胜出都重置 sleep → `poll_alert_tick` 永不执行、扫描静默停摆。**修**:poll 也改为**持久** `tokio::time::interval(poll)`,两个 interval 互不重置。补回归 `watch_poll_not_starved_by_frequent_digest`(digest 1s < poll 2s,断言 `eth_blockNumber` 仍被调用)。
- 确认正确:`select!` 三臂 future 借用不相交(shutdown / poll_timer / digest async 各借各的,`ctx` 仅在胜出 handler 内用、互不重叠);多链**无锁**成立(baseline 指纹 + throttle/grouper 键均含 chain_id,各链独立实例,共享文件 append 行原子);per-chain out 子目录隔离;`Shared` shutdown 停所有链;`join_all` 后传播首个 Err 无悬挂;单行汇总(单/多链各一行);空 prepared 报错不静默。
- 余 LOW(无害):interval 首 tick 立即触发一次空 grouper flush(no-op)。

> 状态:✅ Phase 19 完成(库总 ~98%;全量 400 测试)。

## 后续(超出本批)
- WS `subscribe` 替代轮询;watch 下载模式的多链支持。
