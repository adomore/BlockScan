# BlockScan — 安全审计引擎设计（Security Audit Engine）

一个**独立**的启发式审计引擎:扫描合约的同时检测常见安全漏洞并打分。定位是 **Slither-lite 式的启发式 linter**(模式/规则检测),**不是**形式化验证器或符号执行 —— 结果是分诊信号,需人工复核。

状态:✅ Phase 8–22 全部完成(标准化 + 深度规则 + SARIF + Gov/MEV/Bridge + 抑制 + SCWE/EthTrust 映射 + AST 精化/数据流/reentrancy/access-control/weak-randomness/ecrecover/arbitrary-delegatecall/transfer-send 实参计数/收窄 downcast + 绑定图 scope-aware 名字类型解析;36 检测器)。总览见 [ARCHITECTURE.md](ARCHITECTURE.md)。

## 形态

- **引擎**:`src/audit.rs`,纯函数 `audit(&ContractDetails, &[SourceFile]) -> Audit`(无网络、无 I/O,易测)。
- **扫描时内联**(默认开启):`fetch_and_save` 在源码/代理/Sourcify 回退之后、过滤/落盘之前运行,结果写入 `ContractDetails.audit`(`Option<Audit>`,`#[serde(default)]` 兼容旧 metadata)。
- **`audit` 子命令**:`blockscan audit -o <dir>` 离线遍历已保存的 `metadata.json` + `source/`,重跑引擎并输出(尊重 `--format`、`--min-risk`)。规则升级后无需重新联网即可批量重审/重打分。**源码按各合约 `metadata.json` 的实际所在目录读取**(不再用 `out + address` 重算路径),以兼容非主网/多链时的 `out/<chainname>/<addr>/` 子目录布局——否则源码级检测器会被静默跳过、评分虚低。
- **关闭**:`--no-audit`。

## 检测层面:源码 + 字节码

### 源码检测(已验证合约;按行扫描,**注释感知**避免误报)
| id / category | 严重度 | 模式(启发式) |
|---|---|---|
| `tx-origin` | high | `tx.origin`(用于鉴权是经典漏洞) |
| `selfdestruct` | high | `selfdestruct(` / `suicide(` |
| `unprotected-initializer` | high | `function initialize(` 同行无 `initializer` 修饰符 |
| `delegatecall` | medium | `.delegatecall(` |
| `unchecked-call` | medium | `.call(` / `.call{`(低层调用,返回值常被忽略) |
| `weak-randomness` | medium | `block.timestamp` / `block.number` / `block.difficulty` / `blockhash(` / `now` |
| `old-compiler` + `overflow` | medium | `compiler_version` < 0.8.0(无内建溢出检查) |
| `ecrecover` | low | `ecrecover(`(需校验零地址) |
| `floating-pragma` | low | `pragma solidity ^` / `>=`(版本不固定) |
| `deprecated` | low | `sha3(` / `callcode(` / `throw` / `var ` |
| `assembly` | info | `assembly {`(绕过类型安全,需关注) |

### 字节码检测(所有合约;复用 `analysis.opcodes`)
| id / category | 严重度 | 触发 |
|---|---|---|
| `selfdestruct` | high | 操作码含 SELFDESTRUCT |
| `delegatecall` | medium | 操作码含 DELEGATECALL |
| `callcode` | medium | 操作码含 CALLCODE(已废弃) |
| `create2` | info | 操作码含 CREATE2(工厂/变形合约可能) |
| `unverified` | medium | 源码未验证(不透明,无法做源码级审计) |

> 源码与字节码可能命中同一类(如 selfdestruct);**打分按 category 去重**(取该类最高严重度),不重复计分。

## 打分模型

- 严重度权重:`critical=40, high=25, medium=10, low=4, info=1`。
- **风险分** `risk_score = min(100, Σ_{distinct category} max(weight))`(0=最安全,100=最危险)。
- **等级** `grade`:`0→A`,`1–14→B`,`15–34→C`,`35–59→D`,`≥60→F`(A 最安全,F 最危险)。

## 数据结构(`model.rs`)
```
Audit { risk_score: u8, grade: String, findings: Vec<Finding> }
Finding { id, category, severity, title, detail, source("source"|"bytecode"), locations: Vec<String> }
ContractDetails.audit: Option<Audit>   // #[serde(default)]
```

## 过滤 / 输出 / CLI
- 全局参数:`--no-audit`(关引擎)、`--min-risk <0-100>`(只留风险≥阈值)、`--only-vulnerable`(只留含 high/critical 的合约);后两者并入 `passes_filters`,扫描时即过滤。
- `audit` 子命令(`AuditArgs`):遍历 `-o` 下语料离线重审,按 `--min-risk` 过滤,按 `--format` 输出(human 摘要表 / json 文档 / ndjson 流)。
- 输出落点:`metadata.json.audit`;`report` 表格新增"风险评分/漏洞"行;`export` CSV 新增 `risk_score,risk_grade,findings,top_severity` 列;`--format json/ndjson` 经 `ContractDetails` 序列化自动带上。
- `storage::load_sources(out, addr)`:从 `source/` 目录读回源码,供 `audit` 子命令重审。底层为 `load_sources_from_dir(contract_dir)`;`run_audit` 走 `load_all_metadata_with_dirs(out)`(返回每个 `metadata.json` 的父目录 + 详情),再对该目录调 `load_sources_from_dir`,从而读对子目录下的源码。

## 测试与性能(目标 100% 覆盖)
- **单元**(`audit.rs`):每个检测器命中/不命中、注释感知(注释里的 `tx.origin` 不算)、category 去重计分、分数→等级边界、未验证打分、空源码;`storage::load_sources` 往返。
- **集成**(wiremock,不走真网):扫描后 metadata.json 含 `audit.risk_score`/`findings`;`audit` 子命令对预置语料输出;`--min-risk`/`--only-vulnerable` 过滤;`--no-audit` 不产出。**非主网回归**:`--chain-id 10` 扫描到 `out/optimism/<addr>/`,再 `audit -o out` 必须命中源码级 `tx-origin`(防止子目录语料源码被静默漏读)。
- **真链**:对已知含 `selfdestruct`/旧编译器/代理(delegatecall)的合约跑出预期 findings 与评分。
- **性能**:纯 CPU、按行正则,O(源码字节数);新增 `examples/audit.rs` 计时(或复用 analyze 探针思路)。
- **对抗式审查**:开发后跑一轮(重点:误报/漏报、注释与字符串字面量、评分去重、未验证路径、子命令语料加载)。

## Phase 8:标准化升级（SecurityFinding v2）✅

把审计从"堆规则"升级为**标准化引擎**:先固化分类/证据/分级/损害/修复的数据契约,检测能力再逐步加。下述模型**取代**上文 v1 的 `Finding`/`Audit`/打分。

### 三层漏洞分类
- **L1 `category`** = OWASP Smart Contract Top 10(2025/2026 类):`SC01:Access Control`、`SC02:Price Oracle Manipulation`、`SC03:Logic Errors`、`SC04:Lack of Input Validation`、`SC05:Reentrancy`、`SC06:Unchecked External Calls`、`SC08:Integer Overflow/Underflow`、`SC09:Insecure Randomness` 等;另设 `Code Quality`/`Transparency` 容纳非 Top10 项。
- **L2 `swc`** = SWC Registry 编号(SCWE 的成熟前身,编号确定可查):如 `SWC-115`(tx.origin)、`SWC-106`(selfdestruct)、`SWC-112`(delegatecall)、`SWC-104`(未校验 call)、`SWC-120`(弱随机)、`SWC-103`(浮动 pragma)、`SWC-102`(旧编译器)、`SWC-122`(ecrecover 签名校验)、`SWC-111`(废弃/callcode)。未保护 `initialize()` **无对应 SWC**(注册表早于现代代理模式)→ `swc=None`、仅靠 L1 SC01。SCWE / EthTrust 精确映射已在 **Phase 13** 落地(见下)。
- **L3 `rule_id`** = 项目内部规则 id(UPPER_SNAKE):`TX_ORIGIN_AUTH`、`PROXY_UNPROTECTED_INITIALIZER`、`BYTECODE_SELFDESTRUCT` 等。

### SecurityFinding v2(`model.rs`)
```
SecurityFinding {
  rule_id, title, category(L1), swc(L2 Option),
  severity(Critical/High/Medium/Low/Info), confidence(High/Medium/Low),
  impact_score(0-10), likelihood_score(0-10), exploitability(Easy/Moderate/Hard),
  asset_at_risk, blast_radius(single-contract/protocol/user-funds/governance/cross-chain),
  risk(0-100, 单条), priority(P0-P3), detection("source"/"bytecode"),
  affected_contract, locations[file:line], evidence,
  exploit_scenario, recommendation, references[], false_positive_notes
}
```
每条规则的"常量字段"(分类/SWC/默认 severity/confidence/impact/likelihood/exploitability/asset/blast/scenario/recommendation/refs/fp_notes)集中在**分类表 `RuleSpec`**;检测器只提供 命中 + 位置 + 证据 + 合约。

### 分级评分器
- 单条风险:`risk = (impact/10) × (likelihood/10) × confidence_factor × exposure_factor × 100`(四舍五入,封顶 100)。
  - `confidence_factor`:High 1.0 / Medium 0.75 / Low 0.5。
  - `exposure_factor`(由 `blast_radius` 派生):user-funds 1.0 / governance 0.95 / cross-chain 0.95 / protocol 0.85 / single-contract 0.6 / 其他 0.35。
- 整体风险(合约级):按**弱点键**(`swc` 优先,否则 `category`)取该键最大单条 risk → 对各不同键做"概率 OR"聚合 `100×(1−∏(1−rᵢ/100))`(累积但不重复计同一弱点,封顶 100)。
- 等级 `grade`:`0–9 A · 10–24 B · 25–44 C · 45–69 D · ≥70 F`;`risk_level` 文本:Minimal/Low/Medium/High/Critical。
- 修复优先级 `priority`:Critical→P0,High→P1,Medium→P2,Low/Info→P3。

### 报告层(`Audit` v2 + 渲染)
```
Audit { risk_score, grade, risk_level, findings[SecurityFinding], summary:AuditSummary }
AuditSummary { by_severity, by_category, by_confidence, by_priority, owasp_categories[] }
```
- `--table`:整体评级(grade + risk_score + risk_level)+ 漏洞矩阵(按严重级)+ Top 风险。
- `audit` 子命令:human 摘要(评级/矩阵/优先级)、json `{audited,vulnerable,contracts}`、ndjson 流。
- CSV(`export`)新增扁平列:`risk_score,risk_grade,risk_level,findings,top_severity,top_category,owasp`。
- json/ndjson 经 `ContractDetails` 自动携带完整 v2 findings(机读;SARIF 输出列为后续)。

### 规则映射(本期把 v1 检测器纳入标准)
v1 的 ~16 个检测器逐一赋 `rule_id` + L1/L2 + 分级常量(不新增深度规则)。后续阶段按规则族扩展:Access/Admin、Proxy/Upgrade、External Calls、DeFi/Economic(Oracle/flash-loan/share-inflation)、Token、Governance、Arithmetic、MEV、Bridge。

### 决策记录(本期取的具体默认值)
- L2 采用 **SWC 编号**(真实可查),并在文档注明其为 SCWE 前身;SCWE/EthTrust 精确映射见 **Phase 13**。
- 评分采用用户建议的 `impact×likelihood×exposure×confidence`,exposure 由 blast_radius 量化;整体用概率 OR(避免源/字节码同弱点双计)。
- 兼容性:`ContractDetails.audit` 仍是 `Option<Audit>`;旧 v1 形态的 metadata.json 在重审时由 `load_all_metadata` 跳过(开发期重扫即可重建),无线上数据受影响。

### 测试与性能(目标 100% 覆盖)
- 单元:每规则的 `RuleSpec` 装配、单条 risk 计算、exposure/confidence 因子、整体 OR 聚合与弱点去重、grade/risk_level/priority 边界、注释感知、未验证/字节码路径、summary 矩阵统计。
- 集成:扫描产出 v2 `audit`(含 category/swc/priority/summary);`audit` 子命令 json 输出含矩阵;`--min-risk`/`--only-vulnerable` 仍生效。
- 真链:WETH/USDC/BAYC 跑出带 OWASP/SWC 分类与优先级的 findings。
- 对抗式审查:开发后一轮(分类映射正确性、评分公式边界、聚合去重、u8 溢出)。

### 对抗式审查记录(两轮)
- **v1 引擎**(标准化前,13-agent):确认并修复 ①`code_part` 字符串字面量内 `/*` 跨行污染注释剥离(静默吞高危检测)②未保护 initialize 仅单行匹配漏多行 OZ 形态 ③`assembly` 子串误匹配标识符 ④`audit` 子命令从扁平路径读源码、多链语料漏源码级检测 ⑤`--no-audit` 静默废掉过滤器 ⑥Vyper 版本误判旧 Solidity ⑦`--min-risk`>100 静默全过滤。**这些已全部并入 v2 重写**(字符串感知 `code_part`、跨行 initializer 窗口、`assembly {` 边界、`load_sources_from_dir` 按真实目录、`--no-audit`+过滤器报错、Vyper 跳过、min_risk 封顶)。
- **v2 引擎**(14-agent):确认并修复 ①`PROXY_UNPROTECTED_INITIALIZER` 误挂 `SWC-118`(实为"构造函数命名错误")→ 改 `None` ②`report` 漏洞单元格大小写敏感比较致**真实 findings 恒显空**(被小写测试夹具掩盖)→ `eq_ignore_ascii_case` + 夹具改产线大小写 ③`OUTDATED_COMPILER` `SWC-101`→`SWC-102` ④`ECRECOVER` `SWC-117`→`SWC-122` ⑤`audit` 子命令 `min_risk` 未封顶 → 封顶。均补回归测试。

> 状态:✅ Phase 8 完成(全量 **280 测试**、clippy 零告警;`audit.rs`/`model.rs`/`report.rs` 行覆盖 100%,`storage.rs` 99.5%(余 2 行为文件读失败/`strip_prefix` 防御分支),库总 ~97.3%)。真链:WETH9→B、USDC→B 22/100、BAYC→C 35/100,findings 带 OWASP/SWC/优先级。
> `audit` 子命令离线读源码已按各合约真实目录(`load_sources_from_dir`),非主网/多链子目录语料不再漏源码级检测;新增 lib 单元测试 `run_audit_loads_source_from_per_chain_subdir_and_filters`(进程内可靠计入覆盖,绕开 spawn 子进程不计覆盖的本机限制)+ 集成回归 `binary_audit_finds_source_issues_in_per_chain_subdir`。

## Phase 9:深度规则族(第一批,15 条)✅

按规则族扩展。**纯增量**:只往 `spec()` 分类表加 `rule_id` + 检测器,评分/报告/输出层不动。规则集经"研究验证"工作流逐条核对 SWC/OWASP/检测模式/置信度(SWC 仅在确切匹配时填,否则 `None`,避免再现错挂 SWC)。

新增**函数提取器** `scan_functions`(对剥离后源码做花括号配平,得 {name, 签名段, body, is_external, guarded}),供窗口型规则查询;另有 8 条单行规则并入 `line_hits`。

| rule_id | OWASP / SWC | sev / conf | 检测 |
|---|---|---|---|
| `ACCESS_MISSING_GUARD_PRIVILEGED_FN` | SC01 / — | High/Med | 特权名(mint/burn/setOwner/pause/rescue/upgrade…)public/external 函数无访问守卫 |
| `ACCESS_UNPROTECTED_ETHER_WITHDRAWAL` | SC01 / SWC-105 | Critical/Med | 无守卫 public/external 函数体内有 ETH sink(排除 `msg.sender` 收款) |
| `UUPS_AUTHORIZE_UPGRADE_UNGUARDED` | SC01 / — | High/Med | `_authorizeUpgrade` 体空或无守卫 |
| `PROXY_PUBLIC_UPGRADE_TO_UNGUARDED` | SC01 / — | High/Low | public `upgradeTo(AndCall)` 且窗口内无 `_authorizeUpgrade`/守卫 |
| `HARDCODED_GAS_TRANSFER_SEND` | SC06 / SWC-134 | Low/Med | `.transfer(`/`.send(` 且有 ETH 语境、排除 ERC20 |
| `RAW_CALL_VALUE_ETH_SEND` | SC06 / — | Low/Med | `.call{value:` 低层转账 |
| `REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE` | SC05 / SWC-107 | Med/Low | 外部调用后状态写、函数无 `nonReentrant` |
| `UNCHECKED_ARITHMETIC_BLOCK` | SC08 / SWC-101 | Low/Low | `unchecked {` 块 |
| `UNSAFE_DOWNCAST_TRUNCATION` | SC08 / — | Low/Low | 收窄强转 `uintN(`/`intN(`(N<256,带边界) |
| `ORACLE_SPOT_PRICE_FROM_RESERVES` | SC02 / — | High/Med | `.getReserves(`/`.slot0(`/`sqrtPriceX96` 现货价 |
| `CHAINLINK_LATESTANSWER_DEPRECATED` | SC02 / — | Med/High | `.latestAnswer(`/`.latestRound(`/`.latestTimestamp(` |
| `CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK` | SC02 / — | Med/Low | `.latestRoundData(` 后窗口无 `updatedAt`/`answeredInRound`/时间校验 |
| `FLASHLOAN_CALLBACK_MISSING_CALLER_OR_INITIATOR_AUTH` | SC07 / — | High/Low | flash-loan 回调(onFlashLoan/executeOperation/uniswapV2Call…)无 caller/initiator 校验 |
| `OWNER_BLACKLIST_CONTROL` | SC01 / — | Low/Med | blacklist/freeze/denylist 中心化控制 |
| `OWNER_MUTABLE_FEE` | SC03 / — | Low/Low | `function setFee/setTax/...` 可变费率 |

**决策**:多条规则共享 ETH-sink 子串(`.transfer(`/`.send(`/`.call{value:`)但回答不同问题,**允许同行多触发**(不去重检测器,仅打分时按弱点键去重);FP 偏高的(downcast/reentrancy/upgrade/flashloan/transfer-gas)一律 Low 置信度,`risk` 贡献受 confidence_factor 抑制,文档如实标注。守卫识别为启发式(认已知 `only*`/`require(msg.sender`/`_check*`),未知自定义修饰符可能误报。

**测试**:每条规则命中/不命中(含守卫存在时不报、ERC20 transfer 不误报、`unchecked`/downcast 边界、注释/字符串感知);`scan_functions` 花括号配平(嵌套、跨行签名、接口 `;` 跳过、body 截断、字符串内花括号、多字节 cap 边界);真链(对含 spot-price/旧 feed/无守卫 upgrade 的合约)。

### 对抗式审查记录(Phase 9,11-agent)
确认并修复 3 项(余 5 项 refuted,含字节偏移切片"无越界/字符边界 panic"判 refuted):
1. **(medium)** 函数体 >8000 字节被截成**空**→ 体内检测器在最大/最危险函数上静默失效。**修**:cap 命中时**截断**而非清空(`close.unwrap_or((open+8000).min(len))` + `floor_char_boundary`)。
2. **(medium)** `ACCESS_UNPROTECTED_ETHER_WITHDRAWAL`(Critical)缺 ERC20 token 过滤 → 对 `token.transfer(to,amt)` 误报。**修**:`has_eth_sink` 的 `.transfer/.send` 臂改用 `eth_transfer_context`(与同级 `HARDCODED_GAS_TRANSFER_SEND` 一致),raw value-call 仍恒计。
3. **(nit)** 花括号配平把字符串字面量内的 `{`/`}` 计入 → 体被提前截断(FN)。**修**:配平时跳过字符串/字符字面量(含转义)。

> 状态:✅ Phase 9 完成(深度规则 15 条;真链:Uniswap V2 Router→F、USDC FiatToken→D,findings 带 OWASP/SWC/优先级)。`audit.rs` 行覆盖 100%。

## Phase 10:SARIF 输出（`--format sarif`）✅

把审计 findings 导出为 **SARIF 2.1.0**(Static Analysis Results Interchange Format),对接 GitHub Code Scanning、CI 安全看板、IDE 插件。纯输出层,新增 `OutputFormat::Sarif`,不动检测/评分。

- **模块** `src/sarif.rs`:纯函数 `build_sarif(&[ContractDetails]) -> serde_json::Value`(易测,无 I/O)。
- **结构**:`{ version:"2.1.0", $schema, runs:[{ tool.driver:{name:"blockscan", informationUri, rules:[...] }, results:[...] }] }`。
  - `rules`:按出现的 `rule_id` 去重,每条带 `id`、`name`、`shortDescription`(title)、`fullDescription`(exploit_scenario)、`helpUri`(references[0])、`help.text`(recommendation)、`properties{ security-severity(0–10), tags:[OWASP category, SWC, confidence] }`、`defaultConfiguration.level`。
  - `results`:每个 finding 一条,`ruleId`、`level`(Critical/High→error,Medium→warning,Low/Info→note)、`message.text`(title+evidence)、`locations[].physicalLocation{ artifactLocation.uri=源文件, region.startLine }`(从 `file:line` 解析;字节码级 finding 无位置则给 `logicalLocations`=合约地址)、`properties{ risk, priority, confidence, swc, category, contract }`。
- **接入**:`OutputFormat::Sarif` 与 json 同语义(运行结束输出一个文档);scan 模式经 `emit_run_output`、`audit` 子命令经 `run_audit` 各自走 SARIF 分支;`process_addresses` 在 json/**sarif** 时收集 run-scoped 详情(ndjson 仍流式)。stdout 断管安全。
- **security-severity**:取 `risk`(0–100)/10,保留一位小数(GitHub 用此排序/分级)。
- **测试**:`sarif.rs` 单元(顶层结构、rules 去重、level 映射、有/无位置、security-severity、helpUri 回退、空 findings → 合法空 run);集成(`--format sarif` 真二进制 → stdout 解析为合法 SARIF,`runs[0].results` 与 findings 一致,rule helpUri/tags 存在)。

> 状态:✅ Phase 10 完成(`sarif.rs` 行覆盖 100%)。真链:BAYC `--format sarif` → 合法 SARIF 2.1.0(8 rules/8 results,physicalLocation 源文件、security-severity、OWASP/SWC tags),可直接喂 GitHub Code Scanning。

## Phase 11:Gov/MEV/Bridge 规则族 + SARIF 指纹 ✅

规则集经研究验证工作流核对(SWC 仅 MEV 三条挂 **SWC-114** Transaction Order Dependence,其余 `null`)。

| rule_id | OWASP / SWC | sev/conf | 检测(line=单行, fn=函数窗口) |
|---|---|---|---|
| `GOV_VOTE_CURRENT_BLOCK_VOTING_POWER` | SC07 / — | High/Low | fn:vote 路径体读当前块投票权(getVotes/balanceOf)且无快照(getPriorVotes/getPastVotes/snapshot) |
| `GOV_EXECUTE_NO_TIMELOCK_DELAY` | SC01 / — | High/Low | fn:execute 体有外部调用且无 timelock/eta/delay/queue 门控 |
| `GOV_ZERO_PROPOSAL_THRESHOLD` | SC03 / — | Low/Med | fn:`proposalThreshold` 体 `return 0` |
| `MEV_SWAP_DEADLINE_BLOCK_TIMESTAMP` | SC03 / SWC-114 | Med/Med | line:`deadline: block.timestamp` 或 swap 标记同行 block.timestamp |
| `MEV_SWAP_ZERO_AMOUNT_OUT_MIN` | SC03 / SWC-114 | High/Med | line:`amountOutMin(imum): 0` 或 swap 标记同行 `, 0,` |
| `MEV_FRONTRUNNABLE_ERC20_APPROVE_RACE` | SC03 / SWC-114 | Low/Low | fn:public `approve` 无零值校验直写 allowance |
| `CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION` | SC03 / — | High/Low | fn:跨链收信函数体无 nonce/processed/usedHashes 等 |
| `CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH` | SC01 / — | High/Low | fn:跨链收信(**排除 LZ 名**)public 无守卫且无 trustedRemote/endpoint 等 |
| `LZRECEIVE_MISSING_TRUSTED_REMOTE_CHECK` | SC01 / — | High/Med | fn:`lzReceive` 体无 endpoint 调用方校验/trustedRemote 比对 |

**去重决策**:LayerZero 名(`lzreceive`…)只归 `LZRECEIVE_*`(源认证),不进 `CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH` 的名集,避免同函数双报同类访问控制;但 `CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION` 保留 LZ 名(replay 与 source-auth 是不同缺陷,二者同报是正确的)。FP 偏高的一律 Low 置信度。

**SARIF `partialFingerprints`**:每个 result 加 `{ "blockscan/v1": keccak16(rule_id|contract|file|evidence) }`(用源文件而非行号 → 跨行位移稳定;含 evidence 以区分同文件同规则的不同实例),供 GitHub Code Scanning 做告警基线/去重。

**真链验证**:Uniswap V2 Router→0 条 MEV 误报(用正确 deadline/slippage 参数)、GovernorBravo→0 条 Gov 误报(用 `getPriorVotes` 快照 + Timelock)—— 对规范安全实现不误报;真阳由单元测试覆盖。

### 对抗式审查记录(Phase 11,16-agent)
13 项中 8 confirmed/partial,绝大多数是"确认正确/无 bug"(rule_id↔spec 全部解析、SWC-114 映射正确、指纹确定且 panic-safe、LZ 去重正确)。修复 2 个真实质量项:
1. **(low)** `GOV_EXECUTE` 抑制词裸 `"eta"` 子串命中 `metadata`/`beta` → 误抑制(FN)。**修**:去掉裸 `eta`(`block.timestamp >=` 已覆盖真实模式),改用 `>= eta`/` ETA` 等有界形式。
2. **(low)** `_blockinglzreceive` 在 LZ 名集里却漏在 `XCHAIN_REPLAY_RECV` → LZ 各名 replay 覆盖不一致。**修**:补入 replay 名集。
均补回归测试。SARIF `--format sarif` 输出经真链验证。

> 状态:✅ Phase 11 完成(审计达 **35 检测器**;`audit.rs`/`sarif.rs` 行覆盖 100%,库总 ~98.2%;全量 307 测试)。

## Phase 12:规则去重 / 抑制配置(`--suppress`)✅

启发式 linter 必有误报;团队需要把**已三角验证确认为 FP 的发现**或**已接受的基线**静默掉,而不是每次重审都看同样的噪声。引入一份**抑制配置文件**(JSON),按多种键匹配并在评分前剔除命中项 —— 抑制即降分(剔除后才算 `risk_score`/summary),因为压掉一个 FP 应当同时降低整体风险。

```
blockscan range --from N --to M --suppress suppress.json
blockscan audit --suppress suppress.json
```

### 配置格式(`suppress::Suppressions`,serde_json)
```json
{
  "suppress": [
    { "rule": "DELEGATECALL_USAGE", "reason": "审计后确认仅 delegatecall 到不可变库" },
    { "rule": "ORACLE_SPOT_PRICE", "contract": "0xabc…", "reason": "该合约用 TWAP,误报" },
    { "swc": "SWC-112" },
    { "category": "SC06:Unchecked External Calls" },
    { "fingerprint": "deadbeef12345678" }
  ]
}
```
- 每条 `SuppressEntry` 的键全部可选,任一**非空键全部匹配**才算命中(AND 语义);多条之间 OR。`reason` 仅文档、逻辑忽略。
  - `rule` = `rule_id`;`contract` 大小写不敏感比对 `affected_contract`(给了就把 `rule` 限定到该合约,否则全局)。
  - `swc` / `category` 精确匹配(blanket 压一类)。
  - `fingerprint` = `sarif::fingerprint(finding)`(`keccak16(rule|contract|file|evidence)`,与 SARIF/baseline 同构)→ 精确压单个发现实例(基线用法:把已接受发现的指纹记进来)。
- 单一空条目(所有键为空)视为无效并 `warn` 跳过(避免一不小心压掉全部)。

### 接线
- `sarif::fingerprint` 提升为 `pub`,`suppress` 复用(指纹同构)。
- `audit.rs`:新增 `pub fn audit_with(d, sources, &Suppressions)`;`audit(d, sources)` = `audit_with(…, &Suppressions::default())`(零改动现有调用)。`audit_with` 在合成 findings 后 `retain(|f| !supp.is_suppressed(f))`,再据剩余项算分/summary。
- `Config` 加 `suppressions: Suppressions`;`config_from_cli` 经 `Suppressions::load_or_warn(&g.suppress)` 载入(None→空;**文件缺失/解析失败→warn + 空 = 安全方向**:宁可多显示发现也不静默压掉)。`scanner::fetch_and_save` 与 `run_audit` 改调 `audit_with`。
- CLI:全局 `--suppress <path>`。

**测试**:`Suppressions` 各匹配键(rule、rule+contract 限定、swc、category、fingerprint)单独命中与不命中;空条目跳过;`load_or_warn` 的 None/缺失/坏 JSON 三路;`audit_with` 抑制后 `risk_score` 下降且 summary 一致;集成:`audit --suppress` 压掉某 rule 后该 finding 消失、分数变化。

### 对抗式审查记录(Phase 12,audit)
审查未发现 high/med 缺陷 —— 对安全工具最致命的两点都已显式防住并有测试覆盖:(a) 空/仅 `reason` 条目**绝不**匹配任何发现(`has_key()` 双重防御:`matches` 结构层 + `load_or_warn` 加载层),不会"压掉全部";(b) 抑制在 `overall_risk`/`summarize` **之前** `retain`,分数与 summary 同步下降。AND/OR 语义、`contract` 大小写不敏感、`swc=None` 不被 swc 规则误命中、`fingerprint` 复用 `sarif::fingerprint`、fail-safe 加载(缺失/坏 JSON/keyless → warn+空)、live 扫描与离线 `audit` 双路接线均确认正确;`audit()`(无抑制)对其余调用方逐字节不变。
- 余 1 项 by-design(low):`Suppressions` 未启用 `deny_unknown_fields`,拼错的键被静默忽略(serde 默认行为;且只会让规则"更宽"而非误压)—— 仅文档提示,不改。

> 状态:✅ Phase 12 完成(`suppress.rs` 行覆盖 100%)。

## Phase 13:SCWE + EEA EthTrust 映射 ✅

在三层分类(OWASP SC Top10 `category` → SWC `swc` → `rule_id`)旁,补两条平行外部引用:**SCWE**(OWASP Smart Contract Weakness Enumeration,SWC 的现代继任)与 **EEA EthTrust**(企业以太坊联盟安全级别 [S]/[M]/[Q] 需求)。映射经研究验证工作流对在线注册表逐条核对,沿用 SWC 的既有原则:**只在高置信度精确匹配时赋 ID,否则 `null`,绝不臆测**。

- **实现**:`SecurityFinding` 加 `scwe`/`ethtrust: Option<String>`(均 `#[serde(default)]`,旧 `metadata.json` 兼容);audit.rs 新增独立表 `scwe_ethtrust(rule_id)`(与 35 个 `spec()` arm 解耦,零改动),`build_finding` 填字段并 push SCWE/EthTrust 引用 URL;SARIF 以 tag(`SCWE-xxx` / `EthTrust:req-…`)+ result property 暴露。**评分/检测逻辑完全不变**(纯元数据)。
- **覆盖**:40 个可发出 rule_id 中 **29 条赋 SCWE/EthTrust**(24 SCWE + 17 EthTrust,部分重叠),11 条故意留 null(无精确匹配:PROXY_UNPROTECTED_INITIALIZER、LZRECEIVE_*、FLASHLOAN_*、GOV_ZERO_PROPOSAL_THRESHOLD、OWNER_*、DEPRECATED_CONSTRUCT、BYTECODE_CALLCODE、SOURCE_UNVERIFIED、HARDCODED_GAS_*、RAW_CALL_VALUE_*)。
  - *(Phase 20 起)* 新增 `DELEGATECALL_ARBITRARY_TARGET` 复用 `SCWE-035`(与 `DELEGATECALL_USAGE` 同),故现为 **41 rule_id / 30 条赋值**;计数口径同「检测器 36」脚注(字节码别名合并)。

### 对抗式审查记录(Phase 13,audit)
**未发现真实缺陷**。最高风险项(rule_id 字符串拼写导致静默漏映射)经程序化集合 diff 确认:`scwe_ethtrust` 的 arm ⊆ `spec()` 的 arm,无悬空 arm;发出集 = spec 集 = 40,29 映射 + 11 留 null。别名(selfdestruct/delegatecall/chainlink/proxy-upgrade)在两表一致;EthTrust 锚点 ` [LEVEL]` 剥离正确;helpUri 顺序 SWC→SCWE→EthTrust→OWASP;`overall_risk`/`grade`/`summarize` 不读新字段(评分不变);SARIF null 字段不产生空 tag;back-compat 反序列化测试到位。

> 状态:✅ Phase 13 完成(`audit.rs`/`model.rs`/`sarif.rs` 行覆盖 100%;全量 403 测试)。

## Phase 14:AST 精化层(slang_solidity)✅

行级启发式对两条规则**过度命中**:`TX_ORIGIN_AUTH` 对任何 `tx.origin`(连 `return tx.origin`、日志读取这类非鉴权用法)都报;`UNCHECKED_LOW_LEVEL_CALL` 对任何 `.call(`(连 `(bool ok,)=x.call(...); require(ok);` 这种**已检查**的)都报。注释/字符串已被 `code_part` 剥离,故剩下的真实误报源是**缺少语法上下文**。本期引入一个**真正的 Solidity 解析器**做 AST 级精化,只针对这两条规则消除上述误报 —— **纯增量、可降级、评分不变**。

### 选型与构建环境(已 spike 验证)
- **`slang_solidity = "1.3.6"`**(Nomic Foundation 的模块化 Solidity 编译器前端):**纯 Rust、无 C 依赖**、MSVC 冷编 ~15s、rustc 1.96 通过;会引入 `thiserror 2.x` 与项目现有 `thiserror 1` 并存(cargo 允许多 major 共存,无冲突)。不选 `solang`/`tree-sitter-solidity`(C/C++ 工具链或 FFI,违背"纯 Rust、MSVC 干净构建")。
- **拉取注意**:本机默认 sparse 索引走 HTTP/2 会 `schannel handshake` 失败;新依赖须 `CARGO_HTTP_MULTIPLEXING=false cargo update`(同 reqwest/alloy 的 HTTP/1.1 规避,详见 build-env 记忆)。
- **已验证 API**:`Parser::create(LanguageFacts::LATEST_VERSION)` → `parse_file_contents(src)` → `ParseOutput{ is_valid(), errors(), create_tree_cursor() }`;游标 `go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression)`、`node().unparse()`(节点原文)、`text_range().start.line`(0-based,+1 即行号)、`ancestors()`(直接借用游标;**勿** `spawn().ancestors()` —— spawn 断开 parent 致祖先为空);祖先 `anc.kind == NonterminalKind::X`(祖先恒为非终结符)。Spike 已证:能区分 `require(tx.origin==..)`(auth)vs `return tx.origin`(信息),且不命中注释/字符串里的 `tx.origin`。

### 本期范围(2 个精化检测器,复用既有 rule_id/spec/SCWE/EthTrust)
| rule_id(复用) | AST 命中条件(精确) | 相对启发式的提升 |
|---|---|---|
| `TX_ORIGIN_AUTH` | `MemberAccessExpression` 文本 == `tx.origin`,且祖先链含相等比较 `EqualityExpression`(`==`/`!=`)、关系比较 `InequalityExpression`(`<`/`>`/`<=`/`>=`)、`IfStatement` 条件、或 `require`/`assert` 的 `FunctionCallExpression` | 排除 `return tx.origin` / 纯读取/传入非鉴权函数等用法的误报;且不被 `mytx.origin` 这类子串误命中(启发式会) |
| `UNCHECKED_LOW_LEVEL_CALL` | `.call` 的 `MemberAccessExpression`(含 `.call{…}` 经 `CallOptionsExpression`)且其布尔返回**未被外层表达式消费** —— 自该调用向上,第一个有意义祖先为 `ExpressionStatement`(裸语句弃值)或绑定节点(`=`/`(…,)=`/`bool ok=…`)即判**未检查**;若被 `require/assert/foo(...)` 实参、`if/while` 条件、`return`、布尔/比较表达式、`emit` 实参等消费则**不报** | 排除 `require(x.call(..))`/`if(x.call(..))`/`return x.call(..)`/`foo(x.call(..))`/`emit E(x.call(..))` 这类**结果被直接消费**的误报 |

> **保守取舍(关键,避免漏报)**:`(bool ok,)=x.call(..); require(ok);` 这类"绑定后在后续语句里再检查"的**安全**写法,因确认"绑定变量是否在后文被检查"需**函数内数据流**(本期推迟),故**保守仍按未检查上报**(与旧启发式一致、不引入新误报、也**绝不漏掉**经典 `(bool ok,)=x.call{value:..}(""); /*ok 从不检查*/` 的真实漏洞)。即:本期 UNCHECKED 的净效果是**只移除"结果被直接消费"的误报**,绑定形态一律保留上报。`.call` 仅匹配 `.call`(与启发式同面,**不含** `.delegatecall`/`.staticcall` —— 它们各有规则);无类型信息故无法区分"地址低层 `.call`"与"用户自定义名为 `call` 的函数"(与启发式同限,需 slang bindings,已推迟)。

### 已知召回取舍(诚实声明,经对抗式审查暴露)
AST 比旧子串启发式**更精确**,代价是对少数**间接**鉴权写法**召回下降**(均因本期不做函数内数据流):
- `creator = tx.origin;` 存入存储、在**后续语句** `require(msg.sender==creator)` 鉴权 → 不报(单点祖先无比较/require)。
- `admins[tx.origin] = true;` 以 tx.origin 作映射写入键 → 不报(赋值 LHS,非比较/if/require)。注意非对称:`require(owners[tx.origin])`(映射**读**在 require 内)仍报。
- 这些是不常见模式;常见的 `require(tx.origin==owner)`/`if(tx.origin==x)` 全覆盖。**取舍是有意、有测试**;需要时可后续补"`<lvalue>=tx.origin` 低置信信号"。

### 明确推迟(本期不做,诚实声明)
- **AST 版 reentrancy**(`REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE`):精确需收集合约**状态变量名** + 函数内**语句顺序** + 局部变量/视图函数等 FP 防护,工作量与误报面更大;现有**启发式 reentrancy 保留不变**,AST 版列为下一个 AST 增量(Phase 15)。
- **函数内 / 跨函数数据流、别名分析、Query DSL**:本期游标遍历 + 祖先判定已足够覆盖目标两条规则;不引入 slang 的 stack-graph/bindings 名称解析(虽已随 crate 编入)。"绑定变量是否在后文被检查"即属函数内数据流,故 UNCHECKED 对绑定形态保守上报(见上)。

### 架构与接线
- 新模块 **`src/ast.rs`**:`pub fn detect(content: &str) -> Option<Vec<AstHit>>` —— 解析成功(`is_valid() && errors().is_empty()`)返回 `Some(命中)`,**任何解析失败 / 过深嵌套 / 解析器 panic 均返回 `None`(降级信号)**;`pub struct AstHit { rule_id: &'static str, line: usize, evidence: String }`;`pub const AST_RULES: &[&str] = &["TX_ORIGIN_AUTH", "UNCHECKED_LOW_LEVEL_CALL"]`。
- `audit::audit_with` 每文件:先 `scan_source_file` 收启发式命中 → **若 `ast::detect` 返回 `Some`**:从该文件命中里 `retain` 掉 `AST_RULES` 的启发式项,再追加 AST 命中(`detection:"ast"`、`location:"{path}:{line}"`)。`None` 则该文件启发式照旧。**逐文件、精确归属,无跨文件泄漏**;`RawHit` 仍私有(ast.rs 只回 `AstHit`,由 audit.rs 包装)。
- **指纹稳定**:AST 命中**复用同一 location 处启发式命中的 evidence 串**,使 `sarif::fingerprint`(`rule|contract|file|evidence`)在"启发式→AST"切换后保持不变,旧的 fingerprint 抑制 / `monitor --baseline` 不被静默打断;无对应启发式命中时回退用 AST 自身 evidence。
- 函数级 reentrancy 检测器在 `scan_source_file` 之外、未触及,故与本期零交互;`RAW_CALL_VALUE_ETH_SEND`/`DELEGATECALL_USAGE` 等同源旁路规则因 rule_id 不在 `AST_RULES`,**不被替换、不重复计分**。

### 稳健性(经审查加固)
- **解析器 panic**:slang 对部分畸形源会 **panic**(而非返回 invalid),故 `detect` 用 `std::panic::catch_unwind(AssertUnwindSafe(..))` 包裹,panic 即降级 `None`(项目无 `panic=abort`,可正常 unwind)。
- **栈溢出**:深度嵌套表达式会让 slang 递归下降**爆栈**,而 Windows `STATUS_STACK_OVERFLOW` 是**非 unwind 异常,`catch_unwind` 拦不住**;源码来自不可信(已验证)合约。对策:解析**前**用 `too_deeply_nested` 单遍数括号深度,超 `MAX_NESTING_DEPTH=96`(远低于观测到的 ~150 debug/~300 release 溢出阈、远高于真实合约嵌套)即返回 `None` 走启发式。

### 降级与不变量
- 解析失败 / 过深 / panic / 空源 / 未验证合约 → `detect` 返回 `None` → 行为**完全等同当前**(启发式 + 字节码级)。
- **评分完全不变**:同 rule_id ⇒ 同 category/严重度/SCWE/EthTrust,category 去重逻辑不动;`finding_risk`/`overall_risk`/`summarize`/SARIF severity 均不读 `detection`(仅作信息字段)。无新 CLI 参数。

### 测试与性能(目标 100% 覆盖)
- **功能(`ast.rs` 单测)**:tx.origin 在 `==`/`!=`/关系比较/`if`/`require`/`assert` 各路径命中、`return tx.origin`/传入普通函数/`mytx.origin` 不命中、空白容错(`tx . origin`);低层 call 裸语句/`.call{value:}`/绑定(元组/声明/赋值)均命中、`require/if/return/foo(...)/emit(...)` 消费不命中、绑定后 `require(ok)` 保守仍命中、`.delegatecall`/`.staticcall`/`abi.encodeCall` 不命中;降级:不可解析→`None`、解析器 panic 被 `catch_unwind` 收为 `None`、过深嵌套(1000 层括号)→`None`、适度嵌套仍解析。
- **功能(`audit.rs` 接线单测)**:非 auth tx.origin 经 AST 抑制启发式、消费式 call 经 AST 抑制启发式、AST 命中 `detection=="ast"`、不可解析源**降级**为 `detection=="source"`、经典 `(bool ok,)=a.call{value:..}("")` 绑定未检查**必报**(审查回归)。集成层:per-chain 子目录离线 `audit` 的 tx-origin 命中现为 `detection=="ast"`。
- **性能**:`detect_perf_and_scale_on_large_contract`:200 函数(各 1 auth tx.origin + 1 未检查 call)单遍 `detect` 计数精确且总耗时 `< 5s`(实际数 ms;`Parser::create`+parse 为每文件固定成本,仅在有源码时执行)。
- **覆盖**:`ast.rs` 行覆盖 99%(余 2 处防御性分支:`Parser::create` 对 `LATEST_VERSION` 不可能失败的 `?` None 臂、祖先链穷尽后不可达的尾 `false`),`audit.rs` 接线 100%。llvm-cov 不计子进程,但 `ast::detect` 是库内纯函数,进程内单测可达。

### 对抗式审查记录(Phase 14,3-lens workflow + 1 复核 agent)
3 视角(漏报 / 误报+稳健 / 接线不变量)并行审 + 综合,确认并修复 **2 个 ship-blocker**;评分不变性、panic 容纳、squeeze 近似拒识、同源旁路规则未受影响等均经核对确认正确:
1. **(ship-blocker,安全漏报)`UNCHECKED_LOW_LEVEL_CALL` 把"绑定即已检查"** → `(bool ok,)=a.call{value:..}(""); /*ok 不检查*/` 这一**经典 SWC-104 资金外流**被静默漏掉(旧启发式能抓),且单测把该漏报**固化为期望**。**修**:`call_is_unchecked` 改为"结果未被外层表达式消费即上报",绑定(元组/声明/赋值)**不再算检查**;仅 `require/assert/if/return/foo/emit` 等消费才不报。绑定后再检查的安全写法保守仍报(无新误报、无漏报)。三个固化漏报的单测**反转**为"必报",并加经典资金外流的端到端回归。
2. **(ship-blocker,DoS/崩溃)深度嵌套爆栈** → 不可信已验证源里的深层嵌套表达式触发 slang 递归下降**栈溢出**,Windows 下为非 unwind 异常,`catch_unwind` **拦不住**,整批扫描进程 abort。**修**:解析前 `too_deeply_nested` 单遍数括号深度,超 96 即降级 `None`;加 1000 层回归(不再 abort)。
- 同时修的非阻断项:tx.origin 漏识关系比较 → 补 `InequalityExpression`;AST evidence 改变 SARIF 指纹会打断旧 baseline/抑制 → AST 命中复用同 location 启发式 evidence 保指纹稳定;并在文档诚实记录 tx.origin 的间接鉴权(跨语句存储 / 映射写键)召回取舍与 `.call`-名歧义限制。

**第二轮复核(ground-truth probe,专攻修复本身)** 又抓出 **2 个真问题**(基于真实 CST 探针验证,非推断):
3. **(ship-blocker,DoS)深度阈值建在错误度量上**:`too_deeply_nested` 数的是括号深度,但**语句嵌套**(嵌套 `if`/`for`/块)每层只加 ~1 个 `{` 却推多个解析帧,debug 下在括号深度 ~90 即爆栈 —— **低于**当时的 96 阈值;且 `audit_with` 跑在 tokio worker 线程(栈更小)。**修**:阈值降到保守的 **32**(≈观测溢出的 1/3,远高于真实合约嵌套),加 90 层嵌套块回归(修前会 abort 进程)。
4. **(high,漏报回归)括号 / 三元里的弃值 call 被漏**:`(a.call(""));`(单值 `TupleExpression` 包裹)与 `cond ? a.call() : b.call();`(`ConditionalExpression`)的首个有意义祖先命中 `_=>消费` 默认而被静默漏掉(旧启发式能抓)。**修**:把 `TupleExpression`/`TupleValues`/`TupleValue`/`ConditionalExpression` 加入"透明上行"臂,使弃值 call 能上达 `ExpressionStatement` 被正确上报;加括号 / 三元回归。
- 复核同时核对确认:无新误报(消费式 `require/if/foo/return/emit` 仍不报)、指纹复用 location/rule 匹配正确无借用 bug、`InequalityExpression` 仅略放宽且严格窄于旧启发式(非回归)。

> 状态:✅ Phase 14 完成(`ast.rs` 行覆盖 99.2% —— 余 2 处防御性分支:`Parser::create` 对 `LATEST_VERSION` 不可能失败的 `?` None 臂、祖先穷尽后不可达的尾 `false`;`audit.rs` 接线 100%;全量 **450 测试** = 347 单元 + 103 集成;2 轮对抗式审查共 4 个 ship-blocker/high 全修 + 回归)。

## Phase 15:函数内数据流 —— UNCHECKED 绑定检查精化 ✅

Phase 14 对低层 `.call` 的**绑定**形态(`(bool ok,)=a.call()` / `bool ok=a.call()` / `ok=a.call()`)采取**保守上报**:因当时不做函数内数据流,无法确认"绑定的成功布尔是否在后文被检查",故一律上报 —— 这把**最常见的安全写法** `(bool ok,)=a.call(""); require(ok);` 也报成误报(与旧启发式同)。本期引入**函数内、单变量、名字基**的轻量数据流,只在"绑定布尔在调用后确被 gate 检查"时**抑制**该命中,消除这一主导误报;**对裸弃值 / 消费式 / 绑定但未检查一律不变**(无新漏报)。

### 检测精度(per-occurrence 控制流模型)
对一个**绑定**形态的低层 `.call`:
1. 抽**成功布尔名** = 绑定 LHS(`=` 左)第一个逗号段的末个标识符(覆盖 `(bool ok,`、`bool ok`、`ok`)。
2. `clone()`+`go_to_parent()` 上溯到**最近的函数体定义**(`FunctionDefinition`/`Modifier`/`Constructor`/`Fallback`/`Receive`/`Unnamed`),记其起始 offset 作缓存键,`spawn()` 得**子树游标**。
3. **每函数一次** `collect_controls`:遍历函数内所有 `Identifier`,对每个用 `classify_occurrence`(`go_to_parent` 时用 `cursor.label()` 取**入边标签**)精确归类为:
   - **Gate(已检查)**:`if`/`while`/`for`/`do-while` 的**条件**(入边 `Condition`,**区分条件 vs 循环体**)、`return` 直接操作数、或 `require`/`assert` 实参。
   - **Rebind(重绑定)**:`AssignmentExpression` 左操作数(`LeftOperand`)、`VariableDeclarationStatement` 声明名、`TupleDeconstructionStatement` 目标(入边 ≠ `Expression`)。
   - **None(普通使用)**:被非 require/assert 调用消费(`foo(ok)`/`abi.encode(ok)`)、`emit`、裸表达式语句等 —— **不是检查**。
   结果按名字存入 `HashMap<name, Vec<(offset, Gate|Rebind)>>`(文档序升序)。
4. `is_checked(name, call_offset)`:取该名 offset **严格大于**调用的**第一个**控制occurrence —— 是 `Gate` → 已检查(抑制);是 `Rebind` → 该绑定值已被覆盖,**未检查**(上报);无 → 上报。
5. 抽不出名 / 找不到函数 → **保守上报**(无漏报)。

### 净效果与不变量
- 仅可能**移除**绑定形态的命中;裸弃值 / 消费式 / 绑定未检查与 Phase 14 一致。
- 不再上报:`(bool ok,)=call(); require(ok);`、`if(!ok) revert()`、`bool ok=call(); require(ok,"..")`、`ok=call(); if(ok){}`、`while(ok){}`、`return ok`、嵌套块内的条件 gate。
- 仍上报(SWC-104,**无漏报**):`(bool ok,)=call(); /*不用*/`、仅 `emit E(ok)`、`return g(ok)`(传给 helper)、`if(x){use(ok)}`(ok 在**循环/分支体**而非条件)、`while(x){sink(ok)}`、以及**名字复用**(更早的未检查调用不被后来同名调用的 gate 误抑制 —— `is_checked` 遇到先出现的 Rebind 即判未检查)。
- 评分 / 指纹 / 降级不变;**复用 Phase 14 基础设施**。新增的"函数子树游标 + per-occurrence 控制流 + 名字缓存"是后续 **AST reentrancy** 的共享地基。
- **性能**:gate 信息**每函数仅算一次**(缓存 by start-offset),单调用查询为名字内二分 —— 避免了"每绑定调用全函数扫描"的 O(调用×标识符) 退化(经 1500 绑定调用/单函数回归,线性)。

### 已知取舍(诚实声明)
- **内层作用域 shadow**:外层未检查调用的 `ok` 被内层**重声明**的同名 `ok` 的 gate 误判?—— `is_checked` 取**第一个** occurrence,内层重声明是 Rebind 且先于其 require,故外层正确判未检查(已测)。真正残留:外层调用后、在内层 shadow 之前若无任何同名控制点则正确上报;名字基分析对极端别名/同名巧合仍非完全 scope-aware(需 slang bindings,推迟)。
- **低误报(安全方向,不阻断)**:三元作语句 `ok ? f() : revert()`(`ConditionalExpression` 未列为 gate)仍上报;`require /*注释*/ (ok)`(注释插在 require 与 `(` 间,squeeze 不去注释)仍上报。二者罕见、均偏保守(多报非漏报),记为后续可选精化。

### 测试与性能(目标 100% 覆盖)
- checked(不报):`require(ok)`/`assert(ok)`/`if(!ok)revert`/`if(ok)`/`while(ok)`/`return ok`/`require(ok,"m")`/嵌套条件 + 声明/元组/赋值三种绑定。
- unchecked(仍报):绑定从不用、仅 `emit E(ok)`、`return g(ok)`、if/while **体内**用、gate 在调用**之前**、名字复用(仅后调用被查)、内层 shadow、抽不出名 `(, data)=call()`。
- 不回归:裸 `a.call("")` 报、`require(a.call())`/`return a.call()` 不报、`.delegatecall`/`.staticcall` 不报。
- 端到端经 `audit()`:`(bool ok,)=a.call(); require(ok);` 不再含 `UNCHECKED_LOW_LEVEL_CALL`;不检查的仍含且 `detection=ast`。
- 性能:`bound_call_dataflow_is_linear_not_quadratic`(1500 绑定调用/单函数,全部上报,< 5s)。
- 覆盖:`ast.rs` 行覆盖 ~98.3%;余 6 处防御性/不可达(三个循环/查找的兜底 `return`、`if-let` 非终结符隐式 else、`is_checked` 名字必在表中故 `None=>false` 不可达 —— 绑定名总有自身 Rebind 入表)。

### 对抗式审查记录(Phase 15,3-lens workflow + 复核 agent)
3 视角并行(漏报 / 误报 / 稳健-覆盖)+ 综合,以**真实 CST 探针**核验,确认并修复 **2 个 ship-blocker(均为安全漏报)** + 1 个 high 性能:
1. **(ship-blocker,漏报)`name_gated_after` 把 if/while/return/revert **体内**对 `ok` 的任意使用都当成检查** → `if(r.length>0){emit Log(ok);}`(ok 仅在体内打日志)、`return g(ok)`、`while(x){sink(ok)}` 等真实未检查被静默抑制(经典 SWC-104 资金外流)。**修**:重写为 per-occurrence `classify_occurrence`,用**入边标签** `Condition` 精确区分条件 vs 体;`return` 仅直接操作数算 gate;被非 require/assert 调用消费一律算普通使用。补全部回归。
2. **(ship-blocker,漏报)名字复用/shadow**:后来的同名已检查绑定的 gate 被错误归给更早的未检查调用 → `(ok,)=a.call(); ...; (ok,)=b.call(); require(ok);` 把第一个也抑制。**修**:引入 `Rebind` 控制点,`is_checked` 取调用后**第一个**控制点;先遇 Rebind 即判未检查。补名字复用 + 内层 shadow 回归。
3. **(high,性能/DoS)** 每绑定调用都全函数扫描 → O(调用×标识符) 二次,攻击者源(单函数堆叠绑定调用,~84KB)实测数十秒,阻塞 tokio worker。**修**:gate 信息**每函数缓存一次**(by start-offset)+ 名字内查询;补 1500 调用线性回归。原 perf 测试只测裸调用、未覆盖绑定路径,已补。
- **第二轮复核(ground-truth probe,专攻 per-occurrence 重写)** 又抓出 **3 个真问题**(均 probe 验证):
  4. **(ship-blocker,漏报)`return (1, ok)` 元组返回**:`ReturnStatement` 无条件判 Gate,但元组里转发的 `ok` 并非检查 → 真实未检查被抑制。**修**:引入 `combined` 标志(上行经元组/三元/运算符/实参等"值组合器"即置位),`return` 仅在 `combined==false`(即 `ok` 是**直接唯一**返回操作数)才算 Gate。
  5. **(ship-blocker,漏报)`return c ? ok : v` 三元返回**:同根因(经 `ConditionalExpression` 透明上行至 `ReturnStatement`)→ 同 `combined` 修复一并解决;`return ok && x`/`return !ok` 亦随之判未检查(偏保守,安全方向)。
  6. **(high,误报)`for(; ok; )` 条件**:slang 把 for 条件包在 `ExpressionStatement`(其父 `ForStatementCondition`)里,`ExpressionStatement=>None` 抢先命中 → for 条件检查被漏(且原 `ForStatement/Condition` 臂成死代码)→ 已检查调用被误报。**修**:`ExpressionStatement` 命中时窥父,若为 `ForStatementCondition` 则判 Gate;`if`/`while`/`do-while` 条件经 `Condition` 入边直达(已 probe 确认),`for` 单独处理。补元组/三元返回(仍报)、for 条件(不报)、for 体内用(仍报)回归。
  - 复核同时 probe 确认正确:调用自身绑定名 offset 严格小于 `.call`(不自掩);`is_checked` 标识符升序故二分有效;函数缓存键(起始 offset)跨函数互异、无串话;require/assert 头匹配稳健且不误吞 `requireXxx`;Assignment/Tuple 入边判定正确;嵌套/链式调用各自独立分类。

> 状态:✅ Phase 15 完成(`ast.rs` 行覆盖 98.4% —— 余 6 处防御性/不可达:三处循环/查找兜底 `return`、`if-let` 非终结符隐式 else、`enclosing_function` 的 `None` 守卫、`is_checked` 的 `None=>false`(绑定名必有自身 Rebind 入表,故不可达);`audit.rs` 接线 100%;全量 **475 测试** = 372 单元 + 103 集成;**2 轮对抗式审查共 5 个 ship-blocker/high 全修 + 回归**)。

## Phase 16:AST reentrancy(检查-生效-交互/CEI 违反)✅

把启发式 `REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE`(SWC-107 / SCWE-046,checks-effects-interactions)在源码可解析时升级为 **AST 级**。复用 Phase 15 的函数子树 + 语句序(text_offset)+ per-occurrence 地基。

### 启发式的不精确(本期修)
`reentrancy_risk(sig, body)`:取首个外部调用 sink(`.call{value:`/`.call(`/`.delegatecall(`/`.transfer(`/`.send(`)位置后,`has_state_write`(子串里有 `=`/`++`/`--`/`delete`)即报(无 `nonReentrant`/`ReentrancyGuard`/`_status` 时)。问题:**任何**写都算 —— 连写**局部变量**也报(主导误报);且基于子串而非真实语句序。

### AST 检测(精确)
对每个 **`FunctionDefinition`**(与启发式 `scan_functions` 同范围 —— 仅 `function`,不含 modifier/constructor/receive/fallback):
1. **收集状态变量名**(文件级):遍历 `StateVariableDefinition`,取 **`Name` 入边**的标识符(**不是**子树首个标识符 —— 用户自定义类型时首个是类型名,如 `S s;`→首 `S` 名 `s`、`Counters.Counter ctr;`→名 `ctr`)。**文件级**而非单合约 —— 验证源常被 flatten 到单文件,故能覆盖**同文件基合约的继承状态变量**;代价是多合约同名"局部 vs 状态"罕见误报(记录)。
2. **最早外部调用**:函数内 `.call`/`.delegatecall`/`.transfer`/`.send` 的 member access(与启发式 SINKS 同面;不含 `.staticcall`/`.functionCall`),取最小 offset。
3. **调用后的状态写**(offset **大于**最早调用,基标识符 = 子树首个 `Identifier`,如 `bal[k]`→`bal`、`s.f`→`s`,∈ 状态变量集):
   - `AssignmentExpression`(=, +=, …)、`PostfixExpression`(`x++`/`x--`)、`PrefixExpression`(`delete x`/`--x`/`++x`);
   - `TupleDeconstructionStatement`(`(…, stateVar, …) = …` 任一 LHS 目标 —— 取 `=` 左每逗号段首标识符);
   - 数组变更 `stateArr.push(…)` / `stateArr.pop()`(member access 以 `.push`/`.pop` 结尾且基 ∈ 状态)。
4. **守卫**:函数含名字含 `reentran`/`nonreentrant`/`lock`/`mutex` 的 `ModifierInvocation` → 判已守卫、不报(**结构化**检测,免注释污染)。
5. 命中即在**外部调用所在行**发 `REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE`(比启发式的函数头行更精确)。

### 净效果 / 不变量
- 加入 `AST_RULES`:源码可解析时 AST 拥有该规则(`audit_with` 既有 per-file `retain` 自动剔除启发式同规则命中、换上 AST 命中),解析失败/panic/深嵌套降级回启发式。
- **精度提升**:写**局部变量**不再误报(`call(); local++` 不报);**语句序精确**(`state=0; call();` 写在调用前 → 不报);视图/纯函数无状态写故自然不报。
- **指纹**:AST 命中在**调用行**(启发式在函数头行),location 变 → evidence 复用不命中 → 本规则 fingerprint **一次性迁移**(记入变更;受影响仅曾 pin 该规则 baseline/fingerprint 的用户)。
- 评分/分类/严重度不变(同 rule_id/spec/SCWE/EthTrust)。

### 已知取舍(诚实声明)
- **跨文件继承**:基合约状态变量若不在同文件 → 漏报(flatten 源不受影响);**外部调用面**仅低层 sink(任意 `x.foo()` 外部调用的 reentrancy 不报,避免海量误报,与启发式同);**守卫**仅认 modifier(手写 `locked` 布尔锁 + require 而无 modifier 的函数 → 误报,安全方向);**基标识符**法对 `f()[0]=x` 等非常规 lvalue 退化(罕见)。
- 仍是**函数内**:跨函数把状态写搬到 helper 里调用 → 不报(跨函数数据流推迟)。

### 测试与性能(目标 100% 覆盖)
- 命中:`call(); bal[k]=0`、`call(); counter++`、`call(); delete owner`、`call(); s.f-=x`、`.delegatecall`/`.transfer`/`.send` 后写状态。
- 不报:CEI(写在调用前)、`nonReentrant`、只写**局部**、无外部调用、视图函数、写状态但**在调用前**。
- 不回归:解析失败 → 启发式接管(`detection=source`,函数头行);AST 命中 `detection=ast`、在调用行。
- 端到端经 `audit()`:经典 reentrant 仍报且 `detection=ast`;`local_write_only` 不再报(消除启发式 FP)。
- 性能:状态变量集每文件一次;函数分析为子树线性扫描。

### 对抗式审查记录(Phase 16,ground-truth 自审)
多 agent 审查工作流因 session 限额未能执行,改由主循环亲自做 **ground-truth probe 自审**(在 spike 工程内镜像真实逻辑、喂真实 slang CST)。抓出并修复 **3 个真漏报**:
1. **(ship-blocker,BUG/漏报)状态变量名抽取错误**:用"子树首个标识符"对**用户自定义类型**取到的是**类型名**而非变量名(`S s;`→收 `S`、`IERC20 token;`→收 `IERC20`),致 `s.amount=0` 等写被漏、并污染状态集。**修**:改用 `Name` 入边的标识符(`definition_name`)。
2. **(high,回归漏报)元组赋值写被漏**:`(x, owner) = …` 是 `TupleDeconstructionStatement` 而非 `AssignmentExpression`,首版只查后者 → 漏(启发式经 `=` 能抓,属回归)。**修**:加 `TupleDeconstructionStatement`,查 `=` 左各目标基标识符。
3. **(medium,常见写法漏报)数组 `push`/`pop` 状态变更被漏**:`stateArr.push(x)`/`.pop()` 是 member 调用而非赋值(启发式也漏,非回归,但常见)。**修**:加 `.push`/`.pop` member access 且基 ∈ 状态。
- 自审同时 probe 确认正确:CEI 安全(写在调用前)不报、写**局部**不报、`staticcall` 不报、多修饰符下 `nonReentrant` 仍识别、`onlyOwner` 不被误当守卫、读状态(`emit/require/局部=state`)不报、嵌套映射/深层成员/`delete bal[k]`/复合下标写均报、双函数各自独立(安全函数不被另一函数影响)。

> 状态:✅ Phase 16 完成(`ast.rs` 行覆盖 98.6% —— 余 7 处防御性/不可达:循环/查找兜底 `return`/`None`、`if-let` 非终结符隐式 else 等;`audit.rs` 接线 100%;全量 **503 测试** = 400 单元 + 103 集成;自审 3 漏报全修 + 回归)。

## Phase 17:AST access-control(特权函数缺访问控制)✅

把启发式 `ACCESS_MISSING_GUARD_PRIVILEGED_FN`(SC01 / SCWE-016,特权状态变更函数无访问控制)在源码可解析时升级为 **AST 级**。复用 Phase 16 的 `FunctionDefinition` 遍历 + `ModifierInvocation`/`Name` 边 + per-occurrence 地基。

### 启发式的不精确(本期修)
`has_access_guard(sig, body)`:`sig` 子串含 `only`/`authorized`/`restricted`/`requiresAuth` → 守卫;或 `body` **前 280 字符**含 `require(msg.sender`/`msg.sender ==`/`_checkOwner` 等 → 守卫。问题:(a) 子串 `only` 会被参数名/函数名(如 `setOnlyFlag`)误中;(b) 仅看前 280 字符 → 靠后的守卫漏判(误报已守卫函数);(c) `sig.contains("public")` 含参数里的 `public`/`external`(函数类型参数)→ 可见性误判;(d) `msg.sender ==` 子串可能落在日志/赋值里而非真正校验。

### AST 检测(精确)
对每个 **`FunctionDefinition`**:
1. **函数名**:取 `Name` 边子节点;**函数名被包在 `FunctionName` 非终结符里**(与状态变量名是直接 `Identifier` 不同)→ `definition_name` 改为:Name 边子节点若为终结符取其文本,若为非终结符取其内首个 `Identifier`(同时修正 Phase 16 状态变量名抽取的通用性)。`is_privileged_name`(复用 audit.rs 的 26 名单)否则跳过。
2. **跳过纯声明**:接口 / 抽象的 `function f() external;`(无 `{ }` 实现体)—— slang 仍给它一个 `FunctionBody` 节点,但**无 `Block`**;无 `Block` 即跳过(声明不是漏洞,守卫在实现合约上)。
3. **可见性 + 状态可变性**(精确,免函数类型参数污染):只看函数**自身** `FunctionAttributes`(其父为该 `FunctionDefinition` 的直接子节点,经 `go_to_parent` 校验,**非**参数里函数类型的 attributes):须含 `PublicKeyword`/`ExternalKeyword`,且**非** `view`/`pure`(只读函数不改状态,非特权风险 —— 比启发式多消一类误报)。
4. **守卫**(任一即视为已守卫,偏 FN 安全方向,沿用启发式"宁漏勿误判已审计代码";名字集对齐启发式):
   - 自身 attributes 内有访问控制 `ModifierInvocation`(名字 `starts_with("only")` 或含 `auth`/`restrict` —— 覆盖 onlyOwner/onlyRole/authorized/requiresAuth/restricted);
   - 或函数内 `msg.sender` member-access 处于 `require`/`assert` 实参、`if`/`while` 条件、或相等/关系比较(`==`/`!=`/`<`/`>`)中;
   - 或调用 `_checkOwner`/`_checkRole`/`_onlyOwner`/`_authorizeUpgrade`/`_checkAuthorized` 类守卫函数(裸调用或成员调用)。
5. 命中(特权名 + 有实现 + public/external + 非 view/pure + 无守卫)在 **`function` 关键字所在行**发 `ACCESS_MISSING_GUARD_PRIVILEGED_FN`。

### 净效果 / 不变量
- 加入 `AST_RULES`:源码可解析时 AST 拥有该规则(`audit_with` per-file `retain` 自动剔除启发式同规则、换 AST),解析失败/panic/深嵌套降级回启发式。
- **精度提升**:结构化修饰符(不被 `setOnlyX`/参数名误中)、精确可见性(不被函数类型参数的 `external` 误中)、`msg.sender` 守卫**全函数**扫描(不只前 280 字符)且须在真实校验上下文(非日志/赋值)。
- **指纹稳定**:AST 在 `function` 关键字行发,与启发式的"函数头行"**同 location** → evidence 复用命中 → 本规则 fingerprint **不变**(优于 reentrancy 的迁移)。
- 评分/分类不变(同 rule_id/spec/SCWE/EthTrust)。

### 已知取舍(诚实声明)
- **特权判定仍基于名字**(`is_privileged_name`,26 名单):非名单内的真特权函数漏报、名单内的非特权同名函数误报(与启发式同;语义级判定需更深分析)。
- **守卫从宽**:任何 `msg.sender` 比较/任何 only*-类修饰符都算守卫(可能漏报"假守卫");这是有意的安全方向(宁漏勿误判已审计代码,见 spec 的 `fp_notes`)。
- 跨函数(在内部 helper 里校验后再调用特权逻辑)不覆盖。

### 测试与性能(目标 100% 覆盖)
- 命中:特权名 + public/external + 无守卫(`mint`/`withdraw`/`pause`/`upgrade`…)。
- 不报:有 only*-类修饰符、`require(msg.sender==..)`/`if(msg.sender!=..)revert`、`_checkOwner()` 调用、internal/private、非特权名、函数类型参数带 `external` 但函数 internal。
- 不回归:解析失败 → 启发式接管(`detection=source`);AST 命中 `detection=ast` 且在 function 行;指纹与启发式一致(同 location evidence 复用)。
- 端到端经 `audit()`:无守卫 `mint(...) external` 报且 `detection=ast`。

### 对抗式审查记录(Phase 17,ground-truth 自审)
多 agent 审查工作流受 session 限额未能执行,改由主循环 **ground-truth probe 自审**(镜像真实逻辑、喂真实 slang CST)。spike + 自审共抓出并修复 2 个真问题:
1. **(spike 阶段,BUG)函数名抽取失败**:函数名被包在 `FunctionName` 非终结符里(与状态变量名是直接 `Identifier` 不同),旧 `definition_name`(找 label==Name 的 `Identifier`)对函数返回 `None` → 特权名匹配静默失效、全不报。**修**:`definition_name` 改为取 Name 边子节点(终结符取文本,非终结符取其内首个 `Identifier`),同时通用化 Phase 16 的状态变量名抽取。
2. **(自审,误报)接口 / 抽象的纯声明被报**:`interface I { function mint(...) external; }` 因 slang 给 `;` 声明也建 `FunctionBody` 节点,被误判为有实现 → 报。**修**:要求函数含 `Block`(真实 `{ }` 实现)才检测,纯声明跳过。补接口/抽象回归。
- 自审同时 probe 确认正确:per-function 隔离(双函数仅未守卫者报)、嵌套块内 `require(msg.sender==..)` 守卫识别、`onlyRole(MINTER)` 带参修饰符识别、`public payable`、函数类型参数 `external` 不污染可见性、`view`/`pure` 跳过、`msg.sender` 仅日志(`emit`)不算守卫、`_checkOwner()`/成员式 `acl._checkRole()` 守卫、`require(isOwner(msg.sender))` 间接守卫。

> 状态:✅ Phase 17 完成(`ast.rs` 行覆盖 98.4% —— 余 11 处防御性/不可达终结分支;`audit.rs` 接线 100%;全量 **524 测试** = 420 单元 + 104 集成;spike+自审 2 问题全修 + 回归)。

## Phase 18:AST weak-block-randomness(弱区块随机数)✅

把启发式 `WEAK_BLOCK_RANDOMNESS`(SC09 / SCWE-024)在源码可解析时升级为 **AST 级**。这是**误报最多**的启发式之一。

### 启发式的不精确(本期修)
`line_hits`:行内含 `block.timestamp`/`block.number`/`block.difficulty`/`block.prevrandao`/`blockhash(` 即报。问题:`block.timestamp` 在 DeFi 里**无处不在**且多为合法用途(deadline/vesting/cooldown 比较、时间戳记账),启发式对每一处都报 → 海量误报。

### AST 检测(精确)
只在区块源**进入随机数上下文**时报:
1. **区块源**:`MemberAccessExpression` 文本 ∈ {`block.timestamp`,`block.number`,`block.difficulty`,`block.prevrandao`},或 `blockhash(...)` 的 `FunctionCallExpression`。
2. **随机数上下文**(祖先链任一):
   - **取模** `MultiplicativeExpression` 且其 `unparse` 含 `%`(`block.timestamp % n`、`uint(blockhash(..)) % n`);
   - 或 **哈希种子** `keccak256`/`sha256`/`ripemd160` 的 `FunctionCallExpression`(`keccak256(abi.encodePacked(block.timestamp, ...))`)。
3. 命中即在**区块源所在行**发 `WEAK_BLOCK_RANDOMNESS`;**按行去重**(同一表达式里 `blockhash(block.number-1) % n` 的 `block.number` 与 `blockhash` 都命中 → 同行折叠为一条)。

### 净效果 / 不变量
- 加入 `AST_RULES`;源码可解析时 AST 拥有该规则(`audit_with` per-file `retain` 自动替换),解析失败/panic/深嵌套降级回启发式。
- **精度提升**:`require(block.timestamp >= deadline)`、`last = block.timestamp`、`if(block.number > x)`、`block.timestamp + 3600`、`block.timestamp / 2` 等合法用途**不再误报**;仅 `% 取模` / `keccak 种子` 的真随机数用法上报。
- **指纹稳定**:AST 在区块源行发,与启发式的行号一致(同 location)→ evidence 复用 → fingerprint 不变。
- 评分/分类不变(同 rule_id/spec/SCWE/EthTrust)。

### 已知取舍(诚实声明)
- 取模上下文用 `MultiplicativeExpression.unparse().contains('%')` 判定:`a % b * block.timestamp` 这类把区块源与无关取模并列的**罕见**写法会多报(安全方向)。
- 仅认 `% 取模` 与 `keccak/sha 种子`两类随机数上下文;经 helper(如自定义 `random()` 把 `block.timestamp` 取模)间接使用不覆盖(跨函数,推迟);把区块源喂给 `% ` 之外的"随机"运算(异或抽取位等)不报。

### 测试与性能(目标 100% 覆盖)
- 命中:`block.timestamp % n`、`block.number % n`、`block.prevrandao % n`、`uint(blockhash(block.number-1)) % n`、`keccak256(abi.encodePacked(block.timestamp,..)) % n`。
- 不报:`require(block.timestamp>=deadline)`、`last=block.timestamp`、`if(block.number>x)`、`block.timestamp+3600`、`block.timestamp/2`、`keccak256(...msg.sender...) % n`(无区块源)。
- 不回归:解析失败 → 启发式接管(`detection=source`);AST 命中 `detection=ast` 在区块源行;同行折叠为一条。
- 端到端经 `audit()`:`block.timestamp % 100` 报且 `detection=ast`;deadline 比较不报。

### 对抗式审查记录(Phase 18,ground-truth 自审)
多 agent 工作流受 session 限额,改由主循环 **ground-truth probe 自审**(镜像逻辑喂真实 slang CST)。本期逻辑简单(祖先 modulo / keccak 上下文判定),**自审未发现新缺陷**(不同于 reentrancy/access 各有 bug);所有"应报/不报"用例首次即符合预期。自审 probe 额外确认:嵌套加法进取模 `(a+block.timestamp)%n` 报、直接 `keccak256(block.prevrandao)` 报、区块源作除数 `12345 % block.timestamp` 报、keccak 种子无取模也报、`block.timestamp ^ 7`(异或,非 %/keccak)不报;**已知缺口如期**:经局部变量间接 `uint t=block.timestamp; t%6`(跨语句,需数据流)不报、`(last%3)*block.timestamp`(无关取模并列)多报(安全方向)。

> 状态:✅ Phase 18 完成(`ast.rs` 行覆盖 98.6% —— 余 11 处防御性/不可达终结分支(与前序相同,本期新代码全覆盖);`audit.rs` 接线 100%;全量 **537 测试** = 433 单元 + 104 集成)。

## Phase 19:AST ecrecover 零地址校验(签名验证)✅

把启发式 `ECRECOVER_NO_ZERO_CHECK`(SC04 / SWC-122)在源码可解析时升级为 **AST 级**。复用 Phase 15 的 `binding_name` + `enclosing_function` 地基。

### 启发式的不精确(本期修)
`line_hits`:行内含 `ecrecover(` 即报。`fp_notes` 已自认"附近可能有 zero-check"。问题:写得好的签名验证(`address s=ecrecover(..); require(s!=address(0));`,EIP-2612 permit / meta-tx 常见)被误报。

### AST 检测(精确)
`ecrecover(...)` 的 `FunctionCallExpression`,**仅当其恢复地址未与 `address(0)`/`0` 比较**时才报:
1. **内联**:ecrecover 调用本身是某 `EqualityExpression`(`==`/`!=`)的操作数,且该比较含零标记(`require(ecrecover(..)!=address(0))`)→ 已校验。
2. **绑定**:结果赋给变量(`address s = ecrecover(..)` / `s = ecrecover(..)`,经 `binding_name` 取名 `s`),在 `enclosing_function` 内某处 `s` 处于含零标记的 `EqualityExpression`(`require(s!=address(0))` / `if(s==address(0)) revert()`)→ 已校验。
3. **零标记**:`EqualityExpression` 的 squeeze 文本含 `address(0)`(精确,不误中 `address(0x123)`)或 `==0`/`!=0`(零字面量,不误中 `==100`)。
4. 都没有 → 在 **ecrecover 所在行**报 `ECRECOVER_NO_ZERO_CHECK`。

### 净效果 / 不变量
- 加入 `AST_RULES`;源码可解析时 AST 拥有该规则(`audit_with` per-file `retain` 替换),解析失败/panic/深嵌套降级回启发式。
- **精度提升**:`require(s!=address(0))`/`if(s==address(0))revert`/`!= 0`/内联零校验等正确写法**不再误报**;`require(s==signer)`(无显式零校验)、原始使用 `m[ecrecover(..)]=true` 仍报(与启发式同,安全方向)。
- **指纹稳定**:AST 在 ecrecover 行发,与启发式同 location → evidence 复用 → fingerprint 不变。评分/分类不变。

### 已知取舍(诚实声明)
- 顺序无关:只要函数内任一处对结果做了零校验即视为安全(校验在使用之后也算 —— 极少见的"先用后查"会漏报,安全方向偏少报已校验代码,符合 spec 的 `fp_notes`)。
- `require(s==signer)`(signer 为非零存储地址时其实安全)按"无显式零校验"上报(规则定义如此,与启发式同);经 helper(如 OZ `ECDSA.recover` 内部 revert)的间接校验不覆盖(跨函数,推迟)。

### 测试与性能(目标 100% 覆盖)
- 命中:`require(ecrecover(..)==signer)`、`address s=ecrecover(..); require(s==signer)`、`m[ecrecover(..)]=true`。
- 不报:`require(s!=address(0))`、`if(s==address(0))revert()`、`require(ecrecover(..)!=address(0))`、`require(s!=0)`、`address s; s=ecrecover(..); require(s!=address(0))`。
- 不回归:解析失败 → 启发式接管(`detection=source`);AST 命中 `detection=ast` 在 ecrecover 行。
- 端到端经 `audit()`:无零校验报且 `detection=ast`;有零校验不报。

### 对抗式审查记录(Phase 19,ground-truth 自审)
subagent 限额未恢复,继续 ground-truth 自审(镜像逻辑喂真实 slang CST)。逻辑复用 Phase 15 地基且直接,**自审未发现新缺陷**(同 Phase 18 一次过)。spike(8)+ 自审 probe(5)确认:双 ecrecover 仅未校验者报、`assert(s!=address(0))` 也识别(扫全部 `EqualityExpression` 非仅 require)、内联 `if(ecrecover(..)==address(0))revert()` 不报、零字面量 `!=0` 识别、reassign 后校验识别;**已知取舍如期**:`require(ecrecover(..)==signer && signer!=address(0))`(零校验落在 signer 而非恢复地址)与 `require(signer!=address(0)); use(recovered)`(无关零校验)按"恢复地址无显式零校验"上报(安全方向,与启发式同)。

> 状态:✅ Phase 19 完成(`ast.rs` 行覆盖 98.7% —— 余 ~11 处防御性/不可达终结分支(本期新代码全覆盖);`audit.rs` 接线 100%;全量 **548 测试** = 444 单元 + 104 集成)。

## Phase 20:AST 任意 delegatecall(Parity 级接管)✅

**首个 AST 新增规则**(前 6 个 AST 阶段都是精化既有规则,本期**新增** `DELEGATECALL_ARBITRARY_TARGET`,检测器 35→36)。检测**任意目标 delegatecall**:`delegatecall` 到**调用者可控地址** = 在本合约存储上下文里执行任意代码 = 全合约接管(Parity 多签冻结事件)。现有启发式只有泛化的 `DELEGATECALL_USAGE`(Medium,任何 delegatecall 都报);本期补一条**精确的 Critical**。

### 检测(精确)
- 找 `.delegatecall` 的 `MemberAccessExpression`,取**接收者基标识符**(子树首个 `Identifier`,如 `target.delegatecall`→`target`、`address(target).delegatecall`→`target`)。
- 若该标识符 ∈ **所在函数的形参名**(`enclosing_function` 含 fallback/receive + 新 `function_param_names`:函数自身 `Parameter` 的 `Name` 边)→ 报 `DELEGATECALL_ARBITRARY_TARGET`。
- 不报:目标为状态变量 / immutable(代理实现)、函数调用结果(`_impl().delegatecall`)、局部变量、无 delegatecall。

### 规则与接线
- 新 `RuleSpec`:`category="SC06:Unchecked External Calls"`、`swc=SWC-112`、`severity=Critical`(impact 10/likelihood 7/confidence Medium/exploitability Easy/blast_radius protocol);`scwe_ethtrust` = `(SCWE-035, req-1-delegatecall [S])`(与 `DELEGATECALL_USAGE` 同)。**与 `DELEGATECALL_USAGE` 同 category/swc** → `overall_risk` 按 swc 去重取 max(Critical),不重复计分。
- **AST-only**(不在 `AST_RULES`):无对应启发式可替换,纯增量;源码可解析才检出(解析失败时泛化 `DELEGATECALL_USAGE` 仍由启发式/字节码报)。`audit_with` 的 AST 块 `extend` 自动纳入(`retain` 仅动 `AST_RULES`,不影响本规则)。在 delegatecall 行发。

### 已知取舍(诚实声明)
- 仅认**直接形参接收者**;经局部变量中转(`address t=param; t.delegatecall`,跨语句)、或形参先存入状态变量再 delegatecall 不报(需数据流,安全方向偏少报)。
- 形参经白名单校验后再 delegatecall 仍报(无法证明白名单充分,安全方向偏多报);`fp_notes` 注明。
- 任意 delegatecall 的 delegatecall 同时也命中泛化 `DELEGATECALL_USAGE`(两条 finding:Medium 泛化 + Critical 精确;分数按 swc 去重不双计)。

### 测试与性能(目标 100% 覆盖)
- 命中:`function exec(address target,bytes data){ target.delegatecall(data); }`、`address(target).delegatecall(..)`。
- 不报:状态变量 impl、immutable impl、`_impl().delegatecall`、局部变量目标、无 delegatecall、纯声明(无 Block)。
- 端到端经 `audit()`:任意 delegatecall 报 `DELEGATECALL_ARBITRARY_TARGET`(Critical,`detection=ast`)且整体风险升至 Critical;代理 impl delegatecall 不报本规则。

### 对抗式审查记录(Phase 20,ground-truth 自审)
subagent 限额未恢复,继续 ground-truth 自审。逻辑直接(形参集合 + 接收者成员判定),spike(7)+ 自审 probe(5)**未发现新缺陷**:per-function 隔离(双函数仅形参 delegatecall 报)、modifier 形参报、constructor 形参报、形参 shadow 状态变量时报(形参胜)、`address(param)` 转型报;不报:状态变量/immutable/调用结果/局部/无 delegatecall/形参存在但 delegatecall 目标是状态变量。评分确认:与 `DELEGATECALL_USAGE` 同 swc(SWC-112)故 `overall_risk` 去重取 Critical、不双计;两条 finding(泛化 Medium + 精确 Critical)并存。

> 状态:✅ Phase 20 完成(**检测器 35→36**;`ast.rs` 行覆盖 98.7%(本期新代码全覆盖,余 ~11 处前序防御性终结分支);`audit.rs` 接线 100%;全量 **557 测试** = 453 单元 + 104 集成)。

## Phase 21:AST transfer/send 实参计数 + 收窄 downcast 精化 ✅

把**两条误报最高的启发式**升级为 AST(均加入 `AST_RULES`,解析失败降级回启发式):`HARDCODED_GAS_TRANSFER_SEND` 与 `UNSAFE_DOWNCAST_TRUNCATION`。两条原本都是粗子串匹配,FP 极高。

### A. `HARDCODED_GAS_TRANSFER_SEND`(SWC 无 / 2300-gas ETH send)
- **启发式痛点**:`line_hits` 命中 `.transfer(`/`.send(` 后,靠 `eth_transfer_context` **猜关键词**(`token`/`IERC20`/`amount`/`payable`/…)区分 ETH send 与 ERC-20 转账 → `dai.transfer(to, amt)`、`usdc.transfer(...)` 这类**二参 ERC-20 转账**被误判成 ETH send。
- **AST 精化(精确)**:`.transfer`/`.send` 的 `MemberAccessExpression` 是某 `FunctionCallExpression` 的 `Operand` 时,数其**顶层位置实参个数**(`PositionalArguments` 下 `Item` 边)。**恰好 1 个实参** = `addr.transfer(amount)`/`addr.send(amount)`(ETH stipend send,2300 gas,合约接收者/gas 重定价下会失败)→ 报;**≥2 个** = ERC-20 `transfer(to,amt)`/`transferFrom(...)` → 不报。实参个数是**确定性结构判别**,取代关键词猜测。
- **payload 排除(对抗审查后补,零漏报)**:1 参但实参是**字符串/字节字面量或 `abi.encode*` 调用** → 必是同名消息方法(`bridge.send(payload)`),非 ETH send(`address.transfer/send` 只收 `uint256`)→ 不报。
- **副带召回提升**:`addr.transfer(x)` 这类行内无 `amount`/`value` 关键词、原启发式漏报的 1 参 ETH send,AST 也能命中(评分不变,仅 `detection=ast`)。

### B. `UNSAFE_DOWNCAST_TRUNCATION`(SCWE-041,收窄转换)
- **启发式痛点**:`has_narrowing_downcast` 命中任意 `uintN(`/`intN(`(N<256)token → `uint128(0)`(零初始化)、`uint8(0xff)`(掩码)、`uint128(uint64(x))`(嵌套**加宽**)全部误报。
- **AST 精化**:走 `FunctionCallExpression`,operand 为 `ElementaryType` 且关键词解析为 `uintN`/`intN`(N<256)时才算收窄转换;唯一实参满足下列**可证不截断**形态则抑制:
  - **数字字面量**(`DecimalNumberExpression`/`HexNumberExpression`):`uint8(0)`/`uint8(0xff)`/`uint64(1e18)` —— 作者明写的常量。
  - **同族、等宽或更窄的嵌套转换**(`uint128(uint64(x))`,同 unsigned/signed 且内宽≤外宽):外层只加宽;内层转换仍单独检查(若内层收窄则单独报)。
  - **`address(...)` 转型到 ≥160 bit 目标**(`uint160(address(x))`,对抗审查后补):address 恰 160 bit,无损;`uint128(address(x))` 仍报(128<160 确实截断)。
  - 其余(标识符、算术 `a+b`、更宽/异族嵌套转换)→ 报。
- **诚实取舍**:无类型推断,无法证明"变量值必然 fit",故标识符/算术参数仍报(安全方向偏多报);溢出自身目标的字面量(`uint8(300)`)= 罕见的有意掩码,不报(偏少报,文档注明)。

### 关键实现细节(slang trivia 陷阱)
- 新增 `to_child(cursor, EdgeLabel)`:`go_to_first_child` 后按**边标签**前移到目标子节点。**必须如此**:slang 把前导空白/注释作为**trivia 终结子节点**挂在节点下,直接 `go_to_first_child` 会落到 `Whitespace`(如 `uint128 y = uint128(x)` 里 `=` 后那个空格使 cast operand 的 `ElementaryType` 首子节点是空格而非关键词)。按 `Variant`/`Operand`/`Arguments`/`Item` 边导航天然跳过 trivia。现有检测器用 `go_to_next_terminal_with_kind`(前向找特定 kind)故不受影响,仅本期的显式子节点导航需要。
- 接线:两条均入 `AST_RULES`;`audit_with` 对解析成功的文件 `retain` 掉这两条的启发式命中、`extend` AST 命中,并在同 location 复用启发式 evidence 保 SARIF 指纹稳定。`spec`/`scwe_ethtrust`/severity 全不变,仅精度与 `detection` 变。

### 测试与性能(目标 100% 覆盖)
- transfer/send 命中:`payable(msg.sender).transfer(amount)`、`r.send(amount)`、`addr.transfer(x)`(无关键词)、`payable(a).transfer(g(x,y))`(实参嵌套调用不误数);不报:`dai.transfer(to,amount)`、`dai.transferFrom(a,b,c)`、`IERC20(t).transfer(to,amount)`。
- cast 命中:`uint128(x)`、`uint160(addr)`、`int64(s)`、`uint128(a+b)`、`uint64(uint128(x))`(内外皆收窄→2)、`uint8(uint16(uint32(x)))`(→3)、`int128(uint64(z))`(异族→外+内=2);不报:`uint128(0)`、`uint8(0xff)`、`uint128(uint64(z))`(仅内层 1)、`uint256(x)`/`uint(x)`(非收窄)、`bytes32(x)`/`address(x)`(非整型)。
- 端到端经 `audit()`:ERC-20 二参转账不再报 `HARDCODED_GAS_TRANSFER_SEND`;字面量 cast 不再报 `UNSAFE_DOWNCAST_TRUNCATION`;解析失败时两条均回退启发式。

### 对抗式审查记录(Phase 21)
**两轮审查:**

1. **Ground-truth 自审**(把真实算法镜像进 `slang_spike` 跑真 CST):发现并修复 **1 个真实缺陷** —— 显式 `go_to_first_child` 取 cast 目标关键词时落到**前导 trivia(空白)** → 最外层(`= ` 后)的 cast 全部漏报、嵌套 cast 正常;改用 `to_child(Variant)` 按边导航跳过 trivia 后 21/21 用例全过。该 trivia 陷阱亦在 `first_argument_variant`(字面量参数识别)中规避,否则 `uint128( 0 )` 带空格会误报。

2. **多智能体对抗式审查**(subagent 限额恢复,3 lens:false-positive / false-negative / CST-correctness,共 37 个对抗用例,全部用真 slang CST 复核预测)。提出 6 个候选缺陷,逐一在 spike 验证为真后,**修复 2 类零漏报结构性误报**:
   - **`uint160(address(x))` 误报**(评审标记"最常见 FP"):address 恰为 160 bit,`uintN(address(..))`(N≥160)无损;`cast_arg_non_truncating` 增加 address-cast 抑制(`uint128(address(x))` 仍报,因 128<160 确实截断)。
   - **`bridge.send(payload)` 误报 + 回归**:旧启发式要求 value cue 故不报 `messenger.send(payload)`,新 arg-count 规则会报 = 引入回归。修复:实参为**字符串/字节字面量或 `abi.encode*` 调用**(`address.transfer/send` 只收 `uint256`,故必非 ETH send)则抑制 —— 零漏报。
   - **明确推迟到下一阶段(需类型/作用域解析,非本期 AST 能判)**:`uint160(addrVar)`/`uint8(enumVar)`/`endpoint.send(payloadVar)`(标识符接收者/实参无类型信息)、自定义 `transfer(tokenId)`、`using-for` 改写、`type(T).max` 常量、字面量自身溢出(`uint8(300)`,已文档化召回取舍)。这些正是 **scope-aware 名字解析 + 类型解析**(下一阶段)要解决的。

> 状态:✅ Phase 21 完成(检测器仍 36,两条规则**精度大幅提升**,`HARDCODED_GAS_TRANSFER_SEND` 顺带提升召回;`AST_RULES` 6→8;`ast.rs` 行覆盖 98.0%(新代码核心全覆盖,余为 bool/Option 游标 API 的防御性导航守卫,与既有 ~11 处同类);`audit.rs` 接线 100%;全量 **599 测试** = 495 单元 + 104 集成,clippy 零告警)。

## Phase 22:绑定图基础设施(scope-aware 名字/类型解析)——选项 2 第一期 ✅

**目标**:引入 slang **绑定图(BindingGraph)**,把 AST 层从"纯语法树"升级到"带名字解析 + 类型信息"。这是**多期工程(选项 2)的地基**;本期(Phase 22)落地基础设施 + **首批最干净的类型解析精化**(正好消除 Phase 21 对抗审查推迟的那批类型相关误报)。后续 Phase 23+ 再把绑定图用到 reentrancy(任意外部调用面 + 跨文件继承状态)、access-control 等。

### 可行性已验证(spike,2026-06-30)
slang 1.3.6 的 `compilation::CompilationBuilder` + `CompilationBuilderConfig`(从内存喂源码)→ `CompilationUnit::binding_graph()` → `BindingGraph`:
- `bg.reference_at(&ident_cursor) -> Option<Reference>`;`reference.definitions() -> Vec<Definition>`(go-to-definition,**作用域正确、处理同名 shadow**)。
- `definition.definiens_location()`(`BindingLocation::UserFile(u)` → `u.cursor()`)给出**声明节点**(`Parameter`/`StateVariableDefinition`/`VariableDeclarationStatement`)→ 可读其**声明类型**。
- spike 实测:`target.delegatecall`→`target`=Parameter/address;`impl.delegatecall`→`impl`=StateVariable/address;`uint160(a)`→`a`=Parameter/address。建图 ~27ms/小合约(可接受,远小于网络抓取)。
- 纯 Rust(stack-graphs),**MSVC 干净**,无新增 C 依赖。注意:`InternalCompilationBuilder`、`Definition::get_cursor` 被 `#[cfg(feature=...)]` 私有化,只能走公开 `CompilationBuilder` 路径。

### 架构变化(关键)
- 绑定图按**编译单元(整个合约的全部源文件一起)**构建,而非单文件 → 能跨文件解析继承。故 AST 层需从 `detect(content: &str)`(单文件)增加一个**合约级入口** `detect_unit(files: &[SourceFile]) -> Option<…>`:一次建图,跑需要解析的检测器。
- `audit_with` 在 per-file 启发式扫描之外,先尝试 `detect_unit` 建图;成功则绑定图增强的检测器接管;**任何失败(建图错/版本不符/解析错)整体降级**回 Phase 14–21 的 per-file `detect`,再降级回启发式(三级 graceful degradation)。
- 评分/指纹/`AST_RULES` 语义不变;只增精度。

### 本期落地的精化(消除 Phase 21 推迟的类型相关 FP,零漏报方向)
1. **`UNSAFE_DOWNCAST_TRUNCATION`**:`uintN(x)` 的实参 `x` 经绑定图解析——若 `x` 声明类型是 **`address`** 且 `N≥160`(或 **enum**,或位宽 ≤ N 的整型)→ 无损 → 不报。消除 `uint160(addrVar)`、`uint8(enumVar)`、`uint128(uint64Var)`(变量而非内联 cast)等。
2. **`HARDCODED_GAS_TRANSFER_SEND`**:`recv.transfer/send(x)` 的接收者 `recv` 经绑定图解析——声明类型为 **`address`/`address payable`** → 真 ETH send → 报;为**合约/接口类型**(messenger/bridge/endpoint)→ 非 ETH → 不报。彻底解决 `endpoint.send(payload)`(标识符接收者)这一对抗审查 high。
3. **`DELEGATECALL_ARBITRARY_TARGET`**:接收者经局部变量中转(`address t = param; t.delegatecall`)现可经绑定图回溯到形参 → 补 Phase 20 的跨语句 alias 漏报。

### graceful degradation 与降级语义
- 绑定图解析返回 `None`(无法解析、跨文件缺失、内置类型)时,**回退到 Phase 21 的纯语法判断**(保守方向:该报还报),绝不因解析失败而漏报。
- 类型解析只用于**收紧(抑制已知无损/非 ETH)**或**补召回(alias 回溯)**,不改变"无信息时保守报"的基线。

### 测试与性能(目标 ~100% 覆盖)
- 单元(绑定图解析):addr 变量/enum 变量/窄整型变量的 cast 不报;uint256 变量 cast 仍报;address 接收者 send 报、合约接收者 send 不报;局部 alias delegatecall 报。
- 降级:坏语法 / 多文件缺失 → `detect_unit` None → 退回 `detect` → 退回启发式(三级各一测试)。
- 性能:大合约(N 函数)建图 + 解析的 wall-clock 上界回归(绑定图比纯解析重,需基准护栏)。

### 对抗式审查记录(Phase 22)
**两轮:**

1. **Ground-truth 自审**(spike 跑真绑定图):发现并修复 1 个真实导航缺陷 —— 用 `clone()`(保留全树上下文)而非 `spawn()`(子树有界)做 `go_to_next_*` 时**逃出声明子树**,导致用户类型(enum/interface)解析到错误节点;改 `spawn()` 后全部正确。另确认 `mapping`/`address[]`/函数类型声明经 `_ => Other` 正确兜底(不误判)。

2. **3-lens 多智能体审查**(false-negative / binding-correctness / degradation,20 用例)。提出 **7 个真实缺陷,全部修复**:
   - **(高×2 + 中×2)`resolve_import` 不健全**:① 忽略相对路径(`./Token.sol` 不按导入文件目录归一化,而 Etherscan `sanitize_path` 把 key 里的 `./` 剥掉 → 主流相对导入静默失败,`endpoint.send(payload)` 误报复活);② 双向裸 `ends_with` 无路径边界(`"@oz/ERC20.sol".ends_with("20.sol")` 误中无关文件 / `xToken.sol` 误中 `Token.sol`)。**修复**:相对路径按导入文件目录 `normalize_join`(折叠 `.`/`..`)后精确匹配;后缀匹配改为**路径段边界对齐**(`id == tail || id.ends_with("/tail")`),去掉不健全的反向 `ends_with`。
   - **(中 + 低)重复 path**:Etherscan 清单两个 key 经 `sanitize_path` 折叠成同一 path → `Vec<SourceFile>` 出现重复 path,`audit_with` 的 `map.remove`(消费式)在第二次命中 None → 重复文件的 `AST_RULES` 启发式命中未被丢弃,FP 复活;`add_file` 也被调两次。**修复**:`detect_unit` 内按 path 去重(首个胜),`audit_with` 循环按 path 去重。
   - **(中)深度守卫不全**:`too_deeply_nested` 只数括号;**扁平链**(`a.b.c…`/`1+1+…`)每 token 一帧而无括号 → spike 实测 20k 链**栈溢出**(`catch_unwind` 拦不住)。**修复**:守卫增加按语句重置的**操作符/成员链长上界** `MAX_EXPR_CHAIN=256`。

> 状态:✅ Phase 22 完成(绑定图基础设施 + scope-aware 类型解析;消除 Phase 21 推迟的 `uint160(addrVar)`/`uint8(enumVar)`/`endpoint.send(payload)` 等类型相关 FP;三级 graceful degradation;`AST_RULES` 仍 8;检测器仍 36)。全量 **625 测试** = 521 单元 + 104 集成(Phase 22 收尾时的快照;其后的发布前加固审计又补了 12 个用例,当前总数为 **637** = 532 单元 + 105 集成,以 [ARCHITECTURE.md](ARCHITECTURE.md) 为准);全工作区行覆盖 **97.9%**(`audit.rs` 100%,`ast.rs` 97.0%);clippy 零告警。后续 Phase 23+:绑定图扩到 reentrancy(跨函数/继承状态)、access-control;delegatecall 局部 alias 回溯。

## Phase 23:绑定图扩面(一)——delegatecall 局部 alias 回溯 ✅

**目标**:Phase 20 的 `DELEGATECALL_ARBITRARY_TARGET` 只在 delegatecall 的接收者**字面上就是形参名**时才报。真实的接管漏洞常常隔着一次局部赋值:

```solidity
function exec(address target, bytes calldata data) external {
    address impl = target;      // 一次中转
    impl.delegatecall(data);    // Phase 20 漏报:impl 不在形参名集合里
}
```

Phase 22 已把绑定图接进 AST 层,本期用它把接收者**回溯到定义**,消除这类漏报。这是「选项 2」多期工程的第二期,只动一条规则,把绑定图从「读类型」推进到「读定义 + 跟数据流」。

### 现在的不精确
`detect_arbitrary_delegatecall` 用 `function_param_names(&func).contains(&receiver)` —— 纯名字集合匹配,两个方向都不准:
- **漏报**:经任意局部变量中转即失效(上例)。这是 Parity 级接管,漏掉的代价最高。
- **误报**:名字匹配**不区分作用域**。局部 `address target = address(this); target.delegatecall(…)` 若与某形参同名会被误报——固定地址的正常代理模式被判成任意接管。

### 本期检测(精确)
接收者标识符经绑定图 `reference_at → definitions → definiens_location` 解析到**声明节点**,按节点种类判定:

| 声明节点 | 判定 | 理由 |
|---|---|---|
| `Parameter` | **报** | 形参可控 = 调用者可控;含 Phase 20 的直接情形,且**作用域正确** |
| `VariableDeclarationStatement` | **回溯** | 取初始化表达式的基标识符递归,深度上限 `MAX_ALIAS_HOPS` |
| `StateVariableDefinition` | 不报 | 固定实现地址,正常代理模式 |
| 其他 / 无初始化 / 解析失败 | 不报 | 无信息时不制造误报 |

### 净效果 / 不变量
- `AST_RULES` 仍 8;检测器仍 36;rule_id / 评分 / SARIF 指纹语义**均不变**——只增精度。
- **降级严格保持 Phase 20 语义**:`bg` 为 `None`(单文件 `detect` 路径、建图失败、跨文件未解析)时,回退到原有名字匹配,一行行为都不变。
- 与泛化的 `DELEGATECALL_USAGE` 仍按 swc 去重,不重复计分。

### 已知取舍(诚实声明)
- 只回溯**直接赋值链**(`address t = param;`)。经数组/映射/结构体字段、函数返回值、`abi.decode` 中转的不追——这些需要真正的跨语句数据流,属后续。
- 回溯深度封顶 `MAX_ALIAS_HOPS = 4`,超长链按未命中处理(**保守方向:不报**),避免病态输入放大解析成本。
- **只跟随裸别名** `address a = b;`。任何复合初始化(三元、比较、函数调用、成员访问、类型转换)一律不跟随 → 该追的追不到(漏报),但**绝不会把复合表达式里的某个标识符误当成目标**。
  - 初版曾试图「取初始化表达式的第一个标识符」,被对抗式审查判为 ship-blocker:slang 的 `ConditionalExpression` 把**条件排在最前**,于是 `address impl = useV2 ? v2 : v1;`(两分支都是固定状态变量、仅条件是形参)会解析到 `useV2` 并报 Critical —— 对一个标准的双实现代理误报。详见下方审查记录。
- 仍是单函数内的回溯;跨函数传递(`helper(target)` 内部 delegatecall)不在本期。

### 测试与性能(目标 ~100% 覆盖)
- 命中:一跳 alias、两跳 alias、直接形参(Phase 20 回归)。
- 不命中:状态变量接收者、`address(this)` 局部、无初始化声明、超过深度上限的链。
- **消除误报**:局部变量与形参同名(shadow)且初值为固定地址 → 不报(名字匹配会误报,绑定图不会)。
- 降级:`detect`(无 bg)路径下行为与 Phase 20 逐条一致。

### 对抗式审查记录(Phase 23,3-lens workflow + 双证伪 agent,13 个 agent)

三个独立视角(false-negative / binding-correctness / degradation)并行审查,每条发现再由**两个持反对立场的 agent 尝试证伪**(默认判定不成立——似是而非的发现比没有发现更糟)。12 条原始发现 → 取严重度最高的 5 条进入证伪 → **2 条确认、3 条被证伪**;7 条低严重度未进入证伪(诚实声明:未验证 ≠ 不存在)。

**确认的 ship-blocker(binding-correctness 与 degradation 两个视角独立收敛到同一处 `ast.rs:1176`)**

初版在 `VariableDeclarationStatement` 分支用 `go_to_next_terminal_with_kind(Identifier)` 取「初始化表达式的第一个标识符」。但该调用返回的是**整个子树里的第一个** Identifier,而 slang 的 `ConditionalExpression` 把条件排在真假分支之前 —— 于是形参只要出现在**条件**里就会被当成 delegatecall 目标追下去:

```solidity
contract P { address v1; address v2;
  function run(bool useV2, bytes calldata data) external {
    address impl = useV2 ? v2 : v1;   // 两个分支都是合约固定的实现
    impl.delegatecall(data);          // 初版:报 Critical(误报)
  } }
```

**本地实测复现(未采信 agent 结论,自行跑了探针)**:

| 用例 | `detect_unit` | `detect` |
|---|---|---|
| 形参作**条件**,两分支固定 | **true(误报)** | false |
| 对照:条件是状态变量 | false | false |
| 对照:形参在**分支**上 | false | false |

第二行证明确实是**条件标识符**在驱动误报;第三行说明本节原先声明的「三元漏报」是**另一个**案例,方向与实际危险相反。

这同时破坏了两条不变量:**「只增精度」**(Phase 20 在此不报,Phase 23 报了,是净新增的误报类别)与**「不确定时保守」**(三元正是「哪个值流过来」的典型不确定性,代码却做了猜测)。

**修复**:只跟随**裸别名**——比较 `VariableDeclarationValue` 的 `squeeze` 文本与 `={标识符}` 是否完全相等,不等即停止回溯。两条回归测试同时钉住误报案例与若干复合初始化形态。

**被证伪的 3 条(记录在案,避免重复提出)**
- *内联汇编 `delegatecall` 不可见* —— 机制属实但并非本期引入,且证伪方指出其核心论断(「审计器对含汇编代理零 delegatecall 发现」)不成立。
- *非裸标识符接收者会静默退回名字匹配* —— 这是**已声明的降级契约**,非缺陷,且不违反三条不变量。
- *只读声明初始化、后续重赋值追不到* —— 机制属实,但既非本期引入也不违反不变量(且属已声明取舍)。

> 状态:✅ Phase 23 完成(delegatecall 接收者经绑定图回溯到定义,补上「一次局部赋值即漏报」的 Parity 级接管;顺带消除 `function_param_names` 过度收集导致的误报)。`AST_RULES` 仍 8、检测器仍 36、rule_id / 评分 / SARIF 指纹不变。全量 **655 测试** = 550 单元 + 105 集成,clippy 零告警(**本机实测**,非仅 CI)。对抗式审查确认并修复 1 个 ship-blocker。后续 Phase 24+:reentrancy 跨文件继承状态、access-control 消除名字启发式。

## Phase 24:绑定图扩面(二)——reentrancy 跨文件继承状态 ✅

**目标**:`REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE` 判断「写的是不是状态变量」目前靠**当前文件的名字集合**(`state_variable_names(root)`)。这在两个方向都不准。

**漏报(主要,也是本期动机)**——状态变量继承自另一个文件时,当前文件的名字集合里根本没有它:

```solidity
// Base.sol
contract Base { mapping(address => uint) internal balances; }

// Vault.sol
import "./Base.sol";
contract Vault is Base {
    function withdraw() external {
        (bool ok, ) = msg.sender.call{value: balances[msg.sender]}("");
        balances[msg.sender] = 0;   // 教科书级 CEI 违反 —— 却不报
    }
}
```

**误报**——局部变量遮蔽同名状态变量时,写局部被当成写状态:

```solidity
contract C {
    uint total;
    function f() external {
        uint total = 1;                    // 局部,遮蔽
        (bool ok, ) = msg.sender.call("");
        total = 2;                         // 写的是局部,不是 CEI 违反
    }
}
```

**还有一处结构性漏报**:`detect_reentrancy` 开头有 `if state.is_empty() { return; }` 的提前返回。子合约若**自身不声明任何状态变量、全部继承**,当前文件名字集合为空 → 整个函数体不再检查。这恰好是本期要覆盖的场景,必须一并解除。

### 本期检测(精确)
写入目标的**基标识符**经绑定图解析到定义:

| 定义节点 | 判定 |
|---|---|
| `StateVariableDefinition` | 是状态写入(**跨文件、含继承**) |
| `VariableDeclarationStatement` / `Parameter` | 不是(局部/形参,消除遮蔽误报) |
| 解析失败 | **退回当前文件名字集合**——既有行为,不产生任何方向的回归 |

有绑定图时,`state.is_empty()` 提前返回同步解除(名字集合仅作兜底,不再是「有没有状态变量」的判据)。

### 把 Phase 23 的教训带进来(初版没带够,已修正)
本节初稿写的是:四种写入形态都是「操作数在前」,所以复用既有的「取子树第一个标识符」是安全的。**这个论证是错的**,并被本期对抗式审查当场证伪。

「操作数在前」成立,但**不蕴含「子树里第一个 `Identifier` 终结符就是左值基」**——操作数本身可以是带括号的三元:

```solidity
(useFirst ? a : b)[0] = 1;   // 首标识符 = useFirst(条件),而非 a/b
this.x = 1;                  // 首标识符 = x(成员名),base 是关键字
```

于是 Phase 23 的缺陷类别**原样复发**。修正后改为**按边标签导航**:`AssignmentExpression` 走 `LeftOperand`,前缀/后缀/成员访问走 `Operand`;随后要求该标识符**位于操作数文本开头**。不满足则返回 `None`,调用方保留旧答案,而不是把错误的 token 喂给绑定图。

### 净效果 / 不变量
- `AST_RULES` 仍 8;检测器仍 36;rule_id / 评分 / SARIF 指纹**不变**——只增精度。
- 无绑定图(单文件 `detect` 路径、建图失败)时**逐行退回 Phase 16 行为**,含 `state.is_empty()` 提前返回。
- 解析失败时退回名字集合,而非武断判定——不确定不改变既有结论。

### 已知取舍(诚实声明)
- **元组解构** `(a, stateVar) = f()` 仍走字符串解析 + 名字集合,本期不改:它需要逐个左值目标的结构化定位,风险与收益不匹配。故继承来的状态变量若只在元组左值里被写,仍漏报。
- 仍不区分「写的是同一个存储槽」——`balances[k]` 与 `balances` 视作同一变量。
- **同文件**的三元左值(`(cond ? a : b)[0] = 1`,`cond` 为本文件状态变量)仍会误报:那是 Phase 16 起的既有不精确,走的是名字集合兜底路径。本期只修了绑定图路径扩大出来的跨文件部分——修兜底路径会改变无图时的行为,违反「精确降级」不变量,故留待单独一期。
- 外部调用面仍限于 `REENTRANCY_SINKS` 的低层调用,任意外部方法调用(`token.transfer(...)`)不在本期。

### 测试与性能(目标 ~100% 覆盖)
- 跨文件:`Base.sol` 声明状态、`Vault.sol` 继承并在外部调用后写 → 单文件 `detect` 不报、`detect_unit` 报。
- 提前返回解除:子合约自身零状态变量的同一场景 → 仍报。
- 消除遮蔽误报:局部与状态同名、调用后写局部 → 名字集合报、绑定图不报。
- 回归:Phase 16 的既有用例全部维持原判。

### 对抗式审查记录(Phase 24,3-lens workflow + 双证伪 agent,13 个 agent)

三视角(false-positive / false-negative / navigation)并行,每条发现两个 agent 尝试证伪。**3 条确认、2 条被证伪、6 条低严重度未验证**。

**确认 1+2(两个视角独立收敛)——Phase 23 缺陷类别复发**

本期最初的正确性论证(见上)被证伪:带括号三元作左值时,首标识符是**条件**。实测:

| 用例 | `detect_unit` | `detect` |
|---|---|---|
| 跨文件 `(useFirst ? a : b)[0] = 1`(`useFirst` 为继承状态,a/b 是 memory) | **true(误报)** | false |
| 同文件同形态 | true | true |

第二行说明**这处导航缺陷自 Phase 16 就存在**;Phase 24 的责任是把它**扩大到跨文件**,并且因为解除了 `state.is_empty()` 提前返回,让它能在此前根本不会触发的文件里发作。修复见上(边标签导航)。

**确认 3 —— `.push`/`.pop` 把外部调用当成状态写入**

`.push`/`.pop` 分支只看名字后缀与「基是否为状态变量」。若状态变量是**合约/接口类型**,`q.push(1)` 其实是一次外部方法调用,本合约什么都没写:

```solidity
contract QHolder { IQueue internal q; }
contract QUser is QHolder {
  function ping() external { (bool ok,) = msg.sender.call(""); q.push(1); }  // 误报
}
```

同样是 Phase 16 起就有、被 Phase 24 扩到跨文件。修复:复用 `resolve_decl_type`,基解析为 `ContractLike` 时不计作状态写入(与 `detect_eth_transfer_send` 区分 `endpoint.send(payload)` 同一套机制)。配套反向用例钉住「继承来的真数组 `xs.push(1)` 仍要报」,确保没有连真发现一起压掉。

**被证伪的 2 条**:storage 指针别名解析为 `VariableDeclarationStatement`(机制属实,但本期未改变任何判定)、单个文件触发 `too_deeply_nested` 导致整单元降级(可复现,但行为与改动前逐字节相同)。

> 状态:✅ Phase 24 完成(reentrancy 的状态判定由「当前文件名字集合」升级为绑定图定义解析:跨文件继承状态可见、局部遮蔽误报消除、`state.is_empty()` 提前返回在有图时解除)。`AST_RULES` 仍 8、检测器仍 36、rule_id / 评分 / 指纹不变。全量 **663 测试** = 558 单元 + 105 集成,clippy 零告警(本机实测)。对抗式审查确认并修复 3 个问题,其中 2 个是 Phase 23 缺陷类别的复发。后续 Phase 25+:access-control 消除名字启发式;reentrancy 的任意外部方法调用面。

## Phase 25:绑定图扩面(三)——access-control 由名字清单升级为守卫变量写入 ✅

**目标**:`ACCESS_MISSING_GUARD_PRIVILEGED_FN` 判定「这个函数是否特权」靠 `is_privileged_name`——**26 个名字的精确匹配**。这在真实语料上漏得很厉害。

### 先量化(本地语料 out/,248 个 .sol,46 个合约)
外部可调用、非 view 的函数名 153 个(出现 868 次)。其中「特权样貌」的 55 个 / 243 次:

| | 名字数 | 出现次数 |
|---|---|---|
| 26 名单精确命中 | 9 | 93 |
| **漏掉** | **46** | **150(约 62%)** |

漏掉的高频项:`initialize`(31)、`setFeeTo`(13)、`setFeeToSetter`(13)、`setProtocolFee`、`updateDynamicLPFee`、`collectProtocolFees`……

> ⚠️ **这个 62% 不是「漏报率」,当初拿它当立项依据是个范畴错误**(经本期对抗式审查暴露)。它衡量的是「名字清单匹配不到多少特权样貌的名字」,而不是「规则漏掉多少真实漏洞」——那 46 个名字里大多数要么**本来就有守卫**(会被正确跳过、不该报),要么**根本不是特权函数**(`setApprovalForAll`)。真实收益见下方「实测收益」。

**但同一批数据也否掉了「简单扩大名单」这条路**:漏掉的里面有 `setApprovalForAll`(ERC-721/1155 标准,任何用户设自己的 operator)、`swapExactTokensForETH…`、`burnFrom`——**都不是特权函数**。按名字放宽会立刻制造误报。所以必须换语义判据。

### 语义判据:写入「守卫变量」
定义:**守卫变量** = 编译单元里被拿来与 `msg.sender` 比较的状态变量(`require(msg.sender == owner)`、`if (owner != msg.sender) revert`)。

一个函数若**外部可调用、非 view、有实现、无守卫,却写入某个守卫变量**,那它就是在无鉴权地改变「谁有权限」——与它叫什么名字无关。

这个判据在上面的数据上区分得恰到好处:
- `setFeeToSetter` 写 `feeToSetter`,而 `feeToSetter` 正是 `require(msg.sender == feeToSetter)` 里的守卫 → **命中**(名单漏掉的)
- `setApprovalForAll` 写的是 `_operatorApprovals[msg.sender][op]`,不是守卫变量 → **不报**(正确)
- `setFeeTo` 自身带 `require(msg.sender == feeToSetter)` → 有守卫 → 不报(正确)

**与名字清单取并集**,不做替换:纯增召回,不动既有检出。

### 导航:复用 Phase 24 建立的正确范式
守卫收集与写入判定都**按边标签导航**(`EqualityExpression`/`InequalityExpression` 的 `LeftOperand`/`RightOperand`,已实测确认),并要求标识符**位于操作数文本开头**——不满足就跳过。连续两期的确认缺陷都源于「取子树第一个标识符」,本期把该判断抽成单一助手 `leading_identifier`,由 `lvalue_base_identifier` 与守卫收集共用,不再各写一份。

### 跨文件
守卫变量在 `detect_unit` 里**先扫全部文件收集一遍**,再逐文件跑检测器——因为守卫往往定义在基合约(`Ownable`)所在的另一个文件里,而无守卫的写入在子合约文件里。

### 实测收益:在现有语料上为 0(诚实声明)

实现完成后,用真实编译单元路径跑了全部语料:

```
units=42  degraded=0  access_by_name=31  access_guard_only=0
```

**新判据贡献 0 条新发现。** 两种解读都要说清楚:

- **有利**:语料是 42 个已审计、已上线的生产合约。本判据检出的是「无鉴权地改变谁有权限」这一**真实漏洞**;在没有该漏洞的代码上返回 0 是正确答案,同时说明**误报面在真实代码上实测为 0**。
- **不利**:收益是**前瞻性的、未在真实数据上证实的**。机制正确不等于召回已兑现。

结论:保留本期(语义正确、误报实测为 0、覆盖一个真实漏洞类别),但**不主张已兑现的召回收益**。

### 净效果 / 不变量
- `AST_RULES` 仍 8;检测器仍 36;rule_id / 评分 / 指纹**不变**。
- 无绑定图时守卫集合为空,判定退化为「仅名字清单」= Phase 17 行为,逐行不变。
- 与名字清单取并集 → 既有检出一条不少。

### 已知取舍(诚实声明)
- 守卫变量按**定义名**去重,不带合约身份:两个不同合约各有一个 `owner`、其中之一用作守卫时,另一个的写入也会被算作特权 → 可能误报。跨合约同名消解需要定义级身份,留待后续。
- 只认 `msg.sender` 比较。`hasRole(ROLE, msg.sender)` / `onlyRole(...)` 形态的角色常量不算守卫变量(授予角色本身另有 `grantrole` 在名单里)。
- 只看**直接赋值 / 前后缀**写入形态;元组解构与 `.push` 不计入特权判定。
- 守卫只认**裸标识符**:`require(msg.sender == cfg.admin)` / `stakes[u].delegate` 不进守卫集合(见审查记录)。按完整访问路径记录可恢复这部分召回,留待后续。
- 只认字面 `msg.sender`。OpenZeppelin 的 `_msgSender()` 间接层、`hasRole(ROLE, msg.sender)`、`require(admins[msg.sender])` 映射守卫均不算。

### 对抗式审查记录(Phase 25,4-lens workflow + 双证伪 agent,14 个 agent)

四视角(corpus-truth / false-positive / false-negative / invariants),其中 corpus-truth 专门要求在真实语料上量化。

**确认的 ship-blocker —— 守卫集合的粒度错误**

`collect_guard_variables` 用 `leading_identifier` 取比较另一侧的标识符。该助手对**左值**正确(`cfg.feeBps = b` 确实写入 `cfg`),但用在**读**操作数上语义反转:`msg.sender == cfg.admin` **不能**让整个 `cfg` 成为守卫。于是「写了守卫容器的任一字段」被当成「写了守卫」。

本地实测(修复前):

| 布局 | 结果 |
|---|---|
| 普通 `address admin` 守卫 | `[]` ✓ |
| 守卫在结构体字段 `cfg.admin` | 误报 `setFeeBpsX` |
| **AppStorage / diamond** | **3 条**,含普通 ERC-20 `transfer` |

第三行是要害:diamond 模式把全部状态放在一个结构体变量后面,于是**单元内每个 public 函数都被报**——而这是 2021 年后 Solidity 的主流布局。

**归因(采纳验证方的修正)**:这**不是** Phase 23/24 的「取错 token」。`leading_identifier` 在两个调用点都取对了;错的是**守卫集合按变量名记录**这一层的过度近似。所以该修的是键的粒度,不是助手。

**修复**:守卫只认**裸标识符**(新增 `bare_identifier`);`cfg.admin` / `stakes[u].delegate` 这类形态不进守卫集合,对这些形状退回 Phase 17 行为。修复后实测 `member=0`、`appstorage=0`。

**同一轮的第二个结论:立项依据站不住**(见「实测收益」)。审查测出新判据在语料上贡献 0 条,并指出开头那个 62% 是**名字覆盖率**而非漏报率。这条比代码缺陷更重要——它纠正的是我的推理,不是我的导航。

> 状态:✅ Phase 25 完成(access-control 判据由「26 名字精确匹配」扩为「名字 ∪ 写入守卫变量」;守卫变量 = 单元内与 `msg.sender` 比较的**裸**状态变量,跨文件收集)。`AST_RULES` 仍 8、检测器仍 36、rule_id / 评分 / 指纹不变。全量 **670 测试** = 565 单元 + 105 集成,clippy 零告警(本机实测)。对抗式审查确认并修复 1 个覆盖面极广的误报类别,并纠正了本期立项依据。后续 Phase 26+:守卫按**完整访问路径**记录(恢复本期让出的召回)、`_msgSender()` / `hasRole` 形态、同文件三元左值的既有不精确。

## 明确的局限(诚实声明)
- 启发式 linter,非形式化验证:会有误报/漏报。源码可解析时走 **AST 精化**(slang_solidity):Phase 14 `TX_ORIGIN_AUTH`(仅鉴权上下文)/`UNCHECKED_LOW_LEVEL_CALL`(结果被消费);Phase 15 函数内数据流(绑定成功布尔在调用后确被 gate 才抑制);Phase 16 `REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE`(低层外部调用后写**状态变量**、无 `nonReentrant` 守卫;排除写局部、CEI 安全);Phase 17 `ACCESS_MISSING_GUARD_PRIVILEGED_FN`(特权名 + public/external + 有实现 + 非 view/pure + 无修饰符/msg.sender 守卫;结构化修饰符 + 全函数 msg.sender 扫描,跳过接口/抽象声明);Phase 18 `WEAK_BLOCK_RANDOMNESS`(区块源仅在 `% 取模` / `keccak/sha 种子`上下文才报,消除 deadline/记账等合法用途的海量误报);Phase 19 `ECRECOVER_NO_ZERO_CHECK`(恢复地址未与 `address(0)`/`0` 比较才报,消除写得好的签名验证误报);Phase 20 **新增** `DELEGATECALL_ARBITRARY_TARGET`(Critical,AST-only:delegatecall 到形参可控地址 = Parity 级接管);Phase 21 `HARDCODED_GAS_TRANSFER_SEND`(按**实参个数**区分 1 参 ETH send 与 ≥2 参 ERC-20 转账,消除 `dai.transfer(to,amt)` 误报)/`UNSAFE_DOWNCAST_TRUNCATION`(抑制字面量与同族嵌套加宽)。解析失败/panic/深嵌套自动降级回启发式(AST-only 的 `DELEGATECALL_ARBITRARY_TARGET` 解析失败时不检出,但泛化 `DELEGATECALL_USAGE` 仍报)。**仍待后续**:access-control/reentrancy 的特权判定仍基于名字、守卫从宽;reentrancy 任意外部方法调用面 + 跨文件继承状态;跨函数数据流、scope-aware 名字解析(消除同名 shadow / 跨合约同名残留)。
- 源码检测仅对已验证合约;未验证合约只有字节码级信号 + `unverified` 标记。
- 行级正则做注释感知,但不解析字符串字面量(极少数字面量内的关键字可能误报)。
