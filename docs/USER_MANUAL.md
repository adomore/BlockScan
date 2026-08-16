# BlockScan 用户手册

> 🌐 语言:**中文** · [English](USER_MANUAL.en.md)

BlockScan 是一个 Rust 命令行工具,用于**发现以太坊(及兼容 EVM 链)智能合约 → 下载已验证源码 + 链上字节码 + 合约详情 → 静态分析与安全审计 → 过滤 → 落盘 → 机器/人类可读输出**,并提供一条**防御性监控/告警**支线,以及一个把全部能力暴露给 AI agent 的 **MCP 服务器**。

> 🚀 **第一次用?** 先读 [新手指南 GETTING_STARTED.md](GETTING_STARTED.md) —— 十分钟装好、配好、扫到第一个合约。本手册是逐参数的完整参考。

> 本手册面向使用者。架构与模块内部见 [ARCHITECTURE.md](ARCHITECTURE.md);各功能域详细设计见 [AUDIT_DESIGN.md](AUDIT_DESIGN.md) / [MONITOR_DESIGN.md](MONITOR_DESIGN.md) / [DISCOVERY_DESIGN.md](DISCOVERY_DESIGN.md) / [OUTPUT_DESIGN.md](OUTPUT_DESIGN.md) / [MCP_DESIGN.md](MCP_DESIGN.md)。

### 功能状态一览

**✅ 已完成**:扫描三模式(`addresses`/`range`/`watch` 下载 + `--trace` 工厂发现 + `--chains` 多链)· 项目发现 `discover`(Blockscout/GitHub/官网/Google/DefiLlama/TokenList/CoinGecko/事件 topic)· 详情下载(RPC + Etherscan V2 + Sourcify 回退,代理 EIP-1167/1967/1822)· 静态分析(opcode/ERC 接口/keccak 指纹/克隆聚类)· **安全审计引擎**(36 检测器 · OWASP→SWC→rule_id→SCWE/EthTrust · 多因子评分 · **AST 精化 + 函数内数据流 + reentrancy + access-control + weak-randomness + ecrecover + 任意 delegatecall + transfer/send 实参计数 + 收窄 cast**)· `--suppress` 抑制 · SARIF 2.1.0 · 机器/人类输出(`--format`/`--manifest`/`--table`)· **防御监控**(`monitor` 区间 + `watch` 跟链头 + 部署风险评分 + `--baseline` 去重 + `--throttle`/`--group` + `--digest-interval` + alert 模式多链并行)· **MCP 服务器**(9 工具 + resources;stdio + 本地 HTTP 传输)。

**🔜 下一步**:绑定图后续(审计 Phase 23+)——把 Phase 22 的 `BindingGraph` 扩到 reentrancy(任意外部调用面 + 跨文件继承状态)、access-control(消除名字启发式)、delegatecall 局部 alias 回溯;更多发现源(CMC、ethereum-lists、Sourcify 全量、4byte 聚类、工厂展开、Dune);WS `subscribe` 替代轮询;下载模式多链并行。

**📋 TODO**:更多发现源(CMC、ethereum-lists、Sourcify 全量枚举、4byte 聚类、工厂展开、Dune)· 更多 AST 检测器与深度规则族。

> 完整「✅ 已完成 / 🔜 下一步 / 📋 TODO」状态矩阵见 [ARCHITECTURE.md#功能状态矩阵](ARCHITECTURE.md)。

---

## 目录
1. [安装与构建](#1-安装与构建)
2. [配置](#2-配置)
3. [快速上手](#3-快速上手)
4. [子命令参考](#4-子命令参考)
5. [安全审计引擎](#5-安全审计引擎)
6. [防御监控与告警](#6-防御监控与告警)
7. [MCP 服务器](#7-mcp-服务器)
8. [输出格式与落盘结构](#8-输出格式与落盘结构)
9. [全局选项速查](#9-全局选项速查)
10. [故障排查 / FAQ](#10-故障排查--faq)

---

## 1. 安装与构建

需要 Rust(2021 edition)与一个可链接的 C 工具链。

```bash
# 构建(Windows 上需 MSVC 工具链;见下方注意)
cargo build --release        # 产物:target/release/blockscan
cargo test                   # 637 个用例全绿(532 单元 + 105 集成)
cargo clippy --all-targets   # 零告警
```

- **Windows**:工具链需为 `stable-x86_64-pc-windows-msvc`(gnu 缺 dlltool/gcc 无法链接),并安装 MSVC Build Tools(C++ 工作负载 + Windows SDK)。
- **网络**:对 `api.etherscan.io` 与公共 RPC 默认 HTTP/2 可能报 "error sending request";BlockScan 内部已对 Etherscan 与 RPC 客户端强制 **HTTP/1.1 + 30s 超时 + 重试**,无需额外配置。

把 `target/release/blockscan` 放进 `PATH` 后即可全局使用 `blockscan`。

---

## 2. 配置

凭据与端点可用**命令行参数**或**环境变量**(支持 `.env`,放在工作目录)。

| 环境变量 | 等价参数 | 说明 |
|---|---|---|
| `ETH_RPC_URL` | `--rpc-url` | JSON-RPC 端点(发现/字节码/链上状态)。如 `https://ethereum-rpc.publicnode.com`(免 key) |
| `ETHERSCAN_API_KEY` | `--etherscan-key` | Etherscan **V2** API key(拉已验证源码/元数据)。`monitor`(纯事件)与 `watch --alert-events` 不需要 |
| `GITHUB_TOKEN` | `--github-token` | 提高 GitHub 发现的速率上限(可选) |
| `GOOGLE_API_KEY` / `GOOGLE_CSE_ID` | `--google-api-key` / `--google-cse-id` | 启用 Google 网页搜索发现(可选) |

`.env` 示例:
```
ETH_RPC_URL=https://ethereum-rpc.publicnode.com
ETHERSCAN_API_KEY=YourEtherscanV2Key
```

> Etherscan 免费档常为 **3 req/s**,按你的档位设 `--rate`(超额会被限流但自动退避重试)。

---

## 3. 快速上手

```bash
# 下载一个已验证合约(最快验证):源码 + 字节码 + 详情 + 审计
blockscan addresses 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 -o out

# 扫一个历史区块区间里的新部署
blockscan range --from 19000000 --to 19000050 -o out

# 按项目名发现并扫描相关合约(Blockscout 搜索 + GitHub 部署文件)
blockscan discover "Uniswap V4" --github Uniswap/v4-core -o out

# 离线对已下载语料重新审计,按风险排序
blockscan audit --by-risk -o out

# 监控一个区间的安全事件(代理升级/所有权变更…),落 alerts.jsonl
blockscan monitor --from 21000000 --to 21000100 --alerts alerts.jsonl -o out

# 起一个 MCP 服务器,把审计/扫描能力给 agent 调用
blockscan mcp -o out
```

机器可读输出:任意命令加 `--format json`(或 `ndjson`/`sarif`),**stdout 只放数据**,日志/进度/汇总走 stderr,可直接 `| jq`。

---

## 4. 子命令参考

### `addresses` — 扫描指定地址
```bash
blockscan addresses <地址...> [--file addrs.txt] [全局选项] -o out
```
- 直接给一个或多个地址,或用 `--file`(每行一个,`#` 注释、空行忽略),可同时用。
- 对每个地址:取链上 runtime 字节码(空即非合约/已自毁,跳过)+ 余额 + Etherscan 源码/ABI/元数据 + 创建信息;识别代理(EIP-1167/1967/1822);未验证时回退 Sourcify(除非 `--no-sourcify`);跑安全审计(除非 `--no-audit`);通过过滤后落盘。

### `range` — 扫描历史区块区间
```bash
blockscan range --from <N> --to <M> [--trace] -o out
```
- 遍历 `[N, M]`,用交易回执的 `contractAddress` 找**顶层部署**。`--trace` 额外用 RPC `trace_block` 发现工厂(CREATE/CREATE2)子合约(需 RPC 开放 `trace_` 命名空间;失败仅告警)。

### `watch` — 实时跟链头
两种模式:
- **下载模式(默认)**:跟链头,把每个新确认块的新部署下载入库。
  ```bash
  blockscan watch --confirmations 2 --poll-ms 4000 -o out   # Ctrl-C 优雅退出
  ```
- **实时告警模式**(加任一告警开关):每个确认块跑告警管线,不再批量下载。见 [§6](#6-防御监控与告警)。
  ```bash
  blockscan watch --alert-on-risk --alert-events --min-risk 50 \
    --alerts alerts.jsonl --baseline seen.fp --confirmations 2 -o out
  ```
- `--confirmations` 落后链头的块数(避免重组);`--poll-ms` 轮询间隔。

### `discover` — 按项目发现并扫描
```bash
blockscan discover [项目名] [--github owner/repo]... [--website url]... \
  [--defillama slug]... [--tokenlist url]... [--coingecko id]... \
  [--topic 0x.. --from N --to M] -o out
```
多源 fan-out(各源失败仅告警),合并去重后进扫描流水线(**至少需一个源,否则报错**):
- **项目名** → Blockscout 名称搜索(+ 可选 Google 网页搜索,需凭据)。
- `--github owner/repo`(可重复)→ hardhat-deploy / Foundry broadcasts / 审计 scope 里的地址。
- `--website <url>`(可重复)+ `--crawl-depth` → 抓官网/文档页与 explorer 链接里的地址(同域浅爬)。
- `--defillama <slug>`(可重复)→ 协议主合约锚点。
- `--tokenlist <url>`(可重复)→ 标准 Token List 的 `tokens[]`(按 `--chain-id` 过滤)。
- `--coingecko <id>`(可重复)→ CoinGecko `/coins/{id}` 的 `platforms` 取该 `--chain-id` 上的合约(免 key)。
- `--topic <hash> --from --to` → `eth_getLogs` 按事件 topic 扫区间,取发出事件的合约(`--log-chunk`/`--log-concurrency` 控分块并发)。

### `monitor` — 区间安全事件监控
见 [§6](#6-防御监控与告警)。

### `audit` — 离线重审已下载语料
```bash
blockscan audit [--by-risk] [--min-risk N] [--only-vulnerable] [--suppress f.json] \
  [--format human|json|ndjson|sarif] -o out
```
- **无需联网**:对 `-o` 目录下已存合约重跑审计(规则升级后批量重打分)。`--by-risk` 按风险分降序。过滤同扫描期。见 [§5](#5-安全审计引擎)。

### `mcp` — MCP 服务器
默认 stdio;`--http <addr>` 切本地 HTTP 传输,`--http-token <token>`(或环境变量 `BLOCKSCAN_MCP_TOKEN`)加 Bearer 鉴权。见 [§7](#7-mcp-服务器)。

---

## 5. 安全审计引擎

一个**独立的标准化启发式审计引擎**:扫描合约的同时检测漏洞并打分,结果写入 `metadata.json` 的 `audit` 字段、`--manifest` CSV、`--table` 表格,并随 `--format json/ndjson/sarif` 输出。定位是 **Slither-lite 式 linter** —— **分诊信号,需人工复核**(会有误报/漏报)。默认开启,`--no-audit` 关闭。

- **三层分类**:OWASP Smart Contract Top 10(`category`)→ SWC 注册表(`swc`,仅确切匹配时填)→ 内部 `rule_id`;另附 `scwe`(OWASP SCWE)与 `ethtrust`(EEA EthTrust 需求)外部引用(高置信度精确匹配时填);共 **36 个检测器**(Access/Proxy-Upgrade/External-Calls/Reentrancy/Oracle/Flash-loan/Token/Governance/MEV/Bridge/Arithmetic…),源码(注释/字符串感知)+ 字节码 + 函数级窗口。
- **AST 精化 + 函数内数据流**(源码可解析时,`slang_solidity` 解析器):`TX_ORIGIN_AUTH` 仅在鉴权上下文(`==`/`!=`/`<`/`>`/`if`/`require`/`assert`)、`UNCHECKED_LOW_LEVEL_CALL` 仅在低层 `.call` 结果未被消费时命中,消除子串启发式的误报(如 `return tx.origin`、`mytx.origin`、`require(x.call())`),`detection` 标为 `ast`。对绑定形态(`(bool ok,)=a.call()`)再做**函数内数据流**:成功布尔在调用后确被 gate(`require`/`assert`/`if`-`while`-`for` 条件/直接 `return`)检查才抑制 —— `(bool ok,)=a.call(); require(ok);` 不再误报,而绑定后不检查的 `(bool ok,)=x.call{value:..}("")` 仍报(SWC-104)。`REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE` 升级为 AST:低层外部调用后写**状态变量**(赋值/`++`/`delete`/元组/`push`-`pop`)且无 `nonReentrant` 守卫才报,写**局部**变量或 CEI 安全不再误报。`ACCESS_MISSING_GUARD_PRIVILEGED_FN` 升级为 AST:特权名 + public/external + 有实现 + **非 view/pure** + 无守卫(结构化 only*/auth/restrict 修饰符、或 require/if/比较里的 `msg.sender`、或 `_checkOwner`/`_checkRole` 调用)才报,跳过接口/抽象声明。`WEAK_BLOCK_RANDOMNESS` 升级为 AST:区块源(`block.timestamp`/`number`/`difficulty`/`prevrandao`/`blockhash(..)`)仅在 **`%` 取模 / `keccak`-`sha` 种子**上下文才报 —— deadline 比较、时间戳记账等合法用途不再误报。`ECRECOVER_NO_ZERO_CHECK` 升级为 AST:`ecrecover(..)` 恢复地址未与 `address(0)`/`0` 比较才报 —— 写得好的签名验证(`require(s!=address(0))`)不再误报。另**新增 AST-only** `DELEGATECALL_ARBITRARY_TARGET`(**Critical**,SWC-112):仅当 `.delegatecall` 的目标基标识符是**所在函数的形参**(调用者可控,Parity 钱包级合约接管)才报 —— 固定 `impl` 状态变量目标、他函数同名形参均不误报,正确命中 modifier/constructor 形参。`HARDCODED_GAS_TRANSFER_SEND` 升级为 AST:按**实参个数**辨别——1 参 `addr.transfer/send(x)`(2300-gas ETH send)才报,≥2 参 ERC-20 `transfer(to,amt)`/`transferFrom(..)` 不报(消除 `dai.transfer(to,amt)` 误报),实参为字符串/字节字面量或 `abi.encode*` 则为消息发送(`bridge.send(payload)`)不报。`UNSAFE_DOWNCAST_TRUNCATION` 升级为 AST:收窄 `uintN/intN`(N<256)仅当实参非字面量、非同族等宽/更窄嵌套转换、非 `uint160+(address(..))` 无损转型才报。解析失败 / 过深嵌套 / 解析器 panic 自动**降级**回行级启发式;**评分不变**。(依赖类型解析的残余误报,如 `uint160(addrVar)`/`uint8(enumVar)`/标识符接收者的 `endpoint.send(x)`,推迟到 scope-aware 名字/类型解析阶段。)
- **评分**:单条 `risk = impact × likelihood × confidence × exposure`;整体按弱点键去重后做"概率 OR"聚合(封顶 100)→ **风险分 0–100 + 等级 A–F + risk_level + 优先级 P0–P3**。
- **过滤**:`--min-risk <0–100>` 只保留风险分 ≥ 阈值;`--only-vulnerable` 只保留含 high/critical 发现的合约。
- **SARIF**:`--format sarif` 输出 SARIF 2.1.0(含 `partialFingerprints`),可直接喂 GitHub Code Scanning / CI。

### 抑制误报:`--suppress <file>`
一份 JSON,把已三角验证确认的**误报**或**已接受基线**静默掉;命中项在**评分前**剔除(分数与摘要同步下降)。扫描与离线 `audit` 均生效。

```json
{
  "suppress": [
    { "rule": "ORACLE_SPOT_PRICE", "contract": "0xabc…", "reason": "该合约用 TWAP" },
    { "rule": "DELEGATECALL_USAGE" },
    { "swc": "SWC-112" },
    { "category": "SC06:Unchecked External Calls" },
    { "fingerprint": "deadbeef12345678" }
  ]
}
```
- 每条的键全部可选,**非空键全部匹配**才算命中(AND),多条之间 OR。`reason` 仅文档。
- `rule`=rule_id;`contract` 大小写不敏感(给了就把 rule 限定到该合约);`swc`/`category` 精确;`fingerprint` 为某条发现的 SARIF 指纹(`keccak16(rule|contract|file|evidence)`,用于精确压单实例 / 做基线)。
- **安全方向**:文件缺失 / 坏 JSON / 无键条目 → 仅 `warn`、不抑制任何东西(宁可多显示,绝不误压)。

### 局限
启发式、非形式化验证;`TX_ORIGIN_AUTH`/`UNCHECKED_LOW_LEVEL_CALL`/`REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE`/`ACCESS_MISSING_GUARD_PRIVILEGED_FN`/`WEAK_BLOCK_RANDOMNESS`/`ECRECOVER_NO_ZERO_CHECK` 在源码可解析时走 AST 精化 + 函数内数据流(否则降级回启发式)。残留取舍:tx.origin 的间接鉴权(存入存储后在后续语句 require、或作映射写键)不报;低层 `.call` 无类型信息,名为 `call` 的用户函数会误报;reentrancy 仅认低层外部调用 sink(任意 `x.foo()` 外部调用不报)+ 同文件状态变量(跨文件继承基合约的状态变量漏报,flatten 源不受影响)+ `nonReentrant`-类 modifier 守卫(手写布尔锁无 modifier 会多报);access-control 的特权判定基于名字(26 名单)、守卫从宽(任何 `msg.sender` 比较/`only*` 修饰符即算守卫);weak-randomness 仅认 `%`/`keccak` 上下文(经局部变量间接取模不报);ecrecover 只要函数内任一处对恢复地址做了 `!=address(0)` 校验即视为安全(`require(s==signer)`、零校验落在别的变量上仍按"无显式零校验"上报);数据流是函数内、名字基,极端同名 shadow / 跨函数检查偏保守。源码检测仅对已验证合约,未验证只有字节码级信号 + `unverified` 标记。

---

## 6. 防御监控与告警

把链上安全事件与高危新部署变成可消费的**结构化告警流**(落 `alerts.jsonl` / 推 webhook / stdout JSONL),可 cron 周期化或实时跟链头。

### 监控的事件(默认集,8 类)
| 事件 | 含义 |
|---|---|
| `Upgraded` / `BeaconUpgraded` | 代理实现 / beacon 升级 |
| `OwnershipTransferred` | 所有权转移 |
| `AdminChanged` | 代理管理员变更 |
| `RoleGranted` / `RoleRevoked` | AccessControl 角色授予/撤销 |
| `Paused` / `Unpaused` | Pausable 紧急暂停/恢复 |

`Transfer`(大额)**不在默认集**(高频),仅 `--min-transfer` 时纳入。`--alert-topic 0x..`(可重复)可追加自定义 topic0(无专用解码器的记 `event=unknown`)。

### `monitor`(区间)
```bash
blockscan monitor --from <N> --to <M> [选项] -o out
```
| 选项 | 作用 |
|---|---|
| `--alerts <file>` | 追加 JSON 行到 `alerts.jsonl`(写错仅 warn) |
| `--webhook-url <url>` | best-effort POST 每条告警 |
| `--watchlist <file>` | 只对清单内地址(每行一个,`#` 注释)告警 |
| `--audit-deployments` | 审计区间内**新部署**合约,`risk≥--min-risk` 发 `risky-deployment` 告警(含 `risk_score`/`grade`);需 Etherscan key;与 `--no-audit` 互斥 |
| `--min-transfer <amount>` | 纳入 ERC-20 `Transfer`,只报 `value ≥ amount`(原始最小单位 uint256)的;自动排除 ERC-721;建议配 `--watchlist` |
| `--baseline <file>` | **跨轮去重**:每条算稳定指纹,已见的抑制、新的追加;重叠区间/周期化重跑不重复 |
| `--throttle <N>` | **突发封顶**:每 `(链, 合约, kind)` 本次最多 N 条,超出丢弃(被节流者不写基线,下轮可重发) |
| `--group` | **分组摘要**:把同 `(链, 合约, event)` 折叠成运行结束时一条 digest(`event:"Grouped"`,`amount`=条数);与 `--throttle` 互斥(group 优先) |
| `--log-chunk` / `--log-concurrency` | `eth_getLogs` 分块大小 / 并发 |

汇总行会报 `(N suppressed, M throttled, G grouped)`;某窗口日志/回执拉取失败会附"部分扫描"提示。

### `watch`(实时跟链头)
`watch` 加 `--alert-on-risk`(审计新部署、需 key)和/或 `--alert-events`(纯事件、免 key)即进入实时告警模式,复用上面所有 sink/过滤/去重/节流/分组选项。某块区间拉取失败时**不推进、下个 tick 重扫**(配 `--baseline` 去重);Ctrl-C 优雅退出后按 `--format` 收尾。

- **`--digest-interval <secs>`**(配 `--group`):每 N 秒周期性 flush 一次摘要,而非仅在 shutdown 时。
- **`--chains 1,10,…`**(仅 alert 模式):**多链并行** watch。各链 RPC 取自 `ETH_RPC_URL_<id>`(主链回退 `--rpc-url`);各链独立去重/节流/分组(键含 chain_id,无需锁),共享 `alerts.jsonl`/baseline 文件按行原子追加,单一 Ctrl-C 经 `Shared` 停全部并汇总。下载模式仍单链。

### 告警结构(`alerts.jsonl` 每行)
```json
{ "block": 21000002, "chain_id": 1, "contract": "0x…", "event": "OwnershipTransferred",
  "kind": "ownership", "new_value": "0x…(新)", "previous": "0x…(旧)", "tx_hash": "0x…",
  "log_index": 0, "amount": null, "risk_score": null, "grade": null }
```
`risky-deployment` 告警带 `risk_score`/`grade`;`large-transfer` 带 `amount`;`Grouped` digest 的 `amount`=折叠条数、`previous`="blocks first..last"。

---

## 7. MCP 服务器

`blockscan mcp` 跑一个 **Model Context Protocol** 服务器(JSON-RPC 2.0),把 BlockScan 暴露为 **agent 可调用的工具 + 资源**。默认走 **stdio**(换行分隔,**stdout 只放协议消息、日志走 stderr**),也可 `--http` 切到**本地 HTTP** 传输(见下)。手写实现、依赖精简。

在 MCP 客户端(Claude Desktop / IDE 等)里注册为 stdio server:
```json
{ "mcpServers": { "blockscan": { "command": "blockscan", "args": ["mcp", "-o", "out"] } } }
```
`-o`/`--out` 成为离线工具与 resources 的默认语料目录。

#### 本地 HTTP 传输(可选)

需要按 URL 接入(而非 stdio 子进程)时,加 `--http <addr>` 在**回环地址**起一个 Streamable HTTP 端点(单 `/mcp`,POST JSON-RPC,与 stdio 完全同源):

```bash
blockscan mcp -o out --http 8765                  # 监听 127.0.0.1:8765/mcp
blockscan mcp -o out --http 127.0.0.1:9000 \
  --http-token "$BLOCKSCAN_MCP_TOKEN"             # 加 Bearer 鉴权(也可经环境变量)
```

- `<addr>` 可为裸端口(`8765`)、`host:port` 或裸 host(默认端口 8765);**仅允许回环**,非 loopback 启动即报错。
- 服务器校验 `Origin`(仅放行 `localhost`/`127.0.0.1`/`::1`,精确 host 匹配)防 DNS-rebinding;body 上限 1 MiB(超即 413)。
- tools-only 无服务器主动推流,故 **POST 即得响应,无需 SSE / 会话**(`GET`/`DELETE`→405)。
- ⚠️ **不带 `--http-token` 时,该端点对本机任意进程开放(无鉴权)** —— Origin/loopback 只挡浏览器跨站,不挡本机恶意进程。多用户 / 共享主机务必设 token;客户端以 `Authorization: Bearer <token>` 提供。

### 工具
| 工具 | 网络 | 作用 |
|---|---|---|
| `audit_source` | 离线 | 审计内联 Solidity 源码 + / 或字节码,返回标准化 `Audit` |
| `audit_corpus` | 离线 | 重审 `out` 下全部已存合约 |
| `get_contract` | 离线 | 读某合约 metadata(可含源码) |
| `list_contracts` | 离线 | 轻量列出已存合约(按最后保存的审计过滤) |
| `export_sarif` | 离线 | 重审语料并导出 SARIF 2.1.0 |
| `cluster_corpus` | 离线 | 按去元数据字节码哈希聚类克隆族 |
| `scan_addresses` | 在线 | 链上扫描给定地址(需 `rpc_url`+`etherscan_key`) |
| `scan_block_range` | 在线 | 扫描**有界**区间(≤500 块)新部署并审计落盘(需 key) |
| `monitor_range` | 在线 | 解码**有界**区间(≤500 块)安全事件(可 `min_transfer`/`watchlist`)并**返回**告警(仅需 `rpc_url`) |

### 资源
- `resources/list`:列出 `out` 下每个已存合约 `blockscan://contract/<address>`。
- `resources/read`:读 `blockscan://contract/<address>` → 该合约 metadata JSON。

### 约定与安全
- 工具**执行失败**(合约未找到、网络出错、参数校验失败)以 `result.isError=true` + 文本返回(让模型可见);仅**参数/方法**错误才走 JSON-RPC `error`(`-32700/-32601/-32602`)。
- `resources/read` 与 `get_contract` 的地址参数经 `Address` 校验,**杜绝路径穿越**;`scan_block_range`/`monitor_range` 拒绝超 500 块的区间(让 agent 分页)。
- 连续 `watch` 循环不适合同步 `tools/call`,故只提供有界原语 + agent 轮询。
- 在线工具的 `rpc_url`/`etherscan_key` 随调用内联,由 MCP 客户端配置注入,**勿硬编码到提示词**。

---

## 8. 输出格式与落盘结构

### `--format`(全局,默认 `human`)
| 模式 | stdout |
|---|---|
| `human` | 中文宽度感知表格(`--table`)+ 汇总;日志/进度走 stderr |
| `json` | 运行结束一个 `{ run, stats, contracts }` 文档(含完整 `analysis`/`audit`) |
| `ndjson` | **流式**:每保存一个合约一行紧凑 JSON |
| `sarif` | **SARIF 2.1.0** 审计日志(GitHub Code Scanning / CI / IDE) |

机器模式下 **stdout 只放数据**,可直接 `| jq`;`monitor`/`watch` 的 stdout 恒为逐告警 JSONL 流。

### 落盘目录(每合约一个目录,地址小写)
```
<out>/<address>/
  metadata.json     # 全量详情(含 analysis 与 audit)
  bytecode.hex      # 链上 runtime 字节码
  abi.json          # ABI(已验证时)
  source/           # 已验证源码(多文件工程保留原始路径)
```
- **续跑/去重**:已存在 `metadata.json` 默认跳过,`--overwrite` 强制重拉。
- `--manifest <file.json|.csv>`:把全部已存合约导汇总;同目录另写 `clusters.json`(按去元数据字节码哈希聚类克隆族)。
- `--table`:打印每合约的中文归一化表格(需 Blockscout 富化名称标签/项目URL/代币持仓时会调 Blockscout 免费 API)。
- **多链** `--chains 1,10,8453,…`:每链 RPC 取自 `ETH_RPC_URL_<id>`(回退 `ETH_RPC_URL`);非主网/多链时输出按链名分子目录,避免同址跨链冲突。

---

## 9. 全局选项速查

| 选项 | 默认 | 说明 |
|---|---|---|
| `--rpc-url` / `ETH_RPC_URL` | — | JSON-RPC 端点 |
| `--etherscan-key` / `ETHERSCAN_API_KEY` | — | Etherscan V2 key |
| `--chain-id` | 1 | 链 id |
| `--chains 1,10,…` | — | 多链一次扫 |
| `-o`/`--out` | `output` | 输出目录 |
| `--concurrency` | 5 | 并发处理合约数 |
| `--rate` | 5 | Etherscan 每秒请求上限 |
| `--retries` | 5 | 每请求重试次数 |
| `--overwrite` | false | 重拉已存合约 |
| `--trace` | false | `range`/`watch` 额外发现工厂子合约 |
| `--table` | false | 打印详情表格 |
| `--no-sourcify` | false | 关闭 Sourcify 源码回退 |
| `--only-verified` / `--only-proxy` / `--min-balance <eth>` | — | 落盘前过滤 |
| `--no-audit` | false | 关闭安全审计 |
| `--min-risk <0–100>` / `--only-vulnerable` | — | 审计过滤 |
| `--suppress <file>` | — | 审计抑制配置 |
| `--manifest <file>` | — | 导出 json/csv 汇总 + clusters.json |
| `--format human\|json\|ndjson\|sarif` | human | 输出格式 |
| `-v` / `-vv` | — | 提高日志详细度(走 stderr) |

子命令独有选项见 [§4](#4-子命令参考) / [§6](#6-防御监控与告警)。

---

## 10. 故障排查 / FAQ

- **"error sending request" / 连不上 Etherscan 或 RPC**:多为 HTTP/2 问题;BlockScan 已内部强制 HTTP/1.1,通常无需处理。确认 `--rpc-url` 可达、key 有效。
- **被限流(Etherscan)**:把 `--rate` 调到你的档位(免费常 3),会自动退避重试;并发也可降 `--concurrency`。
- **合约"未验证"**:Etherscan 无已验证源码;BlockScan 会回退 Sourcify(除非 `--no-sourcify`),仍无则只存字节码 + 字节码级审计信号 + `is_verified=false`。
- **`--min-risk`/`--only-vulnerable` 把一切都过滤掉了**:它们需要审计结果;别同时加 `--no-audit`(会报错)。`--min-risk` 上限 100。
- **`watch`/`monitor` 没有告警**:确认区间内确有相应事件;`--watchlist` 为空会**抑制全部**(会 warn);纯事件监控不需要 Etherscan key。
- **`monitor --audit-deployments` 报错**:它与 `--no-audit` 互斥,且需要 Etherscan key。
- **MCP 客户端收不到响应 / 连接断开**:确保没有别的程序往该进程 stdout 写东西;BlockScan 自身保证 stdout 纯净(日志走 stderr)。
- **机器管道里混进了日志**:用 `--format json|ndjson|sarif`;数据在 stdout,日志/进度/汇总在 stderr。
- **退出码**:成功 0;配置/校验错误等以非 0 退出并在 stderr 打印 `error: …`。

---

> 反馈与设计细节见仓库 `docs/` 下各设计文档;测试覆盖与质量门槛见 [ARCHITECTURE.md](ARCHITECTURE.md)。
