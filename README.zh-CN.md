# BlockScan

**简体中文** · [English](README.md)

扫描以太坊（及兼容 EVM 链）上的智能合约，下载**已验证源码**、**链上字节码**与**合约详情**，按合约落盘保存；并能按项目自动**发现**相关合约。Rust 实现。

> 状态：**1.1.0 正式版** —— 功能完整、**798 个测试全绿、clippy 零告警**、核心路径均经真实链上验证。
>
> 新手请先读 **新手指南:[中文](docs/GETTING_STARTED.md) · [English](docs/GETTING_STARTED.en.md)**(约 10 分钟:安装 → 配置 → 扫到第一个合约)。
> 用户手册:**[中文](docs/USER_MANUAL.md)** · **[English](docs/USER_MANUAL.en.md)**;架构 / 模块盘点 / 代码量 / 功能状态矩阵见 **[docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)**(顶层开发设计文档)。

## 功能总览

| 类别 | 能力 |
|---|---|
| **扫描模式** | `addresses` 指定地址 · `range` 历史区块 · `watch` 实时跟链头（Ctrl-C 优雅退出） |
| **数据来源** | RPC（发现/字节码/余额） + Etherscan V2（源码/ABI/元信息/creator） + **Sourcify 回退**（未验证时拉源码） |
| **代理识别** | EIP-1167（字节码）· EIP-1967 impl · **Beacon**（`eth_call implementation()` 解析真实逻辑地址）· EIP-1822 UUPS —— 未验证也能识别 |
| **静态分析** | 对已下载字节码做零网络派生:**ERC 接口识别**（20/721/1155/165,未验证也能识别）· **危险操作码标记**（SELFDESTRUCT/DELEGATECALL/CALLCODE/CREATE/CREATE2）· **字节码指纹 + 克隆聚类**（去元数据 keccak,`--manifest` 时落 `clusters.json`） |
| **安全审计引擎** | 独立标准化引擎,扫描同时**检测漏洞并打分**:三层分类(OWASP SC Top 10 → SWC → rule_id)· **36 检测器**(基础 11 + 深度 25:Access/Proxy/Reentrancy/Arithmetic/Oracle/Flash-loan/Token/**Governance/MEV/Bridge-跨链**,源码注释/字符串感知 + 字节码 + 函数级窗口;**8 条规则经 slang AST 精化 + 1 条 AST-only `DELEGATECALL_ARBITRARY_TARGET`**)· 多因子评分(impact×likelihood×confidence×exposure)→ **风险分 0–100 + 等级 A–F + P0–P3** · 报告矩阵 · `--min-risk`/`--only-vulnerable` 过滤 · `audit` 子命令离线重审 · **SARIF 2.1.0 输出 + partialFingerprints**(GitHub Code Scanning 基线/去重) · **`--suppress` 抑制配置**(按 rule/contract/swc/category/fingerprint 压误报,评分前剔除) |
| **项目→合约发现** `discover` | 名称→Blockscout · `--github`→部署文件 + **审计 scope**（README/scope markdown，Code4rena/Sherlock）· `--website`→官网/文档浅爬（实测单页 304 合约）· `--defillama`→协议主合约 · `--tokenlist`→Token List 按链过滤（实测 Uniswap 390）· `--coingecko`→币种 `platforms` 按链取合约 · `--topic`→链上事件扫描 · Google 网页搜索 |
| **富化（`--table`）** | Blockscout 名称标签 / 项目 URL / 代币持仓（USD Top-3），带缓存 + 限速 |
| **防御监控** `monitor` / `watch` | 扫区间 `eth_getLogs` 解码 **8 类安全事件**(代理升级 ×2 · 所有权 · 管理员 · 角色授予/撤销 · 暂停/恢复);**`--min-transfer`** 大额转账、**`--audit-deployments`** 新部署风险评分、**`watch --alert-on-risk`/`--alert-events`** 跟链头实时告警、**`--baseline`** 跨轮去重、**`--throttle`** 同类节流 → 结构化 `Alert` 落 `alerts.jsonl` / 推 webhook / stdout 流;`--watchlist` 限定地址 |
| **输出** | 每合约目录（metadata.json / bytecode.hex / abi.json / source/）· 中文归一化表格 · `--manifest` 导出 json/csv · **`--format json\|ndjson`** 机器可读 stdout（日志/进度/汇总走 stderr,便于 jq/agent 管道) |
| **MCP 服务器** `mcp` | `blockscan mcp` 起 MCP 服务器(JSON-RPC 2.0,手写零新依赖;**stdio 或本地 HTTP** `--http`),把审计/SARIF/扫描暴露为 **agent 可调用工具**:`audit_source` · `audit_corpus` · `get_contract` · `list_contracts` · `export_sarif` · `cluster_corpus` · `scan_addresses` · `scan_block_range` · `monitor_range`,并以 `resources/*` 暴露语料 |
| **多链 & 运维** | `--chains` 多链一次扫 · 过滤器 `--only-verified/--min-balance/--only-proxy` · 并发+限速 · 断点续跑去重 · RPC/Etherscan 自动退避重试（含限流） |

更详细的用法见下文各小节。

## 安装与构建

需要 **Rust 1.97.1 及以上**（声明在 `Cargo.toml` 的 `rust-version`；这个下限来自 `slang_solidity` 解析器，不是偏好）与一个 C/C++ 链接器（Windows 推荐 MSVC Build Tools，或 MinGW）。CI 有一个 job 按该版本构建。

```bash
cargo build --release
```

已打标签的版本会在 GitHub **Releases** 页附上预编译二进制（见[版本发布](#版本发布)）。

## 配置

复制 `.env.example` 为 `.env` 并填写：

```
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
ETHERSCAN_API_KEY=YOUR_ETHERSCAN_KEY
```

也可用命令行 `--rpc-url` / `--etherscan-key` 覆盖。

## 用法

```bash
# 扫描指定地址（最快验证）
blockscan addresses 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48
blockscan addresses --file addrs.txt

# 扫描历史区块范围
blockscan range --from 19000000 --to 19000010

# 实时监听新部署（Ctrl-C 退出）
blockscan watch --confirmations 2 --poll-ms 4000

# 按项目发现并扫描相关合约（Blockscout 名称搜索 + GitHub 部署文件）
blockscan discover "Uniswap V4"
blockscan discover --github Uniswap/v4-core --github aave/aave-v3-core

# 多链一次扫（每条链的 RPC 用 ETH_RPC_URL_<id>），并导出汇总
blockscan addresses 0xA0b8...EB48 --chains 1,8453 --manifest index.csv

# 只保留已验证 / 高余额 / 代理合约
blockscan range --from 19000000 --to 19000010 --only-verified --min-balance 100
```

常用全局参数：

| 参数 | 说明 | 默认 |
| --- | --- | --- |
| `--out, -o` | 输出目录 | `output` |
| `--concurrency` | 并发处理合约数 | `5` |
| `--rate` | Etherscan 每秒请求上限（设成你 key 的档位，免费 key 常为 3–5/s） | `5` |
| `--retries` | 单次 RPC/Etherscan 请求的尝试次数（抗公共节点抖动；也用于 Etherscan 限流自动退避重试） | `5` |
| `--chain-id` | 链 id（1 = 以太坊主网） | `1` |
| `--chains` | 多链一次扫（逗号分隔 id）；每链 RPC 取 `ETH_RPC_URL_<id>` | 单链 |
| `--overwrite` | 重拉已保存合约 | 关闭 |
| `--trace` | 额外用 `trace_block` 发现工厂合约 | 关闭 |
| `--table` | 每个合约打印归一化详情表（余额按 ETH 显示） | 关闭 |
| `--no-sourcify` | 关闭 Sourcify 源码回退 | 开启 |
| `--sourcify-base` | Sourcify 服务地址 | `https://sourcify.dev/server` |
| `--only-verified` | 只保留有已验证源码的合约 | 关闭 |
| `--min-balance` | 只保留余额 ≥ N ETH 的合约 | `0` |
| `--only-proxy` | 只保留代理合约 | 关闭 |
| `--manifest` | 扫完导出汇总到文件（`.json`/`.csv`） | 无 |
| `--blockscout-base` | `--table`/`discover` 用的 Blockscout v2 API；置空禁用 | `https://eth.blockscout.com/api/v2` |
| `--blockscout-rate` | Blockscout 每秒请求上限（富化限速） | `4` |
| `-v, -vv` | 提升日志详细度 | info |

### 代理识别（多标准）

`is_proxy`/`implementation`/`proxy_kind` 按以下顺序解析：Etherscan 标记 → 字节码 **EIP-1167** 最小代理 → 链上存储槽 **EIP-1967**（beacon 会进一步 `eth_call` `implementation()` 解析出最终逻辑地址）/ **EIP-1822 UUPS**（`eth_getStorageAt`）。即使合约未验证也能识别并填出实现地址。

### 源码回退（Sourcify）

Etherscan 无已验证源码时，自动回退到 **Sourcify v2** 拉取源码（`verified_via` 记录来源 `etherscan`/`sourcify`）。`--no-sourcify` 关闭。

### 多链与导出

`--chains 1,8453,42161` 一次扫多链：Etherscan V2 按 chainid 路由，Blockscout base 自动按链映射，输出落到 `<out>/<chainname>/`；每条链的 RPC 从环境变量 `ETH_RPC_URL_<id>` 读取（主链回退 `ETH_RPC_URL`），缺失则跳过并告警。`--manifest index.json|index.csv` 在扫描结束后汇总所有已保存合约（递归读取 `metadata.json`）。

### 项目发现（discover）

给项目名/ GitHub 仓库，自动汇集相关合约地址再走扫描流水线：
- **名称** → Blockscout `/search`（匹配 name tag / token / contract）。
- **名称 + Google 凭据** → Google 网页搜索，从结果里的浏览器 `/address/0x…` 链接提取地址（见下文）。
- **`--github owner/repo`**（可重复）→ 读取仓库部署产物：hardhat-deploy `deployments/<net>/*.json`（含 `implementation`）与 Foundry `broadcast/**/run-latest.json`；并解析 `README.md` / `*scope*.md` 里的 `0x{40}` 与 explorer 链接 —— 因此可直接指向 **Code4rena / Sherlock 竞赛仓库**抓取 scope 中的待审合约（`GITHUB_TOKEN` 可提升限额）。
- **`--website <url>`**（可重复）→ 抓官网/文档页，提取正文与 explorer 链接里的合约地址，并沿**同域**含 `contract/deploy/docs/...` 的链接浅爬一层（`--crawl-depth` 默认 1，页数封顶）。官方文档的「部署地址」页往往是最权威、命中率最高的来源，且**无需任何 API key**。

  ```powershell
  # 官网/文档直取（推荐配合你 key 的限速档）
  blockscan discover --website https://docs.lido.fi/deployed-contracts/ --rate 3 -o out
  ```

  > 真实效果（对上面这页，`--crawl-depth 0` 只抓单页）：提取 **442 个候选地址** → 链上 `eth_getCode` 自动剔除 **138 个非合约**（EOA 等）→ 入库 **304 个合约，且 304/304 已验证**，0 失败。地址会汇入流水线去重并校验，无需人工筛。

- **`--defillama <slug>`**（可重复）→ 取 DefiLlama 协议的主代币/治理合约（`/protocol/{slug}` 的 `address`，1 个/协议）。免费、最广，作"项目锚点"。

  ```powershell
  blockscan discover --defillama lido --rate 3 -o out   # → LDO 0x5a98…1b32
  ```

- **`--tokenlist <url>`**（可重复）→ 拉取标准 Token List JSON 的 `tokens[]`，按当前 `--chain-id` 过滤取 `address`。

  ```powershell
  # Uniswap 默认列表(实测过滤出 390 个 chain-1 代币合约)
  blockscan discover --tokenlist https://tokens.uniswap.org --rate 3 -o out
  ```

- **`--coingecko <id>`**（可重复）→ 取 CoinGecko 币种在当前 `--chain-id` 上的合约地址（`/api/v3/coins/{id}` 的 `platforms` 映射，免费、无需 key）。链 id 映射 platform key（1→ethereum、137→polygon-pos…）。

  ```powershell
  blockscan discover --coingecko dai --coingecko usd-coin --rate 3 -o out
  ```

- **`--topic <hash> --from <block> --to <block>`**（topic 可重复）→ 链上 `eth_getLogs` 按事件 topic 扫区间，收集**发出该事件的合约**。例：`Upgraded`/`BeaconUpgraded` 找代理、`PoolCreated` 找池、`Transfer` 找代币。分块（`--log-chunk`，默认 2000）+ 并发（`--log-concurrency`，默认 4），单块失败仅告警。

  ```powershell
  # BeaconUpgraded(address) 找 beacon 代理（公共 RPC 常限范围，配小 --log-chunk）
  blockscan discover --topic 0x1cf3b03a6cf19fa2baba4df148e9dcabedea7f8a5c07840e207e5c089be95d3e `
    --from 19000000 --to 19000500 --log-chunk 50 --log-concurrency 8 --rate 3 -o out
  ```

  > 实测：Transfer 单块扫出 53 个合约并入库(47 已验证);并发对扫描吞吐影响明显——500 块 `eth_getLogs`，`--log-concurrency 1` 用 36s，`8` 仅 7s(**~5×**)。

#### 接入 Google 网页搜索（可选）

`discover` 默认不做网页搜索；提供两项凭据后自动启用（缺任一则跳过，不影响其它来源）：

1. **API key**：Google Cloud Console → 新建项目 → 启用「**Custom Search API**」→ 创建 API 密钥 → 即 `GOOGLE_API_KEY`。
2. **搜索引擎 id（cx）**：在 [programmablesearchengine.google.com](https://programmablesearchengine.google.com/) 新建搜索引擎，开启「搜索整个网络」→ 复制 **Search engine ID** → 即 `GOOGLE_CSE_ID`。
3. 免费额度 100 次/天。

```powershell
$env:GOOGLE_API_KEY = "AIza..."
$env:GOOGLE_CSE_ID  = "xxxxxxx:yyyy"
blockscan discover "Uniswap V4"          # 名称会同时走 Blockscout + Google
# 或显式传参：
blockscan discover "Uniswap V4" --google-api-key AIza... --google-cse-id xxxx
```

底层调用 `GET https://www.googleapis.com/customsearch/v1?key=<KEY>&cx=<CSE>&q=<查询>`，解析 `items[].link` 中的合约地址。

### 富化表格（`--table`）

`--table` 会通过 **Blockscout 免费 API** 富化三项（best-effort，失败/无数据显示 `-`，不影响扫描）：
**名称标签**、**项目URL**、**代币持仓**（按 USD 取前 3，如 `WBTC(~$32.3M), USDC(~$57.5M) …`）。
非主网用 `--blockscout-base` 指向对应链的 Blockscout，或置空 `--blockscout-base ""` 关闭富化。
富化结果**按地址缓存**（同一次运行内重复地址不重复请求），并以 `--blockscout-rate`（默认 4/s）**令牌桶限速**，避免触发免费节点限流。

加 `--table` 后，每个成功抓取的合约会打印一张对齐表，例如：

```text
+------------+--------------------------------------------------------------------+
| 地址       | 0x000000000004444c5dc75cb358380d2e3de08a90                         |
| 合约名     | PoolManager                                                        |
| 名称标签   | PoolManager                                                        |
| 项目URL    | -                                                                  |
| 已验证     | 是                                                                 |
| 编译器     | v0.8.26+commit.8a97fa7a                                            |
| 代理       | 否                                                                 |
| 余额       | 51,092.965160 ETH                                                  |
| 代币持仓   | DOT(~$141.3M), USDT(~$65.7M), USDC(~$57.5M) …                      |
| 创建者     | 0x6b93e3bb9c0780c0f9042346ffc379530a5882c1                         |
| 字节码大小 | 24009 字节                                                         |
| 源码文件数 | 44                                                                 |
+------------+--------------------------------------------------------------------+
```

## 输出结构

```
output/
  0xa0b8.../                 # 合约地址（小写）
    metadata.json            # 全量合约详情
    bytecode.hex             # 链上 runtime 字节码
    abi.json                 # ABI（已验证时）
    source/                  # 已验证源码（保留工程目录结构）
      Contract.sol
      @openzeppelin/...
```

`metadata.json` 字段：地址、chain_id、字节码与大小、余额(wei)、是否已验证、合约名、编译器版本、优化设置、EVM 版本、license、constructor 参数、是否代理及实现地址、creator、创建交易 hash、是否有 ABI、源码文件数、`analysis`（静态分析,见下）。

> **代理识别**：`is_proxy`/`implementation` 优先取 Etherscan；若 Etherscan 未标记，则从链上字节码识别 **EIP-1167 最小代理（clone）** 并解析出实现地址——即使合约未验证也能识别。

## 安全审计引擎（Security Audit Engine）

一个**独立的标准化审计引擎**(模块 `audit`):扫描合约的**同时**检测漏洞并打分,结果写入 `metadata.json.audit`、`--manifest` CSV、`--table` 表格,随 `--format json/ndjson` 输出。定位是 **Slither-lite 启发式 linter**,是分诊信号,**需人工复核**(会有误报/漏报)。默认开启,`--no-audit` 关闭。详见 [docs/AUDIT_DESIGN.md](docs/AUDIT_DESIGN.md)。

**三层漏洞分类**:`category`(L1 = OWASP Smart Contract Top 10,如 `SC01:Access Control`)→ `swc`(L2 = SWC Registry 编号,如 `SWC-115`,SCWE 前身)→ `rule_id`(L3 内部规则,如 `TX_ORIGIN_AUTH`)。

**SecurityFinding v2**(每条发现):`severity` + `confidence` + `impact_score`/`likelihood_score` + `exploitability` + `asset_at_risk` + `blast_radius` + `risk`(单条 0–100)+ `priority`(P0–P3)+ `locations` + `evidence` + `exploit_scenario` + `recommendation` + `references` + `false_positive_notes`。

**检测层面**:
- **源码**(已验证,按行扫描、**注释与字符串感知**):tx.origin 鉴权、selfdestruct、未保护 `initialize()`(跨行识别修饰符)、delegatecall、低层 call、弱随机、ecrecover、浮动 pragma、旧编译器(<0.8)、assembly、废弃构造。
- **AST 精化**(源码可解析时,`slang_solidity`):对 `TX_ORIGIN_AUTH`(仅当处于 `==`/`!=`/`<`/`>`/`if`/`require`/`assert` 鉴权上下文)与 `UNCHECKED_LOW_LEVEL_CALL`(仅当 `.call` 结果未被消费)消除子串启发式的误报,`detection` 标为 `ast`;并以**函数内数据流**判定绑定的成功布尔是否在调用后被 gate(`require`/`assert`/`if`-`while`-`for` 条件/直接 `return`)检查 —— `(bool ok,)=a.call(); require(ok);` 不再误报,而 `(bool ok,)=a.call{value:..}(); /*不检查*/` 仍报(SWC-104)。`REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE` 升级为 AST:低层外部调用后写**状态变量**(赋值/`++`/`delete`/元组/`push`-`pop`)且无 `nonReentrant` 守卫才报 —— 写**局部**变量、CEI 安全(写在调用前)不再误报。`ACCESS_MISSING_GUARD_PRIVILEGED_FN` 升级为 AST:特权名 + public/external + 有实现 + **非 view/pure** + 无守卫(结构化 only*/auth/restrict 修饰符、或 require/if/比较里的 `msg.sender`、或 `_checkOwner`/`_checkRole` 调用)才报 —— 结构化修饰符(不被 `setOnlyX`/参数名误中)、全函数 `msg.sender` 扫描、跳过接口/抽象声明。`WEAK_BLOCK_RANDOMNESS` 升级为 AST:区块源(`block.timestamp`/`number`/`difficulty`/`prevrandao`/`blockhash(..)`)仅在 **`%` 取模 / `keccak`-`sha` 种子**上下文才报 —— `require(block.timestamp>=deadline)`、记账等合法用途不再误报。`ECRECOVER_NO_ZERO_CHECK` 升级为 AST:`ecrecover(..)` 恢复地址未与 `address(0)`/`0` 比较(内联或经绑定变量)才报 —— 写得好的签名验证(`require(s!=address(0))`,EIP-2612 permit/meta-tx)不再误报。解析失败 / 深嵌套(防栈溢出)/ panic 自动降级回行级启发式。**评分不变**。
- **字节码**(所有合约,复用 `analysis`):SELFDESTRUCT / DELEGATECALL / CALLCODE / CREATE2、源码未验证。

**评分模型**:单条 `risk = impact × likelihood × confidence × exposure`(exposure 由 `blast_radius` 派生);**整体风险**按弱点键(swc 优先)去重后做"概率 OR"聚合(封顶 100,源/字节码同弱点不双计);`grade` A–F、`risk_level` Minimal–Critical、`priority` P0–P3。

**报告层**:整体评级 + 严重度/优先级矩阵 + OWASP 覆盖;`audit` 子命令汇总、CSV 扁平列(`risk_score/risk_grade/risk_level/findings/top_severity/top_category/owasp`)、json/ndjson 携带完整 v2 findings。

```bash
# 扫描并只保留含 high/critical 漏洞的合约,JSON 输出供 jq
blockscan addresses --file addrs.txt --only-vulnerable --format json -o out \
  | jq -r '.contracts[] | "\(.audit.grade) \(.audit.risk_score) \(.address)"'

# 只要风险分 >= 40 的
blockscan range --from 19000000 --to 19000050 --min-risk 40 -o out

# 对已下载到本地的语料离线重审(规则升级后批量重打分,无需联网),按风险排序
blockscan audit --by-risk -o out

# 导出 SARIF 2.1.0,上传到 GitHub Code Scanning / CI 安全看板
blockscan audit --format sarif -o out > findings.sarif

# 抑制已确认的误报 / 已接受基线(评分前剔除,分数随之下降)
blockscan audit --suppress suppress.json -o out
```

**`--suppress <file>`**(全局,扫描与 `audit` 均生效):一份 JSON 抑制配置,把三角验证确认的**误报**或**已接受基线**静默掉。每条按 `rule`/`contract`/`swc`/`category`/`fingerprint`(同 SARIF 指纹)匹配 —— 单条内非空键全部匹配(AND)、多条之间 OR;命中项在**评分前**剔除(分数与 summary 同步下降)。文件缺失/坏 JSON/无键条目 → `warn` 并**不抑制任何东西**(安全方向)。
```json
{ "suppress": [ { "rule": "ORACLE_SPOT_PRICE", "contract": "0xabc…", "reason": "该合约用 TWAP" },
                { "swc": "SWC-112" }, { "fingerprint": "deadbeef12345678" } ] }
```

> 实测(v2):WETH9→`B`、USDC FiatTokenProxy→`B 22/100 (Low)`、BoredApeYachtClub→`C 35/100 (Medium)`,findings 带 OWASP/SWC 分类与 P0–P3 优先级。后续按规则族(Access/Proxy/External Calls/DeFi-Oracle/Governance/Arithmetic/MEV/Bridge)逐步加深。

## 静态分析（`analysis`）

对每个合约**已下载的 runtime 字节码**做一次零网络的派生分析,结果写入 `metadata.json` 的 `analysis` 字段、`--manifest` CSV 追加列,并在 `--table` 表格中显示。即使合约**未验证**也有效(只读链上字节码)。

- **ERC 接口识别** `interfaces`：从字节码的 `PUSH4` 选择器判定 `ERC-20 / ERC-721 / ERC-1155 / ERC-165`(要求该标准核心选择器全部出现,保守低误报)。
- **危险操作码标记** `opcodes`：带 PUSH 立即数跳过的线性扫描,标出 `SELFDESTRUCT / DELEGATECALL / CALLCODE / CREATE / CREATE2`(纯描述性分诊信号)。
- **字节码指纹** `code_hash` / `code_hash_nometa`：全字节码 keccak,以及**去掉尾部 CBOR 元数据**后的 keccak —— 后者让"逻辑相同、仅元数据不同"的克隆得到同一指纹。
- **克隆聚类**：设 `--manifest` 时,在 manifest 同目录额外写 `clusters.json`,按 `code_hash_nometa` 把 size≥2 的克隆族归并(按族大小降序),可把成千上万工厂代理收敛成少数实现族。

```bash
# 扫一批地址并导出 manifest + clusters.json
blockscan addresses --file addrs.txt --manifest out/index.json -o out
# 性能探针(纯 CPU):24KB 字节码约 0.13ms/次(双 keccak 主导,~185 MB/s)
cargo run --release --example analyze -- 24000 100000
```

## 防御监控（`monitor`）

扫描区间内的**安全相关事件**,解码成结构化告警,落地到 `alerts.jsonl` / webhook / stdout —— 把链上"代理升级、所有权/管理员变更"变成可消费的威胁情报流(可 cron 周期化做监控)。

| 事件 | 含义 | 解出字段 |
|---|---|---|
| `Upgraded` / `BeaconUpgraded` | 代理实现/beacon 被升级 | `new_value`=新实现 |
| `OwnershipTransferred` | 所有权转移 | `previous`/`new_value`=新旧 owner |
| `AdminChanged` | 代理管理员变更 | `previous`/`new_value`=新旧 admin |
| `RoleGranted` / `RoleRevoked` | AccessControl 角色授予/撤销 | `new_value`=account,`previous`=sender |
| `Paused` / `Unpaused` | Pausable 紧急暂停/恢复 | `new_value`=account |
| `Transfer`(大额,opt-in) | ERC-20 转账 ≥ `--min-transfer` | `previous`=from,`new_value`=to,`amount`=value |

上 8 个为默认安全事件集;`Transfer` 高频,仅 `--min-transfer <原始最小单位>` 时纳入并按阈值过滤(自动排除 ERC-721)。

```bash
# 监控最近区间的代理升级/所有权变更,落 alerts.jsonl 并推 webhook
blockscan monitor --from 25417000 --to 25417200 \
  --alerts alerts.jsonl --webhook-url https://hooks.example.com/x -o out

# 只盯自己项目的合约(每行一地址),并用 jq 取出所有"新实现地址"
blockscan monitor --from 25417000 --to 25417200 --watchlist mycontracts.txt -o out \
  | jq -r 'select(.kind=="proxy-upgrade") | "\(.contract) -> \(.new_value)"'

# 新部署风险评分:审计区间内所有新合约,只对 risk≥50 的发告警(需 etherscan key)
blockscan monitor --from 25417000 --to 25417200 --audit-deployments --min-risk 50 \
  --alerts alerts.jsonl -o out   # 实测近 8 块 → grade C/risk 39 "未保护特权函数" 等

# 跨轮去重:周期化重跑同一区间,--baseline 记录已发告警指纹,重复的自动抑制
blockscan monitor --from 25417000 --to 25417200 --baseline seen.fp --alerts alerts.jsonl -o out

# 大额转账监控 + 节流:只报 ≥100 万(原始最小单位)的转账,每合约同类最多 5 条
blockscan monitor --from 25417000 --to 25417200 --min-transfer 1000000 --throttle 5 \
  --watchlist mytokens.txt --alerts alerts.jsonl -o out
```

- **`--audit-deployments`**:对区间内每个新部署合约跑完整安全审计,`risk_score>0 且 ≥--min-risk` 时发 `kind:"risky-deployment"` 告警(含 `risk_score`/`grade`);把"谁刚部署了高危合约"变成实时(cron 周期化)威胁情报。需 Etherscan key(拉源码);与 `--no-audit` 互斥。
- **`--baseline <file>`**:跨轮告警去重。每条告警按 `chain|block|contract|event|tx_hash|log_index|…` 算稳定指纹,已记录的抑制、新的发出并追加到文件;重叠区间/周期化重跑不再重复告警。汇总行会报 `(N suppressed)`。
- **`--min-transfer <amount>`**:把 ERC-20 `Transfer` 纳入监控,只对 `value ≥ amount`(原始最小单位 uint256)的发 `large-transfer` 告警(自动排除 ERC-721);高频,建议配 `--watchlist`。
- **`--throttle <N>`**:同类突发封顶 —— 每 `(链, 合约, kind)` 本次运行最多 N 条,超出丢弃(汇总报 `(M throttled)`);被节流者不写基线,下轮凭新预算可重发。
- **`--group`**:把同 `(链, 合约, event)` 的多条告警**折叠成运行结束时的一条 digest**(`event:"Grouped"`,`amount`=条数,`previous`="blocks first..last";risky 摘要保留最高 risk/grade),而非 `--throttle` 的硬丢弃;两者同给时 group 优先(throttle 被忽略并 warn)。
- `--alert-topic 0x..`(可重复)在内置安全事件集外追加自定义 topic0(无专用解码器的仅记录 `contract`+`event=unknown`)。
- **stdout** 是逐告警的 JSON 流(断管安全);`--alerts <file>` 追加写;`--webhook-url` best-effort POST;任一 sink 失败都只 `warn!`,**监控循环永不中断**。
- `--log-chunk` / `--log-concurrency` 同发现的日志扫描;支持 `--chains` 多链。

### 跟链头实时告警(`watch --alert-on-risk` / `--alert-events`)

`watch` 加任一告警开关即进入**实时告警模式**:跟着链头,每个确认块跑告警管线(不再批量下载所有新合约),复用上面的 sink + `--baseline` 去重。

```bash
# 实时监控:新部署审计 + 安全事件,risk≥50 才告警,跨 tick 去重(--alert-on-risk 需 key)
blockscan watch --alert-on-risk --alert-events --min-risk 50 \
  --alerts alerts.jsonl --baseline seen.fp --confirmations 2 -o out   # Ctrl-C 优雅退出

# 纯事件监控:只盯代理升级/所有权变更,无需 Etherscan key(与 monitor 一致)
blockscan watch --alert-events --webhook-url https://hooks.example.com/x
```

- **`--alert-on-risk`**:审计每个新部署、`risk≥--min-risk` 发 `risky-deployment`(需 key)。**`--alert-events`**:解码安全事件发告警(纯 RPC,免 key)。可单开或同开。
- **`--digest-interval <secs>`**(配 `--group`):每 N 秒周期性 flush 一次摘要,而非仅在 Ctrl-C 退出时。
- **`--chains 1,10,…`**(仅 alert 模式):多链**并行** watch(各链 RPC 取自 `ETH_RPC_URL_<id>`);各链独立去重/节流/分组,单一 Ctrl-C 停全部,汇总合并。下载模式仍单链。
- 某个块区间日志/回执拉取失败时**不推进**、下个 tick 重扫(配 `--baseline` 去重),不会静默跳过;`--confirmations` 落后链头避免重组。

## 机器可读输出（`--format`）

`--format`(全局,默认 `human`)控制 **stdout**:机器模式下 **stdout 只放数据**,日志/进度条/汇总一律走 **stderr**,可直接接 `jq` 或喂给 agent。

| 模式 | stdout |
|---|---|
| `human`(默认) | 中文表格(`--table`)、汇总行 |
| `json` | 运行结束输出一个 `{ run, stats, contracts }` JSON 文档(`contracts` 含完整 `analysis`/`audit`) |
| `ndjson` | **流式**:每保存一个合约输出一行紧凑 JSON(逐行可解析) |
| `sarif` | **SARIF 2.1.0** 日志(审计 findings),对接 GitHub Code Scanning / CI / IDE |

```bash
# 一个 JSON 文档,管道给 jq:列出所有检测为 ERC-20 的合约地址
blockscan addresses --file addrs.txt --format json -o out \
  | jq -r '.contracts[] | select(.analysis.interfaces|index("ERC-20")) | .address'

# 流式 ndjson:边扫边处理(内存恒定)
blockscan range --from 19000000 --to 19000010 --format ndjson -o out > stream.ndjson
```

## MCP 服务器（`blockscan mcp`）

把 BlockScan 暴露为 **agent 可调用的工具**:一个 stdio 上的 **MCP(Model Context Protocol)服务器**,说 JSON-RPC 2.0(换行分隔)。手写实现、**零新增运行时依赖**;`stdout` 只放协议消息、日志走 `stderr`。详见 [docs/MCP_DESIGN.md](docs/MCP_DESIGN.md)。

在 MCP 客户端(Claude Desktop / IDE 等)的配置里把 BlockScan 注册为一个 stdio server,命令即 `blockscan mcp`:

```json
{ "mcpServers": { "blockscan": { "command": "blockscan", "args": ["mcp"] } } }
```

**本地 HTTP 传输(Streamable HTTP,可选)**:`blockscan mcp --http <addr>` 在回环地址上起一个 HTTP 端点(单 `/mcp`,POST JSON-RPC),供按 URL 接入的客户端使用。`<addr>` 可为裸端口(`8765`)、`host:port` 或裸 host(默认端口 8765);**仅允许回环地址**(非 loopback 启动即报错),并校验 `Origin` 防 DNS-rebinding。

```bash
blockscan mcp --http 8765                      # 监听 127.0.0.1:8765/mcp
blockscan mcp --http 127.0.0.1:9000 --http-token "$BLOCKSCAN_MCP_TOKEN"   # 加 Bearer 鉴权
```

> ⚠️ **不带 `--http-token` 时端点对本机任意进程开放**(无鉴权;Origin/loopback 防护只挡浏览器跨站,不挡本机恶意进程)。多用户 / 共享主机务必设 `--http-token`(或经环境变量 `BLOCKSCAN_MCP_TOKEN`),客户端以 `Authorization: Bearer <token>` 提供。HTTP 与 stdio **完全同源**(复用同一 `handle` 与 9 工具),tools-only 无服务器主动推流,故无需 SSE/会话。

工具集(离线工具无需网络,直接复用本地语料 / 纯审计):

| 工具 | 网络 | 作用 |
|---|---|---|
| `audit_source` | 离线 | 审计内联 Solidity 源码 + / 或字节码,返回标准化 `Audit`(分数/等级/findings) |
| `audit_corpus` | 离线 | 重审 `--out` 下已下载的全部合约,返回计数 + 合约 |
| `get_contract` | 离线 | 读取某已存合约的 metadata(可含源码) |
| `list_contracts` | 离线 | 列出已存合约(轻量),按最后保存的审计过滤 |
| `export_sarif` | 离线 | 重审语料并导出 SARIF 2.1.0 |
| `cluster_corpus` | 离线 | 按去元数据字节码哈希聚类克隆族 |
| `scan_addresses` | 在线 | 链上扫描给定地址(取码+源码+审计+落盘),需 `rpc_url`+`etherscan_key`(随调用内联) |
| `scan_block_range` | 在线 | 扫描有界区间(≤500 块)内所有新部署并审计落盘,需 key;超界提示分页 |
| `monitor_range` | 在线 | 解码有界区间(≤500 块)安全事件(可 `min_transfer`/`watchlist`)并**返回**告警;仅需 `rpc_url`(无 key) |

并暴露 **resources**:`resources/list` 列出 `-o`/`--out` 下每个已存合约(`blockscan://contract/<address>`),`resources/read` 读取其 metadata JSON。离线工具的 `out` 默认即服务器 `-o`。

> 工具执行失败(合约未找到、网络出错等)以 `result.isError=true` + 文本返回(让模型看见),仅参数/方法错误才走 JSON-RPC `error`。`resources/read`/`get_contract` 的地址参数经 `Address` 校验,杜绝路径穿越。连续 `watch` 循环不适合同步 `tools/call`,故只给有界的 `scan_block_range`/`monitor_range`,由 agent 轮询分页。

## 测试

```bash
cargo test                 # 798 个用例：667 单元 + 131 集成
cargo clippy --all-targets # 零告警
```

集成测试用 `wiremock` 起本地 mock 的 RPC（JSON-RPC，回显 id）与 Etherscan 服务，
覆盖三种扫描模式、续跑/去重、未验证降级、各类错误与重试路径，**不访问真实网络**。

覆盖率（需要 `cargo install cargo-llvm-cov`）：

```bash
cargo llvm-cov --ignore-filename-regex 'main\.rs' --show-missing-lines
```

库代码（`src/` 除 `main.rs` 外）**行覆盖率 97.25%**（区域 96.83%、函数 98.52%），由 CI 的 `coverage` job
每次推送实测、门禁设在 97%；此处只记百分比，精确行数每次提交都会微动，以该 job 日志为准。逐模块数字见 [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md)。
最大缺口是 `lib.rs` 90.2%（约占全部未覆盖行的四成）——watch/monitor
循环与多链 fan-out 的错误路径需真实链才能触达。`main.rs` 仅是入口转发（解析参数 → 初始化日志 → 调 `run`），逻辑全在 `lib.rs` 中并被完整测试，故从指标中排除。
剩余未覆盖行集中于三类**无法在「不访问真实网络」的单元测试中确定性触发**的防御性分支，均经人工审阅、
行为都是"记告警并优雅降级（返回空 / 跳过）"：

1. **网络 I/O 失败路径**——HTTP 已成功响应后 `resp.text().await` 再失败、或连接中途断开
   （`website.rs` / `defillama.rs` / `tokenlist.rs` 的抓取辅助函数，以及 `rpc.rs` 重试耗尽）；
2. **多链编排分支**——仅在真实多链运行 / 某链 RPC 缺失时触发的告警与跳过（`lib.rs` 若干行）；
3. **对实际不会失败的内存序列化/写入的 `?` 传播**。

## 工厂合约发现（`--trace`）

默认区块发现基于交易回执的 `contract_address`，仅捕获**顶层部署**。加 `--trace` 后，
`range`/`watch` 每块会额外调用 RPC 的 `trace_block`，把工厂合约通过 CREATE/CREATE2
**内部部署**的合约也找出来，与回执结果合并去重。

```bash
blockscan range --from 19000000 --to 19000010 --trace
blockscan watch --trace
```

- 需要 RPC 开启 `trace_` 命名空间（Erigon / Reth / Nethermind / 归档型服务商）。
- 若 RPC 不支持，`trace_block` 调用会被记为**告警并跳过**（不中断），当块仍按顶层部署正常处理。

## 已知局限

- 源码来自 Etherscan，未验证时回退 Sourcify；两者都没有则只保存字节码与可得元信息。
- `discover` 网页搜索用 Google Custom Search（需 `GOOGLE_API_KEY` + `GOOGLE_CSE_ID`，免费档 100 次/天）；GitHub 来源解析 hardhat-deploy / Foundry 部署产物，并从 `README.md` / `*scope*.md` 抽取地址与 explorer 链接（审计 scope）。
- 多链 RPC 需各自通过 `ETH_RPC_URL_<id>` 提供；单链时直接用 `--rpc-url`。
- CSV 汇总对以 `= + - @`（以及制表符 / CR）开头的字段加 `'` 前缀，使电子表格按文本而非公式处理。
- 人类模式的 stdout 用标准打印；下游管道被关闭时可能表现为 I/O 错误（本工具的主要产出是落盘文件）。
- 审计引擎是启发式 linter —— 它给的是分诊信号，不是验证结论。发现项需人工复核。

## 版本发布

打了 tag 的版本会在 GitHub **Releases** 页附上预编译的 Windows 二进制：

- `blockscan.zip` —— 内含 `blockscan.exe`（x86_64-pc-windows-msvc）。
- `blockscan-<version>-x86_64-pc-windows-msvc.tar.gz` —— 二进制与 `README.md`、`LICENSE`、`RELEASE_NOTES.md` 打包。
- `SHA256SUMS` —— 每个发布产物的 SHA-256 校验和（用 `sha256sum -c SHA256SUMS` 校验，PowerShell 用 `Get-FileHash`）。
- `RELEASE_NOTES.md` —— 该版本的发布说明。

## 更新记录（Changelog）

本项目所有重要变更记录于此。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [语义化版本](https://semver.org/lang/zh-CN/)。

### [1.1.0] - 2026-08-22

自 1.0.0 以来两条线：八个阶段经绑定图深化审计引擎精度，以及一份外部源码与文档审计的 17 项清单（已完成 13 项）。下文每个语料数字均为对已提交的 42 合约语料**实测**，非估算。

- **审计精度（Phase 23-30）**。重入的状态写入与访问控制判定改由**绑定图**解析而非看名字：特权函数按**它写什么**判定，`_msgSender()` 算调用者，重入调用面覆盖合约类型与转换接收者（`IERC20(a).m()`），不再跟随复合初始化器。语料效果：`PROXY_UNPROTECTED_INITIALIZER` 17 -> 1、`WEAK_BLOCK_RANDOMNESS` 13 -> 0、`UNSAFE_DOWNCAST_TRUNCATION` 138 -> 107，全规则 817 -> 773 次。
- **可重现（T-04）**。所有链上状态读取走同一个区块——启动时解析一次，或用 `--at-block` 指定；`metadata.json` 记录 `block_number` 与 `block_hash`。同一 pin 的两次扫描产出逐字节相同的结果。
- **MCP 硬化（T-01/02/03）**。输出目录限定在服务端基目录内；HTTP 模式**必须**持 bearer 凭据，未传则自行生成；外发 RPC 端点改由**启动时白名单**决定而非请求参数，且传输失败被折叠，使工具无法充当端口扫描器。
- **检测作用域（T-06/07）**。Chainlink 陈旧与未保护 initialize 两条规则改用**函数体**作为作用域而非固定行数，属于相邻调用的守卫不再压掉无守卫的发现。代理识别新增标准前 zeppelinos 槽与 EIP-2535 钻石（loupe 枚举）。
- **诚实输出（T-05/T-16）**。浏览器查询失败记为“未应答”而非“不存在”，并在运行汇总中计入降级；风险分现在会说明抑制从中剔除了多少发现。
- **新增能力**。`blockscan bundle` 产出可验证结果包（in-toto Statement + SLSA provenance，sha256 与 keccak256 双摘要，cosign 分离签名）；`--manifest report.md` / `report.html` 产出**报告文档**而非每合约一行；`import.rs` 将其他分析器的结果归一到相同形状且**不影响评分**。
- **卫生（T-15/T-17）**。声明 `rust-version = "1.97.1"` 并新增**按该版本构建**的 CI job；README 双语对在 CI 中做结构校对；解析错误不再嵌入无界的响应体。
- 工程：**794 测试**（667 单元 + 112 集成 + 11 MCP 硬化 + 4 文档锁步），`cargo clippy --all-targets` 零告警。

### [1.0.0] - 2026-06-30

首个稳定版（自 0.1.0 起的全部能力固化为 1.0）。在 0.1.0 基础上新增/强化：

- **安全审计引擎**深化至 **36 检测器**：源码可解析时 **8 条规则经 slang AST 精化 + 1 条 AST-only `DELEGATECALL_ARBITRARY_TARGET`**（tx-origin / unchecked-call + 函数内数据流 / reentrancy CEI（含 `receive`/`fallback`）/ access-control / weak-randomness / ecrecover / transfer-send 实参计数 / 收窄 cast）；**Phase 22 绑定图**（`slang BindingGraph`）带来 scope-aware 名字/类型解析，消除类型相关误报（`uint160(addrVar)`/`uint8(enumVar)`/`endpoint.send(payload)`），三级 graceful degradation。
- **发现源** 增加 `--coingecko`（按链取币种合约）。
- **防御监控** 全套（`monitor`/`watch` 实时 + 部署风险评分 + `--baseline` 去重 + `--throttle`/`--group`/`--digest-interval` + alert 模式多链并行）；**MCP 服务器** 9 工具 + resources（stdio + 本地 HTTP，loopback + Origin 校验 + 有界 body + 可选 Bearer）。
- **发版前严苛审计**修复一批稳健性/安全问题：Etherscan 5xx/429 重试、websearch/github 状态与地址边界校验、`min_balance` fail-closed、Blockscout 失败不缓存、`storage` 写入边界 sanitize、MCP 常量时间 token 比较 + 拒绝 `Origin: null`、风险摘要稳定排序、AST 深度守卫覆盖扁平链；并补 MIT LICENSE 与发布元数据。
- 工程：**637 测试**（532 单元 + 105 集成），`cargo clippy --all-targets` 零告警，全工作区行覆盖 ~97.9%。

### [0.1.0] - 2026-06-28

首个版本：三种扫描模式、RPC + Etherscan V2 + Sourcify 数据源、多标准代理识别、静态分析 + 克隆聚类、标准化安全审计引擎、多来源 `discover`、防御监控、机器可读输出、MCP 服务器、多链扫描、续跑/去重。逐阶段设计记录见 [docs/](docs/)。

## 许可

[MIT](LICENSE) © 2026 adomore
