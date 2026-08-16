# Discover 设计文档（合约发现）

`discover` 子命令的目标：给一个项目/线索，自动汇集相关合约地址，去重后送入统一扫描流水线
（`eth_getCode` 校验剔除 EOA → Etherscan/Sourcify 源码 → 代理识别 → 落盘/表格/manifest）。

## 状态图例
- ✅ 已实现
- 🔜 本轮实现
- 📋 待办（暂不能/不宜做成自动 `discover` 源，或需较重依赖）

## 已实现的源
| 源 | 参数 | 拿到什么 | 状态 |
|---|---|---|---|
| Blockscout 搜索 | `discover <名称>` | name tag / token / contract 命中地址 | ✅ |
| GitHub 部署产物 | `--github owner/repo` | hardhat-deploy / Foundry 部署 json 里的地址 | ✅ |
| 官网/文档浅爬 | `--website <url> [--crawl-depth]` | 页面正文 + explorer 链接里的地址（同主机浅爬） | ✅ |
| Google 网页搜索 | `--google-api-key/--google-cse-id` | 搜索结果 `/address/0x…` 链接 | ✅（需凭据） |
| DefiLlama | `--defillama <slug>` | `/protocol/{slug}` 主合约锚点地址 | ✅ |
| Token Lists | `--tokenlist <url>` | 标准 Token List `tokens[]`，按 `--chain-id` 过滤 | ✅ |
| **CoinGecko** | `--coingecko <id>` | `/coins/{id}` 的 `platforms` 映射，按 `--chain-id` 映射 platform key 取地址 | ✅ |
| 事件 topic 扫描 | `discover --topic <hash> --from/--to` | 发射该事件的合约地址 | ✅ |

---

## A. 数据聚合 API —— "项目→合约"最干净的来源
| 思路 | 能做成 discover 源？ | 说明 |
|---|---|---|
| **DefiLlama** `--defillama <slug>` | ✅ 已实现 | `/protocol/{slug}` 的 `address` 字段 = 协议主代币/治理合约（1 个/协议，可能 `chain:0x…`）。免费、准、最广。注意：**不是全部合约**，是锚点。 |
| **CoinGecko** `--coingecko <id>` | ✅ 已实现 | `/coins/{id}` 的 `platforms` 映射(platform-slug→合约地址),按当前 `--chain-id` 映射到 CoinGecko platform key 取地址。免费档(无 key)可用。CMC 需 key,仍 📋 待办。 |
| **Token Lists** `--tokenlist <url>` | ✅ 已实现 | 标准 Token List JSON 的 `tokens[]`，按当前 `--chain-id` 过滤取 `address`。轻量、确定。 |
| ethereum-lists/contracts（社区映射） | 📋 待办 | GitHub 仓库 `contracts/<chainId>/0x….json` 是**地址→项目**反向映射，需全量枚举(数千文件)才能"按项目找"，不适合做发现源；更适合后续做"标签/归属"反查。 |
| Sourcify 已验证合约枚举 | 📋 待办 | 可列某链全部已验证合约；量极大，更适合"全量普查"而非"项目发现"。 |

## B. 链上驱动 —— 不靠官网，直接从链上找某类合约
| 思路 | 能做成 discover 源？ | 说明 |
|---|---|---|
| **事件 topic 扫描** `--topic <hash> --from --to` | ✅ 已实现 | `eth_getLogs` 按事件 topic 扫区间，取发出事件的合约地址。例：`Upgraded`/`BeaconUpgraded`（代理）、`PoolCreated`、`Transfer`（代币）。分块（`--log-chunk`）+ 并发（`--log-concurrency`），单块失败仅告警。 |
| 字节码指纹 / 4byte 选择器 | 📋 待办 | 从 runtime bytecode 提选择器判 ERC-20/721/1155 或已知协议；按 bytecode keccak 聚类找同模板 clone。需先有一批候选地址。 |
| 工厂展开（factory → children） | 📋 待办 | 已有「代理→实现」；进一步枚举工厂 `*Created` 事件子合约可归入 topic 扫描。 |
| 活跃/大额榜（Dune 等） | 📋 待办 | 依赖 Dune API key + SQL。 |

## C. 安全/审计生态 —— 审计场景最对口
| 思路 | 能做成 discover 源？ | 说明 |
|---|---|---|
| **Code4rena / Sherlock 竞赛 scope** | ✅ 已实现（via `--github`） | 竞赛仓库的 `README.md` / `*scope*.md` 里常列待审合约地址(scope 表/部署表)。GitHub 源现已额外解析 README/scope markdown 中的 `0x{40}` 与 explorer `/address/` 链接。用法：`discover --github <contest-owner/repo>`。注：纯预部署竞赛(无链上地址)自然无可发现合约。 |
| Immunefi bug bounty assets | 📋 待办 | 项目页 in-scope 合约；有非公开 API，解析较脆。 |
| DeFiHackLabs / rekt.news（历史被攻击合约） | 📋 待办 | DeFiHackLabs GitHub 含 PoC + 受害合约地址，可解析其测试文件。 |

## D. 代码与发布物
| 思路 | 能做成 discover 源？ | 说明 |
|---|---|---|
| NPM `@org/contracts` 包内 deployments | 📋 待办 | 从 npm registry 下 tarball 解析 `deployments/*.json`；比扒 GitHub 稳（发布物必有）。 |
| GitLab / Gitee / Radicle 代码搜索 | 📋 待办 | 同 GitHub 思路，换 API。 |
| 合约 metadata（IPFS/Swarm） | 📋 待办 | 已验证合约 metadata 里有源码路径，少数含项目信息。 |

---

## 第一批实现范围 —— ✅ 已完成
1. **DefiLlama 源** `--defillama <slug>`（可重复）：取协议主合约地址。
2. **链上事件 topic 扫描** `--topic <hash>`（可重复）+ `--from/--to` + `--log-chunk` + `--log-concurrency`：`eth_getLogs` 分块并发扫描，收集发出该事件的合约地址。

两者均汇入现有去重 + `eth_getCode` 校验 + 源码/代理/落盘流水线。

**验证记录**：
- 功能（单元 + 集成，wiremock mock，不走真网）+ 真链：`--defillama lido` → LDO `0x5a98…1b32`；`--topic Transfer` 单块 → 53 合约入库（47 已验证）。
- 性能：`eth_getLogs` 扫 500 块，`--log-concurrency 1`=36s vs `8`=7s（约 5×）。
- `examples/log_scan.rs` 为吞吐测量工具、`examples/resolve_proxy.rs` 为代理探测工具。

## 第二批实现范围 —— ✅ 已完成
1. **C 类审计 scope 导入**（via `--github`）：GitHub 源在原有 hardhat-deploy / Foundry 部署产物之外，额外解析 `README.md` / `*scope*.md`，抽取其中的 `0x{40}` 地址与 explorer `/address/` 链接 —— 直接对接 Code4rena / Sherlock 竞赛仓库的 scope。`lib`/`node_modules` 路径段（vendored）跳过。
2. **Token Lists** `--tokenlist <url>`（可重复）：拉取标准 Token List JSON，按当前 `--chain-id` 过滤 `tokens[]` 取 `address`。

两者同样汇入去重 + `eth_getCode` 校验 + 源码/代理/落盘流水线。

**对抗式代码审查**：开发前对两个新源（DefiLlama + topic 扫描）跑了一轮多 agent 对抗式审查，发现并修复 8 个真实问题（地址边界截断、空 topic、反转区间、slug 注入、分块失败计数等）。

**验证记录**：
- 功能（单元 + 集成，wiremock mock，不走真网）：`github` README/scope markdown 抽取（`discover_extracts_readme_scope_addresses`，含 `lib/` vendored 排除）；`tokenlist` 按链过滤 / 无 tokens / HTTP 错误 / 非法 JSON / dead endpoint 全覆盖。
- 真链功能：`--tokenlist`（Uniswap 默认列表，1473 token）→ 过滤出 **390 个 chain-1 合约**入扫描流水线。
- 性能：Token List fetch+parse 为 O(n)、网络受限，1473 条目毫秒级解析；审计 scope 抽取为 I/O 受限（2 次 API + N 次 raw markdown），随文件数线性。
- 覆盖率：新文件 `defillama.rs`/`tokenlist.rs` 行覆盖各仅差 1 行（`resp.text().await` 成功响应后再失败的不可确定性触发分支）；`github.rs` 97.9%。全量 **210 测试通过、clippy 零告警**，库行覆盖 ~98%（未覆盖 73 行均为网络 I/O 失败 / 多链编排 / 防御性 `?` 分支，详见 README「测试」）。

## 第三批实现范围 —— CoinGecko 源 ✅

**目标**：`--coingecko <id>`（可重复）新增一个干净的「币种→多链合约」发现源，补齐 A 类聚合 API 的 CoinGecko。沿用 `defillama`/`tokenlist` 的成熟模式（独立 `Client`、`http1_only` + 30s 超时、best-effort 出错返空、wiremock 可测），**零新增依赖**。

### 设计（`src/coingecko.rs`）
- API：免费档 `GET {base}/api/v3/coins/{id}`（无 key）；响应含 `platforms` 映射 `{ "ethereum":"0x…", "polygon-pos":"0x…", … }`（CoinGecko platform slug → 合约地址）。
- **按当前 `--chain-id` 取地址**：`coingecko_platform(chain_id)` 把链 id 映射到 CoinGecko platform key —— 1→`ethereum`、10→`optimistic-ethereum`、8453→`base`、42161→`arbitrum-one`、137→`polygon-pos`（未知链 → `None` → 返空，不乱猜）。只取该链的地址（单源单链，与 `tokenlist` 一致）。
- `fetch_addresses(id, chain_id) -> Vec<String>`：拼 URL（`encode_id` 百分号编码，防路径注入，复用 defillama 思路）→ GET → 非 2xx/解析失败仅 `warn!` 返空 → `parse_platforms` 取该 platform key 的值 → `valid_address` 校验（小写 0x+40hex，非零）。
- 接线：`cli.rs` 加 `--coingecko: Vec<String>`；`lib.rs::discover_addresses` fan-out 里 `client.fetch_addresses(id, scanner.chain_id())`，汇入统一 union/dedup + `eth_getCode` 校验 + 落盘流水线。

### 已知取舍（诚实声明）
- 只取**当前链**的合约（与 tokenlist 一致）；多链需配合 `--chains` 多次扫描。
- 免费档限速严（~10–30 req/min）：多 id 顺序拉，出错返空不阻断；不做重试（best-effort）。
- 未知/不支持的链 id → 返空（`coingecko_platform` 仅覆盖项目支持的 5 条链）。

### 测试与性能（目标 ~100% 覆盖）
- 单元：`parse_platforms` 取对链地址 / 缺该链 / 缺 `platforms` / 空串 / 非法地址过滤；`coingecko_platform` 5 链映射 + 未知链；`encode_id` 中和保留字；dead endpoint / HTTP 错误 / 非法 JSON 返空；`new`/`default` 构建。
- 集成：wiremock mock `/api/v3/coins/{id}` 返 `platforms` → 取出该链地址。
- 性能：单次 GET + O(1) map 取值，网络受限。

### 对抗式审查记录
3-lens（地址边界 / 注入 / 链映射健全）对抗式审查 + ground-truth 复核。

> 状态：✅ 第三批（CoinGecko）完成。测试数见 README。
