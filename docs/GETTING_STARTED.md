# BlockScan 新手指南

> 🌐 语言:**中文** · [English](GETTING_STARTED.en.md)

十分钟从零跑通 BlockScan：装好、配好、扫到第一个合约、看懂结果。想要逐参数的完整说明，读完这份再去 [用户手册 USER_MANUAL.md](USER_MANUAL.md)。

---

## 1. BlockScan 是什么

一个 Rust 命令行工具,一条命令完成:

> **发现**以太坊(及兼容 EVM 链)智能合约 → **下载**已验证源码 + 链上字节码 + 合约详情 → **静态分析 + 安全审计打分** → **过滤** → **落盘** → 人类/机器可读输出。

另带两条支线:**防御性监控告警**(`monitor`/`watch`)和一个把全部能力暴露给 AI agent 的 **MCP 服务器**(`mcp`)。

适合谁:安全审计 / 研究人员、需要批量拉合约源码做分析的工程师、想给 AI agent 接上链上审计能力的开发者。

---

## 2. 开跑前需要什么

| 必需? | 东西 | 怎么拿 |
|---|---|---|
| 必需 | **Rust**(2021 edition)+ 可链接的 C 工具链 | Windows 装 MSVC Build Tools;见下 |
| 必需 | **以太坊 RPC 端点** | 免费公共节点即可:`https://ethereum-rpc.publicnode.com`(无需 key) |
| 强烈建议 | **Etherscan V2 API key** | [etherscan.io](https://etherscan.io/) 免费注册 → API Keys;拉已验证源码要用 |
| 可选 | GitHub token / Google CSE 凭据 | 仅在用 `discover` 的对应源时才需要 |

> 没有 Etherscan key 也能跑——但拿不到已验证源码,只会得到字节码 + 字节码级审计信号。**第一次上手强烈建议先弄一把免费 key。**

### Windows 工具链(本项目主力环境)
- rustup 默认工具链切到 **`stable-x86_64-pc-windows-msvc`**(gnu 工具链缺 dlltool/gcc,无法链接):
  ```powershell
  rustup default stable-x86_64-pc-windows-msvc
  ```
- 安装 **MSVC Build Tools**(勾选「使用 C++ 的桌面开发」工作负载 + Windows SDK)。cargo 会自动探测到 `link.exe`。
- 网络说明:对 Etherscan / 公共 RPC,默认 HTTP/2 在部分环境会报 `error sending request`。**无需你处理**——BlockScan 内部已对这些客户端强制 HTTP/1.1 + 超时 + 重试。

---

## 3. 安装(构建)

```bash
cargo build --release      # 产物:target/release/blockscan(Windows 为 blockscan.exe)
```

冒烟验证一下:

```bash
./target/release/blockscan --version      # 打印 blockscan 1.0.0
./target/release/blockscan --help         # 看 7 个子命令
```

把 `target/release/blockscan` 放进 `PATH`,之后就能直接敲 `blockscan`。本指南后续都用 `blockscan` 简写。

---

## 4. 配置凭据(一次搞定)

在工作目录放一个 `.env` 文件(参数也可命令行传,但 `.env` 最省事):

```
ETH_RPC_URL=https://ethereum-rpc.publicnode.com
ETHERSCAN_API_KEY=你的EtherscanV2Key
```

> Etherscan 免费档常限 **3 请求/秒**。若被限流,加 `--rate 3`(会自动退避重试),或降 `--concurrency`。

---

## 5. 你的第一次扫描

扫一个知名的已验证合约——USDC 代币:

```bash
blockscan addresses 0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48 --table -o out
```

这条命令会:取链上字节码 + 余额 → 拉 Etherscan 已验证源码/ABI/元数据 → 识别是否代理 → 跑安全审计打分 → 落盘到 `out/` → `--table` 打印一张中文详情表。

**你会看到**(示意):
```
+------------+--------------------------------------------------------------------+
| 地址       | 0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48                         |
| 合约名     | FiatTokenProxy                                                     |
| 已验证     | 是                                                                 |
| 代理       | 是 -> 0x... (EIP-1967)                                             |
| ...        | ...                                                               |
+------------+--------------------------------------------------------------------+
Done. saved=1 (verified=1), skipped=0, non-contract=0, failed=0
```

**落盘结构**(每个合约一个目录,地址小写):
```
out/0xa0b86991.../
  metadata.json     # 全量详情(含 analysis 与 audit 审计结果)
  bytecode.hex      # 链上 runtime 字节码
  abi.json          # ABI
  source/           # 已验证源码(多文件工程保留原始路径)
```

审计结果在 `metadata.json` 的 `audit` 字段里:风险分(0–100)、等级(A–F)、逐条发现(severity/rule_id/证据/修复建议)。

> 再次运行同一命令会 `skipped`(已存在则跳过)。想重拉加 `--overwrite`。

---

## 6. 五个最常见的任务

```bash
# ① 批量扫一个地址清单(每行一个地址,# 注释)
blockscan addresses --file addrs.txt -o out

# ② 扫一段历史区块里的新部署合约
blockscan range --from 19000000 --to 19000050 -o out

# ③ 按项目发现并扫描相关合约(Blockscout 名称搜索 + GitHub 部署文件)
blockscan discover "Uniswap V4" --github Uniswap/v4-core -o out

# ④ 只保留"有高危发现"的合约(审计过滤,适合筛风险)
blockscan addresses --file addrs.txt --only-vulnerable --min-risk 50 -o out

# ⑤ 离线对已下载的合约重新审计,按风险从高到低排序(规则升级后重打分,不联网)
blockscan audit --by-risk -o out
```

想要机器可读输出(接管道 / CI)?任意命令加 `--format json`(或 `ndjson` / `sarif`):**stdout 只放数据**,日志/进度/汇总走 stderr,可直接 `| jq`。

```bash
blockscan addresses 0xA0b8... --format json -o out | jq '.contracts[0].audit.risk_score'
blockscan audit --format sarif -o out > findings.sarif   # 喂 GitHub Code Scanning
```

---

## 7. 下一步

你已经会用 BlockScan 的核心流程了。深入方向:

| 想做的事 | 去看 |
|---|---|
| 逐参数、逐子命令的完整说明 | [用户手册 USER_MANUAL.md](USER_MANUAL.md) |
| 安全审计引擎(36 检测器 / 评分 / 抑制误报 / SARIF) | [用户手册 §5](USER_MANUAL.md#5-安全审计引擎) · [AUDIT_DESIGN.md](AUDIT_DESIGN.md) |
| 实时监控与告警(`monitor` / `watch --alert-*`) | [用户手册 §6](USER_MANUAL.md#6-防御监控与告警) · [MONITOR_DESIGN.md](MONITOR_DESIGN.md) |
| 把能力接给 AI agent(MCP 服务器) | [用户手册 §7](USER_MANUAL.md#7-mcp-服务器) · [MCP_DESIGN.md](MCP_DESIGN.md) |
| 多源项目发现(DefiLlama/TokenList/CoinGecko/官网…) | [用户手册 §4](USER_MANUAL.md#4-子命令参考) · [DISCOVERY_DESIGN.md](DISCOVERY_DESIGN.md) |
| 架构与模块 | [ARCHITECTURE.md](ARCHITECTURE.md) |

---

## 8. 卡住了?(快速排查)

- **`error sending request` / 连不上**:多为 HTTP/2 问题,BlockScan 已内部强制 HTTP/1.1,通常无需处理;确认 `--rpc-url` 可达、Etherscan key 有效。
- **被限流(Etherscan)**:`--rate 3`(免费档),会自动退避重试;必要时 `--concurrency` 调低。
- **合约显示"未验证"**:Etherscan 没有已验证源码;会自动回退 Sourcify(除非 `--no-sourcify`),仍无则只存字节码。
- **`--min-risk` / `--only-vulnerable` 把结果全过滤掉了**:这俩依赖审计结果,别同时加 `--no-audit`(会报错)。
- **Windows 链接失败(缺 link.exe / dlltool)**:确认工具链是 `msvc` 且装了 MSVC Build Tools(见 §2)。

完整 FAQ 见 [用户手册 §10](USER_MANUAL.md#10-故障排查--faq)。
