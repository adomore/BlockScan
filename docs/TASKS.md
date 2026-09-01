# BlockScan — 外部审计任务清单（TASKS T-01…T-17）

一份**外部源码与文档审计**开出的 17 条任务清单。与 `AUDIT_DESIGN.md` 的 Phase 序列不同：Phase 是本项目自己推进的能力演化，T 系列是**别人指着代码提出的问题**，因此每条的判据是「这个缺陷能不能再次发生」，而不是「功能是否更强」。

状态：**13 / 17 完成**。剩下四项被同一件事挡着——语料需要真实地址，而真实地址需要人来判断；其中 T-11 技术上今天就能做，是被一个**明确交给项目所有者的排序判断**拦住的。见[文末](#-未完成t-08t-11)。

> 驱动这批工作的外部审计包（`blockscan-evolution/`）与其提示词按 `.gitignore` 不入库——它们是这项工作的**输入**，不是本仓库的产物。本文是这批工作在仓库内的记录：状态矩阵里写着 `TASKS T-xx` 的行，指的就是下表。
>
> 总览与模块盘点见 [ARCHITECTURE.md](ARCHITECTURE.md)；审计引擎自身的演化见 [AUDIT_DESIGN.md](AUDIT_DESIGN.md)。

---

## ✅ 已完成

### 安全边界（MCP 与出站请求）

| 任务 | 缺陷 | 修法 | 看守 |
|---|---|---|---|
| **T-01** | `arg_out` 把请求里的 `out` 原样当作基路径。同一函数旁边的 `address` 参数**先解析成 `Address` 再拼路径**，注释写明理由是穿越——守卫装在了路径的叶子上，根上却没有，于是调用方可以选择本进程读写哪棵目录树。后续补丁另修 `post_raw` 与它自己断言的 body 上限竞争 | `out` 必须落在配置的 base 之内，父级穿越与越界一律拒绝 | `tests/mcp_hardening.rs`:`out_argument_with_parent_traversal_is_rejected` / `..._outside_the_server_base_is_rejected` / `omitting_the_out_argument_still_uses_the_server_base` |
| **T-02** | token 是 `Option<String>`，缺省时**跳过校验且不告警**。那个面上的其他控制项都是强制的（拒绝非回环绑定、Origin 精确匹配、body 有界、常数时间比较）——唯独防「同一台机器上另一个进程」的那一项默认关着 | HTTP 模式必须有 bearer 凭据；未提供则用 OS CSPRNG（`getrandom`）当场自签一个并打印 | `http_mode_started_without_a_token_still_requires_one` · `a_wrong_token_is_rejected` · `the_configured_token_is_accepted` · `stdio_mode_does_not_gain_a_credential_requirement` |
| **T-03** | `monitor_range` 从请求参数取 RPC 端点——调用方决定本进程下一个包发去哪里，是一个指向宿主可路由范围的**请求伪造原语**；传输错误又原样返回，拒绝 / 超时 / 协议不符彼此可区分，于是这个工具成了端口扫描器 | 出站端点收进 allow-list，**开 socket 之前**就拒绝；传输失败对调用方**不可区分** | `rpc_url_outside_the_allow_list_is_refused_before_any_socket_opens` · `an_allow_listed_rpc_url_is_accepted` · `transport_failures_are_indistinguishable_to_the_caller` |
| **T-17** | `etherscan.rs` 三处解析错误把**整个响应体**插进错误信息。凭据走 query string 所以此路不泄 key，且这份啰嗦有真实诊断价值（信封形状意外时，body 是唯一说明对方返回了什么的东西）——不该由本工具决定的是**长度与字节**，那是对方选的 | `clip_body` 限到 512 字节，**显式标出截断与原始字节数**，控制字符转义（否则 body 里的换行会向日志写出一行伪造记录）。预算管**输出**而非输入：一个控制字节转义后最长 7 字符，管输入等于对恰好是恶意构造的 body 失去界 | `etherscan.rs` 内联单测 |

### 结果的可复现与可验证

| 任务 | 缺陷 | 修法 | 看守 |
|---|---|---|---|
| **T-04** | `get_code` / `get_balance` / `storage_address` 都读链头。一次扫描要跑几分钟，每次读落在**当时**的头上：同一地址扫两遍可能不一致，且落盘结果里没有任何东西说明它由哪个链状态产生 | 每次状态读固定到**同一个区块**；`--at-block` 可显式指定，无法解析的显式 pin 直接报错而非静默回退 | `two_scans_at_the_same_pin_produce_identical_metadata` · 两份手册均记 `--at-block` |
| **T-13** | 审计结果一旦离开本机，收件方无法验证 | `blockscan bundle --into <dir> <产物>...`：产物原样 + in-toto Statement v1 清单（携 SLSA Provenance v1 predicate）+ 分离签名。三件事刻意不自己发明——**格式**用 in-toto/SLSA；**签名**外包给 `cosign sign-blob`（本 crate 不碰密钥，自制信任链比没有更糟，因为它看起来像）；**快照**必须来自 T-04 的区块固定，任一记录无 pin 则**拒绝打包且不创建目录**。摘要同时给 `sha256`（生态工具能核，实测与 `sha256sum` 逐字匹配）与 `keccak256` | `bundle.rs` 18 个内联单测 |
| **T-05** | `parse_source_code` 在信封 status 非 success 时返回携带浏览器消息的错误；二十行之后 `parse_creation` 把**同一个条件**映射成 `Ok(None)`。一种歧义，两个函数，相反的答案，且没有任何东西标出这个区别 | 两种响应失败模型统一：明确区分「对方说没有」与「对方说不出来」 | `etherscan.rs` 内联单测 · `a_failed_creation_lookup_degrades_the_record` |

### 检测精度与覆盖面

| 任务 | 缺陷 | 修法 | 看守 |
|---|---|---|---|
| **T-06** | `CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK` 与 `PROXY_UNPROTECTED_INITIALIZER` 按**固定行数**看前后。锚在使用点上本来就是对的（这正是它们区别于全文关键字匹配之处），错的是**行数不是作用域**：相邻调用的守卫会压掉一个本没有守卫的发现 | 两条规则改用 `scan_functions` 的**函数体**作用域。新鲜度判据从「附近有 require」改为「该调用解构出的**非价格槽**名字是否参与比较」；`initializer_has_body` 整个删除（作用域自身就排掉无体声明）。语料 172 发现 / 773 出现**逐行不变**，Phase 29 的 17 → 1 保持 | `audit.rs` / `ast.rs` 内联单测 |
| **T-07** | 实现槽、beacon 槽、proxiable 槽都覆盖了，最小代理按长度匹配——**标准前的 zeppelinos 槽**与**EIP-2535 钻石**没有，两类代理都被当成普通合约保存 | 补 `keccak256("org.zeppelinos.proxy.implementation")`（无 EIP-1967 的「减一」推导）与钻石的 `facetAddresses()` loupe 调用。钻石探测每合约多一次 `eth_call`，故以**字节码是否含 DELEGATECALL** 为闸（复用已有的操作码扫描，零成本）；返回值严格解码（头偏移、长度与载荷一致、每词高 12 字节为零），因为被问的合约本就不知自己是否钻石、带 fallback 的合约会回答**某个东西** | `a_diamond_is_detected_through_the_loupe` · `a_contract_that_never_delegates_is_not_probed` |
| **T-12** | 已经在跑成熟分析器的团队无法在一处看到两套结果，blockscan 的精度也无法在同一输入上与另一工具对比 | `audit --import <file>`（可重复）读 SARIF 2.1.0 或 Slither JSON，**按形状识别**，归一化进现有 `SecurityFinding` 不扩字段（新增的只有 `source`）。**只读文件，从不执行任何进程**（由一个扫描本模块源码的测试看守）。归属先看路径里的地址段，再看整路径分量后缀唯一匹配；**多个合约都拥有的路径不猜**（记 ambiguous 并告警）。`overall_risk` / `summarize` / `build_sarif` 均只取 `source == blockscan`，因此导入无法移动评分、不会被 blockscan 的 SARIF 冒领 | `import.rs` 12 个内联单测 |

### 输出与工程约束

| 任务 | 缺陷 | 修法 | 看守 |
|---|---|---|---|
| **T-14** | 输出服务于终端和管道，但没服务于「审计结果是一份要人读、要转发、要归档的**文档**」这一情形 | `--manifest` 按扩展名分发新增 `.md` / `.html`：总览 + 严重度（**出现次数**）+ 每合约发现（位置/证据/修复）。HTML 为单一自包含文件（样式内联、零脚本、零外部请求，由「文档内标签集必须是白名单子集」而非字串探针断言）。所有链上/浏览器来源的文本均视为敌对：HTML 全量转义，Markdown 用**自适应宽度的代码跨度**一次性中和全部构造。`.pdf` 显式拒绝并指向外部管道——不向二进制里加 PDF 写器 | `export.rs` 内联单测（含敌对字段夹具） |
| **T-15** | `README.md` 与其中文镜像已经分叉，而手册与新手指南两对仍然对齐——**做法是存在的，是 README 长出了它**。镜像之间的结构漂移从任一文件内部都看不见，所以它会累积 | 恢复 README 对的结构一致，并把检查写成测试：`tests/docs_lockstep.rs` 比对**标题层级序列 + 代码围栏数**，文字自由。放在 `tests/` 而非 CI 脚本，在引入漂移的那台机器上就红 | `readme_pair_is_in_lockstep` 等 4 个用例 |
| **T-16** | 两条隐含主张被显式化 | ①**编译器下限是量出来的，不是选的**：Cargo.lock 482 个包里最高的 `rust-version` 是 1.97.1，来自 `slang_solidity` 1.3.8 及 metaslang 系列（AST 层依赖的解析器）；写进 `Cargo.toml`，CI 新增 `msrv` job **从该文件读取**（不硬编码，否则第二份真相会静默漂移）。②`AuditSummary.suppressed` 记录被抑制规则剔除的发现数——剔除发生在**评分之前**，所以分数是抑制文件的函数，不报出剔了多少就是不可审计的数；JSON / SARIF `runs[0].properties.suppressedFindings` / `--table` 单元格 / `audit` 人类行 / T-14 报告文档均显示，为零时不显示 | CI `msrv` job · `audit.rs` 内联单测 |

### 本次补充

| 任务 | 内容 |
|---|---|
| **T-15 事实层** | T-15 的结构检查通过了，README 对却仍在它看不见的维度上分叉：同一个 `cargo test` 围栏英文写 693、中文写 637；英文「已知局限」有「分诊信号，不是验证器」的声明而中文没有；中文 `monitor` 一节记了四组英文完全没提的开关；事件表两边都是 8 行，第三列只有中文有。`tests/docs_lockstep.rs` 因此补上**事实层**四项断言——命令+flag 面、列表条目数、表格行×列、链接数——并各配一个「制造该漂移必须被抓到」的自检。用例 4 → 8 |

---

## 📋 未完成（T-08…T-11）

这四项不是「还没排上」，而是**被同一件事挡住**：语料需要真实地址，而真实地址需要人来判断。原清单 `TASKS.yaml` 底部的 `corpus_deferred` 块把边界写死了：

```yaml
hard_blocked:   [T-08, T-09, T-10]     # 缺语料，技术上做不了
held_by_policy: [T-11]                 # 技术上今天就能做，被排序判断拦住
free_now:       [T-01…T-07, T-12…T-17] # 正好 13 项,即上面已完成的那批
gate_condition: "corpus lands before T-11 merges"
```

依赖链是 **T-08 →（T-09、T-10）→〔政策〕→ T-11**。根在 T-08，不在 `known_good.json`。

| 任务 | 内容 | 产物 | 阻断 |
|---|---|---|---|
| **T-08** | **把语料发布成可复现清单**。规则注释里记着对 42 单元语料的真实测量——出现次数、点名的精确率/召回率取舍，是本代码库最强的信号——而**别人无法复现其中任何一条**。清单按 `chain_id` + 地址逐条列出、带上各自测量时固定的区块，并有一条文档化的命令能从空目录重建语料、不含手工步骤；不提交任何合约源码，消费清单的工具就是取语料的工具 | `corpus/manifest.json` | 硬阻断。依赖 T-04（已完成）——**未固定区块的语料无法重新测量**。原文注明这是数据收集而非编码,是全清单里唯一真正需要人对「每个标签意味着什么」做判断的一项 |
| **T-09** | **在 CI 里守检测质量，而不只是行覆盖**。覆盖率回答「代码有没有跑到」，而扫描器要回答的是「答案对不对」。跑 T-08 的语料算出**逐规则的精确率与召回率**，对入库的期望文件做断言，回归即挂构建；现有覆盖率门禁保留而非替换。验收方式是**故意弄坏一条规则，该 job 必须红** | `.github/workflows/ci.yml` | 硬阻断，依赖 T-08 |
| **T-10** | **误报预算**。没有任何东西断言「广泛持有、被反复审计的合约保持干净」。这道门禁要挡的正是对照组暴露的那种失败：把 WETH 合约以五条误报判成 critical 100/100,而它自己的 320 个测试一个都没察觉 | `corpus/known_good.json` | 硬阻断，依赖 T-08。**当前 8 槽填 1**（WETH9）,`pinned_block` 仍是占位符 `PIN_ME`,未接入 CI 或任何测试 |
| **T-11** | **协议级分析（批次 1）**。合约目前逐个分析、仅靠克隆聚类相互关联。而协议是一张图：共享管理员、共享实现、依赖边——有几类严重发现**只存在于这一层**,最要紧的是「共享实现里的缺陷,就是挂在它上面每一个代理的缺陷」,此时**爆炸半径本身就是那个发现** | `src/protocol.rs`,五条规则 `PROTO_SHARED_IMPLEMENTATION` / `PROTO_SHARED_DEPLOYER` / `PROTO_DANGLING_DEPENDENCY` / `PROTO_UNVERIFIED_DEPENDENCY` / `PROTO_VALUE_CONCENTRATION` | **政策阻断,非技术依赖**（`depends_on: []`）——见下 |

### T-11 为什么单独拦着

它 **`depends_on: []`**：随包附有失败测试规格（`blockscan-evolution/specs/protocol.rs`,541 行 26 个测试）,**今天就能编译、今天就能全绿**。拦住它的是一个排序判断,原清单标注 `decision_owner: project owner, not the implementing agent`——**实现者不得自行越权,必须停下来把决定交给项目所有者**。

- **越权代价**：五条规则上线时背后没有回归闸门。此后任何对协议级规则严重度、阈值、分组的改动,在语料落地前都**无法验证**；期间引入的任何误报,将由用户而非 CI 发现。
- **最便宜的缓解**：闸门的价值是**非线性**的——**三条 `known_good` 条目即可拿到大部分保护效果**,十条是覆盖目标而非开启门槛。播 WETH9 + 一个 AMM pair + 一个稳定币代理,**约一小时**就能把闸打开。流程见 [../corpus/KNOWN_GOOD_HOWTO.md](../corpus/KNOWN_GOOD_HOWTO.md)。

另有一条硬约束随任务给出：**不要造叙事层**。对照组用关键词匹配发现自身的文本去套固定模板,生成与合约无关的散文,读者分辨不出它和真实分析的区别。T-11 只出图与规则,不出威胁模型、不出滥用场景、**不引入协议级综合评分**（异构对象上的单一数字没有意义）。

### 为什么不能自己造地址填上

清单与语料文件都把这条写死了：

> **一个含错误地址的审计语料比没有语料更糟**,因为它产出一道证明不了任何事的绿灯。**永远不要为了解除自己的阻塞而编造地址。**

因此 `corpus/known_good.json` 里**只有 `verified=true` 的条目是对着真实扫描输出确认过的**,其余一律写成**选取程序**而非地址——宁可留空,不可填错。

> 原始清单 `TASKS.yaml` 与失败测试规格随外部审计包（`blockscan-evolution/`）提供,按 `.gitignore` 不入库。本节是它在仓库内的转述,以便判断这四项状态时不必再翻那个包。
