# BlockScan — 合约静态分析设计（Analysis）

下游分析能力的设计文档。原则:**对已经下载到本地的字节码/源码/ABI 做派生分析,几乎零新增网络成本**,结果落入 `ContractDetails`,随 metadata.json / manifest / 表格一并输出。

状态图例:✅ 已实现 · 🔜 本批实现 · 📋 待办

状态:✅ 批量 1 完成(危险操作码 + ERC 接口识别 + 字节码指纹/克隆聚类)。总览见 [ARCHITECTURE.md](ARCHITECTURE.md)。

---

## 第三批 · 批量 1:分析三连（✅ 已完成）

三项分析共享同一次字节码遍历,统一新增到 `model::Analysis` 子结构(挂在 `ContractDetails.analysis`,`#[serde(default)]` 兼容旧 metadata.json),由 `scanner::build_details` 在装配时计算(纯函数、无网络)。新增模块 `src/analysis.rs`。

### A. 危险操作码标记（risk opcodes）
- **先去掉尾部 CBOR 元数据再遍历**(`strip_metadata` → `walk`)—— 否则元数据里常见的 `0xff`/`0xf4` 等字节会被误判成 SELFDESTRUCT/DELEGATECALL。
- 对(去元数据后的)字节码做一次**带 PUSH 立即数跳过**的线性遍历:遇到 `PUSH1..PUSH32`(0x60–0x7f)跳过其 `op-0x5f` 个立即数字节,避免把"嵌在 PUSH 数据里的字节"误判成操作码。
- 收集出现的高危操作码(均 > 0x7f,不会与 PUSH 混淆):
  - `SELFDESTRUCT` 0xff、`DELEGATECALL` 0xf4、`CALLCODE` 0xf2、`CREATE` 0xf0、`CREATE2` 0xf5。
- 输出 `analysis.opcodes: Vec<String>`(去重、字典序),纯描述性三分诊信号,不做拦截。
- **正确性要点**:PUSH 立即数跳过是唯一坑,用单元测试钉死(`60ff` = PUSH1 0xff 不得识别为 SELFDESTRUCT;裸 `ff` 必须识别)。

### B. ERC 接口识别（interfaces）
- 同一次遍历顺带收集合约**派发(dispatch)的**函数选择器:识别 `PUSHk <sel> EQ`(k=1..4,EQ=0x14)模式,把立即数**右对齐**成 u32。这样:
  - 能捕获 solc 因前导零字节而缩短的选择器 —— 例如 `balanceOf(address,uint256)`=`0x00fdd58e` 实际被编译成 `PUSH3 0xfdd58e`(若只认 `PUSH4` 会漏掉,导致 ERC-1155 永远识别不到);
  - 排除仅为**构造 calldata**(合约去*调用*某接口,而非*实现*它)而 PUSH 的选择器 —— 那些后面跟的是 MSTORE 而非 EQ。
- 对每个标准,要求其**核心选择器全部出现**才判定(保守、低误报):
  - **ERC-20**:transfer/transferFrom/approve/balanceOf(address)/totalSupply/allowance。
  - **ERC-721**:ownerOf/balanceOf(address)/transferFrom/approve/setApprovalForAll/getApproved/isApprovedForAll。
  - **ERC-1155**:balanceOf(address,uint256)/balanceOfBatch/setApprovalForAll/isApprovedForAll/safeTransferFrom(1155)/safeBatchTransferFrom。
  - **ERC-165**:supportsInterface(bytes4)。
- 输出 `analysis.interfaces: Vec<String>`。**即使未验证也能识别**(纯字节码),这是核心价值。
- **已知局限**:基于 PUSH4 派发约定的启发式;极端优化器/Vyper/跳转表布局可能漏判;最小代理(EIP-1167)无选择器 → 接口为空(符合预期)。

### C. 字节码指纹 + 克隆聚类（fingerprint + clusters）
- `analysis.code_hash` = `keccak256(runtime 全字节码)`;`analysis.code_hash_nometa` = 去掉尾部 CBOR 元数据后的 `keccak256`。
- 去元数据:读末尾 2 字节大端长度 `L`,若 `L>0 && L+2<=len` 则裁掉末尾 `L+2` 字节再哈希 —— 让"源码路径/元数据不同但逻辑相同"的克隆得到相同 `code_hash_nometa`。
- 哈希用 `alloy::primitives::keccak256`(无新依赖)。
- **克隆聚类**(manifest 后处理):`analysis::cluster_by_code(&[ContractDetails])` 按 `code_hash_nometa` 分组,保留 size≥2 的族,按族大小降序。当 `--manifest` 设置时,在 manifest 同目录额外写 `clusters.json`,把成千上万工厂代理收敛成少数实现族。

### 输出落点(本批统一改一次模型)
- `model::ContractDetails` 新增 `analysis: Analysis`(`#[serde(default)]`)。
- `report.rs` 表格新增行:接口、风险操作码、代码哈希(去元数据,短)。
- `export.rs` CSV 追加列:`code_hash_nometa`、`interfaces`(`;` 连接)、`risk_opcodes`(`;` 连接)。
- `lib.rs::write_manifest_if_set`:写 manifest 后落 `clusters.json`。

### 测试与性能(目标 100% 覆盖)
- **功能**:`analysis.rs` 17 个单元测试覆盖 PUSH 跳过、EQ 门控选择器(含 PUSH3 前导零、calldata 非 EQ 不计)、各 ERC 集命中/不命中、去元数据哈希(含不清空保护)、聚类(size<2 丢弃、空哈希跳过、**去重先于 size 过滤**);经 `run()` 全链路保存后 metadata.json 含非空 `code_hash` 且 `--manifest` 落 `clusters.json`(集成断言)。
- **真链功能验证**:WETH9 → `ERC-20`;BAYC → `ERC-721 + ERC-165`;两者 `opcodes` 均为空(现代 solc 带 CBOR 元数据,证明去元数据后无幻影操作码)。
- **性能**:`analyze` 为 O(n) 单遍、纯 CPU、无网络;`examples/analyze.rs` 实测 24KB 字节码 ≈ 0.13ms/次(双 keccak 主导,~185 MB/s)。

### 对抗式审查(开发后)
12-agent 对抗式审查(4 lens × find → 8 verify)确认并修复 **4 类真实缺陷**:
1. 操作码/选择器遍历跑在**含元数据**的全字节码上 → 元数据字节被误判为危险操作码/幻影选择器。**修**:遍历前 `strip_metadata`。
2. **ERC-1155 永远识别不到** —— `0x00fdd58e` 被 solc 编成 `PUSH3`,而旧实现只认 `PUSH4`。**修**:EQ 门控的 `PUSH1..4` 右对齐捕获。
3. 选择器扫描把"调用接口"误当"实现接口"(路由/聚合器假阳)。**修**:同上,只认 `PUSHk <sel> EQ`。
4. `cluster_by_code` 在 `dedup` **之前**做 size≥2 过滤 → 跨链同地址会产出 `count==1` 的假克隆族;`strip_metadata` 可能把代码清空 → `keccak("")` 误聚类。**修**:去重先于过滤;`strip` 保证至少留 1 字节(`total < n`)。

> 状态:✅ 批量 1 完成(全量 **228 测试** 通过、clippy 零告警、库行覆盖 ~98%)。

---

## 后续批次(规划占位)

- **批量 2:JSON/NDJSON stdout 输出模式**(`--format human|json|ndjson`)—— 详见 [DISCOVERY_DESIGN.md] 之外的输出设计,届时在本文件补章节。
- **批量 3:防御闭环**(代理升级/管理员变更监控 + 结构化告警出口 `alerts.jsonl` / `--webhook-url`)—— 届时补章节。
