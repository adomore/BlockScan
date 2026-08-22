# known_good.json 实操指南

把 `corpus/known_good.json` 的七个空槽位填成真实、已验证的合约条目。这是 T-09 / T-10 的硬前置，也是整个语料工作里唯一需要人做判断的部分。

预计耗时 **3–5 小时**，其中约 80% 是等 API 和读 finding，20% 是真正的判断。

---

## 一、先理解「为什么这件事不能自动化」

要填的不是「找七个有名的合约」。要回答的是**一个具体问题**：

> 当 blockscan 在这个合约上报出一条 High，这条是真的，还是规则的误报？

这个问题只有人能答，因为它需要**看懂那段 Solidity 在做什么**。自动化能做的是把候选拉下来、跑扫描、把 finding 摆到你面前;判断留给你。

有一个容易踩的坑要先说清楚：

**不要把「blockscan 报了零条 High」当作入选标准。** 那是循环论证 —— 如果某条规则因为 bug 而从不触发，用它筛出来的 known-good 集会把这个 bug 永久固化成「正确行为」。

正确的标准是:**这个合约是业界公认安全的,因此它上面的任何 High 都应当被人逐条判为误报或记为已知可接受**。零条 High 是**期望的结果**,不是**筛选的条件**。

## 二、准备

```bash
# 1. 独立的语料输出目录，不要和日常扫描混在一起
mkdir -p corpus/known_good_work

# 2. 凭据（.env 或环境变量，二选一）
export ETHERSCAN_API_KEY=...
export ETH_RPC_URL=https://...

# 3. 确认能跑通
blockscan addresses 0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2 \
  --chain-id 1 --out corpus/known_good_work --table
```

最后一条应当拉到 WETH9 并打印审计表格。跑不通就先解决凭据,不要往下走。

## 三、每个槽位的三步循环

### 步骤 1 — 选候选

七个槽位的选取标准写在 `known_good.json` 的 `candidates_to_seed` 里。每个槽位选合约时,**四个条件全部满足**才算合格:

| 条件 | 怎么查 | 为什么 |
|---|---|---|
| 源码已验证 | 区块浏览器合约页有源码标签 | 未验证合约只能走字节码层,测不到源码规则 |
| 部署 ≥ 2 年 | 合约创建交易的时间 | 时间本身是审计强度的代理指标 |
| 使用量大 | 持有人数 / TVL / 交易数 | 「被很多人依赖」是「公认安全」的操作化定义 |
| 有公开审计报告 | 项目文档 / 审计机构站点 | 你判定误报时的第二意见来源 |

**优先选不可升级的合约。** 可升级的也能用,但实现随时会变,你固定的区块会更快失效。如果槽位本身要的就是代理(稳定币那个),那没办法,把 `pinned_block` 记牢就是了。

### 步骤 2 — 拉取并审计

```bash
ADDR=0x...            # 候选地址
SLOT=amm-pair         # 槽位名

blockscan addresses "$ADDR" \
  --chain-id 1 \
  --out corpus/known_good_work \
  --format json > "corpus/known_good_work/$SLOT.json"
```

产物落在 `corpus/known_good_work/<addr>/`,含 `metadata.json`、`source/`、`bytecode.hex`。

要重看审计而不重新抓网络:

```bash
blockscan audit --out corpus/known_good_work --by-risk
```

这一条是离线的,可以反复跑。

### 步骤 3 — 逐条裁决 finding

看这个合约的全部 finding:

```bash
python3 -c "
import json,sys
d=json.load(open('corpus/known_good_work/$ADDR/metadata.json'))
a=d.get('audit') or {}
print(f\"risk={a.get('risk_score')} grade={a.get('grade')}\")
for f in a.get('findings',[]):
    print(f\"  [{f['severity']:8}] {f['rule_id']}\")
    print(f\"            {f.get('evidence','')[:110]}\")
    for loc in f.get('locations',[])[:3]: print(f'            @ {loc}')
"
```

对每一条 **High 或 Critical**,打开 `locations` 指向的源码行,回答一个问题:

**这段代码真的有这个问题吗?**

三种结论,各有各的动作:

| 结论 | 动作 |
|---|---|
| **是误报** | 这正是这个合约该进语料的理由。记下 rule_id 与理由,它会成为回归保护的锚点。**同时开一张 bug 单修那条规则** —— known-good 集是发现规则缺陷的地方,不是绕过它的地方 |
| **是真的,但在这个合约的语境下可接受**(如稳定币的 blacklist 是有意设计) | 写进条目的 `known_acceptable_findings`,**必须附书面理由** |
| **是真的,且确实是风险** | **换一个候选。** 这个合约不该进 known-good 集 |

Medium 及以下不影响门禁,但值得扫一眼 —— 如果某条 Medium 明显是误报,同样开单。

### 步骤 4 — 固定区块并写入条目

拿当前区块高度:

```bash
cast block-number --rpc-url "$ETH_RPC_URL"     # 或任何能问到高度的方式
```

写进 `known_good.json` 的 `entries`:

```json
{
  "chain_id": 1,
  "address": "0x...",
  "name": "...",
  "verified": true,
  "verified_how": "fetched and audited on <日期>; source verified via etherscan; <持有人数/TVL 等佐证>",
  "pinned_block": 20123456,
  "why_in_set": "填 slot 名 + 它守的是哪条规则不退化",
  "known_acceptable_findings": []
}
```

**`pinned_block` 不能留 `PIN_ME`。** 没有它,一次代理升级就会在零代码改动的情况下改变门禁断言的内容 —— 那正是 T-04 从语料这一侧看到的同一个缺陷。

## 四、已完成条目长什么样(WETH9,可直接照抄格式)

这是包里唯一一条已验证条目,把它当模板:

```json
{
  "chain_id": 1,
  "address": "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2",
  "name": "WETH9",
  "verified": true,
  "verified_how": "present in real scan output; source verified, contract_name WETH9, holding ~2.44M ETH",
  "pinned_block": "PIN_ME",
  "why_in_set": "最被广泛持有的合约,也正是对照工具误判为 critical 100/100 的那个。集合若只剩一条,应当是它",
  "known_acceptable_findings": [
    {
      "rule_id": "OUTDATED_COMPILER",
      "severity": "Medium",
      "reason": "WETH9 是 solc 0.4.x。该 finding 正确且低于门禁阈值;记在此处以免后来者误认为噪音"
    }
  ]
}
```

注意 `known_acceptable_findings` 里那条 **Medium 也记了**。它不影响门禁,但记下来的价值是:下一个读这个文件的人不用重新判断一遍。

## 五、七个槽位的具体着眼点

每个槽位是为了守住某一族规则不退化。选的时候心里要清楚**它守的是哪条**:

| 槽位 | 数量 | 它守什么 |
|---|---|---|
| 稳定币代理 | 1 | 代理解析全链路;`OWNER_BLACKLIST_CONTROL` 必须停在 Low —— 黑名单在这一类里是有意设计,**严重度漂移会直接打破门禁** |
| AMM pair | 1 | `ORACLE_SPOT_PRICE_FROM_RESERVES` **不得**在 pair 上触发 —— pair 持有储备,它不读储备当价格。这是 oracle 规则精确率最有价值的单条 |
| AMM router | 1 | `MEV_SWAP_DEADLINE_BLOCK_TIMESTAMP` / `MEV_SWAP_ZERO_AMOUNT_OUT_MIN` 不得在正确接收 deadline 与 minOut 参数的 router 上触发 |
| 借贷市场 | 1 | Chainlink 新鲜度规则 + 访问控制规则,在一个**确实做对了守卫**的合约上 |
| Governor | 1 | 三条 `GOV_` 规则不得在有 timelock、提案阈值非零的 governor 上触发 |
| ERC-721 蓝筹 | 1 | ERC-721 接口识别;重入规则在合法使用 `safeTransferFrom` 回调的合约上 |
| 最小代理工厂 + 2 克隆 | 3 | EIP-1167 检测、克隆聚类,以及 **T-11 的共享实现规则 —— 这是给协议层唯一的真实正例** |

最后一个槽位是三个地址(工厂 + 两个克隆),所以总数是 10 而不是 8。

**先做 AMM pair 那个。** 它是七个里信息量最大的:如果 `ORACLE_SPOT_PRICE_FROM_RESERVES` 在一个 pair 上触发了,你立刻就知道那条规则的精确率有问题,而这个发现本身就值这几小时。

## 六、收尾校验

七个槽位填完后:

```bash
# 1. JSON 合法 + 无残留占位符
python3 -c "
import json
d=json.load(open('corpus/known_good.json'))
e=d['entries']
print(f'entries: {len(e)}')
bad=[x['address'] for x in e if x.get('pinned_block')=='PIN_ME' or not x.get('verified')]
print('未固定或未验证:', bad or '无')
assert len(e)>=10, f'目标 10 条,当前 {len(e)}'
assert not bad
print('OK')
"

# 2. 全量重跑,确认门禁条件成立
blockscan audit --out corpus/known_good_work --by-risk
```

第二条的期望结果:**每个条目 0 条 High/Critical**,除非它在 `known_acceptable_findings` 里有对应记录。

## 七、三个反模式(它们会让这道门禁变成橡皮图章)

**不要用抑制文件让门禁变绿。** `--suppress` 在计分**之前**丢弃 finding,会把回归同时从门禁和 precision 指标里藏起来。门禁红了只有两条出路:修规则,或写进 `known_acceptable_findings` 并附理由。

**不要为了凑数放宽标准。** 目标是 10 个合约,**小是刻意的** —— 每个条目在触发时都要能被单独辩护、单独复核。一个没人读的大集合是橡皮图章。宁可先交 6 个高质量条目,把另外 4 个留作 TODO。

**不要在同一族里选两个几乎一样的合约。** 两个同一工厂产出的 AMM pair 只能守住一次规则退化,却要花两份维护成本。七个槽位的设计就是让它们**各守一族**。

## 八、维护

- **每次发版重新固定区块。** 陈旧的 pin 仍然是可复现的 —— 那才是要紧的性质;会动的 pin 不是。
- 条目触发新 finding 时,按第三步的三种结论重新裁决一次,不要直接加进 `known_acceptable_findings` 了事。
- 某个条目被弃用或迁移(项目关停、合约被替换),**删掉并补一个新的**,不要留一个指向死合约的条目。
