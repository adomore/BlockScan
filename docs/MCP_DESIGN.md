# BlockScan — MCP 服务器设计（Model Context Protocol）

把 BlockScan 暴露为 **agent 可调用的工具**:一个 stdio 上的 MCP 服务器(`blockscan mcp`),复用既有的审计/SARIF/存储/扫描能力。基于研究工作流(协议 / Rust crate / 工具面 三份调研)并经源码核对。

状态:✅ Phase 16/18/20 完成(`blockscan mcp` 子命令;9 工具 + resources;stdio + 本地 HTTP 传输)。前置 `--format json`(OUTPUT_DESIGN 已铺路)。全项目测试总数以 [ARCHITECTURE.md](ARCHITECTURE.md) 为准。

## 一、选型:hand-roll(不引入 rmcp)

**手写 stdio JSON-RPC 2.0 循环,零新增运行时依赖**(仅给 `tokio` 增 `io-std`/`io-util` feature)。理由:

1. **协议面极小且稳定**:tools-only 服务器只需 `initialize` / `notifications/initialized` / `tools/list` / `tools/call`(+ `ping`),线格式跨版本一致。
2. **依赖精简**:项目已手写 JSON-RPC(`rpc.rs`),刻意保持依赖瘦。`rmcp` 会拽入 `schemars`/`rmcp-macros`/`tokio-util` 等一票传递依赖,为十来个工具不成比例。
3. **可测性是决定项**:本机 `cargo-llvm-cov` 不捕获子进程覆盖率(build-env 已记录),而流程要求高覆盖。手写的 `handle(req) -> Option<resp>` 是(几乎)纯函数,可**进程内**喂 JSON-RPC、断言响应 —— 与现有 `lib::run` + wiremock 模式一致。rmcp 的宏 + transport 间接层会逼出子进程测试。
4. **工具只是薄适配层**:真逻辑都在 lib(`audit_with`/`build_sarif`/`storage::*`/`Scanner`),MCP 层只做参数映射 + 结果格式化 + stdout/stderr 纪律。

> 何时改 rmcp:需要 HTTP/SSE 传输、resources/prompts/sampling、OAuth,或要自动跟踪 spec 修订时。

## 二、协议实现

- **版本协商**:`initialize` **回显客户端请求的 `protocolVersion`**(服务器支持 tools 的全部历史版本,线格式一致),无 `params.protocolVersion` 时回退 `2025-06-18`。回显 = 最大互操作,且不依赖任何"最新版本字符串"的断言。
- **stdio 帧**:**换行分隔 JSON(JSON Lines),无 `Content-Length` 头**。每行一条完整 JSON-RPC 消息(消息内不得含裸换行);UTF-8;紧凑序列化 + 追加单个 `\n` + **每条 flush**。
- **stdout 纪律**:stdout **只放 MCP 消息**。日志经 `init_tracing`(已 `.with_writer(stderr)`)走 stderr;`mcp` 模式不打印任何人类文本到 stdout。
- **握手/循环**:读 stdin 行 → `initialize`(回 `protocolVersion`/`capabilities:{tools:{}}`/`serverInfo`)→ `notifications/initialized`(无 id,不回)→ 运行期处理 `tools/list`/`tools/call`/`ping`,忽略所有 `notifications/*` → stdin EOF 干净退出。
- **错误映射(实际发出)**:解析失败 `-32700`;未知 method `-32601`;未知工具名 / 缺失或非法参数(含坏 bytecode hex)`-32602`。其余 JSON-RPC 码(`-32600`/`-32603`)在 tools-only stdio 下不会触发,故未实现。**关键区分**:工具自身执行失败(如某地址抓取失败、合约未找到、`Config::validate` 失败)**不是协议错误** —— 返回成功 `result` 但置 `isError:true`、错误文本入 `content[].text`,让 LLM 可见。

## 三、工具集

复用既有 serde 类型(`ContractDetails`/`Audit`/`SecurityFinding`/`CloneCluster`/`RunStats`/SARIF `Value`)。**离线/纯工具优先**(无网络、可进程内测到满覆盖)。`tools/call` 成功结果含 `content:[{type:text,text:<pretty json>}]` + `structuredContent:<value>` + `isError:false`。

### Tier 1 — 离线/纯
| 工具 | 包装 | 关键输入 | 返回 |
|---|---|---|---|
| `audit_source`(旗舰) | `audit::audit_with` + `ContractDetails::minimal` + `analysis::analyze` | `address?`/`chain_id?`/`sources?:[{path,content}]`/`bytecode?`(0x-hex)/`compiler_version?`/`is_proxy?` | 单个 `Audit` |
| `audit_corpus` | `lib::audit_corpus`(由 `run_audit` 抽出) | `out?`/`min_risk?`/`only_vulnerable?`/`by_risk?` | `{audited,vulnerable,contracts}` |
| `get_contract` | `storage::load_metadata`(+`load_sources`) | `out?`/`address`/`include_source?` | `{contract, sources?}` |
| `list_contracts` | `storage::load_all_metadata` + 过滤 | `out?`/`min_risk?`/`only_vulnerable?` | `[{address,chain_id,contract_name,is_verified,risk_score,grade}]` |
| `export_sarif` | `audit_corpus` → `sarif::build_sarif` | `out?`/`min_risk?`/`only_vulnerable?` | SARIF 2.1.0 `Value` |
| `cluster_corpus` | `storage::load_all_metadata` → `analysis::cluster_by_code` | `out?` | `[CloneCluster]` |

### Tier 2 — 在线(网络参数随调用内联,自包含)
| 工具 | 包装 | 关键输入 | 返回 |
|---|---|---|---|
| `scan_addresses` | `build_scanner` + `Scanner::process_addresses` | `addresses`、`rpc_url`、`etherscan_key`、`etherscan_base?`、`chain_id?`、`out?`、`overwrite?`、`audit?`、过滤项 | `{stats:RunStats, contracts:[ContractDetails]}` |

内部强制 `format=Json` 以物化 `contracts`;失败(校验/网络)走 `isError:true`。

### 明确排除
连续 `watch` / 无限 `monitor` 循环不适合同步 `tools/call`(无自然完成点)。**对策**:已有的有界原语(离线工具 + 一次性 `scan_addresses`)即可;agent 需要"准实时"时自行轮询。长任务若日后要做,应走异步 job 模式(`*_start`→`job_id`→`*_poll`),不进 `tools/call`。

## 四、模块与接线

- 新模块 **`src/mcp.rs`**(单文件,与全项目风格一致):`serve_stdio()`(transport 循环)、`pub async fn handle(&Value)->Option<Value>`(分发,可进程内测)、工具注册表 `tool_list()` + `call_tool(name,args)`、结果/错误辅助。MCP 是 crate 根的后代模块,可直接调用 `crate::build_scanner` 等 crate-私有项,无需为它放宽可见性。
- `cli.rs`:`Command` 新增 `Mcp`(无参子命令)。
- `lib.rs::run`:match 增 `Command::Mcp => mcp::serve_stdio().await?`;抽出 `pub fn audit_corpus(...)`(供 `run_audit` 与 MCP 共用)。
- `Cargo.toml`:`tokio` 增 `io-std`/`io-util`。**无其它新依赖。**

## 五、测试策略(无 live 客户端、确定性、进程内)

- **协议循环单测**:对 `handle(req)` 喂构造的 JSON-RPC `Value`,断言响应。覆盖 `initialize`(版本回显)、`notifications/*`→`None`、未知 method `-32601`、`ping`、`tools/list`(每个 `inputSchema.type=="object"`)、`tools/call` 往返(`content`/`structuredContent`/`isError`)、解析错误 `-32700`、未知工具/坏参数 `-32602`。
- **离线工具直测**:`tempfile` 造语料测 `audit_corpus`/`list_contracts`/`export_sarif`/`cluster_corpus`/`get_contract`;`audit_source` 喂内联 source/bytecode。
- **在线工具**:`scan_addresses` 经 wiremock 注入 `rpc_url`/`etherscan_base`,沿用既有 Scanner 测试;失败路径断言 `isError:true`。
- **stdout 纪律**:断言序列化消息不含裸 `\n`;`serve_stdio` 的 EOF 退出经一个小的内存往返测试(或 `handle` 级覆盖)。

## 六、风险 / 取舍

- **stdout 污染最致命**:任何 `println!`/panic/库日志写 stdout 即破坏传输。缓解:日志强制 stderr + stdout 纪律单测 + `serve_stdio` 只写序列化响应。
- **手写自担 spec 跟踪**:但三方法形状稳定,负担远小于跟 rmcp 1.x 破坏性升级;版本回显进一步解耦"最新版本"。
- **在线工具把密钥放进 `tools/call` 参数**:由 MCP 客户端配置传入(与 CLI 传 `--etherscan-key` 同信任面);文档提示用环境/配置注入,勿硬编码。

### 对抗式审查记录(Phase 16,2-agent)
协议/传输层与工具层均**无 high/critical**。审查认证:单行 JSON 帧安全(`to_string` 紧凑转义,内嵌换行不可能;`responses_are_single_line_json` 守护)、请求/通知/解析错误分派正确、信封恒带 `jsonrpc:"2.0"`、tool-error 与 protocol-error 区分正确、**stdout 纯净端到端可达性已验证**(含 `scan_addresses` → `process_addresses`:`format=Json`+`table=false` 使两处 stdout 写分支皆死,进度条 hidden 且 indicatif 走 stderr);工具无 panic、无 key 泄漏、`SourceFile` 仅经 `sources_to_json` 输出、`structuredContent` 仅对象、Config 逐字段对齐 CLI 默认。修复/澄清:
1. **(med)** `list_contracts` 用**已存**审计过滤、`audit_corpus` **重审**,跨工具静默不一致 → 在 `list_contracts` 描述中明示"按最后保存的审计过滤、不重审,`--no-audit` 存的会被 min_risk/only_vulnerable 排除"。
2. **(low)** `audit_source` 由调用方 sources 置 `is_verified=true`(仅表"提供了源",非"源与字节码匹配")→ 描述中澄清。
3. **(low/test)** bytecode 测试注释错误(`0x60ff` 中 `0xff` 是 PUSH1 立即数)→ 改用独立 `0xff` 并断言 `BYTECODE_SELFDESTRUCT`,真正覆盖字节码检测器路径。
4. **(doc)** 错误表声称 `-32600/-32603` 但实际不发 → 文档改为"实际发出"并注明二者在 tools-only 下不触发。
5. **(robustness)** 序列化失败分支静默 → 加 `tracing::error!`(近乎不可能,但可观测)。
- 其余为 by-design(unknown-tool 用 `-32602` 是合理选择;无 batch 符合 MCP 2025-06-18 已移除批处理)。

> 状态:✅ Phase 16 完成(`mcp.rs` 行覆盖 98.9%,唯一缺口为 `serve_stdio` 真 stdin 包装器 —— 由二进制子进程测试 `binary_mcp_subcommand_serves_initialize_over_stdio` 覆盖,llvm-cov 不计子进程;库总 ~98%;全量 377 测试)。

## 七、Phase 18 增量:resources + 有界区间工具 ✅

在 Phase 16 的 7 工具上补:把已下载语料暴露为 **MCP resources**,并加两个**有界**在线工具,把 `range`/`monitor` 的能力安全地给到 agent。**HTTP/SSE 传输明确推迟**(需 web/transport 依赖或转 rmcp,与"手写精简 stdio"决策冲突;列为可选后续)。

### ServerCtx(小重构)
resources 无 per-call 参数,需知道语料目录。引入 `ServerCtx{ out: PathBuf }`(来自 `blockscan -o <dir> mcp`),贯穿 `handle(ctx, req)`;**离线工具的 `out` 默认值改用 `ctx.out`**(仍可被 per-call `out` 覆盖)——`-o` 成为服务器级默认,更顺手。`handle` 仍是可进程内测的(几乎)纯函数,测试传入构造的 `ServerCtx`。

### Resources
- `capabilities` 加 `resources: {}`。
- `resources/list`:每个已存合约一条 `{ uri:"blockscan://contract/<address>", name:<合约名或地址>, mimeType:"application/json", description }`(读 `storage::load_all_metadata(ctx.out)`)。
- `resources/read`(参数 `uri`):解析 `blockscan://contract/<address>` → `storage::load_metadata` → 返回 `contents:[{uri, mimeType:"application/json", text:<metadata json>}]`;未知 uri → `-32602`。

### 有界在线工具
| 工具 | 包装 | 输入 | 返回 |
|---|---|---|---|
| `scan_block_range` | `process_block` 循环(`format=Json` → 不写 stdout、收集 contracts) | `from`/`to`(`to-from+1 ≤ MAX=500,否则 BadArgs`)、网络参数、`trace?` | `{stats, contracts}` |
| `monitor_range` | **专用收集式**事件扫描(`rpc.fetch_logs` + `events::parse_alert`,**不经 sink/stdout**) | `from`/`to`(有界)、`rpc_url`、`alert_topic?`、`min_transfer?`、`watchlist?`(内联地址数组) | `{alerts:[Alert], counts:{...}, incomplete}` |

- **关键纪律**:`monitor_range` **绝不**复用 `scan_events_range`(它 `emit_alert_line`→stdout,会污染 MCP 通道);改在 `mcp.rs` 内直接 `fetch_logs`+`parse_alert`+watchlist/min_transfer 过滤,收集进 `Vec<Alert>` 返回。`scan_block_range` 走 `format=Json` 的 `process_block`,该模式只收集不写 stdout(已验证),可安全复用。
- 有界:两者均拒绝超 `MAX_RANGE` 的区间并提示 agent 分页(`chain_head` 微工具可后续补,供 agent 自驱"准实时")。

**测试**:`resources/list`/`resources/read`(命中/未知 uri);`scan_block_range` 经 wiremock(含超界 BadArgs);`monitor_range` 经 wiremock 注入日志 → 返回 alerts 且 **stdout 不被写**(收集式);`ServerCtx.out` 默认值生效。

### 对抗式审查记录(Phase 18,1-agent)
确认并修复 **2 个 ship-blocker**;stdout 纯净(最关键不变量)与其余各点确认正确:
1. **(high,安全)路径穿越**:`resources/read` 与 `get_contract` 把 uri/参数里的 address 未净化传给 `storage::load_metadata`→`out.join(address)`,`../`/绝对路径/`C:\…` 可逃出语料目录(甚至 `include_source` 递归读目标目录)。**修**:先 `address.parse::<Address>()` 校验(解析成功即规范 20 字节十六进制,不含 `/`/`\`/`..`/`:`、非绝对),失败即 `-32602`/`BadArgs`;用规范 `{a:#x}` 再查。补回归 `resources_*`/`get_contract_rejects_non_address`。
2. **(med,正确性)`bounded_range` u64 溢出**:`to-from+1` 在 `to=u64::MAX` 溢出 → release 环绕为 0 绕过上界(变无界扫描)、debug panic 崩服务。**修**:改 `to - from >= MAX_RANGE`(等价 span>MAX,无 `+1`)。补回归 `bounded_range_rejects_overflow_span`。
- 确认正确:**stdout 纯净** —— `monitor_range` 内联 `fetch_logs`+`parse_alert` 收集,绝不调 `scan_events_range`/`deliver_alert`/`emit_alert_line`;`scan_block_range` 走 `format=Json` 的 `process_block`(`process_addresses` 命中 `_=>{}`,无 stdout 写)。`build_scan_config` 逐字段对齐 CLI 默认、validate 先于 build、无 key 泄漏;`ServerCtx` 默认 out 一致;9 工具 schema 合规;tool-error/`-32602` 映射与 Phase 16 一致。

> 状态:✅ Phase 18 完成(`mcp.rs` 行覆盖 97.9%,余 `serve_stdio` stdin 包装器 + 2 个防御性不可达分支;库总 98.0%;全量 397 测试)。

## 八、Phase 20:HTTP 传输(Streamable HTTP,tools-only)✅

在 stdio 之外加一个**本地 HTTP 端点**,与 stdio 并存。核心:**原样复用纯分发 `handle(ctx, &Value) -> Option<Value>`**,不改 9 工具/调度/审计。

- **选型**:`hyper` 1.x(仅 `server`+`http1`)+ `hyper-util` + `http-body-util`;`tokio` 加 `net`。全纯 Rust、MSVC 干净构建、无 TLS(localhost)。不选 rmcp(SSE/会话/handler trait 对 tools-only 是净亏)/axum(过重)/裸 TCP(重造 HTTP)。
- **端点**:单 `/mcp`。**POST**:校验 `Origin`(仅 localhost/127.0.0.1,防 DNS-rebinding → 403)、body ≤ 1 MiB(超 → 413);解析失败 → 200 + JSON-RPC `-32700`;`handle` 返回 `Some` → 200 `application/json`;`None`(通知)→ 202 空。**GET/DELETE** → 405(合法表示无服务器主动推流 ⇒ **无需 SSE**);其它路径 → 404。**无状态**(不签发 `Mcp-Session-Id`)。仅绑 `127.0.0.1`(非 loopback 启动报错)。可选 `--http-token` → `Authorization: Bearer`(否则 401)。
- **关键**:业务错误(`-32602`/`isError`)已由 `handle` 按 MCP 处理,HTTP 层一律包 200,**不**映射成 HTTP 4xx/5xx。
- **CLI**:`McpArgs { http: Option<String>, http_token: Option<String> }`;`mcp` 默认仍 stdio,`--http <addr>` 切 HTTP(addr 校验 loopback,缺端口补 8765)。
- **模块**:`mcp.rs` 加 `serve_http(out, addr, token)`(`parse_loopback_addr` → `TcpListener::bind` → 委托 `serve_http_on`)与 `serve_http_on(listener, out, token)`(在已绑定 listener 上跑 accept 循环 `tokio::select!{ ctrl_c, accept }` + 每连接 `tokio::spawn` + `hyper::server::conn::http1::serve_connection`;日志经 `listener.local_addr()` 打印,两条入口一致)。**拆分 bind/accept 的动机**:调用方(尤其进程内测试)可先绑 listener、从*活的* listener 取真实端口再喂流量——消除 bind→close→rebind 间端口被并发进程抢占的窗口,且连接前 socket 已处 LISTEN(连接进 accept backlog,`connect` 不依赖 accept 是否就绪)。`http_handle_conn`(从 `hyper::Request` 取 parts、**`Limited::new(body, MAX_HTTP_BODY)` 有界读** → 超限即 413,再调下游)、与**纯函数** `http_handle(ctx, token, method, path, headers, body) -> (status, content_type, body)`(路由 `/mcp` + 方法 + token + `origin_allowed` + 调 `handle`,**不触网、不 spawn**,可内存单测)。`parse_loopback_addr` 接受裸端口 / `host:port` / 裸 host,经 `ip().is_loopback()` 拒绝非回环。`origin_allowed`/`origin_host` 精确解析 Origin host(剥 scheme/userinfo/port、处理 IPv6 `[::1]`),仅 `localhost`/`127.0.0.1`/`::1`/无 Origin/`null` 放行。
- **测试**:对 `http_handle` 内存喂参数断言:POST 正常→200 JSON-RPC、通知→202、tools/call 离线工具→与 stdio 一致、坏 JSON→200 `-32700`、非 loopback Origin→403、host 后缀伪装(`http://localhost.evil.com`/`127.0.0.1@evil`)→403、真回环(含 `http://[::1]:9000`/`https://localhost`/`null`)→200/放行、GET→405、未知路径→404、token 不符→401。`serve_http_on` 经**进程内 tokio task + 真 TCP 往返**覆盖 accept 循环(含超大流式 body→413 回归):测试先 `tokio::net::TcpListener::bind("127.0.0.1:0")`、从活的 listener 取端口、把 listener 注入 `serve_http_on` 后再 connect——确定性,无端口抢占/connect-先于-accept 竞态(并发 `cargo test` 下旧 flake 的根因),响应读至 EOF 后才 `handle.abort()`;二进制子进程 e2e(`serve_http` 全路径)兜底(llvm-cov 不计子进程)。
- **安全默认**:不传 `--http-token` 时端点对**本机任意进程开放**(无鉴权),仅 Origin/loopback 防护(挡浏览器跨站,不挡本机恶意进程)。多用户/共享主机务必设 `--http-token`(或经 `BLOCKSCAN_MCP_TOKEN`)。

### 对抗式审查记录(Phase 20,1-agent)
确认并修复 **2 个 ship-blocker**;loopback 绑定、stdout 无关(HTTP 不碰 stdout)、token/路由/方法映射、`handle` 复用一致性均确认正确:
1. **(high,DoS)body 无界缓冲**:`http_handle_conn` 旧实现先 `body.collect()` 再查长度 → 攻击者发超大/无限流式 body 即 OOM。**修**:改 `http_body_util::Limited::new(body, MAX_HTTP_BODY).collect()`,读到上限即报错 → 413,不缓冲整体。补 e2e 回归 `serve_http_in_process_*`(2 MiB 流式 body → 413)。
2. **(med,安全)Origin 前缀绕过**:`origin_allowed` 旧用 `starts_with("http://localhost")` → `http://localhost.evil.com` 通过,DNS-rebinding 防护失效。**修**:新 `origin_host` 精确解析 host(剥 scheme/path/userinfo/port、IPv6 去括号),`matches!` 仅放行精确 `localhost`/`127.0.0.1`/`::1`;`null` 与无 Origin 单独放行,**不可解析/非 http(s) Origin 一律拒绝**(避免 `None` 臂误放)。补回归(`localhost.evil.com`/`127.0.0.1@evil`/`ftp://localhost`→403;`http://[::1]:9000`/`https://localhost`/`null`→放行)。
- 确认正确:仅绑 `127.0.0.1`(`parse_loopback_addr` 经 `is_loopback()` 拒非回环);HTTP 层不写 stdout(传输与 stdio 隔离);业务错误仍包 200(MCP 语义);token 缺省的信任面已在文档显式声明(见上"安全默认");`handle` 与 stdio 路径完全同源(9 工具一致)。

> 状态:✅ Phase 20 完成(`mcp.rs` 行覆盖 97.70%,余 `serve_stdio` stdin 包装器 + 少量防御性不可达分支;库总行覆盖 98.06%;全量 409 测试 = 306 单元 + 103 集成)。

### 后续:HTTP 进程内测试去 flake(确定性绑定)
并发 `cargo test` 下 `serve_http_in_process_dispatches_and_covers_accept_loop` 间歇失败。**根因**:旧测试 `std::net::TcpListener::bind("127.0.0.1:0")` 探测端口后**立即关闭**该 listener,再让 spawn 的 `serve_http` 重新 bind 同端口——bind→close→rebind 之间并发进程可抢占该 ephemeral 端口,`serve_http` bind 失败被 `let _ =` 吞掉、connect 循环要么 50 次全败 panic、要么连到抢占者拿到垃圾响应。**修**:把 accept 循环拆成 `serve_http_on(listener, ...)`;测试先 `tokio::net::TcpListener::bind` 取活 listener 的真实端口、再把 listener 注入 `serve_http_on`——零抢占窗口,且 connect 前 socket 已 LISTEN(连接进 backlog,不依赖 accept 就绪)。响应读至 EOF 后才 `handle.abort()`,断言不放水。新增确定性 `serve_http_wrapper_rejects_bad_and_busy_addrs`(非回环/占用端口→Err,带 5s 超时防挂)回补 wrapper 的 parse+bind 覆盖。验证:目标测试 20×、`serve_http` 两测 20×、全量 `cargo test` 3× 并发均 0 失败;`mcp.rs` 行覆盖 97.62%(余 `serve_http` 委托尾行 98 仅子进程 e2e 覆盖、ctrl_c 关停与防御分支,llvm-cov 不计子进程)。
