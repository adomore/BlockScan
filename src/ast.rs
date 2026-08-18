//! AST-level refinement of the source heuristics, backed by a real Solidity
//! parser (`slang_solidity`).
//!
//! When a source file parses cleanly, [`detect`] replaces the line-based
//! heuristics for the rules in [`AST_RULES`] with context-aware checks that drop
//! the heuristics' false positives, e.g.:
//!   * `tx.origin` only counts in an authorization check (a comparison, an `if`
//!     condition, or a `require`/`assert` argument) — `return tx.origin` no
//!     longer fires;
//!   * a low-level `.call(…)` only fires when its boolean return is discarded or
//!     left unchecked (Phase 14/15 intra-function dataflow);
//!   * reentrancy / access-control / weak-randomness / `ecrecover` zero-checks
//!     (Phase 16–19);
//!   * `.transfer`/`.send` fire only with a single argument — an ETH stipend send,
//!     not a 2-arg ERC-20 transfer — and narrowing `uintN`/`intN` casts skip
//!     literal and same-family-widening arguments (Phase 21).
//!
//! It also adds one AST-only rule with no heuristic counterpart —
//! `DELEGATECALL_ARBITRARY_TARGET` (Phase 20).
//!
//! On *any* parse failure [`detect`] returns `None` and the caller keeps the
//! heuristic results for that file (graceful degradation). The rule ids, specs,
//! categories, severities and SCWE/EthTrust mappings are reused unchanged, so
//! scoring is identical — only precision and the `detection` tag change.

use std::collections::{HashMap, HashSet};
use std::rc::Rc;

use slang_solidity::bindings::{BindingGraph, BindingLocation};
use slang_solidity::compilation::{CompilationBuilder, CompilationBuilderConfig};
use slang_solidity::cst::{Cursor, EdgeLabel, NodeKind, NonterminalKind, TerminalKind};
use slang_solidity::parser::Parser;
use slang_solidity::utils::LanguageFacts;

/// Rule ids owned by the AST layer for a file that parses cleanly. The caller
/// removes the heuristic occurrences of these rules for that file and uses the
/// AST hits instead.
pub const AST_RULES: &[&str] = &[
    "TX_ORIGIN_AUTH",
    "UNCHECKED_LOW_LEVEL_CALL",
    "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE",
    "ACCESS_MISSING_GUARD_PRIVILEGED_FN",
    "WEAK_BLOCK_RANDOMNESS",
    "ECRECOVER_NO_ZERO_CHECK",
    "HARDCODED_GAS_TRANSFER_SEND",
    "UNSAFE_DOWNCAST_TRUNCATION",
];

/// Maximum bracket-nesting depth we are willing to feed to slang's
/// recursive-descent parser. Sources deeper than this are skipped (the caller
/// falls back to the heuristic).
///
/// Deliberately conservative: *statement* nesting (`if`/`for`/`while`/blocks)
/// drives several parser frames per level but adds only ~1 brace of depth, and
/// was observed to overflow at bracket-depth ~90 in a debug build — and
/// `audit_with` runs on a tokio worker thread with a smaller stack than main.
/// Real Solidity nests only a handful of levels, so a cap of 32 leaves a wide
/// safety margin (≈3× below the observed overflow on the largest stack, more on
/// the worker) while never rejecting a legitimate contract.
const MAX_NESTING_DEPTH: usize = 32;

/// Maximum run of binary-operator / member-access tokens within a single
/// statement we will feed to the parser. A *flat* chain (`a.b.c…`, `1+1+1…`)
/// drives one parser-recursion frame per token **without** opening a bracket, so
/// `MAX_NESTING_DEPTH` alone does not bound it — a long enough chain stack-
/// overflows the parser (confirmed: a 20 000-deep `+`/`.` chain aborts the
/// process). Real Solidity statements never chain hundreds of operators, so 256
/// is a wide margin while staying far below the overflow point on the small tokio
/// worker stack. Over-counting (operators inside comments/strings, or summed
/// across sibling sub-expressions of one statement) only makes the guard more
/// conservative — such files simply fall back to the heuristic.
const MAX_EXPR_CHAIN: usize = 256;

/// One AST-derived finding location within a single source file.
pub struct AstHit {
    pub rule_id: &'static str,
    /// 1-based line number of the offending member-access expression.
    pub line: usize,
    pub evidence: String,
}

/// Parse `content` and run the AST detectors. Returns `None` when the source
/// does not parse cleanly, signalling the caller to keep the heuristic results
/// for this file.
///
/// `slang_solidity` can *panic* on some malformed input rather than reporting an
/// invalid parse, so the work is wrapped in `catch_unwind`: a parser panic
/// degrades to `None` (heuristic fallback) instead of crashing the audit.
///
/// A *stack overflow* from a pathologically nested expression is NOT a panic and
/// cannot be contained by `catch_unwind` (on Windows it is a non-unwinding
/// exception that aborts the process). Since the source is attacker-authored
/// (fetched verified code), [`too_deeply_nested`] pre-bounds both bracket nesting
/// ([`MAX_NESTING_DEPTH`]) and flat operator/member chains ([`MAX_EXPR_CHAIN`]),
/// skipping the AST layer for sources beyond either.
pub fn detect(content: &str) -> Option<Vec<AstHit>> {
    if too_deeply_nested(content) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| detect_inner(content)))
        .ok()
        .flatten()
}

/// Cheap single-pass bound on parser-recursion depth, covering BOTH bracket
/// nesting (`MAX_NESTING_DEPTH`) and flat operator/member chains
/// (`MAX_EXPR_CHAIN`). Counts raw bytes (including any inside comments/strings —
/// over-counting only makes the guard more conservative; such files fall back to
/// the heuristic). The `chain` run resets at statement boundaries (`;`/`{`/`}`)
/// so it measures operators within a single statement, where the deep recursion
/// actually accumulates.
fn too_deeply_nested(content: &str) -> bool {
    let mut depth: usize = 0;
    let mut chain: usize = 0;
    for b in content.bytes() {
        match b {
            b'(' | b'[' => {
                depth += 1;
                if depth > MAX_NESTING_DEPTH {
                    return true;
                }
            }
            b'{' => {
                depth += 1;
                chain = 0;
                if depth > MAX_NESTING_DEPTH {
                    return true;
                }
            }
            b')' | b']' => depth = depth.saturating_sub(1),
            b'}' => {
                depth = depth.saturating_sub(1);
                chain = 0;
            }
            b';' => chain = 0,
            // Binary-operator / member-access bytes that each add a parse frame.
            b'+' | b'-' | b'*' | b'/' | b'%' | b'.' | b'&' | b'|' | b'^' | b'<' | b'>' | b'='
            | b'!' | b'?' => {
                chain += 1;
                if chain > MAX_EXPR_CHAIN {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn detect_inner(content: &str) -> Option<Vec<AstHit>> {
    let parser = Parser::create(LanguageFacts::LATEST_VERSION).ok()?;
    let out = parser.parse_file_contents(content);
    if !out.is_valid() || !out.errors().is_empty() {
        return None;
    }
    // Parse-only path: no binding graph, so type-resolution refinements are off
    // (the detectors fall back to their Phase 14–21 syntactic behavior).
    Some(run_detectors(&out.create_tree_cursor(), None))
}

/// Run every AST detector over one file's tree root. `bg` carries the contract's
/// binding graph when available (the `detect_unit` path), enabling scope-aware
/// name/type resolution; it is `None` on the parse-only [`detect`] path.
fn run_detectors(root: &Cursor, bg: Option<&Rc<BindingGraph>>) -> Vec<AstHit> {
    let mut hits = Vec::new();
    detect_tx_origin(root, &mut hits);
    detect_unchecked_call(root, &mut hits);
    detect_reentrancy(root, &mut hits);
    detect_access_control(root, &mut hits);
    detect_block_randomness(root, &mut hits);
    detect_ecrecover_zero_check(root, &mut hits);
    detect_arbitrary_delegatecall(root, bg, &mut hits);
    detect_eth_transfer_send(root, bg, &mut hits);
    detect_narrowing_downcast(root, bg, &mut hits);
    hits
}

/// AST detection for a whole contract (all its source files as one compilation
/// unit). Builds a slang [`BindingGraph`] once so the detectors can resolve
/// identifiers to their definitions and declared **types** (scope-aware), then
/// runs every detector per file with that graph.
///
/// Returns a per-file-path map of hits, or `None` to signal the caller to fall
/// back to the per-file [`detect`] path. `None` on: any file too deeply nested
/// (pre-parse stack-overflow guard), a build/parse error, or a parser panic
/// (contained by `catch_unwind`). `files` are `(path, content)` pairs.
pub fn detect_unit(files: &[(&str, &str)]) -> Option<HashMap<String, Vec<AstHit>>> {
    if files.is_empty() || files.iter().any(|(_, c)| too_deeply_nested(c)) {
        return None;
    }
    std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| detect_unit_inner(files)))
        .ok()
        .flatten()
}

fn detect_unit_inner(files: &[(&str, &str)]) -> Option<HashMap<String, Vec<AstHit>>> {
    // Dedup by path (first occurrence wins) so add_file / the result map / the
    // heuristic merge in `audit_with` stay in 1:1 correspondence even when an
    // Etherscan manifest has two keys that sanitize to the same path.
    let mut paths: Vec<&str> = Vec::with_capacity(files.len());
    let mut map: HashMap<String, String> = HashMap::with_capacity(files.len());
    for (p, c) in files {
        if map.insert((*p).to_string(), (*c).to_string()).is_none() {
            paths.push(*p);
        }
    }
    let cfg = MemFiles { map };
    let mut builder = CompilationBuilder::create(LanguageFacts::LATEST_VERSION, cfg).ok()?;
    for path in &paths {
        builder.add_file(path).ok()?;
    }
    let unit = builder.build();
    let bg = unit.binding_graph();
    let mut out = HashMap::with_capacity(paths.len());
    for path in &paths {
        let file = unit.file(path)?;
        if !file.errors().is_empty() {
            return None; // a parse error anywhere → fall back to per-file path
        }
        let hits = run_detectors(&file.create_tree_cursor(), Some(bg));
        out.insert((*path).to_string(), hits);
    }
    Some(out)
}

/// A `CompilationBuilderConfig` that serves a fixed set of in-memory source files
/// (the contract's downloaded sources). Import resolution is best-effort and
/// path-segment-aware (see [`MemFiles::resolve_import`]); unresolved imports are
/// tolerated by the binding graph (cross-file refs simply stay unresolved,
/// same-file refs still resolve), so a missing dependency never breaks intra-file
/// detection.
struct MemFiles {
    map: HashMap<String, String>,
}

/// The directory part of a file id (`contracts/a/B.sol` → `contracts/a`, a
/// bare `B.sol` → ``).
fn parent_dir(file_id: &str) -> &str {
    match file_id.rfind('/') {
        Some(i) => &file_id[..i],
        None => "",
    }
}

/// Resolve a relative path `rel` against directory `base_dir`, collapsing `.` and
/// `..` segments (`..` past the root is clamped). Returns a `/`-joined id.
fn normalize_join(base_dir: &str, rel: &str) -> String {
    let mut segs: Vec<&str> = if base_dir.is_empty() {
        Vec::new()
    } else {
        base_dir.split('/').collect()
    };
    for part in rel.split('/') {
        match part {
            "" | "." => {}
            ".." => {
                segs.pop();
            }
            p => segs.push(p),
        }
    }
    segs.join("/")
}

/// True if `id` ends with `tail` at a path-segment boundary — `id == tail` or
/// `id` ends with `/tail`. (So `contracts/Token.sol` matches `Token.sol`, but
/// `xToken.sol` does not, and `@oz/ERC20.sol` does not match `20.sol`.)
fn ends_with_segment(id: &str, tail: &str) -> bool {
    id == tail || id.ends_with(&format!("/{tail}"))
}

impl CompilationBuilderConfig for MemFiles {
    type Error = std::convert::Infallible;

    fn read_file(&mut self, file_id: &str) -> Result<Option<String>, Self::Error> {
        Ok(self.map.get(file_id).cloned())
    }

    fn resolve_import(
        &mut self,
        source_file_id: &str,
        import_path: &Cursor,
    ) -> Result<Option<String>, Self::Error> {
        let raw = import_path.node().unparse();
        let spec = raw.trim().trim_matches(['"', '\'']);
        // 1) Exact id match (covers absolute / remapped ids equal to a stored key).
        if self.map.contains_key(spec) {
            return Ok(Some(spec.to_string()));
        }
        // 2) Relative import resolved against the importing file's directory.
        if spec.starts_with("./") || spec.starts_with("../") {
            let joined = normalize_join(parent_dir(source_file_id), spec);
            if self.map.contains_key(&joined) {
                return Ok(Some(joined));
            }
        }
        // 3) Unique path-segment-boundary suffix match (handles remapped/prefixed
        //    keys, e.g. import "@oz/ERC20.sol" → ".../@oz/ERC20.sol"). Strip any
        //    leading ./ and ../ first; match only at a `/` boundary (so xToken.sol
        //    never matches Token.sol, and 20.sol never matches @oz/ERC20.sol).
        let tail = spec.trim_start_matches("../").trim_start_matches("./");
        let mut hit = None;
        for id in self.map.keys() {
            if ends_with_segment(id, tail) {
                if hit.is_some() {
                    return Ok(None); // ambiguous → leave unresolved
                }
                hit = Some(id.clone());
            }
        }
        Ok(hit)
    }
}

/// Collapse all ASCII whitespace so `tx . origin` / `addr . call` compare equal
/// to their canonical spellings regardless of source formatting.
fn squeeze(s: &str) -> String {
    s.split_whitespace().collect()
}

/// Move `c` to its first child reached via edge label `want`, advancing past any
/// preceding siblings. Crucially this skips leading **trivia** (whitespace /
/// comments), which slang attaches as terminal children carrying a *different*
/// edge label — a blind `go_to_first_child` can otherwise land on a `Whitespace`
/// node (e.g. the cast operand's type keyword in `x = uint128(y)`). Returns
/// `false` if no child with that label exists.
fn to_child(c: &mut Cursor, want: EdgeLabel) -> bool {
    if !c.go_to_first_child() {
        return false;
    }
    loop {
        if c.label() == want {
            return true;
        }
        if !c.go_to_next_sibling() {
            return false;
        }
    }
}

fn detect_tx_origin(root: &Cursor, hits: &mut Vec<AstHit>) {
    let mut cur = root.clone();
    while cur.go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression) {
        if squeeze(&cur.node().unparse()) != "tx.origin" {
            continue;
        }
        if tx_origin_is_auth(&cur) {
            hits.push(AstHit {
                rule_id: "TX_ORIGIN_AUTH",
                line: cur.text_range().start.line + 1,
                evidence: "tx.origin".to_string(),
            });
        }
    }
}

/// `tx.origin` is treated as an authorization use when an ancestor is a
/// comparison (`==`/`!=` via `EqualityExpression`, or `<`/`>`/`<=`/`>=` via
/// `InequalityExpression`), an `if` statement, or a `require`/`assert` call.
/// (slang wraps every expression in a transparent `Expression` node, so we scan
/// the whole ancestor chain rather than just the immediate parent.)
///
/// Known recall tradeoff vs the old substring heuristic: a `tx.origin` that is
/// only *stored* (`creator = tx.origin;`) or used as a mapping-write key
/// (`admins[tx.origin] = true;`) and gated in a *later* statement is not flagged,
/// because that needs intra-function dataflow (deferred). The common direct
/// `require(tx.origin == owner)` / `if (tx.origin == x)` patterns are covered.
fn tx_origin_is_auth(c: &Cursor) -> bool {
    for anc in c.ancestors() {
        match anc.kind {
            NonterminalKind::EqualityExpression
            | NonterminalKind::InequalityExpression
            | NonterminalKind::IfStatement => return true,
            NonterminalKind::FunctionCallExpression => {
                let head = squeeze(&anc.unparse());
                if head.starts_with("require(") || head.starts_with("assert(") {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

fn detect_unchecked_call(root: &Cursor, hits: &mut Vec<AstHit>) {
    // Per-function cache of identifier "control" occurrences (gate or rebind),
    // keyed by the function's start offset, so each enclosing function is scanned
    // for gates at most once regardless of how many bound calls it contains
    // (avoids an O(calls × identifiers) blowup).
    let mut gate_cache: HashMap<usize, FnControls> = HashMap::new();
    let mut cur = root.clone();
    while cur.go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression) {
        let text = squeeze(&cur.node().unparse());
        if !text.ends_with(".call") {
            continue;
        }
        let flag = match call_disposition(&cur) {
            Disposition::Discarded => true,
            Disposition::Consumed => false,
            // Bound to a variable: unchecked unless the bound boolean is genuinely
            // *checked* later in the same function (Phase 15 intra-function dataflow).
            Disposition::Bound => match binding_name(&cur).zip(enclosing_function(&cur)) {
                Some((name, (key, func))) => {
                    let controls = gate_cache
                        .entry(key)
                        .or_insert_with(|| collect_controls(&func));
                    !controls.is_checked(&name, cur.text_offset().utf8)
                }
                // Unknown bound name or no enclosing function → conservatively
                // treat as unchecked (never silently drop a real finding).
                None => true,
            },
        };
        if flag {
            hits.push(AstHit {
                rule_id: "UNCHECKED_LOW_LEVEL_CALL",
                line: cur.text_range().start.line + 1,
                evidence: text,
            });
        }
    }
}

/// What happens to a low-level `.call`'s boolean return.
enum Disposition {
    /// Result thrown away as a bare statement.
    Discarded,
    /// Result stored in a variable (still has to be *checked* to be safe).
    Bound,
    /// Result consumed by an enclosing expression (require/assert/foo arg,
    /// if/while condition, return, boolean expr, emit, …) — already used.
    Consumed,
}

/// Classify a low-level `.call` by ascending past its own option/invocation
/// wrappers (and slang's transparent `Expression` nodes); the first *meaningful*
/// ancestor decides. `own_call_seen` distinguishes an actual invocation from a
/// bare `.call` value reference (the latter is `Consumed` — nothing to flag).
fn call_disposition(c: &Cursor) -> Disposition {
    let mut own_call_seen = false;
    for anc in c.ancestors() {
        match anc.kind {
            // Transparent nodes: slang's `Expression` wrapper, the call's own
            // `{opts}` node, parenthesization (`(call())` is a single-value
            // `TupleExpression`), and a ternary whose own value may be discarded.
            NonterminalKind::Expression
            | NonterminalKind::CallOptionsExpression
            | NonterminalKind::TupleExpression
            | NonterminalKind::TupleValues
            | NonterminalKind::TupleValue
            | NonterminalKind::ConditionalExpression => continue,
            // The first FunctionCallExpression is the `.call(...)` invocation itself.
            NonterminalKind::FunctionCallExpression if !own_call_seen => {
                own_call_seen = true;
            }
            NonterminalKind::ExpressionStatement => {
                return if own_call_seen { Disposition::Discarded } else { Disposition::Consumed };
            }
            // Bound to a variable (`VariableDeclarationValue` is the initializer
            // wrapper inside `bool ok = a.call(...)`).
            NonterminalKind::AssignmentExpression
            | NonterminalKind::VariableDeclarationValue
            | NonterminalKind::VariableDeclarationStatement
            | NonterminalKind::TupleDeconstructionStatement => {
                return if own_call_seen { Disposition::Bound } else { Disposition::Consumed };
            }
            // Any other enclosing node consumes the result.
            _ => return Disposition::Consumed,
        }
    }
    Disposition::Consumed
}

/// Extract the success-boolean variable name from the binding enclosing the call:
/// the last identifier of the first comma-segment on the binding's LHS (covers
/// `(bool ok,) = …`, `bool ok = …`, and `ok = …`).
fn binding_name(call: &Cursor) -> Option<String> {
    for anc in call.ancestors() {
        match anc.kind {
            NonterminalKind::AssignmentExpression
            | NonterminalKind::VariableDeclarationStatement
            | NonterminalKind::TupleDeconstructionStatement => {
                let binding = anc.unparse();
                let lhs = binding.split('=').next()?;
                let lhs = lhs.trim().trim_start_matches('(').trim_end_matches(')');
                let tok = lhs.split(',').next()?.split_whitespace().last()?;
                let name: String = tok.chars().filter(|c| c.is_alphanumeric() || *c == '_').collect();
                return (!name.is_empty()).then_some(name);
            }
            _ => {}
        }
    }
    None
}

/// The nearest enclosing function-like definition: its start offset (a per-parse
/// unique key for caching) and a subtree cursor re-rooted at it (via `spawn()`,
/// which bounds later descendant traversals to this function). Found by
/// `clone()` + `go_to_parent()` up the tree.
fn enclosing_function(call: &Cursor) -> Option<(usize, Cursor)> {
    let mut up = call.clone();
    loop {
        if let NodeKind::Nonterminal(k) = up.node().kind() {
            if is_function_like(k) {
                return Some((up.text_offset().utf8, up.spawn()));
            }
        }
        if !up.go_to_parent() {
            return None;
        }
    }
}

fn is_function_like(k: NonterminalKind) -> bool {
    matches!(
        k,
        NonterminalKind::FunctionDefinition
            | NonterminalKind::ModifierDefinition
            | NonterminalKind::ConstructorDefinition
            | NonterminalKind::FallbackFunctionDefinition
            | NonterminalKind::ReceiveFunctionDefinition
            | NonterminalKind::UnnamedFunctionDefinition
    )
}

/// How a particular occurrence of an identifier relates to dataflow control.
#[derive(Clone, Copy, PartialEq)]
enum Control {
    /// The value is *checked*: a `require`/`assert` argument, an `if`/`while`/
    /// `for`/`do-while` **condition**, or a direct `return` operand.
    Gate,
    /// The variable is *re-bound* (declared or assigned-to): from here on, the
    /// name refers to a different value, so a later gate no longer covers an
    /// earlier call.
    Rebind,
}

/// Control occurrences (gates and rebinds) per identifier name within one
/// function, each recorded in ascending document order with its start offset.
/// Plain uses (logging, passing to a non-checking call, etc.) are intentionally
/// NOT recorded — they are not checks.
struct FnControls {
    by_name: HashMap<String, Vec<(usize, Control)>>,
}

impl FnControls {
    /// A call binding `name` at `after` is checked iff the FIRST control
    /// occurrence of `name` strictly after the call is a `Gate` (a `Rebind` first
    /// means the bound value was overwritten before any check).
    fn is_checked(&self, name: &str, after: usize) -> bool {
        match self.by_name.get(name) {
            Some(occ) => {
                // occ is sorted ascending; first entry with offset > after decides.
                let i = occ.partition_point(|(off, _)| *off <= after);
                occ.get(i).is_some_and(|(_, c)| *c == Control::Gate)
            }
            None => false,
        }
    }
}

/// Single pass over a function subtree: classify every identifier occurrence and
/// record the gates/rebinds (in document order) keyed by name.
fn collect_controls(func: &Cursor) -> FnControls {
    let mut by_name: HashMap<String, Vec<(usize, Control)>> = HashMap::new();
    let mut c = func.clone();
    while c.go_to_next_terminal_with_kind(TerminalKind::Identifier) {
        if let Some(ctrl) = classify_occurrence(&c) {
            by_name
                .entry(c.node().unparse())
                .or_default()
                .push((c.text_offset().utf8, ctrl));
        }
    }
    FnControls { by_name }
}

/// Classify one identifier occurrence by walking up (capturing the edge label by
/// which we entered each parent) until a decisive node is reached:
///   * `require`/`assert` call argument, an `if`/`while`/`for`/`do-while`
///     **condition** (edge `Condition`), or a direct `return` operand → `Gate`;
///   * an assignment **left** operand, a `var` declaration name, or a tuple
///     deconstruction **target** → `Rebind`;
///   * consumed by a non-checking call, or any other statement-level use
///     (`emit`, a bare expression, a revert message, …) → `None` (a plain use).
fn classify_occurrence(id: &Cursor) -> Option<Control> {
    let mut p = id.clone();
    // Set once we ascend through a value combinator (tuple, ternary, operator,
    // argument list, …). Matters only for `return`: `return ok;` forwards the
    // success flag (a check), but `return (x, ok)` / `return c ? ok : v` /
    // `return ok && x` merely embed it — not a direct check.
    let mut combined = false;
    loop {
        let edge = p.label();
        if !p.go_to_parent() {
            return None;
        }
        let NodeKind::Nonterminal(k) = p.node().kind() else {
            return None;
        };
        match k {
            // --- gates: the controlling condition of a branch/loop ---
            // (`for` wraps its condition in an ExpressionStatement → handled below;
            // `if`/`while`/`do-while` reach here directly via the `Condition` edge.
            // A use in a body hits a statement/call node before reaching here.)
            NonterminalKind::IfStatement
            | NonterminalKind::WhileStatement
            | NonterminalKind::DoWhileStatement => {
                return (edge == EdgeLabel::Condition).then_some(Control::Gate);
            }
            NonterminalKind::ReturnStatement => return (!combined).then_some(Control::Gate),
            NonterminalKind::FunctionCallExpression => {
                let head = squeeze(&p.node().unparse());
                return if head.starts_with("require(") || head.starts_with("assert(") {
                    Some(Control::Gate)
                } else {
                    None // consumed by a non-checking call (foo(ok), abi.encode(ok), …)
                };
            }
            // --- rebinds ---
            NonterminalKind::AssignmentExpression => {
                return (edge == EdgeLabel::LeftOperand).then_some(Control::Rebind);
            }
            NonterminalKind::VariableDeclarationStatement => return Some(Control::Rebind),
            NonterminalKind::TupleDeconstructionStatement => {
                // LHS targets rebind; the RHS (edge `Expression`) is just a use.
                return (edge != EdgeLabel::Expression).then_some(Control::Rebind);
            }
            // An ExpressionStatement is a plain use UNLESS it is the wrapper slang
            // puts around a `for` loop's condition (`ForStatementCondition`).
            NonterminalKind::ExpressionStatement => {
                let mut q = p.clone();
                let in_for_condition = q.go_to_parent()
                    && matches!(
                        q.node().kind(),
                        NodeKind::Nonterminal(NonterminalKind::ForStatementCondition)
                    );
                return in_for_condition.then_some(Control::Gate);
            }
            // --- other plain statement-level uses (not a check) ---
            NonterminalKind::EmitStatement
            | NonterminalKind::RevertStatement
            | NonterminalKind::Block
            | NonterminalKind::Statements => return None,
            // A pure `Expression` wrapper does not combine the value.
            NonterminalKind::Expression => continue,
            // Anything else we ascend through (tuple/ternary/operator/arg list,
            // call-options, …) embeds the value; keep ascending.
            _ => {
                combined = true;
                continue;
            }
        }
    }
}

// ---------------------------------------------------------------------------
// REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE (checks-effects-interactions)
// ---------------------------------------------------------------------------

/// Low-level external-call sinks that can hand control to an untrusted callee
/// (mirrors the heuristic's set; excludes `staticcall`, which cannot write).
const REENTRANCY_SINKS: [&str; 4] = [".call", ".delegatecall", ".transfer", ".send"];

/// Names of contract-level state variables, collected file-wide. File-level (not
/// per-contract) so that flattened verified sources — where base contracts sit in
/// the same file — still cover inherited state variables. The rare cost is a
/// cross-contract same-name local being treated as state.
fn state_variable_names(root: &Cursor) -> HashSet<String> {
    let mut set = HashSet::new();
    let mut c = root.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::StateVariableDefinition) {
        // The declared name is the identifier on the `Name` edge — NOT the first
        // identifier, which for a user-defined type is the type name (`S s;` →
        // first id `S`, name `s`; `Counters.Counter ctr;` → name `ctr`).
        if let Some(name) = definition_name(&c.spawn()) {
            set.insert(name);
        }
    }
    set
}

/// The declared name reached via the `Name` edge of a definition. The Name-edge
/// child is a bare `Identifier` for state variables, but a `FunctionName`
/// nonterminal (wrapping the identifier) for functions — handle both.
fn definition_name(def: &Cursor) -> Option<String> {
    let mut c = def.clone();
    if !c.go_to_first_child() {
        return None;
    }
    loop {
        if c.label() == EdgeLabel::Name {
            return match c.node().kind() {
                NodeKind::Terminal(_) => Some(c.node().unparse()),
                NodeKind::Nonterminal(_) => base_identifier(&c.spawn()),
            };
        }
        if !c.go_to_next_sibling() {
            return None;
        }
    }
}

/// First `Identifier` terminal in a node's subtree — the "base" of an lvalue
/// (`bal[k]` → `bal`, `s.f` → `s`).
fn base_identifier(node: &Cursor) -> Option<String> {
    let mut sub = node.clone();
    sub.go_to_next_terminal_with_kind(TerminalKind::Identifier)
        .then(|| sub.node().unparse())
}

/// A function is considered reentrancy-guarded if it carries a modifier whose
/// name looks like a reentrancy lock (structural, so comments can't fake it).
fn has_reentrancy_guard(func: &Cursor) -> bool {
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::ModifierInvocation) {
        let name = base_identifier(&c.spawn()).unwrap_or_default().to_ascii_lowercase();
        // `reentran` covers nonReentrant / noReentrancy / reentrancyGuard. The
        // lock/mutex names are matched exactly to avoid `block`/`unlock`/`clock`
        // substring false matches (which would wrongly suppress → false negative).
        if name.contains("reentran") || matches!(name.as_str(), "lock" | "locked" | "mutex") {
            return true;
        }
    }
    false
}

/// Detect external-call-before-state-write (CEI violation) per function.
fn detect_reentrancy(root: &Cursor, hits: &mut Vec<AstHit>) {
    let state = state_variable_names(root);
    if state.is_empty() {
        return; // nothing to write unsafely
    }
    let mut fcur = root.clone();
    while fcur.go_to_next_nonterminal() {
        // Cover every externally-callable function kind — `receive()` / `fallback()`
        // (and the pre-0.6 unnamed fallback) are classic reentrancy entry points,
        // not just named functions. (Constructors/modifiers can't be re-entered.)
        let NodeKind::Nonterminal(k) = fcur.node().kind() else {
            continue;
        };
        if !matches!(
            k,
            NonterminalKind::FunctionDefinition
                | NonterminalKind::ReceiveFunctionDefinition
                | NonterminalKind::FallbackFunctionDefinition
                | NonterminalKind::UnnamedFunctionDefinition
        ) {
            continue;
        }
        let func = fcur.spawn();
        if has_reentrancy_guard(&func) {
            continue;
        }
        let Some((call_off, call_line)) = earliest_external_call(&func) else {
            continue;
        };
        if state_write_after(&func, &state, call_off) {
            hits.push(AstHit {
                rule_id: "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE",
                line: call_line,
                evidence: "external call before state write".to_string(),
            });
        }
    }
}

/// Offset + 1-based line of the earliest low-level external call in `func`.
fn earliest_external_call(func: &Cursor) -> Option<(usize, usize)> {
    let mut best: Option<(usize, usize)> = None;
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression) {
        let text = squeeze(&c.node().unparse());
        if REENTRANCY_SINKS.iter().any(|s| text.ends_with(s)) {
            let off = c.text_offset().utf8;
            if best.is_none_or(|(b, _)| off < b) {
                best = Some((off, c.text_range().start.line + 1));
            }
        }
    }
    best
}

/// True if a write to a state variable occurs at an offset strictly after
/// `call_off`. Recognized write forms (lvalue base must be a state variable):
///   * assignment (`=`, `+=`, …) and postfix `x++`/`x--`;
///   * prefix `delete x` / `--x` / `++x` (not `!x`/`-x`/`~x`);
///   * tuple deconstruction `(…, stateVar, …) = …` (any LHS target);
///   * array mutators `stateArr.push(…)` / `stateArr.pop()`.
fn state_write_after(func: &Cursor, state: &HashSet<String>, call_off: usize) -> bool {
    // Assignments and postfix `x++`/`x--`: the base is a state var.
    for kind in [NonterminalKind::AssignmentExpression, NonterminalKind::PostfixExpression] {
        let mut c = func.clone();
        while c.go_to_next_nonterminal_with_kind(kind) {
            if c.text_offset().utf8 > call_off
                && base_identifier(&c.spawn()).is_some_and(|b| state.contains(&b))
            {
                return true;
            }
        }
    }
    // Prefix forms that mutate: `delete x`, `--x`, `++x`.
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::PrefixExpression) {
        if c.text_offset().utf8 <= call_off {
            continue;
        }
        let text = squeeze(&c.node().unparse());
        let mutating = text.starts_with("delete") || text.starts_with("++") || text.starts_with("--");
        if mutating && base_identifier(&c.spawn()).is_some_and(|b| state.contains(&b)) {
            return true;
        }
    }
    // Tuple deconstruction `(…, stateVar, …) = …`: any LHS target is a state var.
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::TupleDeconstructionStatement) {
        if c.text_offset().utf8 > call_off && tuple_lhs_writes_state(&c.node().unparse(), state) {
            return true;
        }
    }
    // Array mutators `stateArr.push(…)` / `stateArr.pop()`.
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression) {
        if c.text_offset().utf8 <= call_off {
            continue;
        }
        let text = squeeze(&c.node().unparse());
        if (text.ends_with(".push") || text.ends_with(".pop"))
            && base_identifier(&c.spawn()).is_some_and(|b| state.contains(&b))
        {
            return true;
        }
    }
    false
}

/// True if any LHS target of a tuple deconstruction is a state variable. The LHS
/// is the text before the first `=`; each comma-separated target's base is its
/// first identifier (`bal[k]` → `bal`).
fn tuple_lhs_writes_state(stmt: &str, state: &HashSet<String>) -> bool {
    let lhs = stmt.split('=').next().unwrap_or("");
    let lhs = lhs.trim().trim_start_matches('(').trim_end_matches(')');
    lhs.split(',').any(|seg| {
        seg.split(|c: char| !c.is_alphanumeric() && c != '_')
            .find(|t| !t.is_empty())
            .is_some_and(|base| state.contains(base))
    })
}

// ---------------------------------------------------------------------------
// ACCESS_MISSING_GUARD_PRIVILEGED_FN (privileged fn with no access control)
// ---------------------------------------------------------------------------

/// Flag a privileged-named, public/external function that has no access guard.
fn detect_access_control(root: &Cursor, hits: &mut Vec<AstHit>) {
    let mut fcur = root.clone();
    while fcur.go_to_next_nonterminal_with_kind(NonterminalKind::FunctionDefinition) {
        let func = fcur.spawn();
        let Some(name) = definition_name(&func) else { continue };
        if !crate::audit::is_privileged_name(&name.to_ascii_lowercase()) {
            continue;
        }
        // Skip pure declarations (interface / abstract `function f() external;`):
        // slang still gives them a FunctionBody node, but no `Block` — only an
        // implementation can be missing an access guard.
        let mut blk = func.clone();
        if !blk.go_to_next_nonterminal_with_kind(NonterminalKind::Block) {
            continue;
        }
        let Some(attrs) = own_function_attributes(&func) else { continue };
        if !is_public_or_external(&attrs) {
            continue; // internal/private can't be called by an attacker
        }
        if is_view_or_pure(&attrs) {
            continue; // a view/pure function changes no state — not a privileged risk
        }
        if has_access_modifier(&attrs) || has_msg_sender_guard(&func) {
            continue;
        }
        // Emit at the `function` keyword line (matches the heuristic's header line
        // so the SARIF fingerprint stays stable across the heuristic→AST switch).
        let mut kw = func.clone();
        let line = if kw.go_to_next_terminal_with_kind(TerminalKind::FunctionKeyword) {
            kw.text_range().start.line + 1
        } else {
            func.text_range().start.line + 1
        };
        hits.push(AstHit {
            rule_id: "ACCESS_MISSING_GUARD_PRIVILEGED_FN",
            line,
            evidence: format!("function {name}"),
        });
    }
}

/// The function's OWN `FunctionAttributes` (a direct child of this
/// `FunctionDefinition`), re-rooted — NOT a function-type parameter's attributes.
fn own_function_attributes(func: &Cursor) -> Option<Cursor> {
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::FunctionAttributes) {
        let mut up = c.clone();
        if up.go_to_parent()
            && matches!(up.node().kind(), NodeKind::Nonterminal(NonterminalKind::FunctionDefinition))
        {
            return Some(c.spawn());
        }
    }
    None
}

fn is_public_or_external(attrs: &Cursor) -> bool {
    let mut c = attrs.clone();
    if c.go_to_next_terminal_with_kind(TerminalKind::PublicKeyword) {
        return true;
    }
    let mut c = attrs.clone();
    c.go_to_next_terminal_with_kind(TerminalKind::ExternalKeyword)
}

fn is_view_or_pure(attrs: &Cursor) -> bool {
    let mut c = attrs.clone();
    if c.go_to_next_terminal_with_kind(TerminalKind::ViewKeyword) {
        return true;
    }
    let mut c = attrs.clone();
    c.go_to_next_terminal_with_kind(TerminalKind::PureKeyword)
}

/// An access-control modifier invocation in the function's own attributes.
/// Name set mirrors the heuristic's `has_access_guard` (`only*` covers
/// onlyOwner/onlyRole/onlyMinter…; `auth` covers authorized/requiresAuth;
/// `restrict` covers restricted).
fn has_access_modifier(attrs: &Cursor) -> bool {
    let mut c = attrs.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::ModifierInvocation) {
        let n = base_identifier(&c.spawn()).unwrap_or_default().to_ascii_lowercase();
        if n.starts_with("only") || n.contains("auth") || n.contains("restrict") {
            return true;
        }
    }
    false
}

/// A caller check: `msg.sender` used in a require/assert/if/while condition or a
/// comparison, or a call to a `_checkOwner`/`_checkRole`/… guard helper. Broad on
/// purpose (prefer a false negative over flagging audited code), mirroring the
/// heuristic's `has_access_guard`.
fn has_msg_sender_guard(func: &Cursor) -> bool {
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression) {
        if squeeze(&c.node().unparse()) != "msg.sender" {
            continue;
        }
        for anc in c.ancestors() {
            match anc.kind {
                NonterminalKind::IfStatement
                | NonterminalKind::WhileStatement
                | NonterminalKind::EqualityExpression
                | NonterminalKind::InequalityExpression => return true,
                NonterminalKind::FunctionCallExpression => {
                    let h = squeeze(&anc.unparse());
                    if h.starts_with("require(") || h.starts_with("assert(") {
                        return true;
                    }
                }
                _ => {}
            }
        }
    }
    const GUARD_CALLS: [&str; 5] =
        ["_checkOwner", "_checkRole", "_onlyOwner", "_authorizeUpgrade", "_checkAuthorized"];
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::FunctionCallExpression) {
        let h = squeeze(&c.node().unparse());
        if GUARD_CALLS.iter().any(|g| h.starts_with(&format!("{g}(")) || h.contains(&format!(".{g}("))) {
            return true;
        }
    }
    false
}

// ---------------------------------------------------------------------------
// WEAK_BLOCK_RANDOMNESS (block property used as a randomness source)
// ---------------------------------------------------------------------------

const BLOCK_MEMBERS: [&str; 4] =
    ["block.timestamp", "block.number", "block.difficulty", "block.prevrandao"];

/// Flag a block source only when it feeds a randomness context. Without that
/// guard `block.timestamp` (deadlines/vesting/cooldowns) floods false positives.
fn detect_block_randomness(root: &Cursor, hits: &mut Vec<AstHit>) {
    let mut lines: HashSet<usize> = HashSet::new();
    // `block.timestamp` / `block.number` / … member accesses.
    let mut c = root.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression) {
        let text = squeeze(&c.node().unparse());
        if BLOCK_MEMBERS.contains(&text.as_str()) && in_randomness_context(&c) {
            lines.insert(c.text_range().start.line + 1);
        }
    }
    // `blockhash(...)` calls.
    let mut c = root.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::FunctionCallExpression) {
        if squeeze(&c.node().unparse()).starts_with("blockhash(") && in_randomness_context(&c) {
            lines.insert(c.text_range().start.line + 1);
        }
    }
    let mut lines: Vec<usize> = lines.into_iter().collect();
    lines.sort_unstable();
    for line in lines {
        hits.push(AstHit {
            rule_id: "WEAK_BLOCK_RANDOMNESS",
            line,
            evidence: "block property used for randomness".to_string(),
        });
    }
}

/// True if a block source is an operand of a modulo (`%` multiplicative) or an
/// argument to a hash function (`keccak256`/`sha256`/`ripemd160`) — the two
/// dominant weak-randomness shapes.
fn in_randomness_context(c: &Cursor) -> bool {
    for a in c.ancestors() {
        match a.kind {
            NonterminalKind::MultiplicativeExpression => {
                if squeeze(&a.unparse()).contains('%') {
                    return true;
                }
            }
            NonterminalKind::FunctionCallExpression => {
                let h = squeeze(&a.unparse());
                if h.starts_with("keccak256(") || h.starts_with("sha256(") || h.starts_with("ripemd160(") {
                    return true;
                }
            }
            _ => {}
        }
    }
    false
}

// ---------------------------------------------------------------------------
// ECRECOVER_NO_ZERO_CHECK (recovered address not checked against address(0))
// ---------------------------------------------------------------------------

/// Flag an `ecrecover(...)` whose recovered address is never compared to
/// `address(0)`/`0` — a malformed signature returns `address(0)` and would slip
/// through. Well-written verification (`require(s != address(0))`) is not flagged.
fn detect_ecrecover_zero_check(root: &Cursor, hits: &mut Vec<AstHit>) {
    let mut c = root.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::FunctionCallExpression) {
        if !squeeze(&c.node().unparse()).starts_with("ecrecover(") {
            continue;
        }
        if !ecrecover_result_zero_checked(&c) {
            hits.push(AstHit {
                rule_id: "ECRECOVER_NO_ZERO_CHECK",
                line: c.text_range().start.line + 1,
                evidence: "ecrecover result not checked against address(0)".to_string(),
            });
        }
    }
}

/// True if the ecrecover result is compared against zero — either inline
/// (`ecrecover(..) != address(0)`) or via the variable it is bound to
/// (`address s = ecrecover(..); require(s != address(0))`).
fn ecrecover_result_zero_checked(call: &Cursor) -> bool {
    for anc in call.ancestors() {
        if anc.kind == NonterminalKind::EqualityExpression && equality_has_zero(&anc.unparse()) {
            return true;
        }
    }
    if let Some(name) = binding_name(call) {
        if let Some((_, func)) = enclosing_function(call) {
            let mut c = func.clone();
            while c.go_to_next_terminal_with_kind(TerminalKind::Identifier) {
                if c.node().unparse() != name {
                    continue;
                }
                for anc in c.ancestors() {
                    if anc.kind == NonterminalKind::EqualityExpression && equality_has_zero(&anc.unparse()) {
                        return true;
                    }
                }
            }
        }
    }
    false
}

/// An equality comparison against the zero address or zero literal. Matches the
/// exact `address(0)` form (not `address(0x123)`) and `==0`/`!=0` (not `==100`).
fn equality_has_zero(eq_unparse: &str) -> bool {
    let q = squeeze(eq_unparse);
    q.contains("address(0)") || q.contains("==0") || q.contains("!=0")
}

// ---------------------------------------------------------------------------
// DELEGATECALL_ARBITRARY_TARGET (delegatecall to a caller-controlled address)
// ---------------------------------------------------------------------------

/// Flag a `delegatecall` whose receiver is caller-controlled — an
/// attacker-controlled target means arbitrary code runs in this contract's
/// storage context (full takeover). A fixed receiver (state var / immutable /
/// call result / fixed local) is the normal proxy pattern and is not flagged.
///
/// With a binding graph (Phase 23) the receiver is resolved to its definition,
/// so a parameter reached through local aliases (`address impl = target;`) is
/// caught and a local that merely *shares a name* with a parameter is not.
/// Without one, this falls back to Phase 20's parameter-name match.
fn detect_arbitrary_delegatecall(
    root: &Cursor,
    bg: Option<&Rc<BindingGraph>>,
    hits: &mut Vec<AstHit>,
) {
    let mut c = root.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression) {
        if !squeeze(&c.node().unparse()).ends_with(".delegatecall") {
            continue;
        }
        let Some(receiver) = base_identifier(&c) else { continue };
        let Some((_, func)) = enclosing_function(&c) else { continue };
        let controlled = match (bg, receiver_identifier(&c)) {
            // Scope-aware: resolve the receiver to its declaration and follow
            // any local alias chain back to a parameter.
            (Some(g), Some(ident)) => traces_to_parameter(&ident, g, MAX_ALIAS_HOPS),
            // No graph (single-file parse, build failure): Phase 20 behaviour.
            _ => function_param_names(&func).contains(&receiver),
        };
        if controlled {
            hits.push(AstHit {
                rule_id: "DELEGATECALL_ARBITRARY_TARGET",
                line: c.text_range().start.line + 1,
                evidence: format!("{receiver}.delegatecall (caller-controlled target)"),
            });
        }
    }
}

/// How many `address a = b;` hops the receiver may travel before we give up.
/// Beyond this we report nothing rather than risk a pathological walk — the
/// conservative direction for a chain nobody writes by hand.
const MAX_ALIAS_HOPS: usize = 4;

/// Whether `ident` resolves — directly or through local alias assignments — to a
/// function parameter, i.e. to a value the caller chooses.
///
/// `Parameter` is the hit. A `VariableDeclarationStatement` is followed through
/// its initializer's base identifier. Anything else (state variable, no
/// initializer, unresolved) stops the walk without a finding.
fn traces_to_parameter(ident: &Cursor, bg: &Rc<BindingGraph>, hops: usize) -> bool {
    let Some(reference) = bg.reference_at(ident) else {
        return false;
    };
    let Some(def) = reference.definitions().into_iter().next() else {
        return false;
    };
    let BindingLocation::UserFile(loc) = def.definiens_location() else {
        return false;
    };
    let decl = loc.cursor();
    match decl.node().kind() {
        NodeKind::Nonterminal(NonterminalKind::Parameter) => true,
        NodeKind::Nonterminal(NonterminalKind::VariableDeclarationStatement) => {
            if hops == 0 {
                return false;
            }
            // The declaration's initializer, e.g. the `target` in `address impl = target;`.
            let mut v = decl.spawn();
            if !v.go_to_next_nonterminal_with_kind(NonterminalKind::VariableDeclarationValue) {
                return false;
            }
            let mut inner = v.spawn();
            if !inner.go_to_next_terminal_with_kind(TerminalKind::Identifier) {
                return false;
            }
            traces_to_parameter(&inner, bg, hops - 1)
        }
        _ => false,
    }
}


/// Names of the parameters declared by this function (each `Parameter`'s `Name`
/// edge). A function-type parameter's own inner params may also appear — a
/// harmless superset for the receiver-membership check.
fn function_param_names(func: &Cursor) -> HashSet<String> {
    let mut names = HashSet::new();
    let mut c = func.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::Parameter) {
        let mut p = c.spawn();
        while p.go_to_next_terminal_with_kind(TerminalKind::Identifier) {
            if p.label() == EdgeLabel::Name {
                names.insert(p.node().unparse());
            }
        }
    }
    names
}

// ---------------------------------------------------------------------------
// HARDCODED_GAS_TRANSFER_SEND (addr.transfer/.send — a 1-arg ETH stipend send)
// ---------------------------------------------------------------------------

/// Flag a 1-argument `.transfer`/`.send` — an ETH value send capped at the
/// 2300-gas stipend (breaks for contract recipients / after gas repricing). An
/// ERC-20 `token.transfer(to, amount)` / `token.transferFrom(...)` takes >= 2
/// arguments and is NOT flagged: the substring heuristic guessed ETH-vs-token
/// from keyword cues (`token`/`IERC20`/`amount`/…) and misfired on
/// `dai.transfer(to, amt)`, whereas the argument count is exact. As a bonus this
/// also catches a bare `addr.transfer(x)` whose line had no value keyword (a
/// heuristic miss).
///
/// A 1-arg call whose argument is a *data payload* (a string/bytes literal or an
/// `abi.encode*` call) is excluded — `address.transfer/send` only take a
/// `uint256`, so it is a same-named messaging method (`bridge.send(payload)`),
/// not an ETH send. Receivers and amount-typed identifiers can't be type-resolved
/// here, so `endpoint.send(payloadVar)` may still over-report (deferred to the
/// scope-aware name/type resolution phase).
fn detect_eth_transfer_send(root: &Cursor, bg: Option<&Rc<BindingGraph>>, hits: &mut Vec<AstHit>) {
    let mut c = root.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::MemberAccessExpression) {
        let text = squeeze(&c.node().unparse());
        if !(text.ends_with(".transfer") || text.ends_with(".send")) {
            continue;
        }
        let Some(call) = enclosing_call(&c) else {
            continue;
        };
        // address.transfer/send takes exactly one argument (a wei amount).
        if call_arg_count(&call) != 1 || arg_is_data_payload(&call) {
            continue;
        }
        // Binding-aware (Phase 22): if the receiver is a simple identifier whose
        // declared type is a contract/interface, this is a same-named messaging
        // method (`endpoint.send(payload)`), not an ETH send — suppress. An
        // address/payable receiver, or an unresolvable one, stays flagged.
        if let Some(bg) = bg {
            if let Some(recv) = receiver_identifier(&c) {
                if matches!(resolve_decl_type(&recv, bg), Some(ResolvedType::ContractLike)) {
                    continue;
                }
            }
        }
        hits.push(AstHit {
            rule_id: "HARDCODED_GAS_TRANSFER_SEND",
            line: c.text_range().start.line + 1,
            evidence: format!("{text}(…) — 2300-gas ETH send"),
        });
    }
}

/// If `member` (a `MemberAccessExpression`) is the callee — i.e. the `Operand` —
/// of a function call, return a cursor at that `FunctionCallExpression`.
fn enclosing_call(member: &Cursor) -> Option<Cursor> {
    let mut up = member.clone();
    if !up.go_to_parent() {
        return None; // out of the transparent `Expression` wrapper
    }
    let is_operand = up.label() == EdgeLabel::Operand;
    if !up.go_to_parent() {
        return None;
    }
    (is_operand && up.node().kind() == NodeKind::Nonterminal(NonterminalKind::FunctionCallExpression))
        .then_some(up)
}

/// True if the call's single argument is a *data payload* rather than a wei
/// amount — a string/bytes literal or an `abi.encode*(…)` call. `address.transfer`
/// / `.send` only accept a `uint256`, so such a call is a same-named messaging
/// method (`bridge.send(payload)`, `mailbox.send(abi.encode(…))`), not an ETH
/// send — suppressing it cannot hide a real send (zero false-negative risk).
fn arg_is_data_payload(call: &Cursor) -> bool {
    let Some(arg) = first_argument_variant(call) else {
        return false;
    };
    match arg.node().kind() {
        // Both plain "…" and hex"…" literals parse as a StringExpression.
        NodeKind::Nonterminal(NonterminalKind::StringExpression) => true,
        NodeKind::Nonterminal(NonterminalKind::FunctionCallExpression) => {
            squeeze(&arg.node().unparse()).starts_with("abi.encode")
        }
        _ => false,
    }
}

/// Number of top-level positional arguments of a `FunctionCallExpression` (each
/// `Item` edge under its `PositionalArguments`). A named-argument or empty call
/// counts as 0. Nested calls inside an argument are not counted (they sit under
/// an `Item`'s subtree, not as immediate children).
fn call_arg_count(call: &Cursor) -> usize {
    let mut c = call.clone();
    if !to_child(&mut c, EdgeLabel::Arguments) {
        return 0; // ArgumentsDeclaration
    }
    if !to_child(&mut c, EdgeLabel::Variant) || !is_kind(&c, NonterminalKind::PositionalArgumentsDeclaration) {
        return 0; // named arguments → not a positional 1-arg send
    }
    if !to_child(&mut c, EdgeLabel::Arguments) {
        return 0; // PositionalArguments
    }
    let mut n = 0;
    if c.go_to_first_child() {
        loop {
            if c.label() == EdgeLabel::Item {
                n += 1;
            }
            if !c.go_to_next_sibling() {
                break;
            }
        }
    }
    n
}

// ---------------------------------------------------------------------------
// UNSAFE_DOWNCAST_TRUNCATION (narrowing uintN/intN cast that can silently truncate)
// ---------------------------------------------------------------------------

/// Flag a narrowing explicit cast `uintN(x)`/`intN(x)` (N < 256) whose argument
/// could exceed the target width. Two provably non-truncating forms are dropped
/// (the substring heuristic flagged them too, hence the bulk of its false
/// positives):
///   * a numeric literal — `uint8(0)`, `uint8(0xff)`, `uint64(1e18)`: a constant
///     the author wrote on purpose;
///   * a same-family cast of equal-or-narrower width — `uint128(uint64(x))`: the
///     outer cast only widens (the inner cast is still examined on its own);
///   * an `address(...)` cast into a `>= 160`-bit target — `uint160(address(x))`:
///     an address is exactly 160 bits, so this is lossless (the dominant FP).
///
/// Everything else (an identifier, arithmetic, a wider or mixed-family nested
/// cast) is flagged. Cases needing type info — `uint160(addrVar)`, `uint8(enumVar)`,
/// `uint64(type(uint64).max)` — still over-report (deferred to the scope-aware
/// name/type resolution phase). A literal that itself overflows the target
/// (`uint8(300)`) is a rare intentional mask and is not flagged — a documented
/// recall tradeoff.
fn detect_narrowing_downcast(root: &Cursor, bg: Option<&Rc<BindingGraph>>, hits: &mut Vec<AstHit>) {
    let mut c = root.clone();
    while c.go_to_next_nonterminal_with_kind(NonterminalKind::FunctionCallExpression) {
        let Some((unsigned, width)) = cast_target_width(&c) else {
            continue;
        };
        if width >= 256 {
            continue; // uint256/int256/uint/int — not a narrowing cast
        }
        if cast_arg_non_truncating(&c, unsigned, width) || cast_arg_var_fits(&c, unsigned, width, bg) {
            continue;
        }
        let evidence: String = squeeze(&c.node().unparse()).chars().take(80).collect();
        hits.push(AstHit {
            rule_id: "UNSAFE_DOWNCAST_TRUNCATION",
            line: c.text_range().start.line + 1,
            evidence,
        });
    }
}

/// If `call`'s operand is an elementary `uint`/`int` type, return
/// `(is_unsigned, bit_width)`; `uint`/`int` with no suffix → width 256. Returns
/// `None` for any non-cast call or a non-integer elementary type.
fn cast_target_width(call: &Cursor) -> Option<(bool, u16)> {
    int_type_width(&cast_operand_keyword(call)?)
}

/// The elementary-type keyword used as `call`'s operand (`uint128`, `address`,
/// `bytes32`, …), or `None` if the operand is not an elementary type (i.e. the
/// call is not a type cast).
fn cast_operand_keyword(call: &Cursor) -> Option<String> {
    let mut c = call.clone();
    if !to_child(&mut c, EdgeLabel::Operand) {
        return None;
    }
    if !to_child(&mut c, EdgeLabel::Variant) || !is_kind(&c, NonterminalKind::ElementaryType) {
        return None;
    }
    if !to_child(&mut c, EdgeLabel::Variant) {
        return None; // the type keyword terminal (skipping leading trivia)
    }
    Some(c.node().unparse().trim().to_string())
}

/// Parse an elementary type keyword into `(is_unsigned, bit_width)`, or `None` if
/// it is not a `uint`/`int` type. Check `uint` before `int` (the former has the
/// latter's spelling as a non-prefix). `uint`/`int` with no digits → 256.
fn int_type_width(kw: &str) -> Option<(bool, u16)> {
    if let Some(rest) = kw.strip_prefix("uint") {
        return Some((true, if rest.is_empty() { 256 } else { rest.parse().ok()? }));
    }
    if let Some(rest) = kw.strip_prefix("int") {
        return Some((false, if rest.is_empty() { 256 } else { rest.parse().ok()? }));
    }
    None
}

/// True if narrowing cast `call` (family `unsigned`, target width `n`) provably
/// cannot truncate: its single argument is
///   * a numeric literal, or
///   * a same-family cast of width <= n (the outer cast only widens), or
///   * an `address(...)` cast and `n >= 160` — an address is exactly 160 bits,
///     so `uint160(address(x))` / `uint192(address(x))` are lossless (the
///     dominant downcast false positive on real contracts).
fn cast_arg_non_truncating(call: &Cursor, unsigned: bool, n: u16) -> bool {
    let Some(arg) = first_argument_variant(call) else {
        return false;
    };
    match arg.node().kind() {
        NodeKind::Nonterminal(
            NonterminalKind::DecimalNumberExpression | NonterminalKind::HexNumberExpression,
        ) => true,
        NodeKind::Nonterminal(NonterminalKind::FunctionCallExpression) => {
            match cast_operand_keyword(&arg) {
                Some(kw) => match int_type_width(&kw) {
                    // same-family, equal-or-narrower nested cast → outer widens.
                    Some((iu, iw)) => iu == unsigned && iw <= n,
                    // address(...) fits any uint/int target of >= 160 bits.
                    None => kw == "address" && n >= 160,
                },
                None => false,
            }
        }
        _ => false,
    }
}

/// The variant node of a call's first positional argument (skips trivia at each
/// level). `None` for a named-argument or empty call.
fn first_argument_variant(call: &Cursor) -> Option<Cursor> {
    let mut c = call.clone();
    if !to_child(&mut c, EdgeLabel::Arguments) {
        return None; // ArgumentsDeclaration
    }
    if !to_child(&mut c, EdgeLabel::Variant) || !is_kind(&c, NonterminalKind::PositionalArgumentsDeclaration) {
        return None;
    }
    if !to_child(&mut c, EdgeLabel::Arguments) {
        return None; // PositionalArguments
    }
    if !to_child(&mut c, EdgeLabel::Item) {
        return None; // first Item Expression
    }
    if !to_child(&mut c, EdgeLabel::Variant) {
        return None; // its variant
    }
    Some(c)
}

/// True if `c` is at a nonterminal of kind `k`.
fn is_kind(c: &Cursor, k: NonterminalKind) -> bool {
    c.node().kind() == NodeKind::Nonterminal(k)
}

// ---------------------------------------------------------------------------
// Binding-graph type resolution (Phase 22)
// ---------------------------------------------------------------------------

/// The declared type of a variable, coarsened to what the detectors need.
#[derive(Debug, Clone, Copy, PartialEq)]
enum ResolvedType {
    Address,
    AddressPayable,
    Enum,
    Int { unsigned: bool, width: u16 },
    /// A contract / interface instance (a callable object, not an `address`).
    ContractLike,
    /// Anything else (bytes, bool, struct, mapping, builtin, user value type, …).
    Other,
}

/// Resolve a *use* of an identifier (a `MemberAccessExpression` receiver or a cast
/// argument) to the declared type of its definition, via the binding graph.
/// `None` when the reference can't be resolved (unknown symbol, cross-file
/// unresolved import, a built-in) — the caller then keeps its syntactic decision.
fn resolve_decl_type(use_ident: &Cursor, bg: &Rc<BindingGraph>) -> Option<ResolvedType> {
    let reference = bg.reference_at(use_ident)?;
    let def = reference.definitions().into_iter().next()?;
    let BindingLocation::UserFile(loc) = def.definiens_location() else {
        return None;
    };
    decl_resolved_type(loc.cursor(), bg)
}

/// Classify the declared type of a declaration node (the `definiens`: a
/// `Parameter` / `StateVariableDefinition` / `VariableDeclarationStatement`).
fn decl_resolved_type(decl: &Cursor, bg: &Rc<BindingGraph>) -> Option<ResolvedType> {
    let mut c = decl.spawn(); // spawn = bounded to this declaration's subtree
    if !c.go_to_next_nonterminal_with_kind(NonterminalKind::TypeName) {
        return None;
    }
    if !to_child(&mut c, EdgeLabel::Variant) {
        return None;
    }
    match c.node().kind() {
        NodeKind::Nonterminal(NonterminalKind::ElementaryType) => {
            let kw = squeeze(&c.node().unparse());
            Some(match kw.as_str() {
                "address" => ResolvedType::Address,
                "addresspayable" => ResolvedType::AddressPayable,
                _ => match int_type_width(&kw) {
                    Some((unsigned, width)) => ResolvedType::Int { unsigned, width },
                    None => ResolvedType::Other,
                },
            })
        }
        NodeKind::Nonterminal(NonterminalKind::IdentifierPath) => Some(match user_type_kind(&c, bg) {
            Some(NonterminalKind::EnumDefinition) => ResolvedType::Enum,
            Some(NonterminalKind::ContractDefinition | NonterminalKind::InterfaceDefinition) => {
                ResolvedType::ContractLike
            }
            _ => ResolvedType::Other,
        }),
        _ => Some(ResolvedType::Other),
    }
}

/// Resolve a type-name `IdentifierPath` (e.g. `Status`, `IMessenger`, `A.B`) to
/// the *kind* of its definition node (EnumDefinition / ContractDefinition / …).
fn user_type_kind(id_path: &Cursor, bg: &Rc<BindingGraph>) -> Option<NonterminalKind> {
    // The path's last identifier names the type (`A.B` → `B`).
    let mut last = None;
    let mut s = id_path.spawn();
    while s.go_to_next_terminal_with_kind(TerminalKind::Identifier) {
        last = Some(s.clone());
    }
    let reference = bg.reference_at(&last?)?;
    let def = reference.definitions().into_iter().next()?;
    let BindingLocation::UserFile(loc) = def.definiens_location() else {
        return None;
    };
    match loc.cursor().node().kind() {
        NodeKind::Nonterminal(k) => Some(k),
        NodeKind::Terminal(_) => None,
    }
}

/// The receiver of a `MemberAccessExpression` when it is a *simple identifier*
/// (`endpoint.send` → `endpoint`); `None` for a complex receiver
/// (`payable(x).transfer`, `a.b.send`, `IThing(x).send`) which can't be resolved
/// to one declaration here.
fn receiver_identifier(member: &Cursor) -> Option<Cursor> {
    let mut c = member.clone();
    if !to_child(&mut c, EdgeLabel::Operand) {
        return None;
    }
    if !to_child(&mut c, EdgeLabel::Variant) {
        return None;
    }
    (c.node().kind() == NodeKind::Terminal(TerminalKind::Identifier)).then_some(c)
}

/// Binding-aware suppression for a narrowing cast whose argument is a *simple
/// identifier* of a provably-fitting type: `address`/`address payable` into a
/// `>= 160`-bit target, an `enum`, or a same-family integer of width `<= n`.
/// Returns false (no suppression) when `bg` is absent, the arg is not a plain
/// identifier, or the type can't be resolved.
fn cast_arg_var_fits(call: &Cursor, unsigned: bool, n: u16, bg: Option<&Rc<BindingGraph>>) -> bool {
    let Some(bg) = bg else { return false };
    let Some(arg) = first_argument_variant(call) else {
        return false;
    };
    if arg.node().kind() != NodeKind::Terminal(TerminalKind::Identifier) {
        return false;
    }
    match resolve_decl_type(&arg, bg) {
        Some(ResolvedType::Address | ResolvedType::AddressPayable) => n >= 160,
        Some(ResolvedType::Enum) => true,
        Some(ResolvedType::Int { unsigned: iu, width: iw }) => iu == unsigned && iw <= n,
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wrap a function body in a minimal, parseable contract.
    fn contract(body: &str) -> String {
        format!("pragma solidity ^0.8.0;\ncontract C {{\n  function f() public {{ {body} }}\n}}\n")
    }

    fn rules(content: &str) -> Vec<&'static str> {
        detect(content).expect("parses").into_iter().map(|h| h.rule_id).collect()
    }

    fn has(content: &str, rule: &str) -> bool {
        rules(content).contains(&rule)
    }

    // ---- tx.origin (auth-context refinement) ----

    #[test]
    fn tx_origin_in_require_is_auth() {
        assert!(has(&contract("require(tx.origin == owner);"), "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn tx_origin_in_assert_is_auth() {
        assert!(has(&contract("assert(tx.origin == owner);"), "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn tx_origin_in_if_condition_is_auth() {
        assert!(has(&contract("if (tx.origin == owner) { x = 1; }"), "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn tx_origin_in_plain_comparison_is_auth() {
        assert!(has(&contract("bool b = tx.origin == owner; b;"), "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn tx_origin_in_return_is_not_auth() {
        // `return tx.origin;` is informational, not an authorization check.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public view returns (address) { return tx.origin; }\n}\n";
        assert!(!has(src, "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn tx_origin_passed_to_plain_call_is_not_auth() {
        // Conservative: handing tx.origin to a non-require/assert function is not
        // treated as authorization (documented precision/recall tradeoff).
        assert!(!has(&contract("log(tx.origin);"), "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn similarly_named_member_is_not_tx_origin() {
        // `mytx.origin` contains the substring "tx.origin" (a heuristic false
        // positive) but is a distinct member access — the AST excludes it.
        assert!(!has(&contract("require(mytx.origin == owner);"), "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn tx_origin_tolerates_whitespace() {
        assert!(has(&contract("require(tx . origin == owner);"), "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn tx_origin_inside_require_without_comparison_is_auth() {
        // Covers the require/assert arm specifically: tx.origin reaches the
        // require() call with no intervening comparison or if-statement.
        assert!(has(&contract("require(isOwner(tx.origin));"), "TX_ORIGIN_AUTH"));
    }

    #[test]
    fn tx_origin_in_relational_comparison_is_auth() {
        // `<`/`>`/`<=`/`>=` parse to InequalityExpression (distinct from ==/!=);
        // a bare relational compare of tx.origin still counts as auth.
        assert!(has(&contract("bool b = tx.origin > addr; b;"), "TX_ORIGIN_AUTH"));
    }

    // ---- low-level call (unchecked-return refinement) ----

    #[test]
    fn bare_call_statement_is_unchecked() {
        assert!(has(&contract("a.call(\"\");"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn call_with_value_options_is_unchecked() {
        assert!(has(&contract("a.call{value: 1}(\"\");"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn tuple_bound_unchecked_call_fires() {
        // SWC-104: binding the boolean return is NOT a check — the canonical bug.
        assert!(has(&contract("(bool ok, ) = a.call(\"\"); ok;"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn assigned_unchecked_call_fires() {
        assert!(has(&contract("ok = a.call(\"\");"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn var_declared_unchecked_call_fires() {
        assert!(has(&contract("bool ok = a.call(\"\"); ok;"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    // ---- Phase 15: intra-function dataflow (bound boolean checked later) ----

    #[test]
    fn bound_then_required_is_not_flagged() {
        // The dominant SAFE pattern: bound, then `require(ok)` later in the fn.
        assert!(!has(&contract("(bool ok,) = a.call(\"\"); require(ok);"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_then_asserted_is_not_flagged() {
        assert!(!has(&contract("(bool ok,) = a.call(\"\"); assert(ok);"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_then_if_revert_is_not_flagged() {
        assert!(!has(&contract("(bool ok,) = a.call(\"\"); if (!ok) { revert(); }"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn var_declared_then_required_is_not_flagged() {
        assert!(!has(&contract("bool ok = a.call(\"\"); require(ok, \"failed\");"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn reassigned_then_if_checked_is_not_flagged() {
        assert!(!has(&contract("bool ok; ok = a.call(\"\"); if (ok) { x = 1; }"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_then_returned_is_not_flagged() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public returns (bool) { (bool ok,) = a.call(\"\"); return ok; }\n}\n";
        assert!(!has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_but_only_emitted_still_flagged() {
        // `emit E(ok)` is not a gate — the failure is logged, not handled.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  event E(bool); function f() public { (bool ok,) = a.call(\"\"); emit E(ok); }\n}\n";
        assert!(has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_but_never_used_still_flagged() {
        // The canonical SWC-104 bug: bound and never checked.
        assert!(has(&contract("(bool ok,) = a.call(\"\"); other();"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn gate_on_same_name_before_call_still_flagged() {
        // A same-named gate that PRECEDES the call must not suppress (offset-after).
        assert!(has(
            &contract("if (ok) { y = 1; } (bool ok,) = a.call(\"\"); z = 2;"),
            "UNCHECKED_LOW_LEVEL_CALL",
        ));
    }

    #[test]
    fn check_of_different_variable_does_not_suppress() {
        // A require on a DIFFERENT variable name must not suppress the call.
        assert!(has(&contract("(bool ok,) = a.call(\"\"); require(other);"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_then_while_checked_is_not_flagged() {
        assert!(!has(&contract("(bool ok,) = a.call(\"\"); while (ok) { break; }"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_then_passed_to_nongate_fn_still_flagged() {
        // The bound flag flows into a non-require call (`sink(ok)`), which is not a
        // gate — still flagged. (Exercises the non-require FunctionCallExpression
        // ancestor path in the gate scan.)
        assert!(has(&contract("(bool ok,) = a.call(\"\"); sink(ok);"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn tuple_skipping_success_flag_is_flagged() {
        // `(, data) = a.call("")` keeps only the bytes and DISCARDS the success
        // bool — the result is effectively unchecked, so it must fire. (The bound
        // name is unextractable → conservative flag.)
        assert!(has(&contract("(, bytes memory data) = a.call(\"\"); data;"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    // ---- Phase 15 review regressions: body-use / consumed / name-reuse FNs ----

    #[test]
    fn bound_flag_used_only_in_if_body_is_flagged() {
        // `ok` is logged inside an if-BODY whose condition tests something else —
        // it is NOT checked. (Review ship-blocker: body use must not suppress.)
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  event E(bool); function f() public { (bool ok, bytes memory r) = a.call(\"\"); if (r.length > 0) { emit E(ok); } }\n}\n";
        assert!(has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_flag_used_only_in_while_body_is_flagged() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { (bool ok,) = a.call(\"\"); while (block.timestamp > 0) { sink(ok); break; } }\n  function sink(bool) internal {}\n}\n";
        assert!(has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn bound_flag_passed_to_helper_in_return_is_flagged() {
        // `return g(ok)` passes ok to a helper that ignores it — not a check.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public returns (uint) { (bool ok,) = a.call(\"\"); return g(ok); }\n  function g(bool) internal pure returns (uint) { return 1; }\n}\n";
        assert!(has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn nested_if_condition_gate_is_not_flagged() {
        // A gate inside a nested block (the bound flag IS the condition) suppresses.
        assert!(!has(&contract("if (x) { if (ok) { y = 1; } } "), "UNCHECKED_LOW_LEVEL_CALL"));
        // sanity: the call is the bound one
        assert!(!has(&contract("(bool ok,) = a.call(\"\"); if (x) { if (ok) { y = 1; } }"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn name_reuse_later_check_does_not_suppress_earlier_call() {
        // Two calls reassign the same `ok`; only the SECOND is checked. The first
        // must still fire — the later require(ok) belongs to the second value.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { bool ok; (ok,) = a.call(\"\"); other(); (ok,) = b.call(\"\"); require(ok); }\n  function other() internal {}\n}\n";
        let r = rules(src);
        assert_eq!(r.iter().filter(|x| **x == "UNCHECKED_LOW_LEVEL_CALL").count(), 1, "only the first (unchecked) call fires");
    }

    #[test]
    fn inner_block_shadow_does_not_suppress_outer_call() {
        // An inner-scope `bool ok` shadows and is checked, but the OUTER call's ok
        // is never checked — the outer call must still fire.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { (bool ok,) = a.call(\"\"); if (block.timestamp > 0) { bool ok = true; require(ok); } }\n}\n";
        assert!(has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn tuple_return_forwarding_bound_flag_is_flagged() {
        // `return (1, ok)` merely embeds ok in a tuple — not a check. (Re-review
        // ship-blocker: only a direct `return ok;` counts.)
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public returns (uint, bool) { (bool ok,) = a.call(\"\"); return (1, ok); }\n}\n";
        assert!(has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn ternary_return_of_bound_flag_is_flagged() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public returns (bool) { (bool ok,) = a.call(\"\"); return block.timestamp > 0 ? ok : false; }\n}\n";
        assert!(has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn direct_return_of_bound_flag_is_not_flagged() {
        // `return ok;` forwards the success flag to the caller — a real check.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public returns (bool) { (bool ok,) = a.call(\"\"); return ok; }\n}\n";
        assert!(!has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn for_loop_condition_gate_is_not_flagged() {
        // slang wraps a for-condition in an ExpressionStatement; the bound flag as
        // the loop condition IS a check. (Re-review FP fix.)
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { (bool ok,) = a.call(\"\"); for (uint i; ok; i++) { break; } }\n}\n";
        assert!(!has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn for_loop_body_use_of_bound_flag_is_flagged() {
        // A use of ok in the for-BODY (not the condition) is not a check.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { (bool ok,) = a.call(\"\"); for (uint i; i < 1; i++) { sink(ok); } }\n  function sink(bool) internal {}\n}\n";
        assert!(has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn returned_call_is_consumed_not_flagged() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public returns (bool, bytes memory) { return a.call(\"\"); }\n}\n";
        assert!(!has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn required_call_is_consumed_not_flagged() {
        assert!(!has(&contract("require(a.call(\"\"));"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn call_in_if_condition_is_consumed_not_flagged() {
        assert!(!has(&contract("if (a.call(\"\")) { x = 1; }"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn call_passed_as_function_arg_is_consumed_not_flagged() {
        // The result is consumed by `foo(...)` — not discarded.
        assert!(!has(&contract("foo(a.call(\"\"));"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn call_consumed_by_emit_is_not_flagged() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  event E(bool, bytes); function f() public { emit E(a.call(\"\")); }\n}\n";
        assert!(!has(src, "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn parenthesized_discarded_call_fires() {
        // `(a.call(""));` wraps the call in a single-value tuple but the result is
        // still discarded — must flag (regression caught in re-review).
        assert!(has(&contract("(a.call(\"\"));"), "UNCHECKED_LOW_LEVEL_CALL"));
        assert!(has(&contract("((a.call(\"\")));"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn ternary_statement_discarded_calls_fire() {
        // A ternary used as a bare statement discards both branch results.
        let hits = rules(&contract("flag ? a.call(\"\") : b.call(\"\");"));
        assert_eq!(hits.iter().filter(|r| **r == "UNCHECKED_LOW_LEVEL_CALL").count(), 2);
    }

    #[test]
    fn ternary_result_consumed_is_not_flagged() {
        // When the ternary's value is consumed (assigned), it is not discarded.
        assert!(!has(&contract("require(flag ? a.call(\"\") : true);"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn delegatecall_and_staticcall_are_not_in_scope() {
        // UNCHECKED_LOW_LEVEL_CALL covers `.call` only (delegatecall/staticcall
        // have their own handling); the AST detector must match that surface.
        assert!(!has(&contract("a.delegatecall(\"\");"), "UNCHECKED_LOW_LEVEL_CALL"));
        assert!(!has(&contract("a.staticcall(\"\");"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn call_tolerates_whitespace() {
        assert!(has(&contract("a . call (\"\");"), "UNCHECKED_LOW_LEVEL_CALL"));
    }

    #[test]
    fn uninvoked_call_reference_is_not_flagged() {
        // A `.call` member access used as a value with no enclosing statement
        // (a state-variable initializer) exercises the defensive non-statement
        // path: there is nothing to discard, so it is not flagged.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  bool x = a.call;\n}\n";
        let hits = detect(src).expect("parses");
        assert!(!hits.iter().any(|h| h.rule_id == "UNCHECKED_LOW_LEVEL_CALL"));
    }

    // ---- line numbers, degradation, metadata ----

    #[test]
    fn hit_reports_one_based_line() {
        // tx.origin sits on line 3 of the wrapped contract.
        let src = contract("require(tx.origin == owner);");
        let hit = detect(&src).unwrap().into_iter().find(|h| h.rule_id == "TX_ORIGIN_AUTH").unwrap();
        assert_eq!(hit.line, 3);
        assert_eq!(hit.evidence, "tx.origin");
    }

    #[test]
    fn unparseable_source_degrades_to_none() {
        assert!(detect("this is not solidity ((( ").is_none());
    }

    #[test]
    fn parser_panic_is_contained_as_none() {
        // This malformed contract makes slang's parser *panic* (not merely report
        // an invalid parse); `detect` must contain it and return None rather than
        // crash the audit. (Stderr backtrace from the contained panic is expected.)
        let src = "contract C { function f( { require(tx.origin == owner); } }";
        assert!(detect(src).is_none());
    }

    #[test]
    fn deeply_nested_source_degrades_to_none() {
        // A pathologically nested expression would overflow slang's recursive
        // parser (a stack overflow is NOT catchable by catch_unwind). The depth
        // guard must reject it BEFORE parsing so it degrades to None (heuristic).
        let deep = format!(
            "pragma solidity ^0.8.0;\ncontract C {{\n  function f() public {{ uint x = {}1{}; x; }}\n}}\n",
            "(".repeat(1000),
            ")".repeat(1000),
        );
        assert!(detect(&deep).is_none());
    }

    #[test]
    fn moderate_nesting_still_parses() {
        // Nesting well within the bound is not rejected by the guard.
        let ok = format!(
            "pragma solidity ^0.8.0;\ncontract C {{\n  function f() public {{ uint x = {}1{}; x; }}\n}}\n",
            "(".repeat(8),
            ")".repeat(8),
        );
        assert!(detect(&ok).is_some());
    }

    #[test]
    fn deeply_nested_statements_degrade_to_none() {
        // STATEMENT nesting (nested blocks) drives slang's recursion harder than
        // expression parens and overflowed near bracket-depth ~90 in debug; the
        // conservative cap must reject this BEFORE parsing (re-review ship-blocker).
        let mut body = String::new();
        for _ in 0..90 {
            body.push_str("{ ");
        }
        body.push_str("uint x = 1;");
        for _ in 0..90 {
            body.push_str(" }");
        }
        let src = format!(
            "pragma solidity ^0.8.0;\ncontract C {{\n  function f() public {{ {body} }}\n}}\n"
        );
        assert!(detect(&src).is_none());
    }

    #[test]
    fn ast_rules_are_the_refined_rules() {
        assert_eq!(
            AST_RULES,
            &[
                "TX_ORIGIN_AUTH",
                "UNCHECKED_LOW_LEVEL_CALL",
                "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE",
                "ACCESS_MISSING_GUARD_PRIVILEGED_FN",
                "WEAK_BLOCK_RANDOMNESS",
                "ECRECOVER_NO_ZERO_CHECK",
                "HARDCODED_GAS_TRANSFER_SEND",
                "UNSAFE_DOWNCAST_TRUNCATION",
            ]
        );
    }

    #[test]
    fn clean_source_with_no_targets_yields_empty() {
        let hits = detect(&contract("uint x = 1; x;")).unwrap();
        assert!(hits.is_empty());
    }

    #[test]
    fn detect_perf_and_scale_on_large_contract() {
        // Functional + performance: a 200-function contract, each with one auth
        // tx.origin and one unchecked call. Asserts exact counts (scale) and a
        // generous wall-clock bound (guards against pathological regressions;
        // real cost is a few ms).
        let mut src = String::from("pragma solidity ^0.8.0;\ncontract Big {\n");
        for i in 0..200 {
            src.push_str(&format!(
                "  function f{i}(address a) public {{ require(tx.origin == a); a.call(\"\"); }}\n"
            ));
        }
        src.push_str("}\n");

        let t = std::time::Instant::now();
        let hits = detect(&src).expect("parses");
        let dt = t.elapsed();

        assert_eq!(hits.iter().filter(|h| h.rule_id == "TX_ORIGIN_AUTH").count(), 200);
        assert_eq!(hits.iter().filter(|h| h.rule_id == "UNCHECKED_LOW_LEVEL_CALL").count(), 200);
        assert!(dt.as_secs() < 5, "ast::detect too slow on 200 functions: {dt:?}");
    }

    #[test]
    fn bound_call_dataflow_is_linear_not_quadratic() {
        // Regression for the review's O(calls × identifiers) finding: many BOUND
        // unchecked calls in ONE function (the worst case for the gate scan). The
        // per-function control cache makes this linear; assert all fire and that
        // it stays well under a generous bound.
        let mut body = String::new();
        for i in 0..1500 {
            body.push_str(&format!("(bool ok{i},) = a.call(\"\");\n"));
        }
        let src = format!(
            "pragma solidity ^0.8.0;\ncontract C {{\n  function f() public {{ {body} }}\n}}\n"
        );
        let t = std::time::Instant::now();
        let hits = detect(&src).expect("parses");
        let dt = t.elapsed();
        assert_eq!(
            hits.iter().filter(|h| h.rule_id == "UNCHECKED_LOW_LEVEL_CALL").count(),
            1500
        );
        assert!(dt.as_secs() < 5, "bound-call dataflow too slow (quadratic?): {dt:?}");
    }

    // ---- Phase 16: AST reentrancy (CEI external-call-before-state-write) ----

    const REENTRANCY: &str = "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE";

    /// A contract with one state var `bal` (mapping) + `counter`/`owner`, and the
    /// given function body.
    fn reentrancy_src(body: &str) -> String {
        format!(
            "pragma solidity ^0.8.0;\ncontract C {{\n  mapping(address => uint) bal;\n  uint counter;\n  address owner;\n  function f() public {{ {body} }}\n}}\n"
        )
    }

    #[test]
    fn classic_reentrancy_call_then_state_write_fires() {
        assert!(has(&reentrancy_src("(bool ok,) = msg.sender.call{value: bal[msg.sender]}(\"\"); require(ok); bal[msg.sender] = 0;"), REENTRANCY));
    }

    #[test]
    fn reentrancy_in_receive_and_fallback_fires() {
        // receive()/fallback() are classic reentrancy entry points — must be
        // covered, not just named functions (audit fix).
        let recv = "pragma solidity ^0.8.0;\ncontract C {\n  mapping(address => uint) bal;\n  receive() external payable { msg.sender.call{value: bal[msg.sender]}(\"\"); bal[msg.sender] = 0; }\n}\n";
        assert!(has(recv, REENTRANCY));
        let fb = "pragma solidity ^0.8.0;\ncontract C {\n  mapping(address => uint) bal;\n  fallback() external payable { msg.sender.call{value: bal[msg.sender]}(\"\"); bal[msg.sender] = 0; }\n}\n";
        assert!(has(fb, REENTRANCY));
    }

    #[test]
    fn checks_effects_interactions_order_is_not_flagged() {
        // State write BEFORE the external call → safe, not flagged.
        assert!(!has(&reentrancy_src("bal[msg.sender] = 0; (bool ok,) = msg.sender.call{value: 1}(\"\"); require(ok);"), REENTRANCY));
    }

    #[test]
    fn nonreentrant_guard_is_not_flagged() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  mapping(address => uint) bal;\n  function f() public nonReentrant { msg.sender.call{value: bal[msg.sender]}(\"\"); bal[msg.sender] = 0; }\n}\n";
        assert!(!has(src, REENTRANCY));
    }

    #[test]
    fn local_variable_write_after_call_is_not_flagged() {
        // Writing a LOCAL after the call is not a CEI violation (the heuristic FP).
        assert!(!has(&reentrancy_src("msg.sender.call{value: 1}(\"\"); uint local = 5; local = local + 1; local;"), REENTRANCY));
    }

    #[test]
    fn state_counter_postfix_after_call_fires() {
        assert!(has(&reentrancy_src("msg.sender.call(\"\"); counter++;"), REENTRANCY));
    }

    #[test]
    fn state_delete_after_call_fires() {
        assert!(has(&reentrancy_src("msg.sender.call(\"\"); delete owner;"), REENTRANCY));
    }

    #[test]
    fn state_compound_assign_after_call_fires() {
        assert!(has(&reentrancy_src("msg.sender.call(\"\"); counter -= 1;"), REENTRANCY));
    }

    #[test]
    fn transfer_send_delegatecall_sinks_fire() {
        assert!(has(&reentrancy_src("msg.sender.transfer(1); counter++;"), REENTRANCY));
        assert!(has(&reentrancy_src("msg.sender.send(1); counter++;"), REENTRANCY));
        assert!(has(&reentrancy_src("t.delegatecall(\"\"); counter++;"), REENTRANCY));
    }

    #[test]
    fn staticcall_is_not_a_reentrancy_sink() {
        // staticcall cannot mutate state in the callee → not a reentrancy vector.
        assert!(!has(&reentrancy_src("t.staticcall(\"\"); counter++;"), REENTRANCY));
    }

    #[test]
    fn no_external_call_is_not_flagged() {
        assert!(!has(&reentrancy_src("counter++; bal[msg.sender] = 0;"), REENTRANCY));
    }

    #[test]
    fn no_state_vars_short_circuits() {
        // A contract with no state variables can't have a CEI violation.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { msg.sender.call{value: 1}(\"\"); uint x = 1; x = 2; x; }\n}\n";
        assert!(!has(src, REENTRANCY));
    }

    #[test]
    fn reentrancy_hit_reports_call_line() {
        // The finding points at the external-call line (line 6 in this layout).
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  mapping(address=>uint) bal;\n  function f() public {\n    require(true);\n    msg.sender.call{value: bal[msg.sender]}(\"\");\n    bal[msg.sender] = 0;\n  }\n}\n";
        let hit = detect(src).unwrap().into_iter().find(|h| h.rule_id == REENTRANCY).unwrap();
        assert_eq!(hit.line, 6);
    }

    #[test]
    fn inherited_state_var_in_same_file_is_covered() {
        // Flattened source: base contract's state var is in the same file.
        let src = "pragma solidity ^0.8.0;\ncontract Base { mapping(address=>uint) bal; }\ncontract C is Base {\n  function f() public { msg.sender.call{value: bal[msg.sender]}(\"\"); bal[msg.sender] = 0; }\n}\n";
        assert!(has(src, REENTRANCY));
    }

    #[test]
    fn access_control_modifier_is_not_a_reentrancy_guard() {
        // `onlyOwner` is access control, NOT a reentrancy guard — still flagged.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  uint counter;\n  function f() public onlyOwner { msg.sender.call{value: 1}(\"\"); counter++; }\n}\n";
        assert!(has(src, REENTRANCY));
    }

    #[test]
    fn custom_lock_modifier_is_treated_as_guard() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  uint counter;\n  function f() public lock { msg.sender.call{value: 1}(\"\"); counter++; }\n}\n";
        assert!(!has(src, REENTRANCY));
    }

    #[test]
    fn state_write_only_before_prefix_is_safe() {
        // A prefix `--counter` BEFORE the call is CEI-safe (covers the prefix
        // before-call skip with no later write).
        assert!(!has(&reentrancy_src("--counter; msg.sender.call(\"\");"), REENTRANCY));
    }

    #[test]
    fn nonmutating_prefix_after_call_is_not_a_write() {
        // A `!flag` prefix after the call is not a state mutation.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  bool flag;\n  function f() public { msg.sender.call(\"\"); bool b = !flag; b; }\n}\n";
        assert!(!has(src, REENTRANCY));
    }

    // ---- Phase 16 review regressions: write forms that were missed ----

    #[test]
    fn struct_typed_state_var_member_write_fires() {
        // Review BUG: a user-typed state var (`S s`) collected its TYPE name `S`
        // instead of `s`, so `s.amount = 0` was missed. Now uses the Name edge.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  struct S { uint amount; }\n  S s;\n  function f() public { msg.sender.call(\"\"); s.amount = 0; }\n}\n";
        assert!(has(src, REENTRANCY));
    }

    #[test]
    fn qualified_type_state_var_write_fires() {
        // `Counters.Counter ctr;` → name is `ctr` (not `Counters`/`Counter`).
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  struct Counter { uint v; }\n  Counter ctr;\n  function f() public { msg.sender.call(\"\"); ctr.v++; }\n}\n";
        assert!(has(src, REENTRANCY));
    }

    #[test]
    fn tuple_assignment_to_state_fires() {
        // Review regression: `(x, owner) = ...` is a TupleDeconstructionStatement,
        // which the heuristic caught via `=` but the first AST cut missed.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  uint x; address owner;\n  function f() public { msg.sender.call(\"\"); (x, owner) = (1, address(0)); }\n}\n";
        assert!(has(src, REENTRANCY));
    }

    #[test]
    fn array_push_to_state_after_call_fires() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  uint[] items;\n  function f() public { msg.sender.call(\"\"); items.push(1); }\n}\n";
        assert!(has(src, REENTRANCY));
    }

    #[test]
    fn array_pop_to_state_after_call_fires() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  uint[] items;\n  function f() public { msg.sender.call(\"\"); items.pop(); }\n}\n";
        assert!(has(src, REENTRANCY));
    }

    #[test]
    fn push_on_local_array_is_not_flagged() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  uint dummy;\n  function f() public { msg.sender.call(\"\"); uint[] memory m; m.push(1); }\n}\n";
        assert!(!has(src, REENTRANCY));
    }

    #[test]
    fn tuple_assignment_to_locals_only_is_not_flagged() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  uint dummy;\n  function f() public { msg.sender.call(\"\"); (uint a, uint b) = (1, 2); a; b; }\n}\n";
        assert!(!has(src, REENTRANCY));
    }

    #[test]
    fn arbitrary_external_method_call_is_a_documented_limitation() {
        // Known limitation (shared with the heuristic): a non-low-level external
        // method call (`token.transfer(...)` on an interface) is NOT a recognized
        // reentrancy sink, so a following state write is not flagged.
        let src = "pragma solidity ^0.8.0;\ninterface I { function transferFrom(address,address,uint) external; }\ncontract C {\n  uint counter;\n  function f(address t) public { I(t).transferFrom(msg.sender, address(this), 1); counter++; }\n}\n";
        assert!(!has(src, REENTRANCY));
    }

    // ---- Phase 17: AST access-control ----

    const ACCESS: &str = "ACCESS_MISSING_GUARD_PRIVILEGED_FN";

    /// A contract with `owner` + the given function(s).
    fn ac_src(fns: &str) -> String {
        format!("pragma solidity ^0.8.0;\ncontract C {{\n  address owner;\n  {fns}\n}}\n")
    }

    #[test]
    fn unguarded_privileged_external_fn_fires() {
        assert!(has(&ac_src("function mint(address t, uint a) external { _mint(t, a); }"), ACCESS));
    }

    #[test]
    fn unguarded_privileged_public_fn_fires() {
        assert!(has(&ac_src("function withdraw() public { payable(msg.sender).transfer(1); }"), ACCESS));
    }

    #[test]
    fn access_modifier_guard_is_not_flagged() {
        assert!(!has(&ac_src("function mint(address t, uint a) external onlyOwner { _mint(t, a); }"), ACCESS));
    }

    #[test]
    fn custom_auth_modifier_is_not_flagged() {
        assert!(!has(&ac_src("function upgrade() external requiresAuth { }"), ACCESS));
    }

    #[test]
    fn require_msg_sender_guard_is_not_flagged() {
        assert!(!has(&ac_src("function mint(address t, uint a) external { require(msg.sender == owner); _mint(t, a); }"), ACCESS));
    }

    #[test]
    fn if_revert_msg_sender_guard_is_not_flagged() {
        assert!(!has(&ac_src("function pause() external { if (msg.sender != owner) revert(); }"), ACCESS));
    }

    #[test]
    fn check_owner_helper_call_is_not_flagged() {
        assert!(!has(&ac_src("function burn(uint a) external { _checkOwner(); _burn(a); }"), ACCESS));
    }

    #[test]
    fn internal_privileged_fn_is_not_flagged() {
        assert!(!has(&ac_src("function mint(address t, uint a) internal { _mint(t, a); }"), ACCESS));
    }

    #[test]
    fn non_privileged_name_is_not_flagged() {
        assert!(!has(&ac_src("function totalSupply() external view returns (uint) { return 1; }"), ACCESS));
    }

    #[test]
    fn function_type_param_external_does_not_count_as_visibility() {
        // The param's `external` must not be read as the function's visibility:
        // the function is internal, so it is not flagged.
        assert!(!has(&ac_src("function mint(function() external cb) internal { cb(); }"), ACCESS));
    }

    #[test]
    fn msg_sender_only_logged_is_not_a_guard() {
        // `emit W(msg.sender)` is not an access check → still flagged.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  event W(address);\n  function withdraw() external { emit W(msg.sender); payable(tx.origin).transfer(1); }\n}\n";
        assert!(has(src, ACCESS));
    }

    #[test]
    fn access_finding_reports_function_keyword_line() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function mint(address t, uint a) external { _mint(t, a); }\n}\n";
        let hit = detect(src).unwrap().into_iter().find(|h| h.rule_id == ACCESS).unwrap();
        assert_eq!(hit.line, 3);
        assert_eq!(hit.evidence, "function mint");
    }

    #[test]
    fn restricted_modifier_is_a_guard() {
        assert!(!has(&ac_src("function mint(address t, uint a) external restricted { _mint(t, a); }"), ACCESS));
    }

    #[test]
    fn non_access_modifier_does_not_guard() {
        // `whenNotPaused` is not access control — a privileged fn with only that
        // modifier (and no other guard) is still flagged.
        assert!(has(&ac_src("function mint(address t, uint a) external whenNotPaused { _mint(t, a); }"), ACCESS));
    }

    #[test]
    fn member_form_guard_call_is_not_flagged() {
        // A qualified guard call `acl._checkRole(...)` (member form) counts.
        assert!(!has(&ac_src("function burn(uint a) external { acl._checkRole(ADMIN); _burn(a); }"), ACCESS));
    }

    #[test]
    fn require_wrapping_msg_sender_is_a_guard() {
        // `require(isOwner(msg.sender))` — msg.sender reaches the require call with
        // no direct comparison; still a guard.
        assert!(!has(&ac_src("function mint(address t, uint a) external { require(isOwner(msg.sender)); _mint(t, a); }"), ACCESS));
    }

    #[test]
    fn view_privileged_named_fn_is_not_flagged() {
        // A view/pure function changes no state — a privileged-named getter is not
        // an access-control risk (precision win over the heuristic).
        assert!(!has(&ac_src("function withdraw() external view returns (uint) { return 1; }"), ACCESS));
    }

    #[test]
    fn interface_and_abstract_declarations_are_not_flagged() {
        // A pure declaration (no `{ }` body) is not an implementation — the guard
        // lives on the implementing contract, so it must not be flagged.
        let iface = "pragma solidity ^0.8.0;\ninterface I { function mint(address t, uint a) external; }\n";
        assert!(!has(iface, ACCESS));
        let abstr = "pragma solidity ^0.8.0;\nabstract contract A { function withdraw() external virtual; }\n";
        assert!(!has(abstr, ACCESS));
    }

    // ---- Phase 18: AST weak-block-randomness ----

    const RANDOMNESS: &str = "WEAK_BLOCK_RANDOMNESS";

    fn rnd_src(body: &str) -> String {
        format!("pragma solidity ^0.8.0;\ncontract C {{\n  uint x; uint last;\n  function f() public {{ {body} }}\n}}\n")
    }

    #[test]
    fn timestamp_modulo_is_weak_randomness() {
        assert!(has(&rnd_src("x = block.timestamp % 100;"), RANDOMNESS));
    }

    #[test]
    fn number_modulo_is_weak_randomness() {
        assert!(has(&rnd_src("x = block.number % 7;"), RANDOMNESS));
    }

    #[test]
    fn prevrandao_modulo_is_weak_randomness() {
        assert!(has(&rnd_src("x = block.prevrandao % 2;"), RANDOMNESS));
    }

    #[test]
    fn blockhash_modulo_is_weak_randomness() {
        assert!(has(&rnd_src("x = uint(blockhash(block.number - 1)) % 10;"), RANDOMNESS));
    }

    #[test]
    fn keccak_seed_of_block_is_weak_randomness() {
        assert!(has(&rnd_src("x = uint(keccak256(abi.encodePacked(block.timestamp, msg.sender))) % 6;"), RANDOMNESS));
    }

    #[test]
    fn deadline_comparison_is_not_randomness() {
        assert!(!has(&rnd_src("require(block.timestamp >= last + 1 days);"), RANDOMNESS));
    }

    #[test]
    fn timestamp_assignment_is_not_randomness() {
        assert!(!has(&rnd_src("last = block.timestamp;"), RANDOMNESS));
    }

    #[test]
    fn block_number_comparison_is_not_randomness() {
        assert!(!has(&rnd_src("if (block.number > 100) { x = 1; }"), RANDOMNESS));
    }

    #[test]
    fn timestamp_non_modulo_arithmetic_is_not_randomness() {
        assert!(!has(&rnd_src("x = block.timestamp + 3600;"), RANDOMNESS));
        assert!(!has(&rnd_src("x = block.timestamp / 2;"), RANDOMNESS));
    }

    #[test]
    fn keccak_without_block_source_is_not_randomness() {
        assert!(!has(&rnd_src("x = uint(keccak256(abi.encodePacked(msg.sender))) % 6;"), RANDOMNESS));
    }

    #[test]
    fn randomness_hits_dedup_per_line() {
        // `blockhash(block.number-1) % 10` has two block sources on one line —
        // collapse to a single finding.
        let hits: Vec<_> = detect(&rnd_src("x = uint(blockhash(block.number - 1)) % 10;"))
            .unwrap()
            .into_iter()
            .filter(|h| h.rule_id == RANDOMNESS)
            .collect();
        assert_eq!(hits.len(), 1);
    }

    // ---- Phase 19: AST ecrecover zero-check ----

    const ECRECOVER: &str = "ECRECOVER_NO_ZERO_CHECK";

    fn ec_src(body: &str) -> String {
        format!("pragma solidity ^0.8.0;\ncontract C {{\n  address signer;\n  function f(bytes32 h, uint8 v, bytes32 r, bytes32 ss) public {{ {body} }}\n}}\n")
    }

    #[test]
    fn ecrecover_compared_to_signer_only_is_flagged() {
        assert!(has(&ec_src("address s = ecrecover(h, v, r, ss); require(s == signer);"), ECRECOVER));
    }

    #[test]
    fn ecrecover_inline_no_check_is_flagged() {
        assert!(has(&ec_src("require(ecrecover(h, v, r, ss) == signer);"), ECRECOVER));
    }

    #[test]
    fn ecrecover_result_used_raw_is_flagged() {
        assert!(has(&ec_src("address s = ecrecover(h, v, r, ss); use(s);"), ECRECOVER));
    }

    #[test]
    fn ecrecover_bound_zero_check_not_flagged() {
        assert!(!has(&ec_src("address s = ecrecover(h, v, r, ss); require(s != address(0)); use(s);"), ECRECOVER));
    }

    #[test]
    fn ecrecover_bound_eq_zero_revert_not_flagged() {
        assert!(!has(&ec_src("address s = ecrecover(h, v, r, ss); if (s == address(0)) revert(); use(s);"), ECRECOVER));
    }

    #[test]
    fn ecrecover_inline_zero_check_not_flagged() {
        assert!(!has(&ec_src("require(ecrecover(h, v, r, ss) != address(0));"), ECRECOVER));
    }

    #[test]
    fn ecrecover_zero_literal_check_not_flagged() {
        assert!(!has(&ec_src("address s = ecrecover(h, v, r, ss); require(s != 0); use(s);"), ECRECOVER));
    }

    #[test]
    fn ecrecover_reassigned_then_zero_checked_not_flagged() {
        assert!(!has(&ec_src("address s; s = ecrecover(h, v, r, ss); require(s != address(0));"), ECRECOVER));
    }

    #[test]
    fn equality_has_zero_matches_exact_zero_only() {
        assert!(equality_has_zero("s != address(0)"));
        assert!(equality_has_zero("s == 0"));
        assert!(!equality_has_zero("s != address(0x123)"));
        assert!(!equality_has_zero("s == 100"));
        assert!(!equality_has_zero("s == owner"));
    }

    // ---- Phase 20: AST arbitrary delegatecall ----

    const ARBITRARY_DC: &str = "DELEGATECALL_ARBITRARY_TARGET";

    #[test]
    fn delegatecall_to_param_is_arbitrary() {
        let src = "pragma solidity ^0.8.0;\ncontract C { function exec(address target, bytes calldata data) external { target.delegatecall(data); } }\n";
        assert!(has(src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_address_cast_param_is_arbitrary() {
        let src = "pragma solidity ^0.8.0;\ncontract C { function exec(address target, bytes calldata data) external { address(target).delegatecall(data); } }\n";
        assert!(has(src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_state_var_is_not_arbitrary() {
        let src = "pragma solidity ^0.8.0;\ncontract C { address impl; function f(bytes calldata data) external { impl.delegatecall(data); } }\n";
        assert!(!has(src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_immutable_is_not_arbitrary() {
        let src = "pragma solidity ^0.8.0;\ncontract C { address immutable impl; constructor(address i){impl=i;} function f(bytes calldata d) external { impl.delegatecall(d); } }\n";
        assert!(!has(src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_call_result_is_not_arbitrary() {
        let src = "pragma solidity ^0.8.0;\ncontract C { function _impl() internal view returns (address) {} fallback() external { _impl().delegatecall(msg.data); } }\n";
        assert!(!has(src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_local_from_param_is_not_arbitrary() {
        // Cross-statement alias (param -> local) is the documented intra-statement gap.
        let src = "pragma solidity ^0.8.0;\ncontract C { address impl; function f(bytes calldata d) external { address t = impl; t.delegatecall(d); } }\n";
        assert!(!has(src, ARBITRARY_DC));
    }

    #[test]
    fn non_delegatecall_on_param_is_not_arbitrary() {
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(address target) external { target.call(\"\"); } }\n";
        assert!(!has(src, ARBITRARY_DC));
    }

    // ---- Phase 21: AST transfer/send arg-count + narrowing downcast ----

    const TRANSFER_SEND: &str = "HARDCODED_GAS_TRANSFER_SEND";
    const DOWNCAST: &str = "UNSAFE_DOWNCAST_TRUNCATION";

    fn count(content: &str, rule: &str) -> usize {
        detect(content).expect("parses").iter().filter(|h| h.rule_id == rule).count()
    }

    // -- transfer / send: argument count discriminates ETH send from ERC-20 --

    #[test]
    fn one_arg_transfer_is_eth_send() {
        assert!(has(&contract("payable(msg.sender).transfer(amount);"), TRANSFER_SEND));
    }

    #[test]
    fn one_arg_send_is_eth_send() {
        assert!(has(&contract("bool ok = recipient.send(amount); ok;"), TRANSFER_SEND));
    }

    #[test]
    fn bare_addr_transfer_without_value_keyword_is_eth_send() {
        // The heuristic's `eth_transfer_context` missed this (no value keyword on
        // the line); the arg-count AST catches it — a recall improvement.
        assert!(has(&contract("addr.transfer(x);"), TRANSFER_SEND));
    }

    #[test]
    fn two_arg_transfer_is_erc20_not_flagged() {
        // The keyword heuristic false-positived on this; the arg count makes it
        // unambiguous (an ERC-20 transfer takes 2 args).
        assert!(!has(&contract("dai.transfer(to, amount);"), TRANSFER_SEND));
    }

    #[test]
    fn transfer_from_is_not_flagged() {
        assert!(!has(&contract("dai.transferFrom(from, to, amount);"), TRANSFER_SEND));
    }

    #[test]
    fn wrapped_ierc20_transfer_not_flagged() {
        assert!(!has(&contract("IERC20(t).transfer(to, amount);"), TRANSFER_SEND));
    }

    #[test]
    fn transfer_with_nested_call_arg_counts_as_one() {
        // The inner `g(x, y)` has two args; the outer call must still count 1.
        assert_eq!(count(&contract("payable(a).transfer(g(x, y));"), TRANSFER_SEND), 1);
    }

    #[test]
    fn transfer_send_reported_on_member_line() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public {\n    addr.transfer(amount);\n  }\n}\n";
        let h = detect(src).unwrap();
        let t = h.iter().find(|h| h.rule_id == TRANSFER_SEND).expect("flagged");
        assert_eq!(t.line, 4);
    }

    // -- narrowing downcast: suppress literals and same-family widening --

    #[test]
    fn narrowing_cast_of_identifier_flagged() {
        assert!(has(&contract("uint128 y = uint128(x); y;"), DOWNCAST));
    }

    #[test]
    fn narrowing_cast_int_family_flagged() {
        assert!(has(&contract("int64 y = int64(s); y;"), DOWNCAST));
    }

    #[test]
    fn narrowing_cast_of_arithmetic_flagged() {
        assert!(has(&contract("uint128 y = uint128(a + b); y;"), DOWNCAST));
    }

    #[test]
    fn narrowing_cast_of_address_flagged() {
        assert!(has(&contract("uint160 y = uint160(addr); y;"), DOWNCAST));
    }

    #[test]
    fn cast_of_decimal_literal_not_flagged() {
        assert!(!has(&contract("uint128 y = uint128(0); y;"), DOWNCAST));
    }

    #[test]
    fn cast_of_hex_literal_not_flagged() {
        assert!(!has(&contract("uint8 y = uint8(0xff); y;"), DOWNCAST));
    }

    #[test]
    fn widening_cast_to_256_not_flagged() {
        assert!(!has(&contract("uint256 y = uint256(x); y;"), DOWNCAST));
    }

    #[test]
    fn uint_alias_is_256_not_narrowing() {
        assert!(!has(&contract("uint y = uint(x); y;"), DOWNCAST));
    }

    #[test]
    fn bytes_and_address_casts_not_flagged() {
        assert!(!has(&contract("bytes32 a = bytes32(x); address b = address(x); a; b;"), DOWNCAST));
    }

    #[test]
    fn nested_same_family_widening_flags_inner_only() {
        // uint128(uint64(z)): outer widens (suppress), inner uint64 narrows (flag).
        assert_eq!(count(&contract("uint128 y = uint128(uint64(z)); y;"), DOWNCAST), 1);
    }

    #[test]
    fn nested_both_narrowing_flags_both() {
        assert_eq!(count(&contract("uint64 y = uint64(uint128(x)); y;"), DOWNCAST), 2);
    }

    #[test]
    fn triple_nested_narrowing_flags_all() {
        assert_eq!(count(&contract("uint8 y = uint8(uint16(uint32(x))); y;"), DOWNCAST), 3);
    }

    #[test]
    fn mixed_family_nested_flags_outer_and_inner() {
        // int128(uint64(z)): different family — the outer is not treated as a
        // widening of the inner (flag), and the inner uint64 narrows (flag).
        assert_eq!(count(&contract("int128 y = int128(uint64(z)); y;"), DOWNCAST), 2);
    }

    #[test]
    fn cast_reported_on_cast_line() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public {\n    uint128 y = uint128(x);\n    y;\n  }\n}\n";
        let h = detect(src).unwrap();
        let c = h.iter().find(|h| h.rule_id == DOWNCAST).expect("flagged");
        assert_eq!(c.line, 4);
    }

    #[test]
    fn literal_cast_with_inner_whitespace_not_flagged() {
        // Regression for the slang trivia trap: `uint8( 0 )` with spaces must still
        // recognize the literal argument (else it would false-positive).
        assert!(!has(&contract("uint8 y = uint8( 0 ); y;"), DOWNCAST));
    }

    #[test]
    fn outermost_cast_after_assignment_flagged() {
        // Regression: the space after `=` makes the cast operand's first child a
        // Whitespace trivia node; `to_child(Variant)` must skip it to read the type
        // keyword (a blind go_to_first_child would miss every outermost cast).
        assert!(has(&contract("uint128 y; y = uint128(x);"), DOWNCAST));
    }

    #[test]
    fn int_type_width_parses_widths_and_rejects_non_int() {
        assert_eq!(int_type_width("uint128"), Some((true, 128)));
        assert_eq!(int_type_width("int64"), Some((false, 64)));
        assert_eq!(int_type_width("uint"), Some((true, 256)));
        assert_eq!(int_type_width("int"), Some((false, 256)));
        assert_eq!(int_type_width("uint256"), Some((true, 256)));
        assert_eq!(int_type_width("address"), None);
        assert_eq!(int_type_width("bytes32"), None);
        assert_eq!(int_type_width("bool"), None);
    }

    // -- edge syntax: defensive navigation paths (graceful, no misclassification) --

    #[test]
    fn named_argument_send_is_not_a_one_arg_eth_send() {
        // `recipient.send({value: x})` uses named-argument syntax — not a positional
        // 1-arg send, so not flagged (exercises the named-arguments guard).
        assert!(!has(&contract("recipient.send({value: x});"), TRANSFER_SEND));
    }

    #[test]
    fn empty_argument_transfer_is_not_flagged() {
        // `addr.transfer()` has zero arguments — not a 1-arg ETH send.
        assert!(!has(&contract("addr.transfer();"), TRANSFER_SEND));
    }

    #[test]
    fn named_argument_cast_is_flagged_conservatively() {
        // `uint128({x: 1})` has a non-positional argument that can't be proven a
        // literal/widening → flagged (the conservative, never-drop-a-real-finding
        // direction; exercises the named-arguments arg guard).
        assert!(has(&contract("uint128 y = uint128({x: 1}); y;"), DOWNCAST));
    }

    #[test]
    fn empty_argument_cast_is_flagged_conservatively() {
        // `uint128()` has no argument to prove safe → flagged (defensive path).
        assert!(has(&contract("uint128 y = uint128(); y;"), DOWNCAST));
    }

    // -- adversarial-review fixes: address-cast downcast + messaging-send payload --

    #[test]
    fn uint160_of_address_cast_not_flagged() {
        // address is exactly 160 bits → uint160(address(x)) is lossless.
        assert!(!has(&contract("uint160 a = uint160(address(this)); a;"), DOWNCAST));
        assert!(!has(&contract("uint160 a = uint160(address(o)); a;"), DOWNCAST));
    }

    #[test]
    fn wide_cast_of_address_cast_not_flagged() {
        // uint192(address(x)) widens an address → lossless.
        assert!(!has(&contract("uint192 a = uint192(address(o)); a;"), DOWNCAST));
    }

    #[test]
    fn narrow_cast_of_address_still_flagged() {
        // uint128 < 160 bits → casting a 160-bit address into it truncates → flag.
        assert!(has(&contract("uint128 a = uint128(address(o)); a;"), DOWNCAST));
    }

    #[test]
    fn uint160_of_plain_identifier_still_flagged() {
        // Without type info we can't prove `v` is an address → conservatively flag
        // (documented: needs the scope-aware name/type resolution phase).
        assert!(has(&contract("uint160 a = uint160(v); a;"), DOWNCAST));
    }

    #[test]
    fn send_of_string_payload_is_not_eth_send() {
        // `bridge.send("…")` — a string arg can't be a wei amount → messaging, not ETH.
        assert!(!has(&contract("bridge.send(\"hello\");"), TRANSFER_SEND));
    }

    #[test]
    fn send_of_hex_literal_payload_is_not_eth_send() {
        assert!(!has(&contract("bridge.send(hex\"00ff\");"), TRANSFER_SEND));
    }

    #[test]
    fn send_of_abi_encode_payload_is_not_eth_send() {
        assert!(!has(&contract("endpoint.send(abi.encodePacked(a, b));"), TRANSFER_SEND));
        assert!(!has(&contract("endpoint.send(abi.encode(x));"), TRANSFER_SEND));
    }

    #[test]
    fn transfer_of_amount_identifier_still_flagged() {
        // An identifier/number amount is still a real ETH send → flag (the payload
        // exclusion must not suppress genuine sends).
        assert!(has(&contract("r.transfer(amount);"), TRANSFER_SEND));
        assert!(has(&contract("r.send(msg.value);"), TRANSFER_SEND));
    }

    // ---- Phase 22: binding-graph type resolution ----

    /// Rule ids from the binding-aware (`detect_unit`) path for a single file.
    fn unit_rules(content: &str) -> Vec<&'static str> {
        detect_unit(&[("main.sol", content)])
            .expect("unit builds")
            .into_values()
            .flatten()
            .map(|h| h.rule_id)
            .collect()
    }
    fn unit_has(content: &str, rule: &str) -> bool {
        unit_rules(content).contains(&rule)
    }

    // -- downcast: resolved arg type suppresses provably-fitting casts --

    #[test]
    fn binding_suppresses_uint160_of_address_var() {
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(address a) external pure returns (uint160) { return uint160(a); } }\n";
        assert!(!unit_has(src, DOWNCAST));
    }

    #[test]
    fn binding_suppresses_uint8_of_enum_var() {
        let src = "pragma solidity ^0.8.0;\ncontract C { enum S { A, B } function f(S s) external pure returns (uint8) { return uint8(s); } }\n";
        assert!(!unit_has(src, DOWNCAST));
    }

    #[test]
    fn binding_suppresses_narrower_same_family_var() {
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(uint64 x) external pure returns (uint128) { return uint128(x); } }\n";
        assert!(!unit_has(src, DOWNCAST));
    }

    #[test]
    fn binding_still_flags_uint256_var_downcast() {
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(uint256 x) external pure returns (uint128) { return uint128(x); } }\n";
        assert!(unit_has(src, DOWNCAST));
    }

    #[test]
    fn binding_still_flags_narrow_cast_of_address_var() {
        // uint128 < 160 bits → casting an address into it truncates → still flag.
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(address a) external pure returns (uint128) { return uint128(uint160(a)); } }\n";
        assert!(unit_has(src, DOWNCAST));
    }

    // -- transfer/send: resolved receiver type --

    #[test]
    fn binding_suppresses_interface_receiver_send() {
        let src = "pragma solidity ^0.8.0;\ninterface IM { function send(bytes calldata m) external; }\ncontract C { IM endpoint; function f(bytes calldata m) external { endpoint.send(m); } }\n";
        assert!(!unit_has(src, TRANSFER_SEND));
    }

    #[test]
    fn binding_still_flags_address_payable_receiver_transfer() {
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(address payable r, uint256 amt) external { r.transfer(amt); } }\n";
        assert!(unit_has(src, TRANSFER_SEND));
    }

    // -- three-level graceful degradation --

    #[test]
    fn parse_only_path_conservatively_flags_address_var_cast() {
        // The parse-only `detect` path (no binding graph) cannot resolve `a`'s type
        // → conservatively flags; only the binding path suppresses it.
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(address a) external pure returns (uint160) { return uint160(a); } }\n";
        assert!(has(src, DOWNCAST));
    }

    #[test]
    fn detect_unit_none_on_parse_error() {
        assert!(detect_unit(&[("bad.sol", "contract C { function f( {")]).is_none());
    }

    #[test]
    fn detect_unit_none_on_deep_nesting() {
        let deep = format!(
            "pragma solidity ^0.8.0;\ncontract C {{ function f() public {{ uint x = {}1{}; x; }} }}\n",
            "(".repeat(1000),
            ")".repeat(1000),
        );
        assert!(detect_unit(&[("d.sol", &deep)]).is_none());
    }

    #[test]
    fn detect_unit_none_on_empty_files() {
        assert!(detect_unit(&[]).is_none());
    }

    #[test]
    fn detect_unit_covers_every_file() {
        // Multi-file unit: every file path is present in the result map.
        let a = "pragma solidity ^0.8.0;\ncontract A { function g(uint256 x) external pure returns (uint128) { return uint128(x); } }\n";
        let b = "pragma solidity ^0.8.0;\ncontract B { uint256 v; }\n";
        let map = detect_unit(&[("a.sol", a), ("b.sol", b)]).expect("unit builds");
        assert!(map.contains_key("a.sol") && map.contains_key("b.sol"));
        assert!(map["a.sol"].iter().any(|h| h.rule_id == DOWNCAST));
    }

    #[test]
    fn binding_flags_cast_of_non_numeric_var() {
        // A bool var resolves to neither address/enum/int → ResolvedType::Other →
        // not suppressed → flagged (conservative; the type can't prove it fits).
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(bool b) external pure returns (uint8) { return uint8(b); } }\n";
        assert!(unit_has(src, DOWNCAST));
    }

    #[test]
    fn binding_resolves_cross_file_import_exact() {
        // The interface type IM is defined in a.sol and imported into b.sol by an
        // exact file-id path; the binding graph must resolve `endpoint`'s type
        // across files → endpoint.send(m) suppressed.
        let a = "pragma solidity ^0.8.0;\ninterface IM { function send(bytes calldata m) external; }\n";
        let b = "pragma solidity ^0.8.0;\nimport \"a.sol\";\ncontract C { IM endpoint; function f(bytes calldata m) external { endpoint.send(m); } }\n";
        let hits: Vec<_> = detect_unit(&[("a.sol", a), ("b.sol", b)])
            .expect("unit builds")
            .into_values()
            .flatten()
            .map(|h| h.rule_id)
            .collect();
        assert!(!hits.contains(&TRANSFER_SEND));
    }

    #[test]
    fn binding_resolves_cross_file_import_suffix() {
        // A relative import path `./a.sol` resolves to file id `a.sol` by the
        // suffix-match fallback in MemFiles::resolve_import.
        let a = "pragma solidity ^0.8.0;\ninterface IM { function send(bytes calldata m) external; }\n";
        let b = "pragma solidity ^0.8.0;\nimport \"./a.sol\";\ncontract C { IM endpoint; function f(bytes calldata m) external { endpoint.send(m); } }\n";
        let hits: Vec<_> = detect_unit(&[("a.sol", a), ("b.sol", b)])
            .expect("unit builds")
            .into_values()
            .flatten()
            .map(|h| h.rule_id)
            .collect();
        assert!(!hits.contains(&TRANSFER_SEND));
    }

    // -- Phase 22 adversarial-review fixes: import resolution, dedup, chain guard --

    #[test]
    fn import_path_helpers() {
        assert_eq!(parent_dir("contracts/a/B.sol"), "contracts/a");
        assert_eq!(parent_dir("B.sol"), "");
        assert_eq!(normalize_join("contracts", "./Token.sol"), "contracts/Token.sol");
        assert_eq!(normalize_join("contracts/sub", "../Token.sol"), "contracts/Token.sol");
        assert_eq!(normalize_join("", "./a.sol"), "a.sol");
        assert_eq!(normalize_join("a/b", "../../x.sol"), "x.sol");
        // path-segment-boundary suffix: no mid-segment or unrelated-tail matches.
        assert!(ends_with_segment("contracts/Token.sol", "Token.sol"));
        assert!(ends_with_segment("Token.sol", "Token.sol"));
        assert!(!ends_with_segment("xToken.sol", "Token.sol"));
        assert!(!ends_with_segment("@oz/ERC20.sol", "20.sol"));
    }

    #[test]
    fn binding_resolves_relative_dir_prefixed_import() {
        // Review bug 1: a dir-prefixed key + a `./` import must resolve cross-file
        // (resolve against the importing file's directory) so the interface
        // receiver is suppressed — the dominant real-world import form.
        let user = "pragma solidity ^0.8.0;\nimport \"./IM.sol\";\ncontract U { IM endpoint; function f(bytes calldata p) external { endpoint.send(p); } }\n";
        let im = "pragma solidity ^0.8.0;\ninterface IM { function send(bytes calldata m) external; }\n";
        let hits: Vec<_> = detect_unit(&[("contracts/User.sol", user), ("contracts/IM.sol", im)])
            .expect("unit builds")
            .into_values()
            .flatten()
            .map(|h| h.rule_id)
            .collect();
        assert!(!hits.contains(&TRANSFER_SEND));
    }

    #[test]
    fn detect_unit_dedups_duplicate_paths() {
        // Review bugs 5/6: two entries with the same path are processed once.
        let a = "pragma solidity ^0.8.0;\ncontract A { function f(uint256 x) external pure returns (uint128) { return uint128(x); } }\n";
        let map = detect_unit(&[("dup.sol", a), ("dup.sol", a)]).expect("unit builds");
        assert_eq!(map.len(), 1);
    }

    #[test]
    fn flat_operator_chain_degrades_to_none() {
        // Review bug 7: a bracket-free `1+1+...` chain would stack-overflow the
        // parser; the chain guard must reject it (both detect and detect_unit).
        let chain = vec!["1"; 500].join("+");
        let src = format!("pragma solidity ^0.8.0;\ncontract C {{ function f() public {{ uint x = {chain}; x; }} }}\n");
        assert!(detect(&src).is_none());
        assert!(detect_unit(&[("c.sol", &src)]).is_none());
    }

    #[test]
    fn flat_member_chain_degrades_to_none() {
        let chain = vec!["a"; 500].join(".");
        let src = format!("pragma solidity ^0.8.0;\ncontract C {{ function f() public {{ uint x = {chain}; x; }} }}\n");
        assert!(detect(&src).is_none());
    }

    #[test]
    fn normal_multi_operator_expression_not_rejected() {
        // A realistic expression stays well under MAX_EXPR_CHAIN.
        assert!(detect(&contract("uint x = a + b * c - d / e + f % g; x;")).is_some());
    }

    // ---- Phase 23: delegatecall local-alias backtracking ----

    /// `exec(address target, bytes data)` with a `logic` state variable, so both
    /// a caller-controlled and a fixed source are in scope for the receiver.
    fn dc(body: &str) -> String {
        format!(
            "pragma solidity ^0.8.0;\ncontract C {{ address logic;\n  function exec(address target, bytes calldata data) external {{ {body} }}\n}}\n"
        )
    }

    #[test]
    fn delegatecall_through_one_alias_is_arbitrary() {
        let src = dc("address a = target; a.delegatecall(data);");
        assert!(unit_has(&src, ARBITRARY_DC));
        // The Phase 20 name match cannot see through the alias — this is exactly
        // the false negative the binding graph closes.
        assert!(!has(&src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_through_four_aliases_is_arbitrary() {
        let src = dc("address a = target; address b = a; address c = b; address d = c; d.delegatecall(data);");
        assert!(unit_has(&src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_alias_chain_beyond_cap_is_not_flagged() {
        // Five hops exceeds MAX_ALIAS_HOPS: stop walking rather than chase a
        // chain nobody writes, and report nothing (the conservative direction).
        let src = dc(
            "address a = target; address b = a; address c = b; address d = c; address e = d; e.delegatecall(data);",
        );
        assert!(!unit_has(&src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_param_still_fires_on_binding_path() {
        // Phase 20's direct case must keep firing once resolution takes over.
        let src = dc("target.delegatecall(data);");
        assert!(unit_has(&src, ARBITRARY_DC));
        assert!(has(&src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_state_var_alias_is_not_arbitrary() {
        // `logic` is fixed by the contract, not by the caller: the normal proxy.
        let src = dc("address a = logic; a.delegatecall(data);");
        assert!(!unit_has(&src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_fixed_local_is_not_arbitrary() {
        let src = dc("address a = address(this); a.delegatecall(data);");
        assert!(!unit_has(&src, ARBITRARY_DC));
    }

    #[test]
    fn delegatecall_to_uninitialised_local_is_not_arbitrary() {
        let src = dc("address a; a.delegatecall(data);");
        assert!(!unit_has(&src, ARBITRARY_DC));
    }

    #[test]
    fn function_type_param_name_no_longer_causes_a_false_positive() {
        // `function_param_names` deliberately over-collects: a function-type
        // parameter's own inner parameter names land in the set too. Here `impl`
        // is such a name, while the actual receiver is a local fed from a state
        // variable — the name match reports it, resolution does not.
        let src = "pragma solidity ^0.8.0;\ncontract C { address logic;\n  function exec(function(address impl) external cb, bytes calldata data) external { address impl = logic; impl.delegatecall(data); cb; }\n}\n";
        assert!(has(src, ARBITRARY_DC));
        assert!(!unit_has(src, ARBITRARY_DC));
    }
}
