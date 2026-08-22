//! Security Audit Engine (standardized, SecurityFinding v2). Pure, no network/I/O.
//!
//! Heuristic detectors (source patterns, comment- AND string-aware, plus bytecode
//! opcode signals) are mapped through a three-layer taxonomy — OWASP SC Top 10
//! (`category`) → SWC registry (`swc`) → internal `rule_id` — and a multi-factor
//! risk model (impact × likelihood × confidence × exposure). A triage aid, NOT a
//! formal verifier: expect false positives/negatives.

use std::collections::BTreeMap;

use crate::model::{Audit, AuditSummary, ContractDetails, SecurityFinding, SourceFile};
use crate::suppress::Suppressions;

const OWASP_URL: &str = "https://owasp.org/www-project-smart-contract-top-10/";

/// Per-rule constant taxonomy + grading defaults. Detectors only supply runtime
/// context (locations, evidence, affected contract); everything else lives here.
struct RuleSpec {
    title: &'static str,
    category: &'static str,
    swc: Option<&'static str>,
    severity: &'static str,
    confidence: &'static str,
    impact: u8,
    likelihood: u8,
    exploitability: &'static str,
    asset_at_risk: &'static str,
    blast_radius: &'static str,
    exploit_scenario: &'static str,
    recommendation: &'static str,
    fp_notes: &'static str,
}

/// The rule taxonomy. Every `rule_id` a detector can emit must have an entry.
fn spec(rule_id: &str) -> RuleSpec {
    match rule_id {
        "TX_ORIGIN_AUTH" => RuleSpec {
            title: "Use of tx.origin for authorization",
            category: "SC01:Access Control", swc: Some("SWC-115"),
            severity: "High", confidence: "Medium", impact: 7, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "Privileged functions / funds",
            blast_radius: "user-funds",
            exploit_scenario: "An attacker lures the owner into calling a malicious contract that re-enters the victim; tx.origin still equals the owner, bypassing the check.",
            recommendation: "Authorize with msg.sender; never use tx.origin.",
            fp_notes: "tx.origin may appear in non-authorization contexts.",
        },
        "SELFDESTRUCT_PRESENT" | "BYTECODE_SELFDESTRUCT" => RuleSpec {
            title: "Contract can self-destruct",
            category: "SC01:Access Control", swc: Some("SWC-106"),
            severity: "High", confidence: "Medium", impact: 9, likelihood: 4,
            exploitability: "Moderate", asset_at_risk: "Entire contract code & balance",
            blast_radius: "protocol",
            exploit_scenario: "If the selfdestruct path is insufficiently guarded, an attacker destroys the contract and forwards its balance.",
            recommendation: "Strictly access-control selfdestruct, or remove it.",
            fp_notes: "The destruct path may be properly access-controlled.",
        },
        "PROXY_UNPROTECTED_INITIALIZER" => RuleSpec {
            title: "Unprotected initialize()",
            // No SWC entry covers the modern upgradeable-proxy initializer pattern
            // (the registry predates it); SWC-118 is "Incorrect Constructor Name".
            category: "SC01:Access Control", swc: None,
            severity: "High", confidence: "Low", impact: 8, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "Proxy ownership / logic control",
            blast_radius: "governance",
            exploit_scenario: "A public initialize() lacking the initializer guard can be front-run/called by anyone to seize ownership of the proxy.",
            recommendation: "Use OpenZeppelin's initializer/reinitializer modifier and _disableInitializers() in the constructor.",
            fp_notes: "An access modifier on a later line may guard it.",
        },
        "DELEGATECALL_USAGE" | "BYTECODE_DELEGATECALL" => RuleSpec {
            title: "delegatecall to external code",
            category: "SC06:Unchecked External Calls", swc: Some("SWC-112"),
            severity: "Medium", confidence: "Low", impact: 7, likelihood: 3,
            exploitability: "Hard", asset_at_risk: "Contract storage & logic",
            blast_radius: "protocol",
            exploit_scenario: "delegatecall into attacker-controlled or mutable code runs in this contract's context and can rewrite its storage.",
            recommendation: "Only delegatecall trusted, immutable targets; validate the target address.",
            fp_notes: "Standard and safe in audited proxy/library patterns.",
        },
        "DELEGATECALL_ARBITRARY_TARGET" => RuleSpec {
            title: "delegatecall to a caller-controlled target",
            category: "SC06:Unchecked External Calls", swc: Some("SWC-112"),
            severity: "Critical", confidence: "Medium", impact: 10, likelihood: 7,
            exploitability: "Easy", asset_at_risk: "Entire contract (storage & logic)",
            blast_radius: "protocol",
            exploit_scenario: "A delegatecall whose target is a caller-supplied address executes arbitrary code in this contract's storage context — an attacker overwrites owner/balances and seizes the contract (cf. the Parity multisig freeze).",
            recommendation: "Never delegatecall a user-supplied address; restrict to a fixed, immutable implementation.",
            fp_notes: "Only fires when the delegatecall receiver is a function parameter; a parameter validated against a whitelist is still flagged.",
        },
        "UNCHECKED_LOW_LEVEL_CALL" => RuleSpec {
            title: "Unchecked low-level call",
            category: "SC06:Unchecked External Calls", swc: Some("SWC-104"),
            severity: "Medium", confidence: "Low", impact: 5, likelihood: 4,
            exploitability: "Moderate", asset_at_risk: "Funds / state consistency",
            blast_radius: "single-contract",
            exploit_scenario: "An ignored call() failure lets execution continue as if a transfer succeeded, corrupting accounting.",
            recommendation: "Check the boolean return of low-level calls and guard against reentrancy.",
            fp_notes: "The return value may be checked on a nearby line.",
        },
        "WEAK_BLOCK_RANDOMNESS" => RuleSpec {
            title: "Weak randomness from block properties",
            category: "SC09:Insecure Randomness", swc: Some("SWC-120"),
            severity: "Medium", confidence: "Medium", impact: 5, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "Game/lottery outcomes / fairness",
            blast_radius: "single-contract",
            exploit_scenario: "Validators or searchers influence block.timestamp/number, biasing any randomness derived from them.",
            recommendation: "Use a verifiable randomness source (Chainlink VRF) or commit-reveal.",
            fp_notes: "Block values may be used for non-security timing.",
        },
        "ECRECOVER_NO_ZERO_CHECK" => RuleSpec {
            title: "ecrecover without zero-address check",
            // SWC-122 (Lack of Proper Signature Verification) fits the unchecked
            // ecrecover-return pitfall better than SWC-117 (Signature Malleability).
            category: "SC04:Lack of Input Validation", swc: Some("SWC-122"),
            severity: "Low", confidence: "Low", impact: 5, likelihood: 3,
            exploitability: "Hard", asset_at_risk: "Signature-gated auth",
            blast_radius: "single-contract",
            exploit_scenario: "ecrecover returns address(0) on malformed signatures; if unchecked, a crafted signature may bypass a signer check.",
            recommendation: "Reject address(0) from ecrecover; prefer EIP-712 / OpenZeppelin ECDSA.",
            fp_notes: "A zero-address check may exist nearby.",
        },
        "FLOATING_PRAGMA" => RuleSpec {
            title: "Floating compiler pragma",
            category: "Code Quality", swc: Some("SWC-103"),
            severity: "Low", confidence: "High", impact: 2, likelihood: 2,
            exploitability: "Hard", asset_at_risk: "Build reproducibility",
            blast_radius: "single-contract",
            exploit_scenario: "A floating pragma lets the contract compile under a version different from the audited one, risking behavior drift.",
            recommendation: "Pin an exact compiler version.",
            fp_notes: "",
        },
        "OUTDATED_COMPILER" => RuleSpec {
            title: "Outdated Solidity compiler (<0.8)",
            // SWC-102 is "Outdated Compiler Version" (what we detect); the overflow
            // consequence (SWC-101) is reflected in the SC08 category.
            category: "SC08:Integer Overflow/Underflow", swc: Some("SWC-102"),
            severity: "Medium", confidence: "High", impact: 5, likelihood: 4,
            exploitability: "Moderate", asset_at_risk: "Arithmetic correctness / funds",
            blast_radius: "single-contract",
            exploit_scenario: "Pre-0.8 arithmetic wraps silently; without SafeMath an overflow can mint or drain balances.",
            recommendation: "Upgrade to >=0.8 (checked arithmetic) or use SafeMath everywhere.",
            fp_notes: "SafeMath may be in use.",
        },
        "DEPRECATED_CONSTRUCT" => RuleSpec {
            title: "Deprecated Solidity construct",
            category: "Code Quality", swc: Some("SWC-111"),
            severity: "Low", confidence: "High", impact: 2, likelihood: 2,
            exploitability: "Hard", asset_at_risk: "Maintainability",
            blast_radius: "single-contract",
            exploit_scenario: "Deprecated constructs (sha3/callcode/throw) indicate outdated, riskier code.",
            recommendation: "Use current equivalents (keccak256 / call / revert).",
            fp_notes: "",
        },
        "INLINE_ASSEMBLY" => RuleSpec {
            title: "Inline assembly",
            category: "Code Quality", swc: None,
            severity: "Info", confidence: "High", impact: 1, likelihood: 1,
            exploitability: "Hard", asset_at_risk: "Type/memory safety",
            blast_radius: "single-contract",
            exploit_scenario: "Inline assembly bypasses Solidity's type and safety checks; bugs here are easy to miss.",
            recommendation: "Minimize assembly; document and test its invariants.",
            fp_notes: "Widely used safely.",
        },
        "BYTECODE_CALLCODE" => RuleSpec {
            title: "Deprecated CALLCODE opcode",
            category: "SC06:Unchecked External Calls", swc: Some("SWC-111"),
            severity: "Medium", confidence: "Medium", impact: 5, likelihood: 3,
            exploitability: "Hard", asset_at_risk: "Execution context",
            blast_radius: "single-contract",
            exploit_scenario: "CALLCODE has confusing, deprecated semantics around storage/context.",
            recommendation: "Replace CALLCODE with delegatecall or call.",
            fp_notes: "",
        },
        "BYTECODE_CREATE2" => RuleSpec {
            title: "CREATE2 deployment",
            category: "SC03:Logic Errors", swc: None,
            severity: "Info", confidence: "Medium", impact: 3, likelihood: 2,
            exploitability: "Hard", asset_at_risk: "Address-based trust assumptions",
            blast_radius: "single-contract",
            exploit_scenario: "CREATE2 enables deterministic and potentially metamorphic deployments; trusting code at a fixed address can be unsafe.",
            recommendation: "Do not assume code at a CREATE2 address is immutable.",
            fp_notes: "Common in legitimate factories.",
        },
        "SOURCE_UNVERIFIED" => RuleSpec {
            title: "Source code not verified",
            category: "Transparency", swc: None,
            severity: "Medium", confidence: "High", impact: 3, likelihood: 6,
            exploitability: "Moderate", asset_at_risk: "Auditability",
            blast_radius: "single-contract",
            exploit_scenario: "Unverified source prevents source-level review; only bytecode signals are available.",
            recommendation: "Verify the source on Etherscan or Sourcify.",
            fp_notes: "",
        },
        // ---- Phase 9: deep rule families ----
        "ACCESS_MISSING_GUARD_PRIVILEGED_FN" => RuleSpec {
            title: "Privileged function without access control",
            category: "SC01:Access Control", swc: None,
            severity: "High", confidence: "Medium", impact: 9, likelihood: 6,
            exploitability: "Easy", asset_at_risk: "Token supply, ownership, protocol funds",
            blast_radius: "protocol",
            exploit_scenario: "A public/external mint/setOwner/withdraw has no modifier; anyone calls it to inflate supply or seize the contract.",
            recommendation: "Add an access-control modifier (onlyOwner/onlyRole) or a msg.sender check to every privileged state-changing function.",
            fp_notes: "Name-based; can't tell self-burn from privileged burn, or recognize custom modifiers — triage, not a definitive bug.",
        },
        "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL" => RuleSpec {
            title: "Unprotected Ether withdrawal",
            category: "SC01:Access Control", swc: Some("SWC-105"),
            severity: "Critical", confidence: "Medium", impact: 10, likelihood: 6,
            exploitability: "Easy", asset_at_risk: "ETH held by the contract",
            blast_radius: "user-funds",
            exploit_scenario: "An unguarded public function sends ETH to an arbitrary recipient/amount; an attacker drains the balance.",
            recommendation: "Guard ETH-withdrawing functions with onlyOwner/onlyRole, or bind recipient/amount to msg.sender's own accounted balance.",
            fp_notes: "Legit pull-withdrawals to msg.sender are suppressed; unknown custom modifiers may cause false positives.",
        },
        "UUPS_AUTHORIZE_UPGRADE_UNGUARDED" => RuleSpec {
            title: "UUPS _authorizeUpgrade empty or unguarded",
            category: "SC01:Access Control", swc: None,
            severity: "High", confidence: "Medium", impact: 9, likelihood: 5,
            exploitability: "Easy", asset_at_risk: "Proxy implementation & all proxied state/funds",
            blast_radius: "governance",
            exploit_scenario: "An empty `_authorizeUpgrade(address) internal override {}` lets anyone upgrade the proxy to attacker code.",
            recommendation: "Guard _authorizeUpgrade with onlyOwner / onlyRole(UPGRADER_ROLE) or an in-body require.",
            fp_notes: "A custom modifier name may not be recognized; a guard placed deep in the body could be missed.",
        },
        "PROXY_PUBLIC_UPGRADE_TO_UNGUARDED" => RuleSpec {
            title: "Public upgradeTo without access guard",
            category: "SC01:Access Control", swc: None,
            severity: "High", confidence: "Low", impact: 9, likelihood: 4,
            exploitability: "Easy", asset_at_risk: "Proxy implementation pointer / all proxied funds",
            blast_radius: "governance",
            exploit_scenario: "A hand-rolled public upgradeTo() sets the implementation slot with no auth; an attacker points it at malicious code.",
            recommendation: "Use OZ UUPSUpgradeable with a guarded _authorizeUpgrade, or add onlyOwner/onlyRole to the upgrade function.",
            fp_notes: "OZ UUPSUpgradeable.upgradeToAndCall is public but delegates to _authorizeUpgrade (not flagged when that call is present); custom modifiers may FP.",
        },
        "HARDCODED_GAS_TRANSFER_SEND" => RuleSpec {
            title: "ETH .transfer()/.send() forwards hardcoded 2300 gas",
            category: "SC06:Unchecked External Calls", swc: Some("SWC-134"),
            severity: "Low", confidence: "Medium", impact: 4, likelihood: 6,
            exploitability: "Moderate", asset_at_risk: "Withdrawal availability (locked funds)",
            blast_radius: "user-funds",
            exploit_scenario: "A contract-wallet recipient with a non-trivial receive() can't be paid via the 2300-gas stipend; withdrawals revert (DoS).",
            recommendation: "Send ETH via `(bool ok,)=to.call{value:amount}(\"\"); require(ok);` with a reentrancy guard, or use pull payments.",
            fp_notes: "Collides with ERC20 token.transfer/send; ETH-context cue + token-name rejection mitigate but can't eliminate.",
        },
        "RAW_CALL_VALUE_ETH_SEND" => RuleSpec {
            title: "Low-level .call{value:} ETH send",
            category: "SC06:Unchecked External Calls", swc: None,
            severity: "Low", confidence: "Medium", impact: 5, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "ETH sent; refund/withdrawal accounting",
            blast_radius: "user-funds",
            exploit_scenario: "A raw value-call forwards all gas and re-enables reentrancy; if the return is ignored a failed send is treated as success.",
            recommendation: "Capture and require() the success flag, pair with nonReentrant, and apply checks-effects-interactions.",
            fp_notes: "Informational: .call{value:} is the modern recommended idiom; only the unchecked-return/ordering cases are real defects.",
        },
        "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE" => RuleSpec {
            title: "External call before state write without reentrancy guard",
            category: "SC05:Reentrancy", swc: Some("SWC-107"),
            severity: "Medium", confidence: "Low", impact: 8, likelihood: 4,
            exploitability: "Moderate", asset_at_risk: "All ETH/tokens held; accounting integrity",
            blast_radius: "user-funds",
            exploit_scenario: "withdraw() sends ETH then zeroes the balance; the recipient's fallback re-enters before the write and drains funds (the DAO bug).",
            recommendation: "Apply checks-effects-interactions (state writes before external calls) and add OpenZeppelin's nonReentrant.",
            fp_notes: "No dataflow: can't confirm exploitability, trusted targets, or guards in base contracts — Low confidence, 'needs manual review'.",
        },
        "UNCHECKED_ARITHMETIC_BLOCK" => RuleSpec {
            title: "unchecked { } disables overflow protection",
            category: "SC08:Integer Overflow/Underflow", swc: Some("SWC-101"),
            severity: "Low", confidence: "Low", impact: 6, likelihood: 3,
            exploitability: "Moderate", asset_at_risk: "Arithmetic correctness / balances",
            blast_radius: "single-contract",
            exploit_scenario: "An unvalidated subtraction inside unchecked{} underflows and wraps to a huge value, inflating a balance.",
            recommendation: "Prove every operation in the block can't overflow (document the invariant) or remove unchecked.",
            fp_notes: "Overwhelmingly benign (OZ loops, Uniswap math); only surfaces that checked arithmetic was deliberately disabled.",
        },
        "UNSAFE_DOWNCAST_TRUNCATION" => RuleSpec {
            title: "Unsafe integer downcast may truncate",
            category: "SC08:Integer Overflow/Underflow", swc: None,
            severity: "Low", confidence: "Low", impact: 6, likelihood: 3,
            exploitability: "Moderate", asset_at_risk: "Amounts / IDs / timestamps",
            blast_radius: "single-contract",
            exploit_scenario: "A uint256 above the target width is cast to uintN; high bits are silently dropped, wrapping the stored amount/deadline.",
            recommendation: "Use OpenZeppelin SafeCast (toUintN) or require(x <= type(uintN).max) before narrowing casts.",
            fp_notes: "Narrowing casts concentrate in SafeCast libraries and range-proven math; no dataflow to see the guarding bound — Low confidence.",
        },
        "ORACLE_SPOT_PRICE_FROM_RESERVES" => RuleSpec {
            title: "Spot price from getReserves()/slot0() (manipulable)",
            category: "SC02:Price Oracle Manipulation", swc: None,
            severity: "High", confidence: "Medium", impact: 9, likelihood: 6,
            exploitability: "Moderate", asset_at_risk: "Collateral valuation / protocol funds",
            blast_radius: "protocol",
            exploit_scenario: "A flash loan skews the pair's reserves/slot0 within one tx; the victim prices collateral off the manipulated value and is drained.",
            recommendation: "Use a manipulation-resistant source: Uniswap V3 TWAP (observe/consult), Chainlink, or median/time-weighted oracles.",
            fp_notes: "Reserves/slot0 may be read for analytics or liquidity math, not pricing; no dataflow to confirm — 'review required'.",
        },
        "CHAINLINK_LATESTANSWER_DEPRECATED" => RuleSpec {
            title: "Deprecated Chainlink latestAnswer()/latestRound()",
            category: "SC02:Price Oracle Manipulation", swc: None,
            severity: "Medium", confidence: "High", impact: 7, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "Funds priced off a Chainlink feed",
            blast_radius: "protocol",
            exploit_scenario: "latestAnswer() exposes no timestamp; if the feed goes stale the protocol keeps using an off-market price for borrows/liquidations.",
            recommendation: "Use latestRoundData() and validate answer>0, updatedAt freshness, and answeredInRound>=roundId.",
            fp_notes: "Very low FP; rare benign hits in mock/test aggregators (suppress by path).",
        },
        "CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK" => RuleSpec {
            title: "Chainlink latestRoundData() without staleness check",
            category: "SC02:Price Oracle Manipulation", swc: None,
            severity: "Medium", confidence: "Low", impact: 7, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "Funds priced off a Chainlink feed",
            blast_radius: "protocol",
            exploit_scenario: "The tuple is consumed but only `answer` is read; a stale feed values positions at an outdated price.",
            recommendation: "After latestRoundData() require updatedAt freshness, answer>0, and answeredInRound>=roundId before using the price.",
            fp_notes: "Scoped to the calling function and to the tuple names the call binds; no interprocedural dataflow, so freshness validated inside a helper or a modifier still reads as unchecked. Low confidence.",
        },
        "FLASHLOAN_CALLBACK_MISSING_CALLER_OR_INITIATOR_AUTH" => RuleSpec {
            title: "Flash-loan callback without caller/initiator validation",
            category: "SC07:Flash Loan Attacks", swc: None,
            severity: "High", confidence: "Low", impact: 8, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "Borrower approvals / state mutated in the callback",
            blast_radius: "single-contract",
            exploit_scenario: "An attacker calls the victim's onFlashLoan/executeOperation directly; with no msg.sender/initiator check it spends the contract's approvals.",
            recommendation: "Verify msg.sender is the expected pool AND initiator==address(this) in every flash-loan callback.",
            fp_notes: "Auth may be a modifier (onlyPool) or internal helper not recognized; multi-line signatures hurt the window — Low confidence.",
        },
        "OWNER_BLACKLIST_CONTROL" => RuleSpec {
            title: "Owner can blacklist/freeze addresses",
            category: "SC01:Access Control", swc: None,
            severity: "Low", confidence: "Medium", impact: 5, likelihood: 6,
            exploitability: "Easy", asset_at_risk: "Holder transferability / funds (censorship)",
            blast_radius: "user-funds",
            exploit_scenario: "The owner blacklists a holder, stranding their balance; a malicious owner can freeze arbitrary victims or the whole market.",
            recommendation: "Disclose the freeze capability; gate it behind a timelock/multisig and emit events; provide an off-ramp.",
            fp_notes: "Regulated stablecoins legitimately need freeze; `frozen`/`banned` also appear in staking/locking — disclosure item, not a bug.",
        },
        "OWNER_MUTABLE_FEE" => RuleSpec {
            title: "Owner-settable transfer fee",
            category: "SC03:Logic Errors", swc: None,
            severity: "Low", confidence: "Low", impact: 5, likelihood: 6,
            exploitability: "Easy", asset_at_risk: "Holder funds on transfer/sell",
            blast_radius: "user-funds",
            exploit_scenario: "The owner raises the transfer/sell tax toward 100% during user sells, so exiting holders forfeit most tokens (honeypot rug).",
            recommendation: "Cap the fee on-chain (require(newFee <= MAX_FEE)), disclose the cap, and put changes behind a timelock with events.",
            fp_notes: "Fee-on-transfer is a legit pattern and many setters are capped (cap needs dataflow to see) — risk-disclosure signal.",
        },
        // ---- Phase 11: Governance / MEV / Bridge ----
        "GOV_VOTE_CURRENT_BLOCK_VOTING_POWER" => RuleSpec {
            title: "Vote power read at current block (flash-loan governance)",
            category: "SC07:Flash Loan Attacks", swc: None,
            severity: "High", confidence: "Low", impact: 9, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "Governance control / treasury",
            blast_radius: "governance",
            exploit_scenario: "An attacker flash-borrows the governance token, calls castVote() while holding it, and the contract counts their current-block balance/getVotes() as voting power — passing a malicious proposal and repaying in the same tx.",
            recommendation: "Tally votes from a snapshot at proposal creation (getPastVotes/getPriorVotes/balanceOfAt), never getVotes(account)/balanceOf(account) at the current block.",
            fp_notes: "Can't distinguish the safe getVotes(account,timepoint) overload or a checkpoint enforced outside the window; balanceOf( is broad. Low confidence triage signal.",
        },
        "GOV_EXECUTE_NO_TIMELOCK_DELAY" => RuleSpec {
            title: "Governance execute() without a timelock/delay gate",
            category: "SC01:Access Control", swc: None,
            severity: "High", confidence: "Low", impact: 8, likelihood: 4,
            exploitability: "Moderate", asset_at_risk: "Protocol funds, upgrade keys, governance params",
            blast_radius: "governance",
            exploit_scenario: "A passed proposal's actions (upgrade/treasury-drain) run immediately in execute() with no delay; holders get no window to exit or veto.",
            recommendation: "Route approved actions through a TimelockController: queue() with a minimum delay and require block.timestamp >= eta before execute().",
            fp_notes: "The timelock is often a separate contract this Governor merely calls (gate lives in the callee, outside the window) -> FP. Low confidence.",
        },
        "GOV_ZERO_PROPOSAL_THRESHOLD" => RuleSpec {
            title: "proposalThreshold() returns zero",
            category: "SC03:Logic Errors", swc: None,
            severity: "Low", confidence: "Medium", impact: 4, likelihood: 5,
            exploitability: "Easy", asset_at_risk: "Governance process integrity (spam/takeover)",
            blast_radius: "governance",
            exploit_scenario: "With proposalThreshold == 0, any zero-balance address can spam unlimited proposals; with low quorum this lowers the bar for a hostile takeover.",
            recommendation: "Set a non-trivial proposalThreshold so a proposer must hold real stake; if zero is intentional, rely on robust quorum + timelock.",
            fp_notes: "Permissionless-proposal DAOs may choose zero deliberately — a disclosure/logic signal, not a definite bug.",
        },
        "MEV_SWAP_DEADLINE_BLOCK_TIMESTAMP" => RuleSpec {
            title: "Swap deadline set to block.timestamp (no protection)",
            category: "SC03:Logic Errors", swc: Some("SWC-114"),
            severity: "Medium", confidence: "Medium", impact: 6, likelihood: 6,
            exploitability: "Moderate", asset_at_risk: "Swap output value (MEV/slippage)",
            blast_radius: "user-funds",
            exploit_scenario: "A deadline equal to block.timestamp never expires; a validator/searcher holds the tx and executes it only when the price has moved in their favor (sandwich).",
            recommendation: "Pass a caller-supplied deadline, never block.timestamp itself.",
            fp_notes: "The swap-marker + block.timestamp arm can match a benign `block.timestamp + 15 minutes`; the exact `deadline: block.timestamp` token is high-signal.",
        },
        "MEV_SWAP_ZERO_AMOUNT_OUT_MIN" => RuleSpec {
            title: "Swap with amountOutMin = 0 (no slippage bound)",
            category: "SC03:Logic Errors", swc: Some("SWC-114"),
            severity: "High", confidence: "Medium", impact: 7, likelihood: 6,
            exploitability: "Easy", asset_at_risk: "Swap output value (full slippage loss)",
            blast_radius: "user-funds",
            exploit_scenario: "amountOutMin=0 accepts any output; a searcher sandwiches the swap and captures nearly all its value.",
            recommendation: "Compute amountOutMin from an off-chain quote with a slippage tolerance; never hardcode 0.",
            fp_notes: "Exact `amountOutMin: 0` is unambiguous; the positional `, 0,` arm can match an unrelated zero field — Medium confidence.",
        },
        "MEV_FRONTRUNNABLE_ERC20_APPROVE_RACE" => RuleSpec {
            title: "ERC20 approve() front-running race",
            category: "SC03:Logic Errors", swc: Some("SWC-114"),
            severity: "Low", confidence: "Low", impact: 4, likelihood: 4,
            exploitability: "Moderate", asset_at_risk: "Token allowance (approval double-spend)",
            blast_radius: "single-contract",
            exploit_scenario: "Changing an allowance from N to M lets the spender front-run to spend N, then spend M after — N+M total.",
            recommendation: "Encourage increaseAllowance/decreaseAllowance or forceApprove (set-to-0 first); prefer EIP-2612 permit.",
            fp_notes: "The canonical low-impact ERC20 race present in nearly every standard token — informational.",
        },
        "CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION" => RuleSpec {
            title: "Cross-chain message handler without replay protection",
            category: "SC03:Logic Errors", swc: None,
            severity: "High", confidence: "Low", impact: 9, likelihood: 5,
            exploitability: "Moderate", asset_at_risk: "Bridged funds / minted supply",
            blast_radius: "cross-chain",
            exploit_scenario: "A delivered cross-chain message is resubmitted; with no nonce/processed mapping the handler runs twice, double-minting bridged tokens or re-releasing escrow.",
            recommendation: "Persist a per-message unique id (keccak256 of srcChainId+nonce+payload) and require it unset before processing, then set it.",
            fp_notes: "Replay protection in a base contract/modifier/helper outside the window is missed (FP); idempotent handlers may not need a nonce. Low confidence.",
        },
        "CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH" => RuleSpec {
            title: "Cross-chain handler without source/sender authorization",
            category: "SC01:Access Control", swc: None,
            severity: "High", confidence: "Low", impact: 9, likelihood: 6,
            exploitability: "Easy", asset_at_risk: "Bridged funds / privileged cross-chain actions",
            blast_radius: "cross-chain",
            exploit_scenario: "An external executeMessage/_credit with no caller or source check is called directly with a forged payload, minting bridged tokens or invoking a privileged action.",
            recommendation: "Restrict the handler to the canonical endpoint/router and validate source chain id + remote sender against a trustedRemote allowlist.",
            fp_notes: "Auth may be a custom modifier or a deep require, or gated upstream by the endpoint — Low confidence.",
        },
        "LZRECEIVE_MISSING_TRUSTED_REMOTE_CHECK" => RuleSpec {
            title: "lzReceive without trusted-remote / source validation",
            category: "SC01:Access Control", swc: None,
            severity: "High", confidence: "Medium", impact: 9, likelihood: 6,
            exploitability: "Easy", asset_at_risk: "OFT/ONFT bridged supply & message-driven state",
            blast_radius: "cross-chain",
            exploit_scenario: "A hand-rolled lzReceive omits the trustedRemote check; an attacker delivers a crafted message from a malicious source app and mints OFT tokens on the destination chain.",
            recommendation: "Require msg.sender == lzEndpoint and verify _srcChainId+_srcAddress against the stored trustedRemote (inherit the audited lzApp/OApp base).",
            fp_notes: "Misses checks in an inherited NonblockingLzApp/OApp base; LayerZero-specific names keep FP lower — Medium confidence.",
        },
        // Unknown rule id: a benign placeholder (should never happen).
        _ => RuleSpec {
            title: "Unknown", category: "Code Quality", swc: None,
            severity: "Info", confidence: "Low", impact: 0, likelihood: 0,
            exploitability: "Hard", asset_at_risk: "-", blast_radius: "single-contract",
            exploit_scenario: "-", recommendation: "-", fp_notes: "",
        },
    }
}

/// A raw detector hit before taxonomy assembly.
struct RawHit {
    rule_id: &'static str,
    detection: &'static str,
    location: Option<String>,
    evidence: String,
}

/// Run the full standardized audit over a contract's details + source files.
/// Audit a contract with no suppressions (the common case).
pub fn audit(d: &ContractDetails, sources: &[SourceFile]) -> Audit {
    audit_with(d, sources, &Suppressions::default())
}

/// Audit a contract, dropping findings matched by `supp` *before* scoring (so a
/// suppressed false positive also lowers the overall risk score and summary).
pub fn audit_with(d: &ContractDetails, sources: &[SourceFile], supp: &Suppressions) -> Audit {
    let mut raws: Vec<RawHit> = Vec::new();
    // Phase 22: try one binding-graph-backed pass over the whole contract (all
    // files as a compilation unit) so the AST detectors can resolve identifiers to
    // their declared types. `None` → fall back to the per-file, parse-only `detect`
    // path (which itself degrades to the heuristics). Three-level graceful
    // degradation: detect_unit → detect → heuristic.
    let unit_files: Vec<(&str, &str)> =
        sources.iter().map(|sf| (sf.path.as_str(), sf.content.as_str())).collect();
    let mut unit_hits = crate::ast::detect_unit(&unit_files);

    // Process each path once. A manifest can carry two keys that sanitize to the
    // same path (storage::sanitize_path strips `.`/`..`); without dedup the second
    // occurrence would find the binding map already drained (consuming `remove`)
    // and wrongly keep the AST_RULES heuristic hits the AST layer owns.
    let mut seen_paths: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for sf in sources {
        if !seen_paths.insert(sf.path.as_str()) {
            continue;
        }
        // Heuristic, line-based pass for this file.
        let mut file_raws: Vec<RawHit> = Vec::new();
        scan_source_file(&sf.path, &sf.content, &mut file_raws);
        // AST hits for this file: prefer the binding-aware unit result; otherwise
        // the per-file parse-only AST. When the AST layer owns the `AST_RULES` for
        // this file (Some, even if empty), drop the heuristic occurrences of those
        // rules and replace them with the context-aware AST hits.
        let file_ast_hits = match unit_hits.as_mut() {
            Some(map) => map.remove(sf.path.as_str()),
            None => crate::ast::detect(&sf.content),
        };
        if let Some(ast_hits) = file_ast_hits {
            // Build the replacement hits first so we can reuse the heuristic's
            // evidence at the same location — keeping the SARIF fingerprint
            // (rule|contract|file|evidence) stable across the heuristic→AST switch
            // so pre-existing baselines / fingerprint suppressions keep matching.
            let ast_raws: Vec<RawHit> = ast_hits
                .into_iter()
                .map(|ah| {
                    let location = format!("{}:{}", sf.path, ah.line);
                    let evidence = file_raws
                        .iter()
                        .find(|h| h.rule_id == ah.rule_id && h.location.as_deref() == Some(location.as_str()))
                        .map(|h| h.evidence.clone())
                        .unwrap_or(ah.evidence);
                    RawHit { rule_id: ah.rule_id, detection: "ast", location: Some(location), evidence }
                })
                .collect();
            file_raws.retain(|h| !crate::ast::AST_RULES.contains(&h.rule_id));
            file_raws.extend(ast_raws);
        }
        raws.append(&mut file_raws);
    }
    if let Some(ev) = outdated_compiler(d) {
        raws.push(RawHit { rule_id: "OUTDATED_COMPILER", detection: "source", location: None, evidence: ev });
    }
    bytecode_hits(d, &mut raws);

    // Group raw hits by rule id (preserving first-seen order), merging locations.
    let mut order: Vec<&'static str> = Vec::new();
    let mut by_rule: BTreeMap<&'static str, (Vec<String>, String, &'static str)> = BTreeMap::new();
    for h in raws {
        let e = by_rule.entry(h.rule_id).or_insert_with(|| {
            order.push(h.rule_id);
            (Vec::new(), h.evidence.clone(), h.detection)
        });
        if let Some(l) = h.location {
            if !e.0.contains(&l) {
                e.0.push(l);
            }
        }
    }

    let mut findings: Vec<SecurityFinding> = order
        .iter()
        .map(|rid| {
            let (locations, evidence, detection) = by_rule.remove(rid).unwrap();
            build_finding(rid, d, locations, evidence, detection)
        })
        .collect();

    // Drop suppressed findings before scoring/summarizing so a silenced false
    // positive lowers the risk score too (not just the displayed list).
    if !supp.is_empty() {
        findings.retain(|f| !supp.is_suppressed(f));
    }

    let risk_score = overall_risk(&findings);
    Audit {
        grade: grade(risk_score).to_string(),
        risk_level: risk_level(risk_score).to_string(),
        risk_score,
        summary: summarize(&findings),
        findings,
    }
}

/// L2 external taxonomy refs beyond SWC: OWASP **SCWE** id and **EEA EthTrust**
/// requirement, per rule. Researched against the live registries; following the
/// project's SWC policy, an id is assigned ONLY when it's a high-confidence exact
/// match — otherwise `None` (never guessed). Kept as its own table so the ~35
/// `spec()` arms stay untouched.
fn scwe_ethtrust(rule_id: &str) -> (Option<&'static str>, Option<&'static str>) {
    match rule_id {
        "TX_ORIGIN_AUTH" => (Some("SCWE-018"), Some("req-1-no-tx.origin [S]")),
        "SELFDESTRUCT_PRESENT" | "BYTECODE_SELFDESTRUCT" => (Some("SCWE-050"), Some("req-1-self-destruct [S]")),
        "DELEGATECALL_USAGE" | "BYTECODE_DELEGATECALL" | "DELEGATECALL_ARBITRARY_TARGET" => (Some("SCWE-035"), Some("req-1-delegatecall [S]")),
        "UNCHECKED_LOW_LEVEL_CALL" => (Some("SCWE-048"), Some("req-1-check-return [S]")),
        "WEAK_BLOCK_RANDOMNESS" => (Some("SCWE-024"), Some("req-2-random-enough [M]")),
        "ECRECOVER_NO_ZERO_CHECK" => (None, Some("req-2-signature-verification [M]")),
        "FLOATING_PRAGMA" => (Some("SCWE-060"), None),
        "OUTDATED_COMPILER" => (Some("SCWE-061"), Some("req-1-compiler-060 [S]")),
        "INLINE_ASSEMBLY" => (None, Some("req-1-no-assembly [S]")),
        "BYTECODE_CREATE2" => (None, Some("req-1-no-create2 [S]")),
        "ACCESS_MISSING_GUARD_PRIVILEGED_FN" => (Some("SCWE-016"), Some("req-3-access-control [Q]")),
        "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL" => (Some("SCWE-049"), Some("req-3-access-control [Q]")),
        "UUPS_AUTHORIZE_UPGRADE_UNGUARDED" | "PROXY_PUBLIC_UPGRADE_TO_UNGUARDED" => (Some("SCWE-005"), None),
        "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE" => (Some("SCWE-046"), Some("req-1-use-c-e-i [S]")),
        "UNCHECKED_ARITHMETIC_BLOCK" => (Some("SCWE-047"), Some("req-2-overflow-underflow [M]")),
        "UNSAFE_DOWNCAST_TRUNCATION" => (Some("SCWE-041"), None),
        "ORACLE_SPOT_PRICE_FROM_RESERVES" => (Some("SCWE-112"), Some("req-3-check-oracles [Q]")),
        "CHAINLINK_LATESTANSWER_DEPRECATED" | "CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK" => {
            (Some("SCWE-086"), Some("req-3-check-oracles [Q]"))
        }
        "GOV_VOTE_CURRENT_BLOCK_VOTING_POWER" => (Some("SCWE-101"), None),
        "GOV_EXECUTE_NO_TIMELOCK_DELAY" => (Some("SCWE-020"), Some("req-3-timelock-for-privileged-actions [Q]")),
        "MEV_SWAP_DEADLINE_BLOCK_TIMESTAMP" => (Some("SCWE-141"), None),
        "MEV_SWAP_ZERO_AMOUNT_OUT_MIN" => (Some("SCWE-090"), None),
        "MEV_FRONTRUNNABLE_ERC20_APPROVE_RACE" => (Some("SCWE-103"), None),
        "CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION" => (Some("SCWE-133"), None),
        "CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH" => (Some("SCWE-108"), None),
        // Deliberately unmapped (no high-confidence exact match): PROXY_UNPROTECTED_INITIALIZER,
        // DEPRECATED_CONSTRUCT, BYTECODE_CALLCODE, SOURCE_UNVERIFIED, HARDCODED_GAS_TRANSFER_SEND,
        // RAW_CALL_VALUE_ETH_SEND, FLASHLOAN_CALLBACK_*, OWNER_BLACKLIST_CONTROL, OWNER_MUTABLE_FEE,
        // GOV_ZERO_PROPOSAL_THRESHOLD, LZRECEIVE_MISSING_TRUSTED_REMOTE_CHECK.
        _ => (None, None),
    }
}

/// Assemble a [`SecurityFinding`] from its rule spec + runtime context.
fn build_finding(
    rule_id: &str,
    d: &ContractDetails,
    locations: Vec<String>,
    evidence: String,
    detection: &str,
) -> SecurityFinding {
    let s = spec(rule_id);
    let risk = finding_risk(&s);
    let (scwe, ethtrust) = scwe_ethtrust(rule_id);
    let mut references = Vec::new();
    if let Some(swc) = s.swc {
        references.push(format!("https://swcregistry.io/docs/{swc}"));
    }
    if let Some(scwe) = scwe {
        references.push(format!("https://scs.owasp.org/SCWE/{scwe}"));
    }
    if let Some(req) = ethtrust {
        // "req-N-slug [LEVEL]" -> strip the trailing " [..]" for the URL anchor.
        let anchor = req.split_whitespace().next().unwrap_or(req);
        references.push(format!("https://entethalliance.org/specs/ethtrust-sl/#{anchor}"));
    }
    references.push(OWASP_URL.to_string());
    SecurityFinding {
        rule_id: rule_id.to_string(),
        title: s.title.to_string(),
        category: s.category.to_string(),
        swc: s.swc.map(String::from),
        scwe: scwe.map(String::from),
        ethtrust: ethtrust.map(String::from),
        severity: s.severity.to_string(),
        confidence: s.confidence.to_string(),
        impact_score: s.impact,
        likelihood_score: s.likelihood,
        exploitability: s.exploitability.to_string(),
        asset_at_risk: s.asset_at_risk.to_string(),
        blast_radius: s.blast_radius.to_string(),
        risk,
        priority: priority(s.severity).to_string(),
        detection: detection.to_string(),
        affected_contract: d.address.clone(),
        locations,
        evidence,
        exploit_scenario: s.exploit_scenario.to_string(),
        recommendation: s.recommendation.to_string(),
        references,
        false_positive_notes: s.fp_notes.to_string(),
    }
}

// ---------------- detection ----------------

/// Scan one source file: comment- and string-aware, line by line, collecting hits.
fn scan_source_file(path: &str, content: &str, out: &mut Vec<RawHit>) {
    let mut in_block = false;
    // Pre-strip every line (carrying block-comment state) so cross-line look-ahead
    // for the initializer detector sees code, not comments.
    let stripped: Vec<String> = content.lines().map(|l| code_part(l, &mut in_block)).collect();

    for (i, code) in stripped.iter().enumerate() {
        if code.trim().is_empty() {
            continue;
        }
        let loc = format!("{path}:{}", i + 1);
        let ev = || code.trim().chars().take(160).collect::<String>();
        for rid in line_hits(code) {
            out.push(RawHit { rule_id: rid, detection: "source", location: Some(loc.clone()), evidence: ev() });
        }
    }

    // Function-scoped (windowed) detectors over the brace-balanced functions.
    function_window_hits(&stripped.join("\n"), path, out);
}

/// Whether the `latestRoundData()` call at byte offset `call` in `body` has the
/// freshness it returns actually checked.
///
/// The old question was "is there a `require(` within twelve lines", which a
/// require belonging to the next statement answers with a yes. The question here
/// is the one the rule means: *does the freshness this call returns participate
/// in a comparison in this function*. So the tuple the call is destructured into
/// is what gets read, and only the names bound to its non-price slots count.
///
/// A call whose freshness slots are all discarded — `(, int p, , ,) =
/// feed.latestRoundData()` — binds no freshness name at all and is unchecked by
/// construction, which is exactly the shape the rule exists to catch.
///
/// Known limitation, unchanged from before and still recorded in `fp_notes`:
/// freshness handed to a helper (`_requireFresh(updatedAt)`) is not recognised
/// as a check, because nothing here follows it into the callee.
fn staleness_checked(body: &str, call: usize) -> bool {
    let names = freshness_names(body, call);
    if names.is_empty() {
        return false;
    }
    // Only what follows the call's own statement can check its result.
    let Some(semi) = body[call..].find(';') else { return false };
    body[call + semi + 1..].split(';').any(|stmt| {
        has_comparison(stmt) && names.iter().any(|n| contains_word(stmt, n))
    })
}

/// The tuple names bound to the non-price slots of a `latestRoundData()` result:
/// `roundId`, `startedAt`, `updatedAt`, `answeredInRound`. Slot 1 is `answer` —
/// the price itself — and `require(answer > 0)` is a sanity check on the value,
/// never evidence that the value is current.
fn freshness_names(body: &str, call: usize) -> Vec<String> {
    // Bound the search to the statement the call is in, so a call used as a bare
    // expression cannot pick up the `=` of some earlier assignment.
    let stmt_start = body[..call].rfind([';', '{', '}']).map_or(0, |i| i + 1);
    let head = body[stmt_start..call].trim_end();
    let Some(eq) = head.rfind('=') else { return Vec::new() };
    if head[..eq].trim_end().ends_with(['=', '!', '<', '>']) {
        return Vec::new(); // a comparison, not an assignment
    }
    let lhs = head[..eq].trim_end();
    if !lhs.ends_with(')') {
        return Vec::new(); // assigned to a single variable, not destructured
    }
    // Backward-balance to the `(` that opens the tuple.
    let b = lhs.as_bytes();
    let mut depth = 0i32;
    let mut open = None;
    for i in (0..b.len()).rev() {
        match b[i] {
            b')' => depth += 1,
            b'(' => {
                depth -= 1;
                if depth == 0 {
                    open = Some(i);
                    break;
                }
            }
            _ => {}
        }
    }
    let Some(open) = open else { return Vec::new() };
    lhs[open + 1..lhs.len() - 1]
        .split(',')
        .enumerate()
        .filter(|(slot, _)| *slot != 1)
        .filter_map(|(_, s)| slot_name(s))
        .collect()
}

/// The variable a tuple slot declares: `uint256 updatedAt` -> `updatedAt`, an
/// empty slot -> `None`.
fn slot_name(slot: &str) -> Option<String> {
    slot.split(|c: char| !c.is_alphanumeric() && c != '_')
        .rfind(|t| !t.is_empty())
        .map(str::to_string)
}

/// Whether `stmt` compares anything at all.
fn has_comparison(stmt: &str) -> bool {
    stmt.contains('<') || stmt.contains('>') || stmt.contains("==") || stmt.contains("!=")
}

/// Whether `word` occurs in `hay` as a whole identifier — `updatedAt` must not
/// match inside `lastUpdatedAt`.
fn contains_word(hay: &str, word: &str) -> bool {
    let is_id = |c: char| c.is_alphanumeric() || c == '_' || c == '$';
    hay.match_indices(word).any(|(i, _)| {
        !hay[..i].chars().next_back().is_some_and(is_id)
            && !hay[i + word.len()..].chars().next().is_some_and(is_id)
    })
}

/// One Solidity function recovered by brace-balancing the stripped source.
struct FnView {
    name_lc: String,
    header_off: usize,
    /// Byte offset of the first character of `body` within the joined source, so
    /// a hit inside the body can be reported at its own line rather than at the
    /// function header.
    body_off: usize,
    signature: String,
    body: String,
}

/// Run the function-scoped detectors (access guards, proxy upgrade, reentrancy,
/// flash-loan callbacks) over every function in `joined` (comment/string-stripped).
fn function_window_hits(joined: &str, path: &str, out: &mut Vec<RawHit>) {
    for f in scan_functions(joined) {
        let loc = format!("{path}:{}", joined[..f.header_off].matches('\n').count() + 1);
        let ev: String = f.signature.split_whitespace().collect::<Vec<_>>().join(" ").chars().take(160).collect();
        let mut emit = |rule_id: &'static str| {
            out.push(RawHit { rule_id, detection: "source", location: Some(loc.clone()), evidence: ev.clone() });
        };
        let public = f.signature.contains("public") || f.signature.contains("external");
        let guarded = has_access_guard(&f.signature, &f.body);

        if public && !guarded && is_privileged_name(&f.name_lc) {
            emit("ACCESS_MISSING_GUARD_PRIVILEGED_FN");
        }
        if public && !guarded && has_eth_sink(&f.body) && !f.body.contains("msg.sender") {
            emit("ACCESS_UNPROTECTED_ETHER_WITHDRAWAL");
        }
        if f.name_lc == "_authorizeupgrade" && !guarded {
            emit("UUPS_AUTHORIZE_UPGRADE_UNGUARDED");
        }
        if (f.name_lc == "upgradeto" || f.name_lc == "upgradetoandcall")
            && public
            && !guarded
            && !f.body.contains("_authorizeUpgrade")
        {
            emit("PROXY_PUBLIC_UPGRADE_TO_UNGUARDED");
        }
        if reentrancy_risk(&f.signature, &f.body) {
            emit("REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE");
        }
        if is_flashloan_callback(&f.name_lc) && !flashloan_authed(&f.signature, &f.body) {
            emit("FLASHLOAN_CALLBACK_MISSING_CALLER_OR_INITIATOR_AUTH");
        }

        // ---- T-06: promoted here from a fixed look-ahead of N lines ----
        // `scan_functions` only yields functions that open a body, so the
        // bodiless interface declarations that were 16 of this rule's 17 corpus
        // findings before Phase 29 are excluded by the scope itself rather than
        // by a separate check.
        if f.name_lc == "initialize"
            && initializer_is_reachable(&f.signature)
            && !initializer_guarded(&f.signature, &f.body)
        {
            emit("PROXY_UNPROTECTED_INITIALIZER");
        }

        // ---- Phase 11: Governance / MEV / Bridge (function-window) ----
        let n = f.name_lc.as_str();
        // Governance: voting power read at the current block in a vote-cast path.
        if matches!(n, "castvote" | "castvotewithreason" | "castvotebysig" | "_castvote" | "_countvote" | "vote" | "_vote")
            && contains_any(&f.body, &["getVotes(", ".balanceOf(", ".getCurrentVotes("])
            && !contains_any(&f.body, &["getPriorVotes(", "getPastVotes(", "getPastTotalSupply(", "balanceOfAt(", "snapshotId", "proposalSnapshot", ".snapshot("])
        {
            emit("GOV_VOTE_CURRENT_BLOCK_VOTING_POWER");
        }
        // Governance: execute() performs actions with no timelock/delay gate.
        if matches!(n, "execute" | "_execute" | "executeproposal" | "executetransaction")
            && contains_any(&f.body, &[".call{value:", ".call(", ".functionCall(", ".delegatecall(", ".functionCallWithValue("])
            // Note: bare "eta" is intentionally excluded — it substring-matches common
            // identifiers like `metadata`/`beta`; the real `require(block.timestamp >= eta)`
            // pattern is already covered by the "block.timestamp >=" tokens.
            && !contains_any(&f.body, &["timelock", "Timelock", "_timelock", " ETA", "delay", "Delay", "executeAfter", "readyAt", "block.timestamp >=", "block.timestamp>=", "queue(", "_queue", ">= eta", ">=eta"])
        {
            emit("GOV_EXECUTE_NO_TIMELOCK_DELAY");
        }
        // Governance: proposalThreshold() returns literal zero.
        if n == "proposalthreshold"
            && contains_any(&f.body, &["return 0;", "return 0 ;", "return uint256(0)"])
        {
            emit("GOV_ZERO_PROPOSAL_THRESHOLD");
        }
        // MEV: public approve() overwrites the allowance with no zero-check guard.
        if n == "approve"
            && public
            && contains_any(&f.body, &["allowed[", "_allowances[", "allowance"])
            && !contains_any(&f.body, &["increaseAllowance", "decreaseAllowance", "== 0", "require(amount == 0", "allowance == 0"])
        {
            emit("MEV_FRONTRUNNABLE_ERC20_APPROVE_RACE");
        }
        // Cross-chain: message handler with no replay protection.
        if XCHAIN_REPLAY_RECV.contains(&n)
            && !contains_any(&f.body, &["nonce", "usedHashes", "processed", "executedMessages", "consumedNonce", "isExecuted", "commitments[", "seenRoots"])
        {
            emit("CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION");
        }
        // Cross-chain: message handler with no source/sender authorization (LZ names handled below).
        if XCHAIN_SRCAUTH_RECV.contains(&n)
            && public
            && !guarded
            && !contains_any(&f.body, &["trustedRemote", "trustedSender", "trustedRemoteLookup", "srcChainId", "sourceChainId", "remoteChainId", "endpoint", "getRouter()", "onlyRouter", "verifyEndpoint"])
        {
            emit("CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH");
        }
        // Cross-chain: LayerZero lzReceive without trusted-remote / endpoint check.
        if matches!(n, "lzreceive" | "_lzreceive" | "_nonblockinglzreceive" | "_blockinglzreceive")
            && !contains_any(&f.body, &["require(msg.sender == address(endpoint", "require(_msgSender() == address(endpoint", "onlyEndpoint", "trustedRemote", "trustedRemoteLookup", "keccak256(_srcAddress)"])
        {
            emit("LZRECEIVE_MISSING_TRUSTED_REMOTE_CHECK");
        }

        // Past the last `emit`, whose borrow of `out` ends here: unlike every
        // rule above, this one reports per call site rather than once per
        // function, and needs its own location.
        for (call, _) in f.body.match_indices(".latestRoundData(") {
            if staleness_checked(&f.body, call) {
                continue;
            }
            // Report at the call, not at the function header: one function can
            // hold several feeds and only some of them be checked.
            let abs = f.body_off + call;
            let line_start = joined[..abs].rfind('\n').map_or(0, |i| i + 1);
            let line_end = joined[abs..].find('\n').map_or(joined.len(), |i| abs + i);
            out.push(RawHit {
                rule_id: "CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK",
                detection: "source",
                location: Some(format!("{path}:{}", joined[..abs].matches('\n').count() + 1)),
                evidence: joined[line_start..line_end].trim().chars().take(160).collect(),
            });
        }
    }
}

/// Cross-chain receiver names for the replay-protection rule (includes LayerZero).
const XCHAIN_REPLAY_RECV: &[&str] = &[
    "relaymessage", "receivemessage", "_receivemessage", "executemessage", "_executemessage",
    "processmessage", "_processmessage", "lzreceive", "_lzreceive", "_nonblockinglzreceive",
    "_blockinglzreceive", "_credit", "ccipreceive", "_ccipreceive", "onmessagereceived", "handlemessage",
];

/// Generic cross-chain receiver names for the source-auth rule (LayerZero names are
/// excluded — handled by the dedicated LZRECEIVE rule to avoid double-flagging).
const XCHAIN_SRCAUTH_RECV: &[&str] = &[
    "relaymessage", "receivemessage", "_receivemessage", "executemessage", "_executemessage",
    "processmessage", "_processmessage", "_credit", "ccipreceive", "_ccipreceive",
    "onmessagereceived", "handlemessage",
];

/// True if `s` contains any of `tokens`.
fn contains_any(s: &str, tokens: &[&str]) -> bool {
    tokens.iter().any(|t| s.contains(t))
}

/// Recover functions by locating `function NAME(...)` and brace-balancing the body.
fn scan_functions(joined: &str) -> Vec<FnView> {
    let b = joined.as_bytes();
    let is_ident = |c: u8| matches!(c, b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'$');
    let mut out = Vec::new();
    let mut search = 0;
    while let Some(rel) = joined[search..].find("function") {
        let kw = search + rel;
        search = kw + 8;
        if kw > 0 && is_ident(b[kw - 1]) {
            continue; // part of an identifier, not the keyword
        }
        // parse: whitespace, name, optional whitespace, '('
        let mut i = kw + 8;
        while i < b.len() && b[i].is_ascii_whitespace() {
            i += 1;
        }
        let name_start = i;
        while i < b.len() && is_ident(b[i]) {
            i += 1;
        }
        let name = &joined[name_start..i];
        let mut j = i;
        while j < b.len() && b[j].is_ascii_whitespace() {
            j += 1;
        }
        if name.is_empty() || b.get(j) != Some(&b'(') {
            continue;
        }
        // find the body-opening '{' (or ';' for an interface/abstract decl -> skip)
        let mut k = j;
        let mut open = None;
        while k < b.len() && k < j + 4000 {
            match b[k] {
                b'{' => {
                    open = Some(k);
                    break;
                }
                b';' => break,
                _ => {}
            }
            k += 1;
        }
        let Some(open) = open else { continue };
        let signature = joined[kw..open].to_string();
        // Brace-balance the body, skipping braces inside string/char literals,
        // capped at 8000 bytes. On hitting the cap unbalanced, TRUNCATE to the cap
        // (not empty) so body-scoped detectors still see the largest functions.
        let mut depth = 0i32;
        let mut p = open;
        let mut close = None;
        while p < b.len() && p < open + 8000 {
            match b[p] {
                b'"' | b'\'' => {
                    // Skip the literal so its `{`/`}` don't affect depth (honor escapes).
                    let q = b[p];
                    p += 1;
                    while p < b.len() {
                        if b[p] == b'\\' {
                            p += 2;
                            continue;
                        }
                        if b[p] == q {
                            p += 1;
                            break;
                        }
                        p += 1;
                    }
                    continue;
                }
                b'{' => depth += 1,
                b'}' => {
                    depth -= 1;
                    if depth == 0 {
                        close = Some(p);
                        break;
                    }
                }
                _ => {}
            }
            p += 1;
        }
        // `close` is an ASCII `}` (boundary); the cap may split a multibyte char
        // (string literals keep their bytes) so back up to a char boundary.
        let end = floor_char_boundary(joined, close.unwrap_or((open + 8000).min(b.len())));
        let body = joined[open + 1..end].to_string();
        out.push(FnView {
            name_lc: name.to_ascii_lowercase(),
            header_off: kw,
            body_off: open + 1,
            signature,
            body,
        });
        search = open + 1;
    }
    out
}

/// Largest char boundary `<= idx` (stable replacement for `str::floor_char_boundary`).
fn floor_char_boundary(s: &str, mut idx: usize) -> usize {
    if idx >= s.len() {
        return s.len();
    }
    while idx > 0 && !s.is_char_boundary(idx) {
        idx -= 1;
    }
    idx
}

/// Known access-control guards in a function signature or the start of its body.
fn has_access_guard(sig: &str, body: &str) -> bool {
    // Any `only*` modifier (onlyOwner/onlyRole/onlyMinter/onlyPauser/onlyBlacklister/
    // project-specific onlyFoo) counts as a guard. Broad on purpose: prefer a false
    // negative over flagging audited code that uses an unrecognized custom modifier.
    if sig.contains("only") || sig.contains("authorized") || sig.contains("restricted")
        || sig.contains("requiresAuth")
    {
        return true;
    }
    let head: String = body.chars().take(280).collect();
    head.contains("require(msg.sender")
        || head.contains("if (msg.sender")
        || head.contains("if(msg.sender")
        || head.contains("_checkOwner")
        || head.contains("_checkRole")
        || head.contains("_onlyOwner")
        || head.contains("msg.sender ==")
        || head.contains("msg.sender==")
}

pub(crate) fn is_privileged_name(name_lc: &str) -> bool {
    const NAMES: [&str; 26] = [
        "mint", "burn", "setowner", "transferownership", "setadmin", "setminter", "setpauser",
        "pause", "unpause", "rescue", "rescuetokens", "rescueeth", "sweep", "withdraw",
        "withdrawtoken", "settreasury", "setrole", "grantrole", "addminter", "blacklist",
        "setpaused", "setoperator", "setgovernance", "setpending", "setfee", "upgrade",
    ];
    NAMES.contains(&name_lc)
}

/// An ETH-sending sink in a function body. A raw value-call (`.call{value:}` /
/// `.call.value(`) is always an ETH send; `.transfer(`/`.send(` only count with an
/// ETH context (not an ERC-20 `token.transfer(...)`) — matching the sibling
/// HARDCODED_GAS_TRANSFER_SEND rule so the Critical withdrawal rule doesn't FP on tokens.
fn has_eth_sink(body: &str) -> bool {
    if body.contains(".call{value:") || body.contains(".call{ value:")
        || body.contains(".call {value:") || body.contains(".call.value(")
    {
        return true;
    }
    (body.contains(".transfer(") || body.contains(".send(")) && eth_transfer_context(body)
}

/// Heuristic reentrancy: an external call followed by a state write, and the
/// function has no reentrancy guard.
fn reentrancy_risk(sig: &str, body: &str) -> bool {
    if sig.contains("nonReentrant") || body.contains("ReentrancyGuard") || body.contains("_status") {
        return false;
    }
    const SINKS: [&str; 5] = [".call{value:", ".call(", ".delegatecall(", ".transfer(", ".send("];
    let first = SINKS.iter().filter_map(|s| body.find(s)).min();
    match first {
        Some(pos) => has_state_write(&body[pos..]),
        None => false,
    }
}

/// True if `s` contains an assignment (plain `=` or compound), `++`/`--`, or `delete`.
fn has_state_write(s: &str) -> bool {
    if s.contains("delete ") || s.contains("++") || s.contains("--") {
        return true;
    }
    let b = s.as_bytes();
    for i in 0..b.len() {
        if b[i] == b'=' {
            let next = b.get(i + 1).copied();
            let prev = if i > 0 { b[i - 1] } else { b' ' };
            if next != Some(b'=') && !matches!(prev, b'=' | b'!' | b'<' | b'>') {
                return true;
            }
        }
    }
    false
}

fn is_flashloan_callback(name_lc: &str) -> bool {
    matches!(
        name_lc,
        "onflashloan" | "executeoperation" | "uniswapv2call" | "receiveflashloan" | "onmorphoflashloan"
    )
}

fn flashloan_authed(sig: &str, body: &str) -> bool {
    has_access_guard(sig, body)
        || body.contains("msg.sender ==")
        || body.contains("msg.sender==")
        || body.contains("require(msg.sender")
        || body.contains("initiator")
}

/// Whether an `initialize` is guarded, given its own signature and its own body.
///
/// Two forms count. On the signature, an OpenZeppelin-style modifier
/// (`initializer` / `reinitializer(n)` / `onlyInitializing`), matched as a whole
/// token so a parameter named `initializerData` is not mistaken for one. In the
/// body, a caller check does the same job: UniswapV2Pair guards its `initialize`
/// with `require(msg.sender == factory)`, and reporting it was this rule's
/// second-largest false-positive class.
///
/// The modifier test is deliberately confined to the signature. Reading it off
/// body lines too — which is what walking forward from the header did — let
/// `_initializer = msg.sender;` inside an unguarded body suppress the finding.
fn initializer_guarded(sig: &str, body: &str) -> bool {
    if ["initializer", "reinitializer", "onlyInitializing"]
        .iter()
        .any(|m| sig_word(sig, m))
    {
        return true;
    }
    body.lines().any(is_caller_check)
}

/// Whether a line *checks* the caller, as opposed to merely mentioning it.
/// `require(msg.sender == factory)` is a guard; `owner = msg.sender` is the
/// archetypal unprotected initializer this rule exists to catch, and reading the
/// mere presence of `msg.sender` as a guard silently suppressed it.
fn is_caller_check(line: &str) -> bool {
    let caller = line.contains("msg.sender") || line.contains("_msgSender()");
    caller
        && (line.contains("require(")
            || line.contains("assert(")
            || line.contains("if(")
            || line.contains("if ("))
}

/// Whether an attacker could call this `initialize` at all, and whether calling it
/// could do anything. An `internal`/`private` function is unreachable from
/// outside, and a `view`/`pure` one initializes nothing — Uniswap V4's
/// `PositionInfoLibrary.initialize(...) internal pure` is both.
fn initializer_is_reachable(sig: &str) -> bool {
    (sig_word(sig, "external") || sig_word(sig, "public"))
        && !sig_word(sig, "view")
        && !sig_word(sig, "pure")
}

/// Whether `word` appears in a signature as a whole token. Substring matching
/// here reads a parameter name as a visibility keyword.
fn sig_word(sig: &str, word: &str) -> bool {
    sig.split(|c: char| !c.is_alphanumeric() && c != '_').any(|t| t == word)
}

/// Detectors that fire on a single comment-/string-stripped source line.
fn line_hits(code: &str) -> Vec<&'static str> {
    let mut h = Vec::new();
    if code.contains("tx.origin") {
        h.push("TX_ORIGIN_AUTH");
    }
    if code.contains("selfdestruct(") || code.contains("suicide(") {
        h.push("SELFDESTRUCT_PRESENT");
    }
    if code.contains(".delegatecall(") {
        h.push("DELEGATECALL_USAGE");
    }
    if code.contains(".call(") || code.contains(".call{") {
        h.push("UNCHECKED_LOW_LEVEL_CALL");
    }
    if code.contains("block.timestamp")
        || code.contains("block.number")
        || code.contains("block.difficulty")
        || code.contains("block.prevrandao")
        || code.contains("blockhash(")
    {
        h.push("WEAK_BLOCK_RANDOMNESS");
    }
    if code.contains("ecrecover(") {
        h.push("ECRECOVER_NO_ZERO_CHECK");
    }
    if code.contains("pragma solidity") && (code.contains('^') || code.contains(">=")) {
        h.push("FLOATING_PRAGMA");
    }
    if code.contains("sha3(") || code.contains("callcode(") || code.contains("throw;") || code.contains("throw ") {
        h.push("DEPRECATED_CONSTRUCT");
    }
    // Require the actual `assembly {` block form, not a substring of an identifier.
    if code.contains("assembly {") || code.contains("assembly{") {
        h.push("INLINE_ASSEMBLY");
    }
    // ---- Phase 9 single-line detectors ----
    if code.contains(".call{value:") || code.contains(".call{ value:") || code.contains(".call {value:") {
        h.push("RAW_CALL_VALUE_ETH_SEND");
    }
    if (code.contains(".transfer(") || code.contains(".send(")) && eth_transfer_context(code) {
        h.push("HARDCODED_GAS_TRANSFER_SEND");
    }
    if code.contains("unchecked {") || code.contains("unchecked{") {
        h.push("UNCHECKED_ARITHMETIC_BLOCK");
    }
    if has_narrowing_downcast(code) {
        h.push("UNSAFE_DOWNCAST_TRUNCATION");
    }
    if code.contains(".getReserves(") || code.contains(".slot0(") || code.contains("sqrtPriceX96") {
        h.push("ORACLE_SPOT_PRICE_FROM_RESERVES");
    }
    if code.contains(".latestAnswer(") || code.contains(".latestRound(") || code.contains(".latestTimestamp(") {
        h.push("CHAINLINK_LATESTANSWER_DEPRECATED");
    }
    if code.contains("blacklist") || code.contains("blocklist") || code.contains("Blacklist")
        || code.contains("denylist") || code.contains("isFrozen") || code.contains("freeze(")
        || code.contains("setFrozen") || code.contains("blacklisted[")
    {
        h.push("OWNER_BLACKLIST_CONTROL");
    }
    if code.contains("function setFee(") || code.contains("function setFees(")
        || code.contains("function setTaxFee(") || code.contains("function setBuyFee(")
        || code.contains("function setSellFee(") || code.contains("function updateFee(")
        || code.contains("function setTax(")
    {
        h.push("OWNER_MUTABLE_FEE");
    }
    // MEV: a swap deadline that is just block.timestamp gives no real protection.
    if code.contains("deadline: block.timestamp")
        || (code.contains("block.timestamp")
            && (code.contains("swapExact")
                || code.contains("swapTokens")
                || code.contains("addLiquidity")
                || code.contains("removeLiquidity")
                || code.contains(".exactInput")
                || code.contains(".exactOutput")))
    {
        h.push("MEV_SWAP_DEADLINE_BLOCK_TIMESTAMP");
    }
    // MEV: a swap with a zero minimum-output bound accepts arbitrarily bad execution.
    if code.contains("amountOutMin: 0")
        || code.contains("amountOutMinimum: 0")
        || ((code.contains("swapExactTokensForTokens")
            || code.contains("swapExactETHForTokens")
            || code.contains("swapExactTokensForETH")
            || code.contains(".exactInputSingle")
            || code.contains(".exactInput("))
            && (code.contains(", 0,") || code.contains(",0,")))
    {
        h.push("MEV_SWAP_ZERO_AMOUNT_OUT_MIN");
    }
    h
}

/// True if a `.transfer(`/`.send(` line looks like an ETH send (not an ERC-20 token
/// call). Heuristic: an ETH-value cue present AND no token-call markers.
fn eth_transfer_context(code: &str) -> bool {
    let token_marker = code.contains(".transferFrom(")
        || code.contains("safeTransfer")
        || code.contains("IERC20")
        || code.contains("token");
    if token_marker {
        return false;
    }
    code.contains("payable")
        || code.contains("msg.value")
        || code.contains("address(this).balance")
        || code.contains("amount")
        || code.contains("value")
        || code.contains("wad")
}

/// Detect a NARROWING explicit cast `uintN(`/`intN(` with N<256, at a token
/// boundary (so `myuint128(` doesn't match). Excludes `uint(`/`uint256(`/`int256(`.
fn has_narrowing_downcast(code: &str) -> bool {
    const WIDTHS: [u16; 31] = [
        8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120, 128, 136, 144, 152, 160, 168,
        176, 184, 192, 200, 208, 216, 224, 232, 240, 248,
    ];
    for w in WIDTHS {
        for prefix in ["uint", "int"] {
            // find_token's token-boundary check already rejects `int128(` inside
            // `uint128(` (preceding `u` is an identifier char), so no extra guard needed.
            if find_token(code, &format!("{prefix}{w}(")).is_some() {
                return true;
            }
        }
    }
    false
}

/// Find `needle` in `code` where the char before it is not an identifier char
/// (token start). Returns the byte index of the match.
fn find_token(code: &str, needle: &str) -> Option<usize> {
    let mut from = 0;
    while let Some(rel) = code[from..].find(needle) {
        let pos = from + rel;
        let ok = pos == 0
            || !matches!(code.as_bytes()[pos - 1], b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'_' | b'$');
        if ok {
            return Some(pos);
        }
        from = pos + 1;
    }
    None
}

/// Bytecode-level signals from `analysis.opcodes` + verification status.
fn bytecode_hits(d: &ContractDetails, out: &mut Vec<RawHit>) {
    let mut push = |rid: &'static str, ev: &str| {
        out.push(RawHit { rule_id: rid, detection: "bytecode", location: None, evidence: ev.to_string() });
    };
    let has = |op: &str| d.analysis.opcodes.iter().any(|o| o == op);
    if has("SELFDESTRUCT") {
        push("BYTECODE_SELFDESTRUCT", "runtime bytecode contains SELFDESTRUCT");
    }
    if has("DELEGATECALL") {
        push("BYTECODE_DELEGATECALL", "runtime bytecode contains DELEGATECALL");
    }
    if has("CALLCODE") {
        push("BYTECODE_CALLCODE", "runtime bytecode contains CALLCODE");
    }
    if has("CREATE2") {
        push("BYTECODE_CREATE2", "runtime bytecode contains CREATE2");
    }
    if !d.is_verified {
        push("SOURCE_UNVERIFIED", "no verified source available");
    }
}

/// `OUTDATED_COMPILER` evidence when the verified Solidity compiler is < 0.8.
/// Skips non-Solidity (e.g. Vyper) version strings.
fn outdated_compiler(d: &ContractDetails) -> Option<String> {
    let v = d.compiler_version.as_ref()?;
    let lower = v.to_ascii_lowercase();
    if lower.contains("vyper") {
        return None;
    }
    let s = v.trim().trim_start_matches('v');
    let mut it = s.split('.');
    let major: u32 = it.next()?.parse().ok()?;
    let minor: u32 = it.next()?.parse().ok()?;
    if major == 0 && minor < 8 {
        Some(format!("compiler {v}"))
    } else {
        None
    }
}

/// Strip comments AND string literals from one line, tracking `/* */` across lines.
/// Quoted strings are copied through verbatim so a `//` or `/*` inside a string
/// can't toggle comment state (a real bug in the naive version).
fn code_part(line: &str, in_block: &mut bool) -> String {
    let chars: Vec<char> = line.chars().collect();
    let mut out = String::new();
    let mut i = 0;
    while i < chars.len() {
        if *in_block {
            if chars[i] == '*' && chars.get(i + 1) == Some(&'/') {
                *in_block = false;
                i += 2;
            } else {
                i += 1;
            }
        } else if chars[i] == '"' || chars[i] == '\'' {
            // Copy the whole string literal through, honoring backslash escapes,
            // so comment markers inside it are inert.
            let quote = chars[i];
            out.push(chars[i]);
            i += 1;
            while i < chars.len() {
                let c = chars[i];
                out.push(c);
                if c == '\\' && i + 1 < chars.len() {
                    out.push(chars[i + 1]);
                    i += 2;
                    continue;
                }
                i += 1;
                if c == quote {
                    break;
                }
            }
        } else if chars[i] == '/' && chars.get(i + 1) == Some(&'/') {
            break; // rest of line is a comment
        } else if chars[i] == '/' && chars.get(i + 1) == Some(&'*') {
            *in_block = true;
            i += 2;
        } else {
            out.push(chars[i]);
            i += 1;
        }
    }
    out
}

// ---------------- scoring ----------------

fn conf_factor(c: &str) -> f64 {
    match c {
        "High" => 1.0,
        "Medium" => 0.75,
        _ => 0.5,
    }
}

fn exposure_factor(blast: &str) -> f64 {
    match blast {
        "user-funds" => 1.0,
        "governance" | "cross-chain" => 0.95,
        "protocol" => 0.85,
        "single-contract" => 0.6,
        _ => 0.35,
    }
}

fn finding_risk(s: &RuleSpec) -> u8 {
    let base = (s.impact as f64 / 10.0) * (s.likelihood as f64 / 10.0);
    let r = base * conf_factor(s.confidence) * exposure_factor(s.blast_radius) * 100.0;
    r.round().clamp(0.0, 100.0) as u8
}

fn priority(severity: &str) -> &'static str {
    match severity {
        "Critical" => "P0",
        "High" => "P1",
        "Medium" => "P2",
        _ => "P3",
    }
}

/// Overall contract risk: take the max per-finding risk per *weakness key*
/// (`swc`, else `category`, so source+bytecode of the same weakness count once),
/// then probabilistically OR the distinct weaknesses together (capped 100).
fn overall_risk(findings: &[SecurityFinding]) -> u8 {
    let mut by_key: BTreeMap<String, u8> = BTreeMap::new();
    for f in findings {
        let key = f.swc.clone().unwrap_or_else(|| f.category.clone());
        let e = by_key.entry(key).or_insert(0);
        if f.risk > *e {
            *e = f.risk;
        }
    }
    let mut survival = 1.0f64;
    for r in by_key.values() {
        survival *= 1.0 - (*r as f64 / 100.0);
    }
    ((1.0 - survival) * 100.0).round().clamp(0.0, 100.0) as u8
}

fn grade(score: u8) -> &'static str {
    match score {
        0..=9 => "A",
        10..=24 => "B",
        25..=44 => "C",
        45..=69 => "D",
        _ => "F",
    }
}

fn risk_level(score: u8) -> &'static str {
    match score {
        0..=9 => "Minimal",
        10..=24 => "Low",
        25..=44 => "Medium",
        45..=69 => "High",
        _ => "Critical",
    }
}

fn summarize(findings: &[SecurityFinding]) -> AuditSummary {
    let mut s = AuditSummary::default();
    for f in findings {
        *s.by_severity.entry(f.severity.clone()).or_insert(0) += 1;
        *s.by_category.entry(f.category.clone()).or_insert(0) += 1;
        *s.by_confidence.entry(f.confidence.clone()).or_insert(0) += 1;
        *s.by_priority.entry(f.priority.clone()).or_insert(0) += 1;
        if !s.owasp_categories.contains(&f.category) {
            s.owasp_categories.push(f.category.clone());
        }
    }
    s.owasp_categories.sort();
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::Analysis;

    fn verified(src: &str, compiler: &str) -> (ContractDetails, Vec<SourceFile>) {
        let mut d = ContractDetails::minimal("0xabc", 1);
        d.is_verified = true;
        d.compiler_version = Some(compiler.to_string());
        (d, vec![SourceFile { path: "C.sol".into(), content: src.into() }])
    }

    fn ids(a: &Audit) -> Vec<String> {
        a.findings.iter().map(|f| f.rule_id.clone()).collect()
    }

    #[test]
    fn detects_core_vulns_with_taxonomy_and_locations() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { require(tx.origin == owner); }\n  function k() public { selfdestruct(payable(msg.sender)); }\n}";
        let (d, s) = verified(src, "v0.8.19");
        let a = audit(&d, &s);
        let tx = a.findings.iter().find(|f| f.rule_id == "TX_ORIGIN_AUTH").unwrap();
        assert_eq!(tx.category, "SC01:Access Control");
        assert_eq!(tx.swc.as_deref(), Some("SWC-115"));
        assert_eq!(tx.severity, "High");
        assert_eq!(tx.priority, "P1");
        assert!(tx.risk > 0 && tx.risk <= 100);
        assert!(tx.locations.iter().any(|l| l.starts_with("C.sol:")));
        assert!(tx.references.iter().any(|r| r.contains("SWC-115")));
        assert!(ids(&a).contains(&"SELFDESTRUCT_PRESENT".to_string()));
        assert!(ids(&a).contains(&"FLOATING_PRAGMA".to_string()));
        // Summary matrices populated.
        assert!(a.summary.by_severity.get("High").copied().unwrap_or(0) >= 2);
        assert!(a.summary.owasp_categories.contains(&"SC01:Access Control".to_string()));
        assert!(a.risk_score > 0);
        assert!(["A", "B", "C", "D", "F"].contains(&a.grade.as_str()));
    }

    #[test]
    fn scwe_ethtrust_mapping_high_confidence_and_conservative() {
        // High-confidence mappings present.
        assert_eq!(scwe_ethtrust("TX_ORIGIN_AUTH"), (Some("SCWE-018"), Some("req-1-no-tx.origin [S]")));
        assert_eq!(scwe_ethtrust("REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE").0, Some("SCWE-046"));
        assert_eq!(scwe_ethtrust("OUTDATED_COMPILER"), (Some("SCWE-061"), Some("req-1-compiler-060 [S]")));
        assert_eq!(scwe_ethtrust("MEV_SWAP_ZERO_AMOUNT_OUT_MIN").0, Some("SCWE-090"));
        // bytecode aliases share the source rule's mapping.
        assert_eq!(scwe_ethtrust("BYTECODE_SELFDESTRUCT"), scwe_ethtrust("SELFDESTRUCT_PRESENT"));
        assert_eq!(scwe_ethtrust("BYTECODE_DELEGATECALL"), scwe_ethtrust("DELEGATECALL_USAGE"));
        // ECRECOVER: scwe ambiguous -> null, but EthTrust requirement is stable.
        assert_eq!(scwe_ethtrust("ECRECOVER_NO_ZERO_CHECK"), (None, Some("req-2-signature-verification [M]")));
        // Conservative: deliberately-unmapped rules stay null (no guessing).
        for rid in [
            "LZRECEIVE_MISSING_TRUSTED_REMOTE_CHECK",
            "GOV_ZERO_PROPOSAL_THRESHOLD",
            "FLASHLOAN_CALLBACK_MISSING_CALLER_OR_INITIATOR_AUTH",
            "PROXY_UNPROTECTED_INITIALIZER",
            "OWNER_MUTABLE_FEE",
            "NONEXISTENT_RULE",
        ] {
            assert_eq!(scwe_ethtrust(rid), (None, None), "{rid} must stay unmapped");
        }
    }

    #[test]
    fn audit_finding_carries_scwe_ethtrust_and_references() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { require(tx.origin == owner); }\n}";
        let (d, s) = verified(src, "v0.8.19");
        let a = audit(&d, &s);
        let tx = a.findings.iter().find(|f| f.rule_id == "TX_ORIGIN_AUTH").unwrap();
        assert_eq!(tx.scwe.as_deref(), Some("SCWE-018"));
        assert_eq!(tx.ethtrust.as_deref(), Some("req-1-no-tx.origin [S]"));
        assert!(tx.references.iter().any(|r| r.contains("scs.owasp.org/SCWE/SCWE-018")));
        assert!(tx.references.iter().any(|r| r.contains("entethalliance.org") && r.contains("req-1-no-tx.origin")));
    }

    #[test]
    fn suppression_drops_findings_and_lowers_score() {
        use crate::suppress::Suppressions;
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { require(tx.origin == owner); }\n  function k() public { selfdestruct(payable(msg.sender)); }\n}";
        let (d, s) = verified(src, "v0.8.19");
        let full = audit(&d, &s);
        assert!(full.risk_score > 0);
        assert!(ids(&full).contains(&"TX_ORIGIN_AUTH".to_string()));

        // Suppress one rule: the finding disappears and the score strictly drops.
        let supp: Suppressions =
            serde_json::from_str(r#"{"suppress":[{"rule":"TX_ORIGIN_AUTH"}]}"#).unwrap();
        let filtered = audit_with(&d, &s, &supp);
        assert!(!ids(&filtered).contains(&"TX_ORIGIN_AUTH".to_string()));
        assert!(filtered.risk_score < full.risk_score);
        // Summary reflects the reduced set (no Access-Control count from tx.origin's category alone).
        assert_eq!(filtered.findings.len(), full.findings.len() - 1);

        // Suppress every emitted rule -> clean audit (score 0, grade A).
        let all: Vec<String> = ids(&full)
            .iter()
            .map(|r| format!(r#"{{"rule":"{r}"}}"#))
            .collect();
        let supp_all: Suppressions =
            serde_json::from_str(&format!(r#"{{"suppress":[{}]}}"#, all.join(","))).unwrap();
        let none = audit_with(&d, &s, &supp_all);
        assert!(none.findings.is_empty());
        assert_eq!(none.risk_score, 0);
        assert_eq!(none.grade, "A");
    }

    #[test]
    fn string_literal_with_comment_marker_does_not_blind_detectors() {
        // Regression (review HIGH): a `/*` inside a string must NOT start a block
        // comment that swallows later lines. The string also contains a backslash
        // escape to exercise escape handling in the string scanner.
        let src = "contract C {\n  string s = \"a\\\"/* not a comment\";\n  function k() public { selfdestruct(payable(msg.sender)); }\n  function f() public { require(tx.origin == o); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        assert!(ids(&a).contains(&"SELFDESTRUCT_PRESENT".to_string()));
        assert!(ids(&a).contains(&"TX_ORIGIN_AUTH".to_string()));
    }

    #[test]
    fn comments_do_not_trigger_and_block_spans_lines() {
        let src = "contract C {\n  // tx.origin selfdestruct(\n  /*\n  selfdestruct(\n  */\n  uint x;\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(audit(&d, &s).findings.is_empty());
    }

    #[test]
    fn unprotected_initializer_multiline_and_guarded() {
        // Multi-line OZ layout, unprotected -> flagged.
        let bad = "function initialize()\n  public\n  virtual\n{\n  owner = msg.sender;\n}";
        let (d, s) = verified(bad, "v0.8.20");
        assert!(ids(&audit(&d, &s)).contains(&"PROXY_UNPROTECTED_INITIALIZER".to_string()));
        // Guard on a later line -> not flagged.
        let good = "function initialize()\n  public\n  initializer\n{\n  owner = msg.sender;\n}";
        let (d2, s2) = verified(good, "v0.8.20");
        assert!(!ids(&audit(&d2, &s2)).contains(&"PROXY_UNPROTECTED_INITIALIZER".to_string()));
        // The initializer rule must NOT cite the wrong SWC-118 ("Incorrect Constructor Name").
        let f = audit(&d, &s).findings.into_iter().find(|f| f.rule_id == "PROXY_UNPROTECTED_INITIALIZER").unwrap();
        assert_eq!(f.swc, None);
    }

    #[test]
    fn initializer_declaration_in_an_interface_is_not_reported() {
        // An interface declaration has no body: nothing to guard, nothing callable.
        // 16 of this rule's 17 corpus findings were exactly this — UniswapV2Pair's
        // `IUniswapV2Pair.initialize`, `IPoolManager`, `IUniswapV3PoolActions`.
        let (d, s) = verified("interface I {
  function initialize(address, address) external;
}", "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"PROXY_UNPROTECTED_INITIALIZER".to_string()));
        // Wrapped across lines, the semicolon arriving well after the signature.
        let (d2, s2) = verified("interface I {
  function initialize(
    uint160 p
  ) external returns (int24);
}", "v0.8.20");
        assert!(!ids(&audit(&d2, &s2)).contains(&"PROXY_UNPROTECTED_INITIALIZER".to_string()));
    }

    #[test]
    fn unreachable_or_stateless_initializer_is_not_reported() {
        // `internal pure` cannot be called from outside and initializes nothing —
        // Uniswap V4's PositionInfoLibrary.initialize is both.
        let (d, s) = verified("library L {
  function initialize(uint a) internal pure returns (uint) { return a; }
}", "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"PROXY_UNPROTECTED_INITIALIZER".to_string()));
    }

    #[test]
    fn a_caller_check_guards_an_initializer_but_an_assignment_does_not() {
        // UniswapV2Pair guards with a require, not an OpenZeppelin modifier.
        let guarded = "function initialize(address a) external {
  require(msg.sender == factory, 'FORBIDDEN');
  token0 = a;
}";
        let (d, s) = verified(guarded, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"PROXY_UNPROTECTED_INITIALIZER".to_string()));
        // But merely *mentioning* the caller is not a check: `owner = msg.sender`
        // in an open initializer is the archetypal takeover this rule exists for.
        // Reading presence as a guard silently suppressed it.
        let open = "function initialize() public virtual {
  owner = msg.sender;
}";
        let (d2, s2) = verified(open, "v0.8.20");
        assert!(ids(&audit(&d2, &s2)).contains(&"PROXY_UNPROTECTED_INITIALIZER".to_string()));
    }

    #[test]
    fn corrected_swc_mappings() {
        let (d, s) = verified("function f() public { address a = ecrecover(h, v, r, ss); }", "v0.7.6");
        let fs = audit(&d, &s).findings;
        let ec = fs.iter().find(|f| f.rule_id == "ECRECOVER_NO_ZERO_CHECK").unwrap();
        assert_eq!(ec.swc.as_deref(), Some("SWC-122"));
        let oc = fs.iter().find(|f| f.rule_id == "OUTDATED_COMPILER").unwrap();
        assert_eq!(oc.swc.as_deref(), Some("SWC-102"));
    }

    #[test]
    fn assembly_requires_block_form_not_identifier() {
        let (d, s) = verified("uint assemblyLine; function reassembly() public {}", "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"INLINE_ASSEMBLY".to_string()));
        let (d2, s2) = verified("function f() public { assembly { let x := 1 } }", "v0.8.20");
        assert!(ids(&audit(&d2, &s2)).contains(&"INLINE_ASSEMBLY".to_string()));
    }

    #[test]
    fn outdated_compiler_and_vyper_skip() {
        let (d, s) = verified("contract C {}", "v0.7.6+commit.7338295f");
        assert!(ids(&audit(&d, &s)).contains(&"OUTDATED_COMPILER".to_string()));
        let (d2, s2) = verified("contract C {}", "v0.8.19");
        assert!(!ids(&audit(&d2, &s2)).contains(&"OUTDATED_COMPILER".to_string()));
        // Vyper version must not be misread as old Solidity.
        let (d3, s3) = verified("# vyper", "vyper:0.3.7");
        assert!(!ids(&audit(&d3, &s3)).contains(&"OUTDATED_COMPILER".to_string()));
    }

    #[test]
    fn bytecode_signals_and_weakness_dedup() {
        let mut d = ContractDetails::minimal("0xabc", 1);
        d.is_verified = true;
        d.compiler_version = Some("v0.8.20".into());
        d.analysis = Analysis {
            opcodes: vec!["SELFDESTRUCT".into(), "DELEGATECALL".into(), "CALLCODE".into(), "CREATE2".into()],
            ..Default::default()
        };
        // Source ALSO has selfdestruct -> two findings, same SWC-106 weakness key.
        let s = vec![SourceFile { path: "C.sol".into(), content: "selfdestruct(payable(0));".into() }];
        let a = audit(&d, &s);
        let i = ids(&a);
        assert!(i.contains(&"SELFDESTRUCT_PRESENT".to_string()));
        assert!(i.contains(&"BYTECODE_SELFDESTRUCT".to_string()));
        assert!(i.contains(&"BYTECODE_CALLCODE".to_string()));
        assert!(i.contains(&"BYTECODE_CREATE2".to_string()));
        // selfdestruct counted once (same SWC-106 key) despite two findings.
        let selfd: Vec<&SecurityFinding> = a.findings.iter().filter(|f| f.swc.as_deref() == Some("SWC-106")).collect();
        assert_eq!(selfd.len(), 2);
    }

    #[test]
    fn detects_call_randomness_ecrecover_deprecated() {
        // `a.call("")` is a bare statement (unchecked low-level call); `block.number
        // % 10` is a genuine weak-randomness use (the AST layer requires a modulo /
        // hash context, not a bare timestamp/number read).
        let src = "function f() public { a.call(\"\"); b.delegatecall(p); uint r = block.number % 10; address s = ecrecover(h, v, rr, ss); bytes32 z = sha3(y); }";
        let (d, s) = verified(src, "v0.8.20");
        let i = ids(&audit(&d, &s));
        assert!(i.contains(&"UNCHECKED_LOW_LEVEL_CALL".to_string()));
        assert!(i.contains(&"DELEGATECALL_USAGE".to_string()));
        assert!(i.contains(&"WEAK_BLOCK_RANDOMNESS".to_string()));
        assert!(i.contains(&"ECRECOVER_NO_ZERO_CHECK".to_string()));
        assert!(i.contains(&"DEPRECATED_CONSTRUCT".to_string()));
        // Every emitted finding carries a populated taxonomy + scenario/recommendation.
        for f in &audit(&d, &s).findings {
            assert!(!f.category.is_empty() && !f.exploit_scenario.is_empty() && !f.recommendation.is_empty());
            assert!(!f.references.is_empty());
        }
    }

    // ---- Phase 14: AST refinement wiring (audit_with) ----

    #[test]
    fn ast_refines_tx_origin_drops_non_auth_use() {
        // Clean-parsing contract whose only tx.origin is a non-auth `return`:
        // the AST layer owns the rule and suppresses the heuristic false positive.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public view returns (address) { return tx.origin; }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"TX_ORIGIN_AUTH".to_string()));
    }

    #[test]
    fn ast_flags_canonical_bound_but_unchecked_send() {
        // Regression for the review's funds-drain scenario: binding the boolean
        // return without checking it is the textbook SWC-104 bug and MUST fire.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function withdraw(address a) public { (bool ok,) = a.call{value: address(this).balance}(\"\"); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "UNCHECKED_LOW_LEVEL_CALL").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn ast_refines_unchecked_call_drops_consumed_call() {
        // The result is consumed directly by require(...), so the AST layer drops
        // the heuristic false positive (the old heuristic fired on any `.call(`).
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { require(a.call(\"\")); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"UNCHECKED_LOW_LEVEL_CALL".to_string()));
    }

    #[test]
    fn ast_dataflow_drops_bound_then_checked_call() {
        // Phase 15: the dominant safe pattern — bind the boolean, require it later
        // — is no longer a false positive (intra-function dataflow confirms the gate).
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { (bool ok,) = a.call(\"\"); require(ok); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"UNCHECKED_LOW_LEVEL_CALL".to_string()));
    }

    #[test]
    fn ast_reentrancy_fires_and_is_tagged_ast() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  mapping(address=>uint) bal;\n  function withdraw() public { (bool ok,) = msg.sender.call{value: bal[msg.sender]}(\"\"); require(ok); bal[msg.sender] = 0; }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn ast_reentrancy_drops_local_write_false_positive() {
        // The heuristic flags any write after a call; the AST layer requires a
        // STATE write, so a local-only write is no longer a false positive.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f(address t) public { t.call{value: 1}(\"\"); uint local = 5; local = local + 1; }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE".to_string()));
    }

    #[test]
    fn ast_access_control_fires_and_is_tagged_ast() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function mint(address t, uint a) external { _mint(t, a); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "ACCESS_MISSING_GUARD_PRIVILEGED_FN").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn ast_access_control_drops_guarded_fn() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function mint(address t, uint a) external onlyOwner { _mint(t, a); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"ACCESS_MISSING_GUARD_PRIVILEGED_FN".to_string()));
    }

    #[test]
    fn ast_weak_randomness_fires_on_modulo_and_is_tagged_ast() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function roll() public view returns (uint) { return block.timestamp % 6; }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "WEAK_BLOCK_RANDOMNESS").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn ast_weak_randomness_drops_deadline_false_positive() {
        // The dominant heuristic FP: block.timestamp in a deadline check is not
        // randomness and is no longer flagged.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  uint d;\n  function set() external { require(block.timestamp <= d); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"WEAK_BLOCK_RANDOMNESS".to_string()));
    }

    #[test]
    fn ast_ecrecover_fires_without_zero_check_and_is_tagged_ast() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  address signer;\n  function v(bytes32 h, uint8 vv, bytes32 r, bytes32 s) external view returns (bool) { return ecrecover(h, vv, r, s) == signer; }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "ECRECOVER_NO_ZERO_CHECK").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn ast_ecrecover_drops_zero_checked_false_positive() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function v(bytes32 h, uint8 vv, bytes32 r, bytes32 s) external pure returns (address) { address a = ecrecover(h, vv, r, s); require(a != address(0)); return a; }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"ECRECOVER_NO_ZERO_CHECK".to_string()));
    }

    #[test]
    fn ast_arbitrary_delegatecall_fires_critical_and_tagged_ast() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function exec(address target, bytes calldata data) external { target.delegatecall(data); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "DELEGATECALL_ARBITRARY_TARGET").expect("must fire");
        assert_eq!(f.detection, "ast");
        assert_eq!(f.severity, "Critical");
        assert!(a.risk_score > 0);
    }

    #[test]
    fn ast_arbitrary_delegatecall_not_fired_on_fixed_impl() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  address impl;\n  function f(bytes calldata data) external { impl.delegatecall(data); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"DELEGATECALL_ARBITRARY_TARGET".to_string()));
    }

    // ---- Phase 21: transfer/send arg-count + narrowing downcast (end-to-end) ----

    #[test]
    fn ast_transfer_send_fires_on_one_arg_and_tagged_ast() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function w(uint256 amount) external { payable(msg.sender).transfer(amount); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "HARDCODED_GAS_TRANSFER_SEND").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn ast_transfer_send_drops_erc20_two_arg_false_positive() {
        // The heuristic FPs here (`.transfer(` + the `amount` value cue); the AST
        // sees two arguments (an ERC-20 transfer) and suppresses it.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function pay(address to, uint256 amount) external { dai.transfer(to, amount); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"HARDCODED_GAS_TRANSFER_SEND".to_string()));
    }

    #[test]
    fn transfer_send_falls_back_to_heuristic_on_parse_failure() {
        // Broken syntax → AST None → heuristic still flags the 1-arg send (source).
        let src = "contract C { function w( { recipient.transfer(amount); } }";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "HARDCODED_GAS_TRANSFER_SEND").expect("heuristic fires");
        assert_eq!(f.detection, "source");
    }

    #[test]
    fn ast_downcast_fires_on_identifier_and_tagged_ast() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f(uint256 x) public pure returns (uint128) { return uint128(x); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "UNSAFE_DOWNCAST_TRUNCATION").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn ast_downcast_drops_literal_cast_false_positive() {
        // The heuristic FPs on `uint128(0)`; the AST recognizes the literal argument.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public pure returns (uint128) { uint128 k = uint128(0); return k; }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"UNSAFE_DOWNCAST_TRUNCATION".to_string()));
    }

    // ---- Phase 22: binding-graph type resolution (end-to-end through audit) ----

    #[test]
    fn binding_audit_drops_uint160_of_address_param() {
        // The binding graph resolves `a` to type address → uint160(a) is lossless.
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f(address a) external pure returns (uint160) { return uint160(a); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"UNSAFE_DOWNCAST_TRUNCATION".to_string()));
    }

    #[test]
    fn binding_audit_still_flags_uint128_of_uint256_param() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f(uint256 x) external pure returns (uint128) { return uint128(x); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "UNSAFE_DOWNCAST_TRUNCATION").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn binding_audit_drops_interface_receiver_send() {
        // `endpoint` resolves to an interface type → endpoint.send(payload) is a
        // messaging call, not a 2300-gas ETH send.
        let src = "pragma solidity ^0.8.0;\ninterface IM { function send(bytes calldata m) external; }\ncontract C {\n  IM endpoint;\n  function f(bytes calldata m) external { endpoint.send(m); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"HARDCODED_GAS_TRANSFER_SEND".to_string()));
    }

    #[test]
    fn binding_audit_still_flags_address_payable_transfer() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f(address payable r, uint256 amt) external { r.transfer(amt); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "HARDCODED_GAS_TRANSFER_SEND").expect("must fire");
        assert_eq!(f.detection, "ast");
    }

    #[test]
    fn audit_dedups_duplicate_source_paths() {
        // Review bugs 5/6: two source files sharing a sanitized path must be
        // processed once — the duplicate must not resurrect a binding-suppressed
        // finding (without dedup the 2nd copy hits the None branch → per-file
        // `detect` re-flags uint160(a)).
        let src = "pragma solidity ^0.8.0;\ncontract C { function f(address a) external pure returns (uint160) { return uint160(a); } }";
        let (mut d, mut s) = verified(src, "v0.8.20");
        d.is_verified = true;
        s.push(SourceFile { path: "C.sol".into(), content: src.into() });
        assert_eq!(s.len(), 2); // two entries, same path
        assert!(!ids(&audit(&d, &s)).contains(&"UNSAFE_DOWNCAST_TRUNCATION".to_string()));
    }

    #[test]
    fn reentrancy_falls_back_to_heuristic_on_parse_failure() {
        // Broken syntax → AST returns None → heuristic reentrancy still fires,
        // tagged `source` (graceful degradation).
        let src = "contract C { mapping(address=>uint) bal; function f( { msg.sender.call{value: bal[msg.sender]}(\"\"); bal[msg.sender] = 0; } }";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a.findings.iter().find(|f| f.rule_id == "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE").expect("heuristic fires");
        assert_eq!(f.detection, "source");
    }

    #[test]
    fn ast_owned_findings_are_tagged_ast() {
        let src = "pragma solidity ^0.8.0;\ncontract C {\n  function f() public { require(tx.origin == owner); a.call(\"\"); }\n}";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        assert_eq!(a.findings.iter().find(|f| f.rule_id == "TX_ORIGIN_AUTH").unwrap().detection, "ast");
        assert_eq!(a.findings.iter().find(|f| f.rule_id == "UNCHECKED_LOW_LEVEL_CALL").unwrap().detection, "ast");
    }

    #[test]
    fn unparseable_source_falls_back_to_heuristics() {
        // A syntax error makes the AST parse fail; the heuristic line scan still
        // fires tx-origin and tags it `source` (graceful degradation).
        let src = "contract C { function f( { require(tx.origin == owner); } }";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let tx = a.findings.iter().find(|f| f.rule_id == "TX_ORIGIN_AUTH").expect("heuristic fires");
        assert_eq!(tx.detection, "source");
    }

    #[test]
    fn unverified_contract_flagged() {
        let mut d = ContractDetails::minimal("0xabc", 1);
        d.is_verified = false;
        let a = audit(&d, &[]);
        assert!(ids(&a).contains(&"SOURCE_UNVERIFIED".to_string()));
    }

    #[test]
    fn scoring_factors_and_boundaries() {
        assert_eq!(conf_factor("High"), 1.0);
        assert_eq!(conf_factor("Medium"), 0.75);
        assert_eq!(conf_factor("Low"), 0.5);
        assert!((exposure_factor("user-funds") - 1.0).abs() < 1e-9);
        assert!((exposure_factor("single-contract") - 0.6).abs() < 1e-9);
        assert!((exposure_factor("weird") - 0.35).abs() < 1e-9);
        assert_eq!(grade(0), "A");
        assert_eq!(grade(9), "A");
        assert_eq!(grade(10), "B");
        assert_eq!(grade(45), "D");
        assert_eq!(grade(70), "F");
        assert_eq!(risk_level(0), "Minimal");
        assert_eq!(risk_level(70), "Critical");
        assert_eq!(priority("Critical"), "P0");
        assert_eq!(priority("High"), "P1");
        assert_eq!(priority("Medium"), "P2");
        assert_eq!(priority("Info"), "P3");
    }

    #[test]
    fn tx_origin_finding_risk_value() {
        // impact 7, likelihood 5, conf Medium(0.75), exposure user-funds(1.0)
        // = 0.7*0.5*0.75*1.0*100 = 26.25 -> 26.
        let f = build_finding("TX_ORIGIN_AUTH", &ContractDetails::minimal("0xa", 1), vec![], "e".into(), "source");
        assert_eq!(f.risk, 26);
    }

    #[test]
    fn initialize_without_body_brace_is_not_reported() {
        // `function initialize(` as the last line: no body, no visibility keyword.
        // A truncated fragment is not evidence of an unprotected initializer, so
        // reporting it was noise. Before Phase 29 this fired.
        let (d, s) = verified("contract C {\n  function initialize(", "v0.8.20");
        assert!(!ids(&audit(&d, &s)).contains(&"PROXY_UNPROTECTED_INITIALIZER".to_string()));
    }

    #[test]
    fn unknown_rule_id_yields_benign_placeholder() {
        let f = build_finding("__NO_SUCH_RULE__", &ContractDetails::minimal("0xa", 1), vec![], "e".into(), "source");
        assert_eq!(f.category, "Code Quality");
        assert_eq!(f.risk, 0);
        assert_eq!(f.severity, "Info");
    }

    #[test]
    fn clean_contract_scores_zero_grade_a() {
        let (d, s) = verified("pragma solidity 0.8.20;\ncontract Safe { uint x; function get() public view returns (uint) { return x; } }", "v0.8.20");
        let a = audit(&d, &s);
        assert_eq!(a.risk_score, 0);
        assert_eq!(a.grade, "A");
        assert_eq!(a.risk_level, "Minimal");
        assert!(a.findings.is_empty());
    }

    #[test]
    fn overall_risk_caps_at_100() {
        // Build many distinct high-risk findings -> OR aggregate approaches but caps 100.
        let f = |rid: &'static str| build_finding(rid, &ContractDetails::minimal("0xa", 1), vec![], "e".into(), "source");
        let findings = vec![
            f("TX_ORIGIN_AUTH"), f("SELFDESTRUCT_PRESENT"), f("PROXY_UNPROTECTED_INITIALIZER"),
            f("DELEGATECALL_USAGE"), f("WEAK_BLOCK_RANDOMNESS"), f("OUTDATED_COMPILER"),
        ];
        assert!(overall_risk(&findings) <= 100);
    }

    // ---------------- Phase 9 deep-rule detectors ----------------

    fn fires(src: &str, rule: &str) -> bool {
        let (d, s) = verified(src, "v0.8.20");
        ids(&audit(&d, &s)).iter().any(|r| r == rule)
    }

    // ---- T-06: both window heuristics scoped to a function body ----

    const STALE: &str = "CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK";

    /// The acceptance test. A guard that belongs to a different call must not
    /// suppress a call that has none — the failure a line count cannot avoid,
    /// because twelve lines of source is not a scope.
    #[test]
    fn a_neighbouring_staleness_guard_does_not_cover_an_unguarded_feed() {
        // One function, two feeds. The second is validated; the first is not.
        let two_feeds = "function p() public {\n\
            (, int256 b, , , ) = feedB.latestRoundData();\n\
            priceB = b;\n\
            (, int256 a, , uint256 upA, ) = feedA.latestRoundData();\n\
            require(block.timestamp - upA < 3600);\n\
            priceA = a;\n\
        }";
        assert!(fires(two_feeds, STALE), "the unvalidated feed must still be reported");

        // Separate functions. The guard is four lines away from the unguarded
        // call and inside a different body, which is the whole point.
        let two_fns = "function b() public {\n\
            (, int256 x, , , ) = feed.latestRoundData();\n\
            priceB = x;\n\
        }\n\
        function a() public {\n\
            (, int256 y, , uint256 u, ) = feed.latestRoundData();\n\
            require(block.timestamp - u < 3600);\n\
            priceA = y;\n\
        }";
        assert!(fires(two_fns, STALE), "a guard in the next function is not this function\\'s");
    }

    /// The other direction: a genuinely validated feed stays unreported, or the
    /// rule is just "mentions latestRoundData".
    #[test]
    fn a_validated_feed_is_not_reported() {
        assert!(!fires(
            "function p() public { (uint80 r, int256 a, , uint256 u, uint80 air) = feed.latestRoundData(); require(u > block.timestamp - 3600); require(air >= r); price = a; }",
            STALE
        ));
        // `if`/`revert` is the same check written the modern way.
        assert!(!fires(
            "function p() public { (, int256 a, , uint256 u, ) = feed.latestRoundData(); if (block.timestamp - u > 3600) revert Stale(); price = a; }",
            STALE
        ));
    }

    /// Checking the price is not checking its age, and the old window accepted
    /// `> 0` as a staleness guard.
    #[test]
    fn validating_only_the_answer_is_not_a_staleness_check() {
        assert!(fires(
            "function p() public { (, int256 a, , , ) = feed.latestRoundData(); require(a > 0); price = a; }",
            STALE
        ));
    }

    /// Whole-identifier matching: a similarly named variable is not the one the
    /// call bound.
    #[test]
    fn a_lookalike_identifier_does_not_count_as_the_guard() {
        assert!(fires(
            "function p() public { (, int256 a, , uint256 updatedAt, ) = feed.latestRoundData(); require(lastUpdatedAt < 3600); price = a; }",
            STALE
        ));
    }

    /// A guard in one function must not cover an unguarded `initialize` in
    /// another — the same adjacency failure, on the other rule. This also pins
    /// the substring bleed: walking forward line by line read `_initializer` in
    /// an unguarded body as an OpenZeppelin `initializer` modifier.
    #[test]
    fn a_neighbouring_initializer_modifier_does_not_cover_an_unguarded_one() {
        let src = "contract C {\n\
            function initialize(address o) public {\n\
                _initializer = msg.sender;\n\
                owner = o;\n\
            }\n\
            function initialize(address o, uint256 n) public initializer {\n\
                owner = o;\n\
                nonce = n;\n\
            }\n\
        }";
        let (d, s) = verified(src, "v0.8.20");
        let a = audit(&d, &s);
        let f = a
            .findings
            .iter()
            .find(|f| f.rule_id == "PROXY_UNPROTECTED_INITIALIZER")
            .expect("the unguarded overload must be reported");
        assert_eq!(
            f.locations.len(),
            1,
            "exactly the unguarded one, not both: {:?}",
            f.locations
        );
    }

    /// The Phase 29 result is a property of the scope now, not of a separate
    /// check: `scan_functions` never yields a bodiless declaration.
    #[test]
    fn interface_declarations_stay_out_of_scope() {
        assert!(!fires(
            "interface I { function initialize(address a, address b) external; }",
            "PROXY_UNPROTECTED_INITIALIZER"
        ));
        assert!(!fires(
            "library L { function initialize(uint256 x) internal pure returns (uint256) { return x; } }",
            "PROXY_UNPROTECTED_INITIALIZER"
        ));
    }

    #[test]
    fn access_missing_guard_privileged_fn() {
        assert!(fires("function mint(address to, uint256 a) external { _mint(to, a); }", "ACCESS_MISSING_GUARD_PRIVILEGED_FN"));
        // Guarded by a modifier -> not flagged.
        assert!(!fires("function mint(address to, uint256 a) external onlyOwner { _mint(to, a); }", "ACCESS_MISSING_GUARD_PRIVILEGED_FN"));
        // Guarded by an inline msg.sender check -> not flagged.
        assert!(!fires("function mint(address to, uint256 a) external { require(msg.sender == owner); _mint(to, a); }", "ACCESS_MISSING_GUARD_PRIVILEGED_FN"));
        // Non-privileged name -> not flagged.
        assert!(!fires("function totalSupply() external view returns (uint256) { return x; }", "ACCESS_MISSING_GUARD_PRIVILEGED_FN"));
        // Project-specific only* modifiers (onlyPauser/onlyBlacklister) count as guards.
        assert!(!fires("function pause() external onlyPauser { _pause(); }", "ACCESS_MISSING_GUARD_PRIVILEGED_FN"));
        assert!(!fires("function blacklist(address a) external onlyBlacklister { _ban(a); }", "ACCESS_MISSING_GUARD_PRIVILEGED_FN"));
    }

    #[test]
    fn access_unprotected_ether_withdrawal() {
        assert!(fires("function drain(address to, uint256 a) external { to.call{value: a}(\"\"); }", "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL"));
        assert!(!fires("function drain(address to, uint256 a) external onlyOwner { to.call{value: a}(\"\"); }", "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL"));
        // Pull-payment to msg.sender is suppressed.
        assert!(!fires("function claim() external { payable(msg.sender).transfer(bal[msg.sender]); }", "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL"));
        // Review fix: an ERC-20 token transfer is NOT an ETH withdrawal (no Critical FP).
        assert!(!fires("function distribute(address to, uint256 amount) external { token.transfer(to, amount); }", "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL"));
    }

    #[test]
    fn brace_inside_string_does_not_truncate_body() {
        // Review fix: a `}` inside a string literal must not end the function body
        // early, which would hide the ETH sink that follows it.
        let src = "function drain(address to, uint256 a) external { string memory s = \"}\"; to.call{value: a}(\"\"); }";
        assert!(fires(src, "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL"));
    }

    #[test]
    fn large_function_body_is_truncated_not_emptied() {
        // Review fix: a body > 8000 bytes must still expose its first ~8000 bytes
        // to body-scoped detectors (the sink is near the start), not be emptied.
        let mut src = String::from("function drain(address to, uint256 a) external { to.call{value: a}(\"\"); ");
        src.push_str(&"uint256 z = 1; ".repeat(700)); // ~10.5KB of filler after the sink
        src.push('}');
        assert!(fires(&src, "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL"));
    }

    #[test]
    fn uups_and_public_upgrade() {
        assert!(fires("function _authorizeUpgrade(address) internal override {}", "UUPS_AUTHORIZE_UPGRADE_UNGUARDED"));
        assert!(!fires("function _authorizeUpgrade(address) internal override onlyOwner {}", "UUPS_AUTHORIZE_UPGRADE_UNGUARDED"));
        assert!(fires("function upgradeTo(address impl) public { _implementation = impl; }", "PROXY_PUBLIC_UPGRADE_TO_UNGUARDED"));
        // OZ pattern: public but delegates to _authorizeUpgrade -> not flagged.
        assert!(!fires("function upgradeToAndCall(address impl, bytes memory d) public { _authorizeUpgrade(impl); }", "PROXY_PUBLIC_UPGRADE_TO_UNGUARDED"));
    }

    #[test]
    fn external_call_rules() {
        assert!(fires("function w() external { payable(msg.sender).transfer(amount); }", "HARDCODED_GAS_TRANSFER_SEND"));
        // ERC-20 token transfers are not ETH stipend sends (token-marker rejection).
        assert!(!fires("function f() external { token.transferFrom(a, b, c); }", "HARDCODED_GAS_TRANSFER_SEND"));
        assert!(!fires("function f() external { token.transfer(to, amount); }", "HARDCODED_GAS_TRANSFER_SEND"));
        // A `.send(` with only a `value` cue still counts as an ETH send.
        assert!(fires("function w() external { recipient.send(value); }", "HARDCODED_GAS_TRANSFER_SEND"));
        // ...and the `wad` cue (DAI-style) is also recognized.
        assert!(fires("function w() external { recipient.transfer(wad); }", "HARDCODED_GAS_TRANSFER_SEND"));
        assert!(fires("function w() external { to.call{value: amount}(\"\"); }", "RAW_CALL_VALUE_ETH_SEND"));
        // Reentrancy: external call then STATE-variable write (assignment and
        // increment forms), no guard. (Full contracts so the AST layer sees the
        // state-variable declarations it now requires.)
        assert!(fires("pragma solidity ^0.8.0; contract C { mapping(address=>uint) bal; function w() external { msg.sender.call{value: bal[msg.sender]}(\"\"); bal[msg.sender] = 0; } }", "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE"));
        assert!(fires("pragma solidity ^0.8.0; contract C { uint counter; function w() external { msg.sender.call{value: 1}(\"\"); counter++; } }", "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE"));
        assert!(!fires("pragma solidity ^0.8.0; contract C { uint y; function w() external nonReentrant { msg.sender.call{value: 1}(\"\"); y = 0; } }", "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE"));
    }

    #[test]
    fn arithmetic_rules() {
        assert!(fires("function f() public { unchecked { x++; } }", "UNCHECKED_ARITHMETIC_BLOCK"));
        assert!(fires("function f() public { y = uint128(x); }", "UNSAFE_DOWNCAST_TRUNCATION"));
        // uint256 is widening, not a truncation; identifier prefix must not match.
        assert!(!fires("function f() public { y = uint256(x); }", "UNSAFE_DOWNCAST_TRUNCATION"));
        assert!(!fires("function f() public { myuint128(x); }", "UNSAFE_DOWNCAST_TRUNCATION"));
    }

    #[test]
    fn oracle_rules() {
        assert!(fires("function p() public view { (uint r0, uint r1,) = pair.getReserves(); }", "ORACLE_SPOT_PRICE_FROM_RESERVES"));
        assert!(fires("function p() public view { (,int a,,,) = feed.latestAnswer(); }", "CHAINLINK_LATESTANSWER_DEPRECATED"));
        // latestRoundData without staleness check fires...
        assert!(fires("function p() public { (,int answer,,,) = feed.latestRoundData(); price = answer; }", "CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK"));
        // ...but not when a staleness guard follows.
        assert!(!fires("function p() public { (,int answer,,uint updatedAt,) = feed.latestRoundData(); require(block.timestamp - updatedAt < 3600); }", "CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK"));
    }

    #[test]
    fn flashloan_and_token_rules() {
        assert!(fires("function onFlashLoan(address i, address t, uint256 a, uint256 f, bytes calldata d) external returns (bytes32) { doStuff(); }", "FLASHLOAN_CALLBACK_MISSING_CALLER_OR_INITIATOR_AUTH"));
        assert!(!fires("function onFlashLoan(address i, address t, uint256 a, uint256 f, bytes calldata d) external returns (bytes32) { require(msg.sender == pool); }", "FLASHLOAN_CALLBACK_MISSING_CALLER_OR_INITIATOR_AUTH"));
        assert!(fires("mapping(address => bool) public isBlacklisted;", "OWNER_BLACKLIST_CONTROL"));
        assert!(fires("function setFee(uint256 f) external onlyOwner { fee = f; }", "OWNER_MUTABLE_FEE"));
    }

    #[test]
    fn scan_functions_balances_nested_braces_and_skips_interfaces() {
        // Interface decl (no body) must be skipped; nested braces must balance.
        let fns = scan_functions("interface I { function f() external; }\ncontract C {\n function g() public { if (x) { y = 1; } }\n}");
        let names: Vec<&str> = fns.iter().map(|f| f.name_lc.as_str()).collect();
        assert!(names.contains(&"g"));
        // The body of g includes the nested block but stops at g's closing brace.
        let g = fns.iter().find(|f| f.name_lc == "g").unwrap();
        assert!(g.body.contains("y = 1"));
    }

    #[test]
    fn has_state_write_forms() {
        assert!(has_state_write("x = 1")); // plain assignment
        assert!(has_state_write("x += 1")); // compound assignment
        assert!(has_state_write("delete a")); // delete
        assert!(has_state_write("a++")); // increment
        assert!(!has_state_write("a == b")); // comparison is not a write
        assert!(!has_state_write("a >= b && c <= d")); // none
    }

    #[test]
    fn brace_balancer_handles_escapes_and_multibyte_cap() {
        // Escaped quote + brace inside a string literal during body brace-balancing:
        // the in-string `}` must not close the body early (exercises the escape branch).
        let fns = scan_functions("contract C { function f() external { string s = \"a\\\"}\"; bal = 0; } }");
        let f = fns.iter().find(|x| x.name_lc == "f").unwrap();
        assert!(f.body.contains("bal = 0"));
        // A >8000-byte body full of multibyte chars: the 8000 cap lands mid-char,
        // so the boundary backup must run — and must not panic on the slice.
        let big = format!("contract C {{ function g() public {{ string s = \"{}\"; }} }}", "中".repeat(3000));
        let fns2 = scan_functions(&big);
        assert!(fns2.iter().any(|x| x.name_lc == "g"));
    }

    #[test]
    fn floor_char_boundary_backs_to_boundary() {
        let s = "ab中cd"; // 中 occupies bytes 2..5
        assert_eq!(floor_char_boundary(s, 3), 2); // mid-char -> back to 2
        assert_eq!(floor_char_boundary(s, 4), 2);
        assert_eq!(floor_char_boundary(s, 2), 2); // already a boundary
        assert_eq!(floor_char_boundary(s, 0), 0);
        assert_eq!(floor_char_boundary(s, 999), s.len()); // past end -> len
    }

    #[test]
    fn scan_functions_skips_identifier_and_nameless_forms() {
        // `function` inside an identifier (xfunction), a nameless `function (`,
        // and whitespace between name and `(` (`function h ()`).
        let fns = scan_functions("uint xfunctionCount; function () external {} function h () public { z = 1; }");
        let names: Vec<&str> = fns.iter().map(|f| f.name_lc.as_str()).collect();
        assert_eq!(names, vec!["h"]); // only the real named function with a body
    }

    #[test]
    fn governance_rules() {
        assert!(fires("function castVote(uint256 id, uint8 s) public { uint256 w = token.balanceOf(msg.sender); _count(id, w); }", "GOV_VOTE_CURRENT_BLOCK_VOTING_POWER"));
        // Snapshot-based read -> not flagged.
        assert!(!fires("function castVote(uint256 id, uint8 s) public { uint256 w = token.getPastVotes(msg.sender, proposalSnapshot[id]); }", "GOV_VOTE_CURRENT_BLOCK_VOTING_POWER"));
        assert!(fires("function execute(address t, bytes memory d) public { t.call(d); }", "GOV_EXECUTE_NO_TIMELOCK_DELAY"));
        assert!(!fires("function execute(address t, bytes memory d) public { require(block.timestamp >= eta); t.call(d); }", "GOV_EXECUTE_NO_TIMELOCK_DELAY"));
        // Review fix: a body containing `metadata` must NOT be suppressed by a bare "eta".
        assert!(fires("function execute(address t, bytes memory metadata) public { t.call(metadata); }", "GOV_EXECUTE_NO_TIMELOCK_DELAY"));
        assert!(fires("function proposalThreshold() public view returns (uint256) { return 0; }", "GOV_ZERO_PROPOSAL_THRESHOLD"));
        assert!(!fires("function proposalThreshold() public view returns (uint256) { return 1000e18; }", "GOV_ZERO_PROPOSAL_THRESHOLD"));
    }

    #[test]
    fn mev_rules() {
        assert!(fires("function s() public { r.exactInputSingle(Params({deadline: block.timestamp})); }", "MEV_SWAP_DEADLINE_BLOCK_TIMESTAMP"));
        assert!(fires("function s() public { r.swapExactTokensForTokens(amtIn, 0, path, to, dl); }", "MEV_SWAP_ZERO_AMOUNT_OUT_MIN"));
        assert!(fires("function s() public { r.exactInputSingle(Params({amountOutMinimum: 0})); }", "MEV_SWAP_ZERO_AMOUNT_OUT_MIN"));
        assert!(fires("function approve(address sp, uint256 a) public returns (bool) { _allowances[msg.sender][sp] = a; return true; }", "MEV_FRONTRUNNABLE_ERC20_APPROVE_RACE"));
        // A zero-check guard suppresses the approve-race finding.
        assert!(!fires("function approve(address sp, uint256 a) public returns (bool) { require(a == 0 || _allowances[msg.sender][sp] == 0); _allowances[msg.sender][sp] = a; return true; }", "MEV_FRONTRUNNABLE_ERC20_APPROVE_RACE"));
    }

    #[test]
    fn crosschain_rules() {
        assert!(fires("function executeMessage(bytes memory m) external { _run(m); }", "CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION"));
        assert!(!fires("function executeMessage(bytes memory m) external { require(!processed[id]); processed[id] = true; _run(m); }", "CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION"));
        assert!(fires("function executeMessage(bytes memory m) external { _run(m); }", "CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH"));
        assert!(!fires("function executeMessage(bytes memory m) external onlyRouter { _run(m); }", "CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH"));
        // lzReceive: dedicated rule fires; the generic source-auth rule must NOT (LZ names excluded).
        let lz = "function lzReceive(uint16 src, bytes memory path, uint64 n, bytes memory payload) external { _handle(payload); }";
        assert!(fires(lz, "LZRECEIVE_MISSING_TRUSTED_REMOTE_CHECK"));
        assert!(!fires(lz, "CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH"));
        assert!(!fires("function lzReceive(uint16 src, bytes memory path, uint64 n, bytes memory p) external { require(trustedRemote[src] == path); _handle(p); }", "LZRECEIVE_MISSING_TRUSTED_REMOTE_CHECK"));
        // Review fix: replay-protection coverage is consistent across all LZ handler names.
        assert!(fires("function _blockingLzReceive(uint16 s, bytes memory path, uint64 n, bytes memory p) internal { _handle(p); }", "CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION"));
    }

    #[test]
    fn phase9_rules_have_specs_and_taxonomy() {
        // Every new rule must resolve to a real spec (not the Unknown placeholder).
        for rid in [
            "ACCESS_MISSING_GUARD_PRIVILEGED_FN", "ACCESS_UNPROTECTED_ETHER_WITHDRAWAL",
            "UUPS_AUTHORIZE_UPGRADE_UNGUARDED", "PROXY_PUBLIC_UPGRADE_TO_UNGUARDED",
            "HARDCODED_GAS_TRANSFER_SEND", "RAW_CALL_VALUE_ETH_SEND",
            "REENTRANCY_EXTERNAL_CALL_BEFORE_STATE_WRITE", "UNCHECKED_ARITHMETIC_BLOCK",
            "UNSAFE_DOWNCAST_TRUNCATION", "ORACLE_SPOT_PRICE_FROM_RESERVES",
            "CHAINLINK_LATESTANSWER_DEPRECATED", "CHAINLINK_LATESTROUNDDATA_NO_STALENESS_CHECK",
            "FLASHLOAN_CALLBACK_MISSING_CALLER_OR_INITIATOR_AUTH", "OWNER_BLACKLIST_CONTROL",
            "OWNER_MUTABLE_FEE",
            // Phase 11
            "GOV_VOTE_CURRENT_BLOCK_VOTING_POWER", "GOV_EXECUTE_NO_TIMELOCK_DELAY",
            "GOV_ZERO_PROPOSAL_THRESHOLD", "MEV_SWAP_DEADLINE_BLOCK_TIMESTAMP",
            "MEV_SWAP_ZERO_AMOUNT_OUT_MIN", "MEV_FRONTRUNNABLE_ERC20_APPROVE_RACE",
            "CROSSCHAIN_HANDLER_MISSING_REPLAY_PROTECTION", "CROSSCHAIN_HANDLER_MISSING_SOURCE_AUTH",
            "LZRECEIVE_MISSING_TRUSTED_REMOTE_CHECK",
        ] {
            let f = build_finding(rid, &ContractDetails::minimal("0xa", 1), vec![], "e".into(), "source");
            assert_ne!(f.title, "Unknown", "{rid} has no spec arm");
            assert!(!f.category.is_empty());
        }
    }
}
