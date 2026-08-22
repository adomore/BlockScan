#!/usr/bin/env python3
"""
seed_known_good.py — operator helper for filling corpus/known_good.json.

Turns a contract blockscan has already fetched into a reviewable adjudication
sheet, then into an entry draft. It automates the fetching and the formatting;
it does NOT decide anything. Every High or Critical finding stops the tool and
waits for you.

WHY IT REFUSES TO DECIDE. The question this corpus answers is "is this finding
false?", and that requires reading the Solidity. A script that auto-accepted a
contract because blockscan reported it clean would be circular: a rule broken
badly enough to never fire would make every contract look eligible, and the
break would be frozen into the corpus as correct behaviour.

USAGE
    # 1. fetch with blockscan first (this script never touches the network)
    blockscan addresses 0xABC... --chain-id 1 --out corpus/known_good_work

    # 2. review what it found
    python3 seed_known_good.py review \
        --out corpus/known_good_work --address 0xABC...

    # 3. after you have adjudicated, emit the entry draft
    python3 seed_known_good.py entry \
        --out corpus/known_good_work --address 0xABC... \
        --slot amm-pair --pinned-block 20123456 \
        --why "guards ORACLE_SPOT_PRICE_FROM_RESERVES against firing on a pair" \
        --accept OUTDATED_COMPILER="solc 0.4.x; correct and below the gate"

    # 4. check the whole file before committing
    python3 seed_known_good.py check --file corpus/known_good.json
"""

from __future__ import annotations

import argparse
import json
import os
import sys

GATE_SEVERITIES = ("High", "Critical")
TARGET_ENTRIES = 10


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def load_metadata(out: str, address: str) -> dict:
    path = os.path.join(out, address.lower(), "metadata.json")
    if not os.path.exists(path):
        sys.exit(
            f"not found: {path}\n"
            f"Fetch it first:\n"
            f"  blockscan addresses {address} --chain-id 1 --out {out}"
        )
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def findings(meta: dict) -> list[dict]:
    return ((meta.get("audit") or {}).get("findings")) or []


def source_root(out: str, address: str) -> str:
    return os.path.join(out, address.lower(), "source")


# ---------------------------------------------------------------------------
# review — the adjudication sheet
# ---------------------------------------------------------------------------


def cmd_review(args: argparse.Namespace) -> int:
    meta = load_metadata(args.out, args.address)
    audit = meta.get("audit") or {}
    fs = findings(meta)

    print("=" * 78)
    print(f"  {meta.get('contract_name') or '(unnamed)'}   {meta.get('address')}")
    print("=" * 78)
    print(f"  chain_id ......... {meta.get('chain_id')}")
    print(f"  verified ......... {meta.get('is_verified')}   via {meta.get('verified_via')}")
    print(f"  compiler ......... {meta.get('compiler_version')}")
    print(f"  proxy ............ {meta.get('proxy_kind') or 'no'}"
          f"{'  -> ' + meta['implementation'] if meta.get('implementation') else ''}")
    print(f"  source files ..... {meta.get('source_file_count')}")
    print(f"  risk ............. {audit.get('risk_score')}  grade {audit.get('grade')}")

    # Eligibility preconditions that do not need judgement.
    problems = []
    if not meta.get("is_verified"):
        problems.append("source is not verified — bytecode-tier rules only, cannot exercise source rules")
    if meta.get("proxy_kind") and not meta.get("implementation"):
        problems.append("proxy with no resolved implementation — the audit examined a shell")
    if problems:
        print()
        print("  PRECONDITION FAILURES — this contract is not eligible as-is:")
        for p in problems:
            print(f"    - {p}")

    gating = [f for f in fs if f.get("severity") in GATE_SEVERITIES]
    other = [f for f in fs if f.get("severity") not in GATE_SEVERITIES]

    print()
    print(f"  findings: {len(fs)} total, {len(gating)} at or above the gate threshold")

    if not gating:
        print()
        print("  No High or Critical. That is the EXPECTED result for a blue chip,")
        print("  not the reason to include it — confirm the contract is genuinely")
        print("  well-regarded before adding it, or the gate proves nothing.")
    else:
        print()
        print("  " + "-" * 74)
        print("  ADJUDICATE EACH OF THESE. Open the source line and answer:")
        print("  does this code really have this problem?")
        print("  " + "-" * 74)
        for i, f in enumerate(gating, 1):
            print()
            print(f"  [{i}] {f.get('severity')}  {f.get('rule_id')}")
            print(f"      category .. {f.get('category')}")
            if f.get("swc"):
                print(f"      swc ....... {f.get('swc')}")
            print(f"      evidence .. {(f.get('evidence') or '')[:160]}")
            for loc in (f.get("locations") or [])[:4]:
                print(f"      at ........ {source_root(args.out, args.address)}/{loc}")
            if f.get("false_positive_notes"):
                print(f"      fp notes .. {f['false_positive_notes'][:160]}")
            print("      -> false positive?  file a bug against the rule, then --accept is NOT needed")
            print("      -> true but acceptable here?  pass --accept "
                  f"{f.get('rule_id')}=\"<reason>\"")
            print("      -> true and a real risk?  pick a different contract")

    if other:
        print()
        print(f"  below the gate ({len(other)}), worth a glance for obvious false positives:")
        for f in other:
            print(f"    {f.get('severity'):8} {f.get('rule_id')}")

    print()
    return 1 if problems else 0


# ---------------------------------------------------------------------------
# entry — emit the draft
# ---------------------------------------------------------------------------


def cmd_entry(args: argparse.Namespace) -> int:
    meta = load_metadata(args.out, args.address)

    accepted: dict[str, str] = {}
    for pair in args.accept or []:
        if "=" not in pair:
            sys.exit(f"--accept expects RULE_ID=\"reason\", got: {pair}")
        rule, reason = pair.split("=", 1)
        if not reason.strip():
            sys.exit(f"--accept {rule} has an empty reason. An accepted finding without a "
                     f"written reason is indistinguishable from one nobody looked at.")
        accepted[rule.strip()] = reason.strip()

    fs = findings(meta)
    gating = [f for f in fs if f.get("severity") in GATE_SEVERITIES]
    unadjudicated = [f for f in gating if f.get("rule_id") not in accepted]

    if unadjudicated:
        print("REFUSING to emit an entry. These gate-level findings are neither accepted")
        print("nor resolved. Adjudicate them first (see `review`):")
        for f in unadjudicated:
            print(f"  {f.get('severity'):8} {f.get('rule_id')}")
        print()
        print("If you judged one a FALSE POSITIVE, do not --accept it: the entry belongs")
        print("in the corpus precisely so the gate catches that rule regressing. Fix or")
        print("file the rule bug, re-run, and try again.")
        return 1

    entry = {
        "chain_id": meta.get("chain_id"),
        "address": meta.get("address", "").lower(),
        "name": meta.get("contract_name") or args.slot,
        "verified": True,
        "verified_how": args.verified_how
        or f"fetched and audited with blockscan; source verified via {meta.get('verified_via')}; "
           f"compiler {meta.get('compiler_version')}",
        "pinned_block": args.pinned_block,
        "why_in_set": args.why or f"slot: {args.slot}",
        "known_acceptable_findings": [
            {
                "rule_id": rule,
                "severity": next((f.get("severity") for f in fs if f.get("rule_id") == rule), "Unknown"),
                "reason": reason,
            }
            for rule, reason in accepted.items()
        ],
    }

    print(json.dumps(entry, indent=2, ensure_ascii=False))
    return 0


# ---------------------------------------------------------------------------
# check — pre-commit validation of the whole file
# ---------------------------------------------------------------------------


def cmd_check(args: argparse.Namespace) -> int:
    with open(args.file, encoding="utf-8") as fh:
        doc = json.load(fh)

    entries = doc.get("entries", [])
    errors: list[str] = []
    seen: set[tuple] = set()

    for e in entries:
        who = e.get("address", "<no address>")
        if not e.get("verified"):
            errors.append(f"{who}: verified is not true")
        if e.get("pinned_block") in (None, "", "PIN_ME"):
            errors.append(f"{who}: pinned_block is unset — the gate would assert a moving target")
        addr = str(e.get("address", ""))
        if not (addr.startswith("0x") and len(addr) == 42):
            errors.append(f"{who}: address is not a 20-byte hex address")
        if addr != addr.lower():
            errors.append(f"{who}: address is not lowercase — it will not match the storage path")
        key = (e.get("chain_id"), addr.lower())
        if key in seen:
            errors.append(f"{who}: duplicate (chain_id, address)")
        seen.add(key)
        for acc in e.get("known_acceptable_findings", []):
            if not (acc.get("reason") or "").strip():
                errors.append(f"{who}: accepted {acc.get('rule_id')} has no reason")

    print(f"entries: {len(entries)} (target {TARGET_ENTRIES})")
    if len(entries) < TARGET_ENTRIES:
        print(f"  note: {TARGET_ENTRIES - len(entries)} slot(s) still open — that is a TODO, not an error")

    if errors:
        print()
        print("ERRORS:")
        for err in errors:
            print(f"  - {err}")
        return 1

    print("all entries verified and pinned.")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = ap.add_subparsers(dest="cmd", required=True)

    r = sub.add_parser("review", help="print the adjudication sheet for one contract")
    r.add_argument("--out", required=True)
    r.add_argument("--address", required=True)
    r.set_defaults(fn=cmd_review)

    e = sub.add_parser("entry", help="emit a known_good.json entry draft")
    e.add_argument("--out", required=True)
    e.add_argument("--address", required=True)
    e.add_argument("--slot", required=True)
    e.add_argument("--pinned-block", required=True, type=int)
    e.add_argument("--why")
    e.add_argument("--verified-how")
    e.add_argument("--accept", action="append", metavar='RULE_ID="reason"')
    e.set_defaults(fn=cmd_entry)

    c = sub.add_parser("check", help="validate the whole file before committing")
    c.add_argument("--file", required=True)
    c.set_defaults(fn=cmd_check)

    args = ap.parse_args()
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main())
