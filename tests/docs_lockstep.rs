//! Structural lockstep between each bilingual document pair.
//!
//! A reader who only speaks one of the two languages cannot see that the other
//! version has a section theirs does not. That drift is invisible from inside
//! either file, which is why it accumulated: `README.md` and its mirror had
//! grown apart by three sections and a code example before anyone noticed,
//! while the manual and getting-started pairs stayed aligned.
//!
//! What is compared is structure, not text — translations differ in wording by
//! definition. Specifically the sequence of heading levels and the number of
//! code fences, both read with fenced content excluded so a `# comment` inside
//! a shell example is not mistaken for a heading.
//!
//! This lives in `tests/` rather than in a CI script so it fails on the machine
//! that introduced the drift, not two minutes later on a runner. CI already
//! runs `cargo test --all-targets --locked`.

use std::path::{Path, PathBuf};

/// The bilingual pairs this repository keeps in lockstep.
const PAIRS: [(&str, &str); 3] = [
    ("README.md", "README.zh-CN.md"),
    ("docs/USER_MANUAL.md", "docs/USER_MANUAL.en.md"),
    ("docs/GETTING_STARTED.md", "docs/GETTING_STARTED.en.md"),
];

/// One structural element: a heading at some level, or a code fence.
#[derive(Debug, PartialEq, Eq)]
enum Node {
    Heading { level: usize, line: usize, text: String },
    Fence { line: usize },
}

impl Node {
    /// The part that must match across the pair. Heading *text* is excluded —
    /// it is the translation.
    fn shape(&self) -> String {
        match self {
            Node::Heading { level, .. } => format!("h{level}"),
            Node::Fence { .. } => "fence".to_string(),
        }
    }
    fn line(&self) -> usize {
        match self {
            Node::Heading { line, .. } | Node::Fence { line } => *line,
        }
    }
    fn describe(&self) -> String {
        match self {
            Node::Heading { level, line, text } => {
                format!("line {line}: {} {text}", "#".repeat(*level))
            }
            Node::Fence { line } => format!("line {line}: ```"),
        }
    }
}

fn spine(path: &Path) -> Vec<Node> {
    let body = std::fs::read_to_string(path)
        .unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut out = Vec::new();
    let mut in_fence = false;
    for (i, raw) in body.lines().enumerate() {
        let line = i + 1;
        if raw.trim_start().starts_with("```") {
            // Only the opening fence is recorded, so one block counts once.
            if !in_fence {
                out.push(Node::Fence { line });
            }
            in_fence = !in_fence;
            continue;
        }
        if in_fence {
            continue;
        }
        let hashes = raw.chars().take_while(|c| *c == '#').count();
        if (1..=6).contains(&hashes) && raw.chars().nth(hashes) == Some(' ') {
            out.push(Node::Heading {
                level: hashes,
                line,
                text: raw[hashes + 1..].trim().to_string(),
            });
        }
    }
    assert!(!in_fence, "{}: a code fence is never closed", path.display());
    out
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
}

/// The failure message is the whole point: "counts differ" sends someone
/// hunting, so this names the first position that disagrees and shows both
/// sides around it.
fn assert_lockstep(a_rel: &str, b_rel: &str) {
    let (a_path, b_path) = (root().join(a_rel), root().join(b_rel));
    let (a, b) = (spine(&a_path), spine(&b_path));

    for i in 0..a.len().max(b.len()) {
        let (x, y) = (a.get(i), b.get(i));
        let same = match (x, y) {
            (Some(x), Some(y)) => x.shape() == y.shape(),
            _ => false,
        };
        if same {
            continue;
        }
        let mut msg = format!(
            "\n{a_rel} and {b_rel} have drifted apart at structural element {i}.\n\
             The pair must agree on the sequence of heading levels and the number of code\n\
             fences; wording is free.\n\n"
        );
        let show = |label: &str, v: &[Node], i: usize| -> String {
            let lo = i.saturating_sub(2);
            let hi = (i + 3).min(v.len());
            let mut s = format!("  {label}:\n");
            for (k, n) in v.iter().enumerate().take(hi).skip(lo) {
                s.push_str(&format!(
                    "    {} [{k}] {}\n",
                    if k == i { "->" } else { "  " },
                    n.describe()
                ));
            }
            if hi <= i {
                s.push_str(&format!("    -> [{i}] (nothing — this file ends here)\n"));
            }
            s
        };
        msg.push_str(&show(a_rel, &a, i));
        msg.push('\n');
        msg.push_str(&show(b_rel, &b, i));
        panic!("{msg}");
    }

    // Redundant once the walk above passes, but these are the three properties
    // the requirement is written in, so they are asserted in those words.
    let heads = |v: &[Node]| v.iter().filter(|n| matches!(n, Node::Heading { .. })).count();
    let fences = |v: &[Node]| v.iter().filter(|n| matches!(n, Node::Fence { .. })).count();
    assert_eq!(heads(&a), heads(&b), "{a_rel} vs {b_rel}: heading count");
    assert_eq!(fences(&a), fences(&b), "{a_rel} vs {b_rel}: code-fence count");
    assert_eq!(
        a.iter().map(Node::shape).collect::<Vec<_>>(),
        b.iter().map(Node::shape).collect::<Vec<_>>(),
        "{a_rel} vs {b_rel}: heading level sequence"
    );
}

#[test]
fn readme_pair_is_in_lockstep() {
    assert_lockstep(PAIRS[0].0, PAIRS[0].1);
}

#[test]
fn user_manual_pair_is_in_lockstep() {
    assert_lockstep(PAIRS[1].0, PAIRS[1].1);
}

#[test]
fn getting_started_pair_is_in_lockstep() {
    assert_lockstep(PAIRS[2].0, PAIRS[2].1);
}

/// The checker has to be able to fail, or it is decoration. Two spines that
/// differ must be caught, and the message must point at where.
#[test]
fn the_check_detects_a_missing_section() {
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a.md");
    let b = dir.path().join("b.md");
    std::fs::write(&a, "# T\n\n## One\n\n```sh\n# not a heading\n```\n\n## Two\n").unwrap();
    std::fs::write(&b, "# T\n\n## 一\n\n```sh\n# not a heading\n```\n").unwrap();
    let (sa, sb) = (spine(&a), spine(&b));
    assert_eq!(
        sa.iter().map(Node::shape).collect::<Vec<_>>(),
        vec!["h1", "h2", "fence", "h2"],
        "a `#` inside a fence is not a heading, and one block is one fence"
    );
    assert_eq!(sb.iter().map(Node::shape).collect::<Vec<_>>(), vec!["h1", "h2", "fence"]);
    assert_ne!(sa.len(), sb.len(), "the missing section has to be visible");
    assert_eq!(sa[3].line(), 9);
}
