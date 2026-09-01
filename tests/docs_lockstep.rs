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
//! Structure alone turned out not to be enough. Between structure and wording
//! there is a third layer — *fact* — and the pair drifted there while every
//! structural check stayed green: the same `cargo test` fence claimed 693 tests
//! in English and 637 in Chinese, the English "Known limitations" carried a
//! disclaimer ("a triage signal, not a verifier") the Chinese list did not, and
//! the Chinese `monitor` section documented four flags the English one never
//! mentioned. None of that moves a heading or adds a fence.
//!
//! So a second family of assertions compares the things that are facts rather
//! than translation:
//!
//! - the **command surface** — every `blockscan`/`cargo` invocation inside a
//!   fence, reduced to `(program, subcommand, sorted long flags)`. Sample
//!   output, placeholder arguments (`<addr...>` vs `<地址...>`) and comments are
//!   all legitimately translated, so comparing fence bodies verbatim produces
//!   noise; which commands and flags a reader is shown is not translation.
//! - the **number of list items**, which is how a missing bullet shows up.
//! - the **shape of every table**, rows *and columns* — the monitored-events
//!   table had eight rows on both sides and a third column on only one.
//! - the **number of links**, which is how a dropped cross-reference shows up.
//!
//! Deliberately not compared: paragraph counts (Chinese splits prose
//! differently), link *targets* (anchors are translated, and each version links
//! to its own mirror), and numbers inside fences (sample output differs on
//! purpose).
//!
//! This lives in `tests/` rather than in a CI script so it fails on the machine
//! that introduced the drift, not two minutes later on a runner. CI already
//! runs `cargo test --all-targets --locked`.

use std::path::{Path, PathBuf};

/// The bilingual pairs this repository keeps in lockstep. Chinese takes the
/// base name and English the `.en` suffix throughout — the README used to be
/// the exception, which meant the one file GitHub renders was the one file that
/// did not follow the convention.
const PAIRS: [(&str, &str); 3] = [
    ("README.md", "README.en.md"),
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

// ---------------------------------------------------------------------------
// The fact layer.
// ---------------------------------------------------------------------------

/// Programs whose invocations are part of the documented interface. A line
/// starting with anything else (`jq`, `$env:`, `export`, rendered output) is
/// prose or illustration, not a claim about this tool's surface.
const PROGRAMS: [&str; 2] = ["blockscan", "cargo"];

/// One demonstrated invocation, stripped down to the part that is not
/// translation: the program, its subcommand, and which long flags it passes.
/// Argument *values* are excluded on purpose — `--file addrs.txt` and
/// `--file 地址.txt` document the same thing.
#[derive(Debug, PartialEq, Eq, PartialOrd, Ord, Clone)]
struct Invocation {
    program: String,
    subcommand: String,
    flags: Vec<String>,
}

impl Invocation {
    fn describe(&self) -> String {
        let mut s = self.program.clone();
        if !self.subcommand.is_empty() {
            s.push(' ');
            s.push_str(&self.subcommand);
        }
        for f in &self.flags {
            s.push(' ');
            s.push_str(f);
        }
        s
    }
}

/// Everything the fact layer compares, read from one file.
#[derive(Debug)]
struct Facts {
    invocations: Vec<Invocation>,
    /// `(rows, columns)` for each pipe table, in document order.
    tables: Vec<(usize, usize)>,
    bullets: usize,
    links: usize,
}

/// Drop a shell comment. `#` only opens one at the start of the line or after
/// whitespace, and never inside quotes — otherwise `README.md#changelog` and
/// `--filter "a #b"` would be truncated.
fn strip_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut prev = ' ';
    for (i, c) in line.char_indices() {
        match quote {
            Some(q) => {
                if c == q {
                    quote = None;
                }
            }
            None => {
                if c == '\'' || c == '"' {
                    quote = Some(c);
                } else if c == '#' && (i == 0 || prev == ' ' || prev == '\t') {
                    return &line[..i];
                }
            }
        }
        prev = c;
    }
    line
}

/// True for a markdown list item: `- `, `* `, `+ `, or `1. `.
fn is_list_item(line: &str) -> bool {
    let t = line.trim_start();
    let mut ch = t.chars();
    match ch.next() {
        Some('-') | Some('*') | Some('+') => ch.next() == Some(' '),
        Some(d) if d.is_ascii_digit() => {
            let rest = t.trim_start_matches(|c: char| c.is_ascii_digit());
            rest.starts_with(". ")
        }
        _ => false,
    }
}

/// Count `[text](target)` occurrences on one line.
fn count_links(line: &str) -> usize {
    let b: Vec<char> = line.chars().collect();
    let (mut i, mut n) = (0usize, 0usize);
    while i < b.len() {
        if b[i] == '[' {
            if let Some(close) = (i + 1..b.len()).find(|&k| b[k] == ']') {
                if close + 1 < b.len() && b[close + 1] == '(' {
                    if let Some(end) = (close + 2..b.len()).find(|&k| b[k] == ')') {
                        n += 1;
                        i = end + 1;
                        continue;
                    }
                }
            }
        }
        i += 1;
    }
    n
}

fn facts(path: &Path) -> Facts {
    let body = std::fs::read_to_string(path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
    let mut f = Facts { invocations: Vec::new(), tables: Vec::new(), bullets: 0, links: 0 };
    let mut in_fence = false;
    let mut continued = String::new();
    let mut table: Vec<usize> = Vec::new();

    for raw in body.lines() {
        if raw.trim_start().starts_with("```") {
            in_fence = !in_fence;
            continued.clear();
            continue;
        }

        if in_fence {
            let mut line = strip_comment(raw).trim().to_string();
            if line.is_empty() {
                continue;
            }
            // Shell line continuations: a trailing `\` glues the next line on.
            if !continued.is_empty() {
                line = format!("{continued} {line}");
                continued.clear();
            }
            if let Some(head) = line.strip_suffix('\\') {
                continued = head.trim_end().to_string();
                continue;
            }
            let toks: Vec<&str> = line.split_whitespace().collect();
            let Some(&program) = toks.first() else { continue };
            if !PROGRAMS.contains(&program) {
                continue;
            }
            let subcommand = match toks.get(1) {
                Some(t) if !t.starts_with('-') => (*t).to_string(),
                _ => String::new(),
            };
            let mut flags: Vec<String> = toks
                .iter()
                .filter(|t| t.starts_with("--") && t.len() > 2)
                .map(|t| t.split('=').next().unwrap_or(t).to_string())
                .collect();
            flags.sort();
            flags.dedup();
            f.invocations.push(Invocation { program: program.to_string(), subcommand, flags });
            continue;
        }

        // Outside fences.
        let t = raw.trim();
        if t.len() > 1 && t.starts_with('|') && t.ends_with('|') {
            table.push(t.trim_matches('|').split('|').count());
            f.links += count_links(raw);
            continue;
        }
        if !table.is_empty() {
            let rows = table.len();
            let cols = table.iter().copied().max().unwrap_or(0);
            f.tables.push((rows, cols));
            table.clear();
        }
        if is_list_item(raw) {
            f.bullets += 1;
        }
        f.links += count_links(raw);
    }
    if !table.is_empty() {
        let cols = table.iter().copied().max().unwrap_or(0);
        f.tables.push((table.len(), cols));
    }
    f.invocations.sort();
    f
}

/// Report one side's surplus against the other, naming the items rather than
/// the counts — "39 vs 34" sends someone hunting through two files.
fn surplus(label: &str, a: &[Invocation], b: &[Invocation]) -> String {
    let mut out = String::new();
    let mut rest: Vec<&Invocation> = b.iter().collect();
    for x in a {
        match rest.iter().position(|y| *y == x) {
            Some(k) => {
                rest.remove(k);
            }
            None => out.push_str(&format!("    only in {label}: {}\n", x.describe())),
        }
    }
    out
}

fn assert_facts(a_rel: &str, b_rel: &str) {
    let (a, b) = (facts(&root().join(a_rel)), facts(&root().join(b_rel)));

    let (extra_a, extra_b) =
        (surplus(a_rel, &a.invocations, &b.invocations), surplus(b_rel, &b.invocations, &a.invocations));
    assert!(
        extra_a.is_empty() && extra_b.is_empty(),
        "\n{a_rel} and {b_rel} demonstrate different commands.\n\
         Sample output and placeholder arguments are free; which commands and flags a\n\
         reader is shown is not.\n\n{extra_a}{extra_b}"
    );

    assert_eq!(
        a.tables, b.tables,
        "\n{a_rel} and {b_rel} disagree on table shape (rows, columns), listed in\n\
         document order. A column present on one side only is a fact the other\n\
         language's reader never sees."
    );

    assert_eq!(
        a.bullets, b.bullets,
        "\n{a_rel} has {} list items, {b_rel} has {}. One side is documenting\n\
         something the other is not.",
        a.bullets, b.bullets
    );

    assert_eq!(
        a.links, b.links,
        "\n{a_rel} has {} links, {b_rel} has {}. Targets are free (anchors are\n\
         translated, each version links to its own mirror) but a dropped\n\
         cross-reference is not.",
        a.links, b.links
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

#[test]
fn readme_pair_agrees_on_facts() {
    assert_facts(PAIRS[0].0, PAIRS[0].1);
}

#[test]
fn user_manual_pair_agrees_on_facts() {
    assert_facts(PAIRS[1].0, PAIRS[1].1);
}

#[test]
fn getting_started_pair_agrees_on_facts() {
    assert_facts(PAIRS[2].0, PAIRS[2].1);
}

/// The four drifts that actually happened, in miniature. Each asserts the
/// checker sees the difference — a check that cannot fail is decoration.
#[test]
fn the_fact_layer_detects_each_drift_it_was_written_for() {
    let dir = tempfile::tempdir().unwrap();
    let write = |name: &str, body: &str| {
        let p = dir.path().join(name);
        std::fs::write(&p, body).unwrap();
        p
    };

    // A flag documented in one language only (the `--alert-topic` case).
    let a = write("cmd_a.md", "```sh\nblockscan monitor --from 1 --alert-topic 0xab\n```\n");
    let b = write("cmd_b.md", "```sh\nblockscan monitor --from 1\n```\n");
    let (fa, fb) = (facts(&a), facts(&b));
    assert_ne!(fa.invocations, fb.invocations, "a flag on one side only must be visible");
    assert!(surplus("a", &fa.invocations, &fb.invocations).contains("--alert-topic"));

    // Same flags, different argument values and comments — NOT drift.
    let a = write("same_a.md", "```sh\nblockscan addresses --file addrs.txt  # scan them\n```\n");
    let b = write("same_b.md", "```sh\nblockscan addresses --file 地址.txt  # 扫描\n```\n");
    assert_eq!(
        facts(&a).invocations,
        facts(&b).invocations,
        "argument values and comments are translation, not fact"
    );

    // A `#` inside a quoted argument does not open a comment.
    let q = write("quote.md", "```sh\nblockscan discover \"a #b\" --github o/r\n```\n");
    assert_eq!(facts(&q).invocations[0].flags, vec!["--github".to_string()]);

    // A line continuation is one invocation, not two.
    let c = write("cont.md", "```sh\nblockscan monitor --from 1 \\\n  --to 2 -o out\n```\n");
    let inv = facts(&c).invocations;
    assert_eq!(inv.len(), 1, "a continued command is one invocation");
    assert_eq!(inv[0].flags, vec!["--from".to_string(), "--to".to_string()]);

    // A column on one side only (the monitored-events table case).
    let a = write("tbl_a.md", "| E | Meaning | Fields |\n|---|---|---|\n| x | y | z |\n");
    let b = write("tbl_b.md", "| E | 含义 |\n|---|---|\n| x | y |\n");
    assert_eq!(facts(&a).tables, vec![(3, 3)]);
    assert_eq!(facts(&b).tables, vec![(3, 2)], "same rows, fewer columns must differ");

    // A missing bullet (the "not a verifier" disclaimer case).
    let a = write("bul_a.md", "- one\n- two\n- 3. not a list\n");
    let b = write("bul_b.md", "- 一\n");
    assert_eq!(facts(&a).bullets, 3);
    assert_eq!(facts(&b).bullets, 1);

    // A dropped cross-reference, and a `#` in a link target surviving.
    let a = write("lnk_a.md", "see [Releases](#releases) and [docs](docs/X.md)\n");
    let b = write("lnk_b.md", "见 [docs](docs/X.md)\n");
    assert_eq!(facts(&a).links, 2);
    assert_eq!(facts(&b).links, 1);

    // Fenced content is not scanned for bullets, tables or links.
    let f = write("fenced.md", "```sh\n- not a bullet\n| not | a table |\n[not](a-link)\n```\n");
    let ff = facts(&f);
    assert_eq!((ff.bullets, ff.tables.len(), ff.links), (0, 0, 0));
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
