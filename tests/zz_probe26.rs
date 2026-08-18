use std::path::{Path, PathBuf};

fn walk(root: &Path, dir: &Path, out: &mut Vec<(String, String)>) {
    let Ok(entries) = std::fs::read_dir(dir) else { return };
    for e in entries.flatten() {
        let p = e.path();
        if p.is_dir() {
            walk(root, &p, out);
        } else if let Ok(c) = std::fs::read_to_string(&p) {
            if let Ok(rel) = p.strip_prefix(root) {
                out.push((rel.to_string_lossy().replace(std::path::MAIN_SEPARATOR, "/"), c));
            }
        }
    }
}

fn units() -> Vec<(String, Vec<(String, String)>)> {
    let out = Path::new("D:/AI/00.Claude/BlockScan/out");
    let mut dirs: Vec<PathBuf> =
        std::fs::read_dir(out).unwrap().flatten().map(|e| e.path()).filter(|p| p.is_dir()).collect();
    dirs.sort();
    let mut res = Vec::new();
    for d in &dirs {
        let cname = d.file_name().unwrap().to_string_lossy().to_string();
        let root = d.join("source");
        let mut files: Vec<(String, String)> = Vec::new();
        walk(&root, &root, &mut files);
        files.sort();
        if files.is_empty() {
            continue;
        }
        res.push((cname, files));
    }
    res
}

#[test]
fn zz_corpus_access_hits() {
    const RULE: &str = "ACCESS_MISSING_GUARD_PRIVILEGED_FN";
    let mut total = 0usize;
    let (mut unit_ok, mut unit_none) = (0usize, 0usize);
    let all = units();
    for (cname, files) in &all {
        let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
        match blockscan::ast::detect_unit(&refs) {
            Some(map) => {
                unit_ok += 1;
                let mut keys: Vec<&String> = map.keys().collect();
                keys.sort();
                for k in keys {
                    for h in &map[k] {
                        if h.rule_id == RULE {
                            println!("HIT {cname} {k}:{} {}", h.line, h.evidence);
                            total += 1;
                        }
                    }
                }
            }
            None => {
                unit_none += 1;
                for (p, c) in files {
                    if let Some(hits) = blockscan::ast::detect(c) {
                        for h in &hits {
                            if h.rule_id == RULE {
                                println!("HIT(perfile) {cname} {p}:{} {}", h.line, h.evidence);
                                total += 1;
                            }
                        }
                    }
                }
            }
        }
    }
    println!("TOTAL {total} unit_ok={unit_ok} unit_none={unit_none} units={}", all.len());
}

#[test]
fn zz_corpus_all_rules() {
    let mut counts: std::collections::BTreeMap<String, usize> = Default::default();
    for (_cname, files) in &units() {
        let refs: Vec<(&str, &str)> = files.iter().map(|(p, c)| (p.as_str(), c.as_str())).collect();
        match blockscan::ast::detect_unit(&refs) {
            Some(map) => {
                for v in map.values() {
                    for h in v {
                        *counts.entry(h.rule_id.to_string()).or_default() += 1;
                    }
                }
            }
            None => {
                for (_p, c) in files {
                    if let Some(hits) = blockscan::ast::detect(c) {
                        for h in &hits {
                            *counts.entry(h.rule_id.to_string()).or_default() += 1;
                        }
                    }
                }
            }
        }
    }
    for (k, v) in &counts {
        println!("RULE {k} {v}");
    }
}
