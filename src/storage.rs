use std::path::{Path, PathBuf};

use serde_json::Value;

use crate::error::{AppError, Result};
use crate::model::{ContractDetails, SourceFile};

/// Directory for one contract: `<out>/<lowercase-address>/`.
pub fn contract_dir(out: &Path, address: &str) -> PathBuf {
    out.join(address.to_lowercase())
}

/// True if this contract was already saved (used for resume / dedup).
pub fn already_saved(out: &Path, address: &str) -> bool {
    contract_dir(out, address).join("metadata.json").exists()
}

/// Read back a previously saved contract's `metadata.json`.
pub fn load_metadata(out: &Path, address: &str) -> Result<ContractDetails> {
    let path = contract_dir(out, address).join("metadata.json");
    let data = std::fs::read_to_string(path)?;
    Ok(serde_json::from_str(&data)?)
}

/// Load every `metadata.json` found under `out` (recursively), each paired with
/// the contract directory it was read from (the file's parent). Unreadable/invalid
/// files are skipped. Sorted by address.
///
/// The directory is preserved because a contract's source lives next to its
/// `metadata.json` — which, for non-mainnet / multichain scans, is a per-chain
/// subdir (`out/<chainname>/<addr>/`), not the flat `out/<addr>/`. Callers that
/// also need the source (e.g. `audit`) must load it relative to this directory
/// via [`load_sources_from_dir`], not by recomputing from `out` + address.
pub fn load_all_metadata_with_dirs(out: &Path) -> Vec<(PathBuf, ContractDetails)> {
    let mut found = Vec::new();
    collect_metadata(out, &mut found);
    found.sort_by(|a, b| a.1.address.cmp(&b.1.address));
    found
}

/// Load every `metadata.json` under `out` (recursively), discarding the on-disk
/// directory. For building a run manifest, where the path isn't needed.
pub fn load_all_metadata(out: &Path) -> Vec<ContractDetails> {
    load_all_metadata_with_dirs(out)
        .into_iter()
        .map(|(_, d)| d)
        .collect()
}

fn collect_metadata(dir: &Path, out: &mut Vec<(PathBuf, ContractDetails)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_metadata(&path, out);
        } else if path.file_name().and_then(|n| n.to_str()) == Some("metadata.json") {
            if let Ok(d) = std::fs::read_to_string(&path) {
                if let Ok(c) = serde_json::from_str::<ContractDetails>(&d) {
                    let contract_dir = path.parent().unwrap_or(dir).to_path_buf();
                    out.push((contract_dir, c));
                }
            }
        }
    }
}

/// Read back the source files saved under `<out>/<addr>/source/`, with paths
/// relative to that root (the inverse of `save_contract`'s source writing).
/// Empty when there's no source dir.
pub fn load_sources(out: &Path, address: &str) -> Vec<SourceFile> {
    load_sources_from_dir(&contract_dir(out, address))
}

/// Like [`load_sources`], but reads `<contract_dir>/source/` directly instead of
/// recomputing the path from `out` + address. Used by the offline `audit`
/// subcommand so it reads a contract's source from its *actual* on-disk directory
/// (e.g. the per-chain `out/<chainname>/<addr>/` subdir), not the flat layout.
pub fn load_sources_from_dir(contract_dir: &Path) -> Vec<SourceFile> {
    let root = contract_dir.join("source");
    let mut files = Vec::new();
    collect_sources(&root, &root, &mut files);
    files.sort_by(|a, b| a.path.cmp(&b.path));
    files
}

fn collect_sources(root: &Path, dir: &Path, out: &mut Vec<SourceFile>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        if path.is_dir() {
            collect_sources(root, &path, out);
        } else if let Ok(content) = std::fs::read_to_string(&path) {
            if let Ok(rel) = path.strip_prefix(root) {
                out.push(SourceFile {
                    path: rel.to_string_lossy().replace('\\', "/"),
                    content,
                });
            }
        }
    }
}

/// Parse Etherscan's `SourceCode` field into individual files.
///
/// Handles three shapes:
///  1. Empty string -> no files (unverified).
///  2. `{{ ... }}` double-wrapped Solidity standard-json-input (multi-file).
///  3. `{ ... }` single-wrapped path->{content} map (multi-file).
///  4. Plain source text (single file).
pub fn parse_sources(raw: &str, contract_name: &str) -> Vec<SourceFile> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Vec::new();
    }

    // Case 2: standard-json-input, double-braced.
    if trimmed.starts_with("{{") && trimmed.ends_with("}}") {
        let inner = &trimmed[1..trimmed.len() - 1]; // strip one brace layer
        if let Ok(val) = serde_json::from_str::<Value>(inner) {
            if let Some(files) = sources_from_standard_json(&val) {
                return files;
            }
        }
    }

    // Case 3: single-braced JSON (either {"sources":..} or a bare path->{content} map).
    if trimmed.starts_with('{') && trimmed.ends_with('}') {
        if let Ok(val) = serde_json::from_str::<Value>(trimmed) {
            if let Some(files) = sources_from_standard_json(&val) {
                return files;
            }
            if let Some(files) = sources_from_path_map(&val) {
                return files;
            }
        }
    }

    // Case 4: plain single-file source.
    let name = if contract_name.is_empty() {
        "Contract"
    } else {
        contract_name
    };
    vec![SourceFile {
        path: format!("{name}.sol"),
        content: raw.to_string(),
    }]
}

/// Extract files from a `{ "sources": { "<path>": { "content": "..." } } }` object.
fn sources_from_standard_json(val: &Value) -> Option<Vec<SourceFile>> {
    let sources = val.get("sources")?.as_object()?;
    let mut files = Vec::new();
    for (path, entry) in sources {
        if let Some(content) = entry.get("content").and_then(|c| c.as_str()) {
            files.push(SourceFile {
                path: sanitize_path(path),
                content: content.to_string(),
            });
        }
    }
    if files.is_empty() {
        None
    } else {
        Some(files)
    }
}

/// Extract files from a bare `{ "<path>": { "content": "..." } }` map.
fn sources_from_path_map(val: &Value) -> Option<Vec<SourceFile>> {
    let obj = val.as_object()?;
    let mut files = Vec::new();
    for (path, entry) in obj {
        if let Some(content) = entry.get("content").and_then(|c| c.as_str()) {
            files.push(SourceFile {
                path: sanitize_path(path),
                content: content.to_string(),
            });
        }
    }
    if files.is_empty() {
        None
    } else {
        Some(files)
    }
}

/// Keep project structure but neutralize traversal / absolute paths.
pub(crate) fn sanitize_path(path: &str) -> String {
    let cleaned = path.replace('\\', "/");
    let parts: Vec<&str> = cleaned
        .split('/')
        .filter(|p| !p.is_empty() && *p != "." && *p != "..")
        .collect();
    if parts.is_empty() {
        "Contract.sol".to_string()
    } else {
        parts.join("/")
    }
}

/// Write all artifacts for one contract to disk.
pub fn save_contract(
    out: &Path,
    details: &ContractDetails,
    sources: &[SourceFile],
    abi: Option<&str>,
) -> Result<()> {
    let dir = contract_dir(out, &details.address);
    std::fs::create_dir_all(&dir)?;

    // Bytecode (hex).
    std::fs::write(dir.join("bytecode.hex"), &details.bytecode)?;

    // ABI (only when verified / present).
    if let Some(abi) = abi {
        // Pretty-print if it parses as JSON, else write as-is.
        match serde_json::from_str::<Value>(abi) {
            Ok(v) => std::fs::write(dir.join("abi.json"), serde_json::to_string_pretty(&v)?)?,
            Err(_) => std::fs::write(dir.join("abi.json"), abi)?,
        }
    }

    // Source files.
    if !sources.is_empty() {
        let src_root = dir.join("source");
        for f in sources {
            // Sanitize at the write boundary (defense in depth): `Path::starts_with`
            // is a lexical check that does NOT resolve `..`, so it can't be trusted
            // alone. `sanitize_path` drops `..`/`.`/empty components, so on Unix the
            // join can never climb out of `src_root`. It deliberately does NOT strip
            // a Windows drive prefix (`C:/…`), which `join` treats as absolute and
            // substitutes wholesale — that is the case the guard below actually
            // catches, and it is reachable only on Windows.
            let target = src_root.join(sanitize_path(&f.path));
            if !target.starts_with(&src_root) {
                return Err(AppError::Io(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    format!("refusing to write outside source dir: {}", f.path),
                )));
            }
            std::fs::create_dir_all(target.parent().unwrap_or(&src_root))?;
            std::fs::write(target, &f.content)?;
        }
    }

    // Metadata last, so its presence signals a complete save (resume marker).
    std::fs::write(
        dir.join("metadata.json"),
        serde_json::to_string_pretty(details)?,
    )?;

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::ContractDetails;

    #[test]
    fn parse_sources_empty_returns_nothing() {
        assert!(parse_sources("", "Foo").is_empty());
        assert!(parse_sources("   ", "Foo").is_empty());
    }

    #[test]
    fn parse_sources_plain_single_file() {
        let f = parse_sources("contract C {}", "MyToken");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "MyToken.sol");
        assert_eq!(f[0].content, "contract C {}");
    }

    #[test]
    fn parse_sources_plain_defaults_name_when_blank() {
        let f = parse_sources("contract C {}", "");
        assert_eq!(f[0].path, "Contract.sol");
    }

    #[test]
    fn parse_sources_double_brace_standard_json() {
        let raw = r#"{{"language":"Solidity","sources":{"contracts/A.sol":{"content":"a"},"@oz/B.sol":{"content":"b"}}}}"#;
        let mut f = parse_sources(raw, "Ignored");
        f.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(f.len(), 2);
        assert_eq!(f[0].path, "@oz/B.sol");
        assert_eq!(f[0].content, "b");
        assert_eq!(f[1].path, "contracts/A.sol");
    }

    #[test]
    fn parse_sources_single_brace_with_sources_key() {
        let raw = r#"{"sources":{"X.sol":{"content":"x"}}}"#;
        let f = parse_sources(raw, "Ignored");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "X.sol");
    }

    #[test]
    fn parse_sources_single_brace_path_map() {
        let raw = r#"{"Y.sol":{"content":"y"},"Z.sol":{"content":"z"}}"#;
        let f = parse_sources(raw, "Ignored");
        assert_eq!(f.len(), 2);
    }

    #[test]
    fn parse_sources_invalid_json_falls_back_to_single_file() {
        // Starts and ends with braces but is not valid JSON.
        let f = parse_sources("{not valid json}", "Fallback");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "Fallback.sol");
        assert_eq!(f[0].content, "{not valid json}");
    }

    #[test]
    fn parse_sources_sanitizes_traversal_and_absolute() {
        let raw = r#"{"../../etc/passwd":{"content":"a"},"/abs/x.sol":{"content":"b"},"win\\path\\c.sol":{"content":"c"}}"#;
        let f = parse_sources(raw, "X");
        for sf in &f {
            assert!(!sf.path.contains(".."));
            assert!(!sf.path.starts_with('/'));
            assert!(!sf.path.contains('\\'));
        }
    }

    #[test]
    fn parse_sources_empty_path_defaults() {
        let raw = r#"{"sources":{"..":{"content":"a"}}}"#;
        let f = parse_sources(raw, "X");
        assert_eq!(f[0].path, "Contract.sol");
    }

    #[test]
    fn parse_sources_double_brace_without_sources_falls_back() {
        // Valid JSON inside braces but no "sources" key -> falls through to single file.
        let f = parse_sources(r#"{{"foo":"bar"}}"#, "Name");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "Name.sol");
    }

    #[test]
    fn parse_sources_double_brace_invalid_inner_falls_back() {
        // Looks double-braced but inner is invalid JSON -> single-file fallback.
        let f = parse_sources("{{not json}}", "Name");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "Name.sol");
        assert_eq!(f[0].content, "{{not json}}");
    }

    #[test]
    fn parse_sources_empty_sources_and_path_map_fall_back() {
        // "sources" present but empty, and as a path-map it has no content entries.
        let f = parse_sources(r#"{"sources":{}}"#, "Name");
        assert_eq!(f.len(), 1);
        assert_eq!(f[0].path, "Name.sol");
    }

    #[test]
    fn contract_dir_lowercases() {
        let d = contract_dir(Path::new("out"), "0xABCDEF");
        assert!(d.ends_with("0xabcdef"));
    }

    fn details(addr: &str, verified: bool) -> ContractDetails {
        ContractDetails {
            address: addr.into(),
            chain_id: 1,
            block_number: None,
            block_hash: None,
            incomplete: Vec::new(),
            bytecode: "0x6001".into(),
            bytecode_size: 2,
            balance_wei: "0".into(),
            is_verified: verified,
            contract_name: None,
            compiler_version: None,
            optimization_used: None,
            optimization_runs: None,
            evm_version: None,
            license_type: None,
            constructor_arguments: None,
            is_proxy: false,
            implementation: None,
            proxy_kind: None,
            verified_via: None,
            creator: None,
            creation_tx_hash: None,
            has_abi: verified,
            source_file_count: 0,
            analysis: Default::default(),
            audit: None,
        }
    }

    #[test]
    fn load_all_metadata_walks_and_skips_invalid() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        // Valid contract metadata in a nested dir.
        let good = out.join("0xaaa");
        std::fs::create_dir_all(&good).unwrap();
        std::fs::write(
            good.join("metadata.json"),
            serde_json::to_string(&details("0xaaa", true)).unwrap(),
        )
        .unwrap();
        // Invalid metadata.json -> skipped.
        let bad = out.join("0xbbb");
        std::fs::create_dir_all(&bad).unwrap();
        std::fs::write(bad.join("metadata.json"), "{not json").unwrap();
        // Unrelated file -> ignored.
        std::fs::write(out.join("README.txt"), "hi").unwrap();

        let all = load_all_metadata(out);
        assert_eq!(all.len(), 1);
        assert_eq!(all[0].address, "0xaaa");
    }

    #[test]
    fn load_all_metadata_missing_dir_is_empty() {
        assert!(load_all_metadata(Path::new("definitely/missing/dir")).is_empty());
    }

    #[test]
    fn with_dirs_pairs_metadata_to_its_real_subdir_for_source_loading() {
        // Reproduces the offline-audit bug: a non-mainnet corpus saved under a
        // per-chain subdir (out/optimism/<addr>/) must have its source loaded
        // from that *actual* directory, not from the flat out/<addr>/ path.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let d = details("0xOPABC", true);
        let chain_dir = out.join("optimism");
        let sources = vec![SourceFile {
            path: "C.sol".into(),
            content: "contract C { function f() public { require(tx.origin == msg.sender); } }".into(),
        }];
        save_contract(&chain_dir, &d, &sources, None).unwrap();

        // load_all_metadata_with_dirs finds it and reports the real subdir.
        let found = load_all_metadata_with_dirs(out);
        assert_eq!(found.len(), 1);
        let (dir, c) = &found[0];
        assert_eq!(c.address, "0xOPABC");
        assert!(dir.ends_with("optimism/0xopabc"), "got dir {}", dir.display());

        // Loading from that real dir yields the source...
        let from_dir = load_sources_from_dir(dir);
        assert_eq!(from_dir.len(), 1);
        assert!(from_dir[0].content.contains("tx.origin"));

        // ...whereas the flat out/<addr> path (the old buggy behavior) is empty.
        assert!(load_sources(out, "0xopabc").is_empty());
    }

    #[test]
    fn already_saved_reflects_metadata_presence() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        assert!(!already_saved(out, "0xABC"));
        let d = contract_dir(out, "0xABC");
        std::fs::create_dir_all(&d).unwrap();
        std::fs::write(d.join("metadata.json"), "{}").unwrap();
        assert!(already_saved(out, "0xabc"));
    }

    #[test]
    fn load_metadata_round_trips() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let d = details("0xLOAD", true);
        save_contract(out, &d, &[], None).unwrap();
        let back = load_metadata(out, "0xload").unwrap();
        assert_eq!(back.address, d.address);
        assert_eq!(back.bytecode_size, d.bytecode_size);
    }

    #[test]
    fn load_metadata_missing_errors() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(load_metadata(tmp.path(), "0xnope").is_err());
    }

    #[test]
    fn save_contract_verified_writes_all_artifacts() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let d = details("0xVERIFIED", true);
        let sources = vec![SourceFile {
            path: "nested/dir/A.sol".into(),
            content: "contract A {}".into(),
        }];
        let abi = r#"[{"type":"function","name":"foo"}]"#;
        save_contract(out, &d, &sources, Some(abi)).unwrap();

        let dir = contract_dir(out, "0xVERIFIED");
        assert!(dir.join("bytecode.hex").exists());
        assert!(dir.join("metadata.json").exists());
        assert!(dir.join("abi.json").exists());
        assert!(dir.join("source/nested/dir/A.sol").exists());
        // ABI was valid JSON, so it should be pretty-printed (multi-line).
        let abi_written = std::fs::read_to_string(dir.join("abi.json")).unwrap();
        assert!(abi_written.contains('\n'));
    }

    #[test]
    fn load_sources_round_trips_nested_files() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let d = details("0xSRC", true);
        let sources = vec![
            SourceFile { path: "A.sol".into(), content: "contract A {}".into() },
            SourceFile { path: "lib/B.sol".into(), content: "contract B {}".into() },
        ];
        save_contract(out, &d, &sources, None).unwrap();
        let mut got = load_sources(out, "0xsrc");
        got.sort_by(|a, b| a.path.cmp(&b.path));
        assert_eq!(got.len(), 2);
        assert_eq!(got[0].path, "A.sol");
        assert_eq!(got[0].content, "contract A {}");
        assert_eq!(got[1].path, "lib/B.sol");
        // Missing source dir -> empty, no panic.
        assert!(load_sources(out, "0xdoesnotexist").is_empty());
    }

    #[test]
    fn save_contract_unverified_skips_source_and_abi() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let d = details("0xUNVERIFIED", false);
        save_contract(out, &d, &[], None).unwrap();

        let dir = contract_dir(out, "0xunverified");
        assert!(dir.join("bytecode.hex").exists());
        assert!(dir.join("metadata.json").exists());
        assert!(!dir.join("abi.json").exists());
        assert!(!dir.join("source").exists());
    }

    #[test]
    fn save_contract_writes_non_json_abi_verbatim() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let d = details("0xRAW", true);
        save_contract(out, &d, &[], Some("not-json-abi")).unwrap();
        let dir = contract_dir(out, "0xraw");
        assert_eq!(
            std::fs::read_to_string(dir.join("abi.json")).unwrap(),
            "not-json-abi"
        );
    }

    #[test]
    fn save_contract_propagates_metadata_write_error() {
        // Pre-create a *directory* named metadata.json so the final write fails.
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let dir = contract_dir(out, "0xMETA");
        std::fs::create_dir_all(dir.join("metadata.json")).unwrap();
        let d = details("0xMETA", false);
        let err = save_contract(out, &d, &[], None).unwrap_err();
        assert!(matches!(err, AppError::Io(_)));
    }

    #[test]
    fn save_contract_rejects_path_escape() {
        let tmp = tempfile::tempdir().unwrap();
        let out = tmp.path();
        let d = details("0xESCAPE", true);
        let contract = contract_dir(out, "0xESCAPE");

        // Hostile paths as they could arrive in an Etherscan source manifest.
        // Whether a given string *is* an escape is platform-specific — `C:/x` is
        // absolute on Windows but an ordinary directory name on Unix — so assert
        // the invariant that holds everywhere instead of demanding a specific
        // error: a save either refuses, or writes strictly inside `source/`.
        for hostile in [
            "../../evil.sol",
            "./../evil.sol",
            "/etc/passwd",
            "C:/evil.sol",
            r"..\..\evil.sol",
        ] {
            let sources = vec![SourceFile {
                path: hostile.into(),
                content: "x".into(),
            }];
            if let Err(e) = save_contract(out, &d, &sources, None) {
                assert!(matches!(e, AppError::Io(_)), "{hostile}: unexpected {e:?}");
                continue;
            }
            for probe in [
                out.join("evil.sol"),
                out.join("passwd"),
                contract.join("evil.sol"),
                contract.join("passwd"),
            ] {
                assert!(!probe.exists(), "{hostile} escaped to {}", probe.display());
            }
        }
    }
}
