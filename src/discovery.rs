use std::path::Path;
use std::str::FromStr;

use alloy::primitives::Address;

use crate::error::{AppError, Result};

/// Parse addresses from CLI args and/or a file (one per line, `#` comments allowed).
pub fn load_addresses(args: &[String], file: Option<&Path>) -> Result<Vec<Address>> {
    let mut raw: Vec<String> = args.to_vec();

    if let Some(path) = file {
        let content = std::fs::read_to_string(path)?;
        for line in content.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            raw.push(line.to_string());
        }
    }

    let mut out = Vec::with_capacity(raw.len());
    for s in raw {
        let s = s.trim();
        let addr = Address::from_str(s).map_err(|_| AppError::Address(s.to_string()))?;
        out.push(addr);
    }

    // Dedup while preserving order.
    let mut seen = std::collections::HashSet::new();
    out.retain(|a| seen.insert(*a));
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const A1: &str = "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48";
    const A2: &str = "0xE592427A0AEce92De3Edee1F18E0157C05861564";

    #[test]
    fn loads_from_args_and_dedups() {
        let args = vec![A1.to_string(), A2.to_string(), A1.to_string()];
        let out = load_addresses(&args, None).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn rejects_invalid_address() {
        let args = vec!["not-an-address".to_string()];
        let err = load_addresses(&args, None).unwrap_err();
        assert!(matches!(err, AppError::Address(_)));
    }

    #[test]
    fn loads_from_file_with_comments_and_blanks() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("addrs.txt");
        std::fs::write(&path, format!("# comment\n{A1}\n\n  {A2}  \n# another\n")).unwrap();
        let out = load_addresses(&[], Some(&path)).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn combines_args_and_file_then_dedups() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("addrs.txt");
        std::fs::write(&path, format!("{A1}\n")).unwrap();
        let out = load_addresses(&[A1.to_string(), A2.to_string()], Some(&path)).unwrap();
        assert_eq!(out.len(), 2);
    }

    #[test]
    fn missing_file_errors() {
        let err = load_addresses(&[], Some(Path::new("does/not/exist.txt"))).unwrap_err();
        assert!(matches!(err, AppError::Io(_)));
    }

    #[test]
    fn empty_inputs_yield_empty() {
        assert!(load_addresses(&[], None).unwrap().is_empty());
    }
}
