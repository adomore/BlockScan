//! Verifiable result bundle (T-13).
//!
//! An audit result that leaves the machine cannot be verified by whoever
//! receives it. A bundle is the directory that fixes that: the artefacts as
//! they were produced, a manifest of their digests, and a detached signature
//! over the manifest.
//!
//! Three deliberate non-decisions, because each is somewhere a tool is tempted
//! to invent something and shouldn't:
//!
//! - **The format is not ours.** The manifest is an [in-toto Statement v1]
//!   carrying a [SLSA Provenance v1] predicate. The mapping is honest rather
//!   than exact — SLSA describes how an artefact was *built*, and here the
//!   build is the scan — but it is the vocabulary the ecosystem's verifiers
//!   already read, and a bespoke schema would need bespoke tooling.
//! - **The signature is not ours.** [`sign_blob`] runs an external signer.
//!   Nothing in this crate touches a key, and there is no code here that could
//!   be mistaken for a trust chain. A homemade one is worth less than none,
//!   because it looks like one.
//! - **The snapshot is not ours to guess.** Every record has to carry the block
//!   pin T-04 records. Attesting to results nobody can return to is the failure
//!   this task exists to avoid, so an unpinned corpus is refused rather than
//!   bundled with the pin field left out.
//!
//! [in-toto Statement v1]: https://in-toto.io/Statement/v1
//! [SLSA Provenance v1]: https://slsa.dev/provenance/v1

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use serde_json::{json, Value};
use sha2::{Digest, Sha256};

use crate::error::{AppError, Result};
use crate::model::ContractDetails;

/// in-toto Statement type URI.
const STATEMENT_TYPE: &str = "https://in-toto.io/Statement/v1";
/// SLSA Provenance predicate type.
const PREDICATE_TYPE: &str = "https://slsa.dev/provenance/v1";
/// This tool's build type within that predicate.
const BUILD_TYPE: &str = "https://github.com/adomore/BlockScan/scan/v1";
/// Builder identity.
const BUILDER_ID: &str = "https://github.com/adomore/BlockScan";
/// Manifest and signature filenames inside the bundle.
pub const MANIFEST_NAME: &str = "manifest.json";
pub const SIGNATURE_NAME: &str = "manifest.sig";
/// Written when `--unsigned` was used, so an unsigned bundle cannot be mistaken
/// for one whose signature merely went missing.
pub const UNSIGNED_MARKER: &str = "UNSIGNED";

/// The chain state a set of records was read at.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Pin {
    pub chain_id: u64,
    pub block_number: u64,
    pub block_hash: String,
}

/// Both digests of one artefact.
///
/// `sha256` because that is what the supply-chain ecosystem verifies with — a
/// bundle only this project can check is not verifiable in any useful sense.
/// `keccak256` because it is this project's hash everywhere else, and because
/// it is the chain-native one; an in-toto `DigestSet` is an open map, so both
/// belong in it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Digests {
    pub sha256: String,
    pub keccak256: String,
}

/// Digest `bytes` with both algorithms.
///
/// Formatting follows the fingerprint idiom in `sarif.rs` and `baseline.rs`:
/// lowercase hex of the raw hash, unprefixed. Those truncate to 16 characters
/// because they are grouping keys; these do not, because they are the thing a
/// recipient re-computes.
pub fn digests(bytes: &[u8]) -> Digests {
    let sha = Sha256::digest(bytes);
    let keccak = alloy::primitives::keccak256(bytes);
    Digests {
        sha256: sha.iter().fold(String::with_capacity(64), |mut a, b| {
            use std::fmt::Write;
            let _ = write!(a, "{b:02x}");
            a
        }),
        keccak256: format!("{keccak:x}"),
    }
}

/// The distinct chain states the corpus was read at.
///
/// Errors when any record carries no pin. That is not pedantry: a bundle over
/// unpinned results applies cryptographic provenance to a snapshot nobody can
/// return to, which is worse than no bundle, because the signature makes it
/// look settled. The message names the first record so the fix is obvious —
/// rescan, or `--at-block`.
pub fn collect_pins(contracts: &[ContractDetails]) -> Result<Vec<Pin>> {
    if contracts.is_empty() {
        return Err(AppError::Config(
            "nothing to attest to: no contract records were found under the corpus".into(),
        ));
    }
    let mut pins = BTreeSet::new();
    for d in contracts {
        match (d.block_number, d.block_hash.as_deref()) {
            (Some(number), Some(hash)) => {
                pins.insert(Pin {
                    chain_id: d.chain_id,
                    block_number: number,
                    block_hash: hash.to_string(),
                });
            }
            _ => {
                return Err(AppError::Config(format!(
                    "{} was read without a block pin, so there is no snapshot to attest to. \
                     Rescan it (optionally with --at-block) before bundling.",
                    d.address
                )))
            }
        }
    }
    Ok(pins.into_iter().collect())
}

/// The in-toto Statement over `subjects`.
///
/// `started` and `finished` are RFC 3339 and come from the caller so this stays
/// pure and testable; [`now_rfc3339`] is what produces them in the real path,
/// and nothing here reads a build-time constant.
pub fn build_statement(
    subjects: &[(String, Digests)],
    pins: &[Pin],
    invocation_id: &str,
    started: &str,
    finished: &str,
) -> Value {
    let subject: Vec<Value> = subjects
        .iter()
        .map(|(name, d)| {
            json!({
                "name": name,
                "digest": { "sha256": d.sha256, "keccak256": d.keccak256 },
            })
        })
        .collect();
    let chain_state: Vec<Value> = pins
        .iter()
        .map(|p| {
            json!({
                "chainId": p.chain_id,
                "blockNumber": p.block_number,
                "blockHash": p.block_hash,
            })
        })
        .collect();

    json!({
        "_type": STATEMENT_TYPE,
        "subject": subject,
        "predicateType": PREDICATE_TYPE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                // The chain state is the external input that decides the
                // result, which is exactly what this field is for.
                "externalParameters": { "chainState": chain_state },
                "internalParameters": {
                    "tool": "blockscan",
                    "version": env!("CARGO_PKG_VERSION"),
                },
                "resolvedDependencies": [],
            },
            "runDetails": {
                "builder": { "id": BUILDER_ID },
                "metadata": {
                    "invocationId": invocation_id,
                    "startedOn": started,
                    "finishedOn": finished,
                },
            },
        },
    })
}

/// The current UTC instant, RFC 3339, seconds precision.
///
/// Read at run time. The distinction matters enough to be named: a provenance
/// record whose timestamp is a compile-time constant says every run happened
/// when the binary was built, which is not a weaker claim but a false one.
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Secs, true)
}

/// A random per-run identifier, hex. From the OS CSPRNG rather than a counter
/// or a clock, so two bundles produced in the same second are still distinct.
pub fn invocation_id() -> String {
    let mut raw = [0u8; 16];
    if getrandom::getrandom(&mut raw).is_err() {
        // Not worth failing a bundle over: the id is for correlation, not for
        // security, and the timestamps already separate runs.
        return String::from("unavailable");
    }
    raw.iter().fold(String::with_capacity(32), |mut a, b| {
        use std::fmt::Write;
        let _ = write!(a, "{b:02x}");
        a
    })
}

/// How a bundle gets its detached signature: given the manifest path and the
/// path to write to, produce one. Named because it is the seam that keeps
/// signing out of this crate — the real implementation is [`sign_blob`], and
/// tests substitute their own.
pub type Signer<'a> = &'a dyn Fn(&Path, &Path) -> Result<()>;

/// What a completed bundle contains.
#[derive(Debug, Clone)]
pub struct BundleReport {
    pub dir: PathBuf,
    /// Artefact filenames inside the bundle, in manifest order.
    pub artefacts: Vec<String>,
    pub pins: Vec<Pin>,
    pub signed: bool,
}

/// The exact command that signs a manifest, for an error message or a log line.
pub fn signing_command(program: &str, manifest: &Path, signature: &Path) -> String {
    format!(
        "{program} sign-blob --yes --output-signature {} {}",
        signature.display(),
        manifest.display()
    )
}

/// Produce a detached signature over `manifest` by running `program`.
///
/// The argument list is cosign's `sign-blob`. Naming one tool and integrating
/// it properly is worth more than a template that fits nothing; point
/// `--sign-with` at another binary only if it honours the same contract —
/// write a detached signature to `--output-signature` and exit zero.
///
/// Nothing here loads a key, and that is the point of the whole function.
pub fn sign_blob(program: &str, manifest: &Path, signature: &Path) -> Result<()> {
    let hint = signing_command(program, manifest, signature);
    let out = std::process::Command::new(program)
        .arg("sign-blob")
        .arg("--yes")
        .arg("--output-signature")
        .arg(signature)
        .arg(manifest)
        .output()
        .map_err(|e| {
            AppError::Config(format!(
                "could not run the signer `{program}`: {e}. \
                 The bundle is written and unsigned; sign it with: {hint}"
            ))
        })?;
    if !out.status.success() {
        let err = String::from_utf8_lossy(&out.stderr);
        let err: String = err.trim().chars().take(400).collect();
        return Err(AppError::Config(format!(
            "the signer exited {}: {err}. The bundle is written and unsigned; retry with: {hint}",
            out.status
        )));
    }
    if !signature.exists() {
        return Err(AppError::Config(format!(
            "the signer reported success but wrote no signature at {}. \
             The bundle is written and unsigned.",
            signature.display()
        )));
    }
    Ok(())
}

/// Assemble a bundle at `dir` from `artefacts`, pinned by `contracts`.
///
/// `sign` is injected rather than called directly so the assembly is testable
/// without a signing tool on the machine, and so this function has no opinion
/// about which one is used.
pub fn write_bundle(
    dir: &Path,
    artefacts: &[PathBuf],
    contracts: &[ContractDetails],
    sign: Option<Signer<'_>>,
) -> Result<BundleReport> {
    if artefacts.is_empty() {
        return Err(AppError::Config(
            "a bundle needs at least one artefact to attest to".into(),
        ));
    }
    let pins = collect_pins(contracts)?;
    let started = now_rfc3339();

    std::fs::create_dir_all(dir)?;
    let mut subjects: Vec<(String, Digests)> = Vec::with_capacity(artefacts.len());
    let mut seen: BTreeSet<String> = BTreeSet::new();
    for src in artefacts {
        let name = src
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| {
                AppError::Config(format!("artefact has no usable filename: {}", src.display()))
            })?
            .to_string();
        // Two artefacts sharing a filename would silently overwrite each other
        // inside the bundle, and the manifest would attest to whichever won.
        if !seen.insert(name.clone()) {
            return Err(AppError::Config(format!(
                "two artefacts are both named {name}; the bundle is flat, so rename one"
            )));
        }
        let bytes = std::fs::read(src)?;
        subjects.push((name.clone(), digests(&bytes)));
        std::fs::write(dir.join(&name), &bytes)?;
    }

    let statement = build_statement(
        &subjects,
        &pins,
        &invocation_id(),
        &started,
        &now_rfc3339(),
    );
    let manifest = dir.join(MANIFEST_NAME);
    std::fs::write(&manifest, serde_json::to_string_pretty(&statement)?)?;

    let signature = dir.join(SIGNATURE_NAME);
    let marker = dir.join(UNSIGNED_MARKER);
    let signed = match sign {
        Some(f) => {
            let _ = std::fs::remove_file(&marker);
            f(&manifest, &signature)?;
            true
        }
        None => {
            // Stated in the bundle, not just on the terminal that produced it:
            // the recipient is the one who needs to know.
            std::fs::write(
                &marker,
                "This bundle was produced with --unsigned. manifest.json describes the \
                 artefacts and the chain state they were read at, but nothing here proves \
                 who produced it. Treat it as unattested.\n",
            )?;
            false
        }
    };

    Ok(BundleReport {
        dir: dir.to_path_buf(),
        artefacts: subjects.into_iter().map(|(n, _)| n).collect(),
        pins,
        signed,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pinned(addr: &str, block: u64) -> ContractDetails {
        let mut d = ContractDetails::minimal(addr, 1);
        d.block_number = Some(block);
        d.block_hash = Some(format!("0x{:064x}", block));
        d
    }

    fn artefact(dir: &Path, name: &str, body: &str) -> PathBuf {
        let p = dir.join(name);
        std::fs::write(&p, body).unwrap();
        p
    }

    // ---- digests ----------------------------------------------------------

    #[test]
    fn digests_follow_the_projects_hex_idiom() {
        let d = digests(b"blockscan");
        assert_eq!(d.sha256.len(), 64, "full sha256, not a grouping-key prefix");
        assert_eq!(d.keccak256.len(), 64);
        assert!(d.sha256.chars().all(|c| c.is_ascii_hexdigit() && !c.is_ascii_uppercase()));
        assert!(!d.keccak256.starts_with("0x"), "unprefixed, as in sarif.rs/baseline.rs");
        // The keccak side must agree with the hash the rest of the codebase computes.
        assert_eq!(d.keccak256, format!("{:x}", alloy::primitives::keccak256(b"blockscan")));
        // And the two algorithms must not be the same function under two names.
        assert_ne!(d.sha256, d.keccak256);
    }

    #[test]
    fn digests_are_sensitive_to_one_bit() {
        assert_ne!(digests(b"a").sha256, digests(b"b").sha256);
        assert_ne!(digests(b"a").keccak256, digests(b"b").keccak256);
        assert_eq!(digests(b"a"), digests(b"a"));
    }

    // ---- the pin ----------------------------------------------------------

    #[test]
    fn an_unpinned_record_refuses_to_be_attested_to() {
        let mut d = pinned("0xa", 100);
        d.block_hash = None;
        let err = collect_pins(&[pinned("0xb", 100), d]).unwrap_err().to_string();
        assert!(err.contains("0xa"), "the offending record must be named: {err}");
        assert!(err.contains("--at-block"), "and the fix stated: {err}");
    }

    #[test]
    fn an_empty_corpus_is_refused() {
        assert!(collect_pins(&[]).is_err());
    }

    #[test]
    fn one_pin_shared_by_every_record_collapses_to_one_entry() {
        let pins = collect_pins(&[pinned("0xa", 19_000_000), pinned("0xb", 19_000_000)]).unwrap();
        assert_eq!(pins.len(), 1);
        assert_eq!(pins[0].block_number, 19_000_000);
        assert_eq!(pins[0].chain_id, 1);
    }

    #[test]
    fn distinct_pins_are_all_recorded() {
        let pins = collect_pins(&[pinned("0xa", 100), pinned("0xb", 101)]).unwrap();
        assert_eq!(pins.len(), 2, "a mixed corpus is described, not flattened");
    }

    // ---- the statement ----------------------------------------------------

    #[test]
    fn the_statement_is_in_toto_carrying_slsa_provenance() {
        let s = build_statement(
            &[("report.md".into(), digests(b"x"))],
            &[Pin { chain_id: 1, block_number: 19_000_000, block_hash: "0xabc".into() }],
            "deadbeef",
            "2026-08-22T10:00:00Z",
            "2026-08-22T10:00:01Z",
        );
        assert_eq!(s["_type"], STATEMENT_TYPE);
        assert_eq!(s["predicateType"], PREDICATE_TYPE);
        assert_eq!(s["subject"][0]["name"], "report.md");
        assert_eq!(s["subject"][0]["digest"]["sha256"], digests(b"x").sha256);
        assert_eq!(s["subject"][0]["digest"]["keccak256"], digests(b"x").keccak256);

        let ext = &s["predicate"]["buildDefinition"]["externalParameters"]["chainState"][0];
        assert_eq!(ext["chainId"], 1);
        assert_eq!(ext["blockNumber"], 19_000_000u64);
        assert_eq!(ext["blockHash"], "0xabc");

        let meta = &s["predicate"]["runDetails"]["metadata"];
        assert_eq!(meta["startedOn"], "2026-08-22T10:00:00Z");
        assert_eq!(meta["finishedOn"], "2026-08-22T10:00:01Z");
        assert_eq!(meta["invocationId"], "deadbeef");
        assert_eq!(s["predicate"]["runDetails"]["builder"]["id"], BUILDER_ID);
    }

    /// The criterion is "no compile-time constant appears in any timestamp
    /// field". A constant is indistinguishable from a real value by inspection,
    /// so this checks the only property that separates them: it tracks the
    /// clock.
    #[test]
    fn timestamps_are_read_at_run_time() {
        let t = now_rfc3339();
        assert!(t.ends_with('Z') && t.len() == 20, "RFC 3339 UTC: {t}");

        // Within a minute of the system clock, which a build-time constant
        // would only be during the build.
        let now = chrono::Utc::now();
        let parsed = chrono::DateTime::parse_from_rfc3339(&t).expect("parses");
        let skew = (now - parsed.with_timezone(&chrono::Utc)).num_seconds().abs();
        assert!(skew < 60, "timestamp is {skew}s from now — is it a constant?");

        // And it is not the build date, which is what a naive implementation
        // would reach for.
        assert_ne!(t, env!("CARGO_PKG_VERSION"));
    }

    #[test]
    fn invocation_ids_differ_between_runs() {
        let a = invocation_id();
        assert_eq!(a.len(), 32);
        assert_ne!(a, invocation_id(), "a per-run id that repeats is not one");
    }

    // ---- assembly ---------------------------------------------------------

    #[test]
    fn a_bundle_holds_the_artefacts_a_manifest_and_a_signature() {
        let tmp = tempfile::tempdir().unwrap();
        let a = artefact(tmp.path(), "report.md", "# report\n");
        let b = artefact(tmp.path(), "audit.sarif", "{}");
        let dir = tmp.path().join("bundle");

        let signed_over = std::cell::RefCell::new(None);
        let sign = |m: &Path, s: &Path| -> Result<()> {
            *signed_over.borrow_mut() = Some(m.to_path_buf());
            std::fs::write(s, "stub-signature")?;
            Ok(())
        };
        let r = write_bundle(&dir, &[a, b], &[pinned("0xa", 19_000_000)], Some(&sign)).unwrap();

        assert!(r.signed);
        assert_eq!(r.artefacts, vec!["report.md", "audit.sarif"]);
        assert_eq!(std::fs::read_to_string(dir.join("report.md")).unwrap(), "# report\n");
        assert!(dir.join(SIGNATURE_NAME).exists());
        assert!(!dir.join(UNSIGNED_MARKER).exists());
        // The signature is over the manifest, not over one of the artefacts.
        assert_eq!(signed_over.into_inner().unwrap(), dir.join(MANIFEST_NAME));

        // Every digest in the manifest re-computes from the bundled bytes —
        // which is the whole claim a recipient checks.
        let m: Value =
            serde_json::from_str(&std::fs::read_to_string(dir.join(MANIFEST_NAME)).unwrap())
                .unwrap();
        for s in m["subject"].as_array().unwrap() {
            let name = s["name"].as_str().unwrap();
            let d = digests(&std::fs::read(dir.join(name)).unwrap());
            assert_eq!(s["digest"]["sha256"], d.sha256, "{name}");
            assert_eq!(s["digest"]["keccak256"], d.keccak256, "{name}");
        }
    }

    #[test]
    fn an_unsigned_bundle_says_so_in_the_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let a = artefact(tmp.path(), "report.md", "x");
        let dir = tmp.path().join("bundle");
        let r = write_bundle(&dir, &[a], &[pinned("0xa", 1)], None).unwrap();
        assert!(!r.signed);
        assert!(!dir.join(SIGNATURE_NAME).exists());
        let marker = std::fs::read_to_string(dir.join(UNSIGNED_MARKER)).unwrap();
        assert!(marker.contains("unattested"), "{marker}");
    }

    #[test]
    fn a_failing_signer_fails_the_bundle() {
        let tmp = tempfile::tempdir().unwrap();
        let a = artefact(tmp.path(), "report.md", "x");
        let dir = tmp.path().join("bundle");
        let sign = |_: &Path, _: &Path| Err(AppError::Config("no key".into()));
        assert!(write_bundle(&dir, &[a], &[pinned("0xa", 1)], Some(&sign)).is_err());
        // The manifest is still on disk: the artefacts and their digests are
        // real work, and the operator can sign it by hand.
        assert!(dir.join(MANIFEST_NAME).exists());
    }

    #[test]
    fn an_unpinned_corpus_stops_before_anything_is_written() {
        let tmp = tempfile::tempdir().unwrap();
        let a = artefact(tmp.path(), "report.md", "x");
        let dir = tmp.path().join("bundle");
        let mut d = pinned("0xa", 1);
        d.block_number = None;
        assert!(write_bundle(&dir, &[a], &[d], None).is_err());
        assert!(!dir.exists(), "a refused bundle must leave no half-written directory");
    }

    #[test]
    fn two_artefacts_with_one_name_are_refused() {
        let tmp = tempfile::tempdir().unwrap();
        let one = tmp.path().join("a");
        let two = tmp.path().join("b");
        std::fs::create_dir_all(&one).unwrap();
        std::fs::create_dir_all(&two).unwrap();
        let a = artefact(&one, "report.md", "first");
        let b = artefact(&two, "report.md", "second");
        let dir = tmp.path().join("bundle");
        let err = write_bundle(&dir, &[a, b], &[pinned("0xa", 1)], None)
            .unwrap_err()
            .to_string();
        assert!(err.contains("report.md"), "{err}");
    }

    #[test]
    fn a_bundle_with_no_artefacts_is_refused() {
        let tmp = tempfile::tempdir().unwrap();
        assert!(write_bundle(&tmp.path().join("b"), &[], &[pinned("0xa", 1)], None).is_err());
    }

    // ---- the signer -------------------------------------------------------

    #[test]
    fn the_signing_command_is_cosigns_and_is_quoted_back_on_failure() {
        let cmd = signing_command("cosign", Path::new("m.json"), Path::new("m.sig"));
        assert!(cmd.starts_with("cosign sign-blob --yes --output-signature"), "{cmd}");
        assert!(cmd.contains("m.sig") && cmd.contains("m.json"));
    }

    /// A missing signer must produce an error a person can act on, not a bare
    /// OS message. Uses a name no PATH will resolve.
    #[test]
    fn a_missing_signer_names_the_command_to_run_by_hand() {
        let tmp = tempfile::tempdir().unwrap();
        let m = artefact(tmp.path(), "manifest.json", "{}");
        let err = sign_blob("blockscan-no-such-signer", &m, &tmp.path().join("m.sig"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("blockscan-no-such-signer"), "{err}");
        assert!(err.contains("sign-blob"), "the exact command must be in it: {err}");
        assert!(err.contains("unsigned"), "{err}");
    }

    /// The invocation itself: a real child process runs, and a signer that
    /// exits zero without writing the file is caught rather than believed.
    #[test]
    fn a_signer_that_writes_nothing_is_not_taken_at_its_word() {
        let tmp = tempfile::tempdir().unwrap();
        let m = artefact(tmp.path(), "manifest.json", "{}");
        // A program that exists everywhere, exits 0, and writes no signature.
        #[cfg(windows)]
        let program = "cmd";
        #[cfg(not(windows))]
        let program = "true";
        let r = sign_blob(program, &m, &tmp.path().join("m.sig"));
        assert!(r.is_err(), "a signature that was never written must not pass");
    }
}
