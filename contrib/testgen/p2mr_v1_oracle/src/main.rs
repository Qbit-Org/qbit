mod corpus;
mod encoding;
mod p2mr;
mod report;
mod script;
mod transaction;

use p2mr::Observation;
use std::env;
use std::path::{Path, PathBuf};
use std::process::Command;

struct Arguments {
    command: String,
    manifest: String,
    source_root: PathBuf,
    report: Option<PathBuf>,
    release: bool,
    oracle_commit: Option<String>,
}

fn parse_args() -> Result<Arguments, String> {
    let mut args = env::args().skip(1);
    let command = args
        .next()
        .ok_or("usage: p2mr-v1-oracle <check-manifest|verify> [options]")?;
    if command != "check-manifest" && command != "verify" {
        return Err(format!("unknown command: {command}"));
    }
    let mut manifest = None;
    let mut source_root = None;
    let mut report = None;
    let mut release = false;
    let mut oracle_commit = None;
    while let Some(argument) = args.next() {
        match argument.as_str() {
            "--manifest" => manifest = Some(args.next().ok_or("--manifest requires a path")?),
            "--source-root" => {
                source_root = Some(PathBuf::from(
                    args.next().ok_or("--source-root requires a path")?,
                ))
            }
            "--report" => {
                report = Some(PathBuf::from(
                    args.next().ok_or("--report requires a path")?,
                ))
            }
            "--release" => release = true,
            "--oracle-commit" => {
                oracle_commit = Some(args.next().ok_or("--oracle-commit requires a commit")?)
            }
            _ => return Err(format!("unknown argument: {argument}")),
        }
    }
    let manifest = manifest.ok_or("missing required --manifest")?;
    if Path::new(&manifest).is_absolute() {
        return Err("--manifest must be relative to --source-root".to_string());
    }
    let source_root = source_root.ok_or("missing required --source-root")?;
    if command == "verify" && report.is_none() {
        return Err("verify requires --report".to_string());
    }
    if command == "check-manifest" && report.is_some() {
        return Err("check-manifest does not accept --report".to_string());
    }
    if command == "check-manifest" && (release || oracle_commit.is_some()) {
        return Err("check-manifest does not accept release evidence options".to_string());
    }
    if let Some(commit) = &oracle_commit {
        if commit.len() != 40
            || !commit
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        {
            return Err("--oracle-commit must be exactly 40 lowercase hex characters".to_string());
        }
    }
    if release && oracle_commit.is_none() {
        return Err("--release requires --oracle-commit".to_string());
    }
    Ok(Arguments {
        command,
        manifest,
        source_root,
        report,
        release,
        oracle_commit,
    })
}

fn validate_release_commit(provided: &str, actual: &str) -> Result<(), String> {
    if provided != actual {
        return Err(format!(
            "--oracle-commit {provided} does not match source checkout HEAD {actual}"
        ));
    }
    Ok(())
}

fn source_checkout_head(source_root: &Path) -> Result<String, String> {
    let root = std::fs::canonicalize(source_root)
        .map_err(|error| format!("cannot resolve source root for commit binding: {error}"))?;
    let output = Command::new("git")
        .args(["-C"])
        .arg(&root)
        .args(["rev-parse", "--verify", "HEAD^{commit}"])
        .output()
        .map_err(|error| format!("cannot execute git for release commit binding: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "cannot resolve source checkout HEAD: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let status = Command::new("git")
        .args(["-C"])
        .arg(&root)
        .args(["status", "--porcelain=v1", "--untracked-files=normal"])
        .output()
        .map_err(|error| format!("cannot execute git for release cleanliness check: {error}"))?;
    if !status.status.success() {
        return Err(format!(
            "cannot inspect source checkout cleanliness: {}",
            String::from_utf8_lossy(&status.stderr).trim()
        ));
    }
    if !status.stdout.is_empty() {
        return Err(
            "release evidence requires a clean source checkout with no uncommitted files"
                .to_string(),
        );
    }
    let commit = String::from_utf8(output.stdout)
        .map_err(|_| "source checkout HEAD is not UTF-8".to_string())?;
    let commit = commit.trim();
    if commit.len() != 40
        || !commit
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("source checkout HEAD is not a canonical 40-character commit".to_string());
    }
    Ok(commit.to_string())
}

fn verify(args: &Arguments, loaded: &corpus::LoadedCorpus) -> Result<(), String> {
    let mut observations: Vec<Observation> = Vec::with_capacity(loaded.manifest.case_count);
    let witness_cases = &loaded
        .files
        .iter()
        .find(|file| file.path == "src/test/data/p2mr_pqc_witness_vectors.json")
        .ok_or("required witness corpus was not loaded")?
        .cases;
    for file in &loaded.files {
        for case in &file.cases {
            let observation = match file.path.as_str() {
                "src/test/data/p2mr_vectors.json" => p2mr::evaluate_commitment(case),
                "src/test/data/p2mr_pqc_witness_vectors.json" => p2mr::evaluate_witness(case),
                "src/test/data/p2mr_cross_profile_vectors.json" => {
                    p2mr::evaluate_cross_profile(case)
                }
                "src/test/data/p2mr_script_boundary_vectors.json" => {
                    p2mr::evaluate_boundary(case, witness_cases)
                }
                _ => Err(format!("unsupported corpus file: {}", file.path)),
            }
            .map_err(|error| format!("{}: {error}", file.path))?;
            observations.push(observation);
        }
    }
    observations.sort_by(|left, right| left.id.cmp(&right.id));
    if observations.len() != loaded.manifest.case_count {
        return Err("oracle result count differs from manifest".to_string());
    }
    for pair in observations.windows(2) {
        if pair[0].id == pair[1].id {
            return Err(format!("duplicate oracle result id: {}", pair[0].id));
        }
    }
    let oracle_commit = args.oracle_commit.as_deref().unwrap_or("unversioned");
    report::write(
        args.report.as_ref().unwrap(),
        &loaded.manifest_sha256,
        &loaded.manifest.reference_implementation.commit,
        &loaded.manifest.case_counts,
        oracle_commit,
        &observations,
    )?;
    println!(
        "P2MR v1 oracle passed {} cases; manifest_sha256={}",
        observations.len(),
        loaded.manifest_sha256
    );
    Ok(())
}

fn run() -> Result<(), String> {
    let args = parse_args()?;
    let loaded = corpus::load(&args.source_root, &args.manifest)?;
    if args.command == "check-manifest" {
        println!(
            "P2MR v1 manifest passed: cases={}, sha256={}",
            loaded.manifest.case_count, loaded.manifest_sha256
        );
        return Ok(());
    }
    if args.release {
        let actual = source_checkout_head(&args.source_root)?;
        validate_release_commit(args.oracle_commit.as_deref().unwrap(), &actual)?;
    }
    if args.release
        && args.oracle_commit.as_deref() == Some(&loaded.manifest.reference_implementation.commit)
    {
        // This is permitted, but make the distinction visible: one commit identifies the
        // frozen behavior and the other identifies the exact oracle source under test.
        eprintln!("warning: oracle commit equals the initial reference implementation commit");
    }
    verify(&args, &loaded)
}

fn main() {
    if let Err(error) = run() {
        eprintln!("p2mr-v1-oracle: {error}");
        std::process::exit(1);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn release_commit_must_equal_checkout_head() {
        let head = "0123456789abcdef0123456789abcdef01234567";
        assert!(validate_release_commit(head, head).is_ok());
        assert!(validate_release_commit(head, "1123456789abcdef0123456789abcdef01234567").is_err());
    }
}
