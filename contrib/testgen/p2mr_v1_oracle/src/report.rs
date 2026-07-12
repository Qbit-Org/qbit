use crate::p2mr::Observation;
use serde::Serialize;
use std::collections::BTreeMap;
use std::fs::{self, OpenOptions};
use std::io::Write;
use std::path::Path;

#[derive(Serialize)]
struct OracleIdentity<'a> {
    name: &'static str,
    version: &'static str,
    commit: &'a str,
}

#[derive(Serialize)]
struct CaseCounts {
    total: usize,
    accepted: usize,
    rejected: usize,
    cross_profile: usize,
}

#[derive(Serialize)]
struct CaseRow<'a> {
    id: &'a str,
    category: &'a str,
    result: &'static str,
    observed_accept: bool,
    observed_stage: &'a str,
    observed_error: &'a str,
}

#[derive(Serialize)]
struct Report<'a> {
    schema_version: u64,
    profile: &'static str,
    profile_version: u64,
    manifest_sha256: &'a str,
    oracle: OracleIdentity<'a>,
    reference_implementation_commit: &'a str,
    manifest_case_counts: &'a BTreeMap<String, usize>,
    case_counts: CaseCounts,
    result: &'static str,
    cases: Vec<CaseRow<'a>>,
}

fn render(
    manifest_sha256: &str,
    reference_commit: &str,
    manifest_counts: &BTreeMap<String, usize>,
    oracle_commit: &str,
    observations: &[Observation],
) -> Result<Vec<u8>, String> {
    let total = observations.len();
    let accepted = observations.iter().filter(|case| case.accepted).count();
    let cross_profile = observations
        .iter()
        .filter(|case| case.category == "cross_profile")
        .count();
    let mut cases: Vec<_> = observations
        .iter()
        .map(|case| CaseRow {
            id: &case.id,
            category: &case.category,
            result: "pass",
            observed_accept: case.accepted,
            observed_stage: &case.stage,
            observed_error: &case.error,
        })
        .collect();
    cases.sort_by(|left, right| left.id.cmp(right.id));
    let report = Report {
        schema_version: 1,
        profile: "qbit-p2mr-v1",
        profile_version: 1,
        manifest_sha256,
        oracle: OracleIdentity {
            name: "p2mr-v1-oracle",
            version: "1",
            commit: oracle_commit,
        },
        reference_implementation_commit: reference_commit,
        manifest_case_counts: manifest_counts,
        case_counts: CaseCounts {
            total,
            accepted,
            rejected: total - accepted,
            cross_profile,
        },
        result: "pass",
        cases,
    };
    let mut bytes = serde_json::to_vec_pretty(&report)
        .map_err(|error| format!("cannot serialize report: {error}"))?;
    bytes.push(b'\n');
    Ok(bytes)
}

pub fn write(
    path: &Path,
    manifest_sha256: &str,
    reference_commit: &str,
    manifest_counts: &BTreeMap<String, usize>,
    oracle_commit: &str,
    observations: &[Observation],
) -> Result<(), String> {
    let bytes = render(
        manifest_sha256,
        reference_commit,
        manifest_counts,
        oracle_commit,
        observations,
    )?;
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    fs::create_dir_all(parent)
        .map_err(|error| format!("cannot create report directory: {error}"))?;
    let filename = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or("report path has no UTF-8 filename")?;
    let temporary = parent.join(format!(".{filename}.{}.tmp", std::process::id()));
    let result = (|| {
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .open(&temporary)
            .map_err(|error| format!("cannot create temporary report: {error}"))?;
        file.write_all(&bytes)
            .and_then(|_| file.sync_all())
            .map_err(|error| format!("cannot write temporary report: {error}"))?;
        fs::rename(&temporary, path)
            .map_err(|error| format!("cannot atomically publish report: {error}"))
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn report_is_deterministic_and_sorts_case_ids() {
        let observations = vec![
            Observation {
                id: "z-case".to_string(),
                category: "witness".to_string(),
                accepted: false,
                stage: "sighash".to_string(),
                error: "SCRIPT_ERR_P2MR_SIG_HASHTYPE".to_string(),
            },
            Observation {
                id: "a-case".to_string(),
                category: "commitment".to_string(),
                accepted: true,
                stage: "script-complete".to_string(),
                error: "SCRIPT_ERR_OK".to_string(),
            },
        ];
        let counts = BTreeMap::from([("commitment".to_string(), 1), ("witness".to_string(), 1)]);
        let first = render("00", "11", &counts, "22", &observations).unwrap();
        let second = render("00", "11", &counts, "22", &observations).unwrap();
        assert_eq!(first, second);
        assert!(first.ends_with(b"\n"));
        let text = String::from_utf8(first).unwrap();
        assert!(text.find("a-case").unwrap() < text.find("z-case").unwrap());
    }
}
