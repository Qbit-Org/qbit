use crate::encoding::sha256;
use serde::de::{Error as _, MapAccess, SeqAccess, Visitor};
use serde::{Deserialize, Deserializer};
use serde_json::{Map, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Component, Path, PathBuf};

const PROFILE: &str = "qbit-p2mr-v1";
const REFERENCE_COMMIT: &str = "988756471aeecdf4463c04be49da2b7b89a98c21";
const ANCESTRY_COMMIT: &str = "6740c533e8dce4e912f17ee85a6f627644e1b783";
const MAX_CORPUS_FILE_BYTES: u64 = 8 * 1024 * 1024;
const MAX_CASES: usize = 10_000;
const REQUIRED_FILES: [&str; 4] = [
    "src/test/data/p2mr_cross_profile_vectors.json",
    "src/test/data/p2mr_pqc_witness_vectors.json",
    "src/test/data/p2mr_script_boundary_vectors.json",
    "src/test/data/p2mr_vectors.json",
];
const REQUIRED_PURPOSES: [(&str, &str); 4] = [
    (
        "src/test/data/p2mr_cross_profile_vectors.json",
        "qbit and pinned-profile boundary vectors",
    ),
    (
        "src/test/data/p2mr_pqc_witness_vectors.json",
        "PQC sighash and witness vectors",
    ),
    (
        "src/test/data/p2mr_script_boundary_vectors.json",
        "script, control, leaf, opcode, and resource boundary vectors",
    ),
    (
        "src/test/data/p2mr_vectors.json",
        "commitment, control block, root, and address vectors",
    ),
];

struct StrictValue(Value);

impl<'de> Deserialize<'de> for StrictValue {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        struct StrictVisitor;

        impl<'de> Visitor<'de> for StrictVisitor {
            type Value = StrictValue;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a JSON value without duplicate object keys")
            }

            fn visit_bool<E>(self, value: bool) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Bool(value)))
            }

            fn visit_i64<E>(self, value: i64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_u64<E>(self, value: u64) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Number(value.into())))
            }

            fn visit_f64<E>(self, value: f64) -> Result<Self::Value, E>
            where
                E: serde::de::Error,
            {
                serde_json::Number::from_f64(value)
                    .map(Value::Number)
                    .map(StrictValue)
                    .ok_or_else(|| E::custom("non-finite JSON number"))
            }

            fn visit_str<E>(self, value: &str) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value.to_owned())))
            }

            fn visit_string<E>(self, value: String) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::String(value)))
            }

            fn visit_none<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_unit<E>(self) -> Result<Self::Value, E> {
                Ok(StrictValue(Value::Null))
            }

            fn visit_seq<A>(self, mut sequence: A) -> Result<Self::Value, A::Error>
            where
                A: SeqAccess<'de>,
            {
                let mut values = Vec::new();
                while let Some(StrictValue(value)) = sequence.next_element()? {
                    values.push(value);
                }
                Ok(StrictValue(Value::Array(values)))
            }

            fn visit_map<A>(self, mut object: A) -> Result<Self::Value, A::Error>
            where
                A: MapAccess<'de>,
            {
                let mut values = Map::new();
                while let Some(key) = object.next_key::<String>()? {
                    if values.contains_key(&key) {
                        return Err(A::Error::custom(format!("duplicate JSON key: {key}")));
                    }
                    let StrictValue(value) = object.next_value()?;
                    values.insert(key, value);
                }
                Ok(StrictValue(Value::Object(values)))
            }
        }

        deserializer.deserialize_any(StrictVisitor)
    }
}

fn parse_json_strict(bytes: &[u8], context: &str) -> Result<Value, String> {
    let mut deserializer = serde_json::Deserializer::from_slice(bytes);
    let StrictValue(value) = StrictValue::deserialize(&mut deserializer)
        .map_err(|error| format!("{context}: invalid JSON: {error}"))?;
    deserializer
        .end()
        .map_err(|error| format!("{context}: invalid JSON: {error}"))?;
    Ok(value)
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReferenceImplementation {
    pub repository: String,
    pub commit: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Ancestry {
    pub name: String,
    pub version: String,
    pub commit: String,
    pub normative: bool,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManifestFile {
    pub path: String,
    pub purpose: String,
    pub case_count: usize,
    pub sha256: String,
}

#[derive(Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u64,
    pub profile: String,
    pub profile_version: u64,
    pub specification: String,
    pub reference_implementation: ReferenceImplementation,
    pub ancestry: Ancestry,
    pub case_count: usize,
    pub case_counts: BTreeMap<String, usize>,
    pub files: Vec<ManifestFile>,
}

pub struct CorpusFile {
    pub path: String,
    pub cases: Vec<Value>,
}

pub struct LoadedCorpus {
    pub manifest: Manifest,
    pub manifest_sha256: String,
    pub files: Vec<CorpusFile>,
}

fn ensure_relative_path(path: &str) -> Result<(), String> {
    let path = Path::new(path);
    if path.as_os_str().is_empty() || path.is_absolute() {
        return Err("manifest path must be a nonempty relative path".to_string());
    }
    if path
        .components()
        .any(|component| !matches!(component, Component::Normal(_)))
        || path
            .to_string_lossy()
            .split('/')
            .any(|component| component.is_empty() || component == "." || component == "..")
    {
        return Err(format!(
            "manifest path is not normalized: {}",
            path.display()
        ));
    }
    Ok(())
}

fn resolve_inside(root: &Path, relative: &str) -> Result<PathBuf, String> {
    ensure_relative_path(relative)?;
    let resolved = fs::canonicalize(root.join(relative))
        .map_err(|error| format!("cannot resolve {relative}: {error}"))?;
    if !resolved.starts_with(root) {
        return Err(format!("manifest path escapes source root: {relative}"));
    }
    Ok(resolved)
}

fn read_bounded(path: &Path) -> Result<Vec<u8>, String> {
    let metadata =
        fs::metadata(path).map_err(|error| format!("cannot stat {}: {error}", path.display()))?;
    if !metadata.is_file() || metadata.len() > MAX_CORPUS_FILE_BYTES {
        return Err(format!("{} is not a bounded regular file", path.display()));
    }
    fs::read(path).map_err(|error| format!("cannot read {}: {error}", path.display()))
}

fn validate_sha256(bytes: &[u8], declared: &str, context: &str) -> Result<(), String> {
    if declared.len() != 64
        || !declared
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(format!("{context}: invalid lowercase SHA256"));
    }
    if hex::encode(sha256(bytes)) != declared {
        return Err(format!("{context}: digest mismatch"));
    }
    Ok(())
}

fn insert_case_id(ids: &mut BTreeSet<String>, id: &str) -> Result<(), String> {
    if !ids.insert(id.to_string()) {
        return Err(format!("duplicate corpus case id: {id}"));
    }
    Ok(())
}

fn exact_keys(object: &Map<String, Value>, expected: &[&str], file: &str) -> Result<(), String> {
    let actual: BTreeSet<&str> = object.keys().map(String::as_str).collect();
    let expected: BTreeSet<&str> = expected.iter().copied().collect();
    if actual != expected {
        return Err(format!("{file}: unknown or missing top-level fields"));
    }
    Ok(())
}

fn validate_metadata<'a>(value: &'a Value, file: &str) -> Result<&'a Map<String, Value>, String> {
    let object = value
        .as_object()
        .ok_or_else(|| format!("{file}: corpus must be an object"))?;
    if object.get("schema_version").and_then(Value::as_u64) != Some(1)
        || object.get("profile").and_then(Value::as_str) != Some(PROFILE)
        || object.get("profile_version").and_then(Value::as_u64) != Some(1)
    {
        return Err(format!("{file}: unsupported schema or profile"));
    }
    Ok(object)
}

fn cases_for(path: &str, value: &Value) -> Result<Vec<Value>, String> {
    let object = validate_metadata(value, path)?;
    let mut cases = Vec::new();
    match path {
        "src/test/data/p2mr_vectors.json" => {
            exact_keys(
                object,
                &[
                    "schema_version",
                    "profile",
                    "profile_version",
                    "generator",
                    "valid",
                    "invalid",
                ],
                path,
            )?;
            for name in ["valid", "invalid"] {
                let values = object[name]
                    .as_array()
                    .ok_or_else(|| format!("{path}: {name} must be an array"))?;
                cases.extend(values.iter().cloned());
            }
        }
        "src/test/data/p2mr_pqc_witness_vectors.json" => {
            exact_keys(
                object,
                &["schema_version", "profile", "profile_version", "vectors"],
                path,
            )?;
            cases.extend(
                object["vectors"]
                    .as_array()
                    .ok_or_else(|| format!("{path}: vectors must be an array"))?
                    .iter()
                    .cloned(),
            );
        }
        "src/test/data/p2mr_cross_profile_vectors.json" => {
            exact_keys(
                object,
                &[
                    "schema_version",
                    "profile",
                    "profile_version",
                    "comparison_profile",
                    "vectors",
                ],
                path,
            )?;
            let comparison = object["comparison_profile"]
                .as_object()
                .ok_or_else(|| format!("{path}: comparison_profile must be an object"))?;
            exact_keys(
                comparison,
                &["name", "version", "commit", "normative"],
                path,
            )?;
            if comparison.get("name").and_then(Value::as_str) != Some("BIP-360")
                || comparison.get("version").and_then(Value::as_str) != Some("0.12.0")
                || comparison.get("commit").and_then(Value::as_str) != Some(ANCESTRY_COMMIT)
                || comparison.get("normative").and_then(Value::as_bool) != Some(false)
            {
                return Err(format!("{path}: unpinned comparison profile"));
            }
            cases.extend(
                object["vectors"]
                    .as_array()
                    .ok_or_else(|| format!("{path}: vectors must be an array"))?
                    .iter()
                    .cloned(),
            );
        }
        "src/test/data/p2mr_script_boundary_vectors.json" => {
            exact_keys(
                object,
                &[
                    "schema_version",
                    "profile",
                    "profile_version",
                    "limits",
                    "cases",
                ],
                path,
            )?;
            let limits = object["limits"]
                .as_object()
                .ok_or_else(|| format!("{path}: limits must be an object"))?;
            exact_keys(
                limits,
                &[
                    "control_path_max_nodes",
                    "initial_stack_max_items",
                    "initial_stack_item_max_bytes",
                    "initial_stack_total_max_bytes",
                    "validation_weight_per_nonempty_pqc_check",
                ],
                path,
            )?;
            for (field, expected) in [
                ("control_path_max_nodes", 128),
                ("initial_stack_max_items", 1000),
                ("initial_stack_item_max_bytes", 16_384),
                ("initial_stack_total_max_bytes", 131_072),
                ("validation_weight_per_nonempty_pqc_check", 3_730),
            ] {
                if limits.get(field).and_then(Value::as_u64) != Some(expected) {
                    return Err(format!("{path}: unexpected {field}"));
                }
            }
            cases.extend(
                object["cases"]
                    .as_array()
                    .ok_or_else(|| format!("{path}: cases must be an array"))?
                    .iter()
                    .cloned(),
            );
        }
        _ => return Err(format!("unsupported manifest corpus file: {path}")),
    }
    if cases.len() > MAX_CASES {
        return Err(format!("{path}: too many cases"));
    }
    Ok(cases)
}

pub fn load(source_root: &Path, manifest_relative: &str) -> Result<LoadedCorpus, String> {
    let root = fs::canonicalize(source_root)
        .map_err(|error| format!("cannot resolve source root: {error}"))?;
    if !root.is_dir() {
        return Err("source root is not a directory".to_string());
    }
    let manifest_path = resolve_inside(&root, manifest_relative)?;
    let manifest_bytes = read_bounded(&manifest_path)?;
    let manifest_value = parse_json_strict(&manifest_bytes, "manifest")?;
    let manifest: Manifest = serde_json::from_value(manifest_value)
        .map_err(|error| format!("invalid manifest: {error}"))?;
    if manifest.schema_version != 1 || manifest.profile != PROFILE || manifest.profile_version != 1
    {
        return Err("unsupported manifest schema or profile".to_string());
    }
    if manifest.specification != "doc/consensus/p2mr-v1.md" {
        return Err("manifest does not pin the qbit P2MR v1 specification".to_string());
    }
    resolve_inside(&root, &manifest.specification)?;
    if manifest.reference_implementation.repository != "Qbit-Org/qbit"
        || manifest.reference_implementation.commit != REFERENCE_COMMIT
    {
        return Err("manifest reference implementation is not pinned".to_string());
    }
    if manifest.ancestry.name != "BIP-360"
        || manifest.ancestry.version != "0.12.0"
        || manifest.ancestry.commit != ANCESTRY_COMMIT
        || manifest.ancestry.normative
    {
        return Err("manifest ancestry is not pinned".to_string());
    }
    let expected_count_keys: BTreeSet<&str> = [
        "commitment_valid",
        "commitment_invalid",
        "witness",
        "cross_profile",
        "script_boundary",
    ]
    .into_iter()
    .collect();
    if manifest
        .case_counts
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>()
        != expected_count_keys
    {
        return Err("manifest case_counts has unknown or missing fields".to_string());
    }
    let paths: Vec<&str> = manifest
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    if paths != REQUIRED_FILES {
        return Err("manifest files are not the exact sorted required corpus".to_string());
    }

    let mut files = Vec::with_capacity(manifest.files.len());
    let mut ids = BTreeSet::new();
    let mut total = 0usize;
    let mut actual_counts = BTreeMap::new();
    for entry in &manifest.files {
        let expected_purpose = REQUIRED_PURPOSES
            .iter()
            .find_map(|(path, purpose)| (*path == entry.path).then_some(*purpose))
            .ok_or_else(|| format!("{}: no required manifest purpose", entry.path))?;
        if entry.purpose != expected_purpose {
            return Err(format!("{}: unexpected manifest purpose", entry.path));
        }
        let path = resolve_inside(&root, &entry.path)?;
        let bytes = read_bounded(&path)?;
        validate_sha256(&bytes, &entry.sha256, &entry.path)?;
        let value = parse_json_strict(&bytes, &entry.path)?;
        let cases = cases_for(&entry.path, &value)?;
        if cases.len() != entry.case_count {
            return Err(format!("{}: manifest case count mismatch", entry.path));
        }
        for case in &cases {
            let id = case
                .get("id")
                .and_then(Value::as_str)
                .filter(|id| !id.is_empty())
                .ok_or_else(|| format!("{}: case has no nonempty id", entry.path))?;
            insert_case_id(&mut ids, id)?;
        }
        total = total
            .checked_add(cases.len())
            .ok_or("corpus case count overflow")?;
        match entry.path.as_str() {
            "src/test/data/p2mr_vectors.json" => {
                actual_counts.insert(
                    "commitment_valid".to_string(),
                    value["valid"].as_array().unwrap().len(),
                );
                actual_counts.insert(
                    "commitment_invalid".to_string(),
                    value["invalid"].as_array().unwrap().len(),
                );
            }
            "src/test/data/p2mr_pqc_witness_vectors.json" => {
                actual_counts.insert("witness".to_string(), cases.len());
            }
            "src/test/data/p2mr_cross_profile_vectors.json" => {
                actual_counts.insert("cross_profile".to_string(), cases.len());
            }
            "src/test/data/p2mr_script_boundary_vectors.json" => {
                actual_counts.insert("script_boundary".to_string(), cases.len());
            }
            _ => unreachable!(),
        }
        files.push(CorpusFile {
            path: entry.path.clone(),
            cases,
        });
    }
    if total != manifest.case_count
        || manifest.case_counts.values().sum::<usize>() != total
        || actual_counts != manifest.case_counts
    {
        return Err("manifest aggregate case count mismatch".to_string());
    }
    Ok(LoadedCorpus {
        manifest,
        manifest_sha256: hex::encode(sha256(&manifest_bytes)),
        files,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_parent_components() {
        assert!(ensure_relative_path("../outside").is_err());
        assert!(ensure_relative_path("/absolute").is_err());
        assert!(ensure_relative_path("a/./b").is_err());
        assert!(ensure_relative_path("src/test/data/file.json").is_ok());
    }

    #[test]
    fn rejects_duplicate_json_keys_at_any_depth() {
        assert!(parse_json_strict(br#"{"a":1,"a":2}"#, "test").is_err());
        assert!(parse_json_strict(br#"{"a":{"b":1,"b":2}}"#, "test").is_err());
        assert_eq!(
            parse_json_strict(br#"{"a":[1,true,null]}"#, "test").unwrap()["a"][0],
            1
        );
    }

    #[test]
    fn required_purposes_are_exact_and_complete() {
        assert_eq!(REQUIRED_PURPOSES.len(), REQUIRED_FILES.len());
        for ((purpose_path, purpose), required_path) in REQUIRED_PURPOSES.iter().zip(REQUIRED_FILES)
        {
            assert_eq!(*purpose_path, required_path);
            assert!(!purpose.is_empty());
        }
    }

    #[test]
    fn rejects_duplicate_ids_and_digest_mismatches() {
        let mut ids = BTreeSet::new();
        insert_case_id(&mut ids, "case-a").unwrap();
        assert!(insert_case_id(&mut ids, "case-a").is_err());
        let digest = hex::encode(sha256(b"fixture"));
        assert!(validate_sha256(b"fixture", &digest, "test").is_ok());
        assert!(validate_sha256(b"changed", &digest, "test").is_err());
        assert!(validate_sha256(b"fixture", &digest.to_uppercase(), "test").is_err());
    }

    #[cfg(unix)]
    #[test]
    fn rejects_symlink_escape() {
        use std::os::unix::fs::symlink;
        use std::time::{SystemTime, UNIX_EPOCH};

        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let base = std::env::temp_dir().join(format!(
            "p2mr-v1-oracle-symlink-{}-{unique}",
            std::process::id()
        ));
        let root = base.join("root");
        let outside = base.join("outside");
        fs::create_dir_all(&root).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("corpus.json"), b"{}").unwrap();
        symlink(outside.join("corpus.json"), root.join("escape.json")).unwrap();
        let canonical_root = fs::canonicalize(&root).unwrap();
        assert!(resolve_inside(&canonical_root, "escape.json").is_err());
        fs::remove_dir_all(base).unwrap();
    }
}
