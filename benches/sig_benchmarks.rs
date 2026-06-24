use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, signature_size, verify,
};
use criterion::{black_box, Criterion};
use secp256k1::{Keypair, Secp256k1, SecretKey};
use serde_json::{json, Value};
use std::env;
use std::fmt::Write;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime};

const REPORT_PATH: &str = "benches/REPORT.md";
const JSON_ARTIFACT_PATH: &str = "benches/benchmark-results.json";
const BLOCK_TIME_SECONDS: f64 = 30.0;
const BLOCK_VERIFY_BUDGET_FRACTION: f64 = 0.01;
const ESTIMATE_FRESHNESS_SLACK: Duration = Duration::from_secs(2);

struct BenchSpec {
    algorithm: &'static str,
    operation: &'static str,
    criterion_id: &'static str,
}

const BENCH_SPECS: [BenchSpec; 6] = [
    BenchSpec {
        algorithm: "bounded_slh_dsa_sha2_128s",
        operation: "keygen",
        criterion_id: "slh_dsa_sha2_128s_bounded/keygen",
    },
    BenchSpec {
        algorithm: "bounded_slh_dsa_sha2_128s",
        operation: "sign",
        criterion_id: "slh_dsa_sha2_128s_bounded/sign",
    },
    BenchSpec {
        algorithm: "bounded_slh_dsa_sha2_128s",
        operation: "verify",
        criterion_id: "slh_dsa_sha2_128s_bounded/verify",
    },
    BenchSpec {
        algorithm: "secp256k1_schnorr",
        operation: "keygen",
        criterion_id: "secp256k1_schnorr/keygen",
    },
    BenchSpec {
        algorithm: "secp256k1_schnorr",
        operation: "sign",
        criterion_id: "secp256k1_schnorr/sign",
    },
    BenchSpec {
        algorithm: "secp256k1_schnorr",
        operation: "verify",
        criterion_id: "secp256k1_schnorr/verify",
    },
];

#[derive(Clone)]
struct PerfRow {
    algorithm: &'static str,
    operation: &'static str,
    latency_ms: f64,
    throughput_ops_per_sec: f64,
}

#[derive(Clone)]
struct ImpactRow {
    algorithm: &'static str,
    verify_latency_ms: f64,
    tps_single_thread: f64,
    tps_four_core: f64,
    tps_eight_core: f64,
}

struct HostMetadata {
    generated_at_utc: String,
    cpu_model: String,
    sha_ni: String,
    arm_sha2: String,
    rustc_version: String,
    commit_hash: String,
    worktree_dirty_at_start: bool,
    os: String,
    arch: String,
    runtime_env_knobs: String,
    opt_profile: String,
    disable_sha_accel: String,
    disable_simd: String,
    fors_threads: String,
    disable_threads: String,
    enable_arm_sha: String,
    sha_backend: String,
}

struct SizeSnapshot {
    slh_public_key_bytes: usize,
    slh_secret_key_bytes: usize,
    slh_signature_bytes: usize,
    secp_public_key_bytes: usize,
    secp_secret_key_bytes: usize,
    secp_signature_bytes: usize,
}

fn find_latency_ms(rows: &[PerfRow], algorithm: &str, operation: &str) -> Option<f64> {
    rows.iter()
        .find(|row| row.algorithm == algorithm && row.operation == operation)
        .map(|row| row.latency_ms)
}

fn slh_entropy() -> [u8; 128] {
    [0x42u8; 128]
}

fn message32() -> [u8; 32] {
    [0xA5u8; 32]
}

fn secp_material() -> (Secp256k1<secp256k1::All>, Keypair, [u8; 32]) {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_byte_array([0x11u8; 32]).expect("valid secp secret key");
    let keypair = Keypair::from_secret_key(&secp, &secret_key);
    let message = message32();
    (secp, keypair, message)
}

fn benchmark_slh_keygen(c: &mut Criterion) {
    let entropy = slh_entropy();
    c.bench_function("slh_dsa_sha2_128s_bounded/keygen", |b| {
        b.iter(|| generate_keypair(black_box(&entropy)).expect("SLH keygen should succeed"))
    });
}

fn benchmark_slh_sign(c: &mut Criterion) {
    let entropy = slh_entropy();
    let keypair = generate_keypair(&entropy).expect("SLH keypair for sign benchmark");
    let message = message32();
    c.bench_function("slh_dsa_sha2_128s_bounded/sign", |b| {
        b.iter(|| sign(black_box(&keypair.secret_key), black_box(&message)).expect("SLH sign"))
    });
}

fn benchmark_slh_verify(c: &mut Criterion) {
    let entropy = slh_entropy();
    let keypair = generate_keypair(&entropy).expect("SLH keypair for verify benchmark");
    let message = message32();
    let signature = sign(&keypair.secret_key, &message).expect("SLH signature");

    c.bench_function("slh_dsa_sha2_128s_bounded/verify", |b| {
        b.iter(|| {
            verify(
                black_box(&keypair.public_key),
                black_box(&message),
                black_box(&signature),
            )
            .expect("SLH verify")
        })
    });
}

fn counter_secret_key(counter: u64) -> [u8; 32] {
    let mut bytes = [0u8; 32];
    bytes[24..32].copy_from_slice(&(counter.max(1)).to_be_bytes());
    bytes
}

fn benchmark_secp_keygen(c: &mut Criterion) {
    let secp = Secp256k1::new();
    let counter = AtomicU64::new(1);

    c.bench_function("secp256k1_schnorr/keygen", |b| {
        b.iter(|| {
            let next = counter.fetch_add(1, Ordering::Relaxed);
            let secret_key_bytes = counter_secret_key(next);
            let secret_key =
                SecretKey::from_byte_array(black_box(secret_key_bytes)).expect("valid secp key");
            let keypair = Keypair::from_secret_key(&secp, &secret_key);
            let (public_key, _) = keypair.x_only_public_key();
            black_box(public_key);
        })
    });
}

fn benchmark_secp_sign(c: &mut Criterion) {
    let (secp, keypair, message) = secp_material();
    c.bench_function("secp256k1_schnorr/sign", |b| {
        b.iter(|| secp.sign_schnorr_no_aux_rand(black_box(&message[..]), black_box(&keypair)))
    });
}

fn benchmark_secp_verify(c: &mut Criterion) {
    let (secp, keypair, message) = secp_material();
    let signature = secp.sign_schnorr_no_aux_rand(&message[..], &keypair);
    let (public_key, _) = keypair.x_only_public_key();

    c.bench_function("secp256k1_schnorr/verify", |b| {
        b.iter(|| {
            secp.verify_schnorr(
                black_box(&signature),
                black_box(&message[..]),
                black_box(&public_key),
            )
            .expect("secp verify")
        })
    });
}

fn capture_sizes() -> SizeSnapshot {
    let (secp, keypair, message) = secp_material();
    let signature = secp.sign_schnorr_no_aux_rand(&message[..], &keypair);
    let (public_key, _) = keypair.x_only_public_key();

    SizeSnapshot {
        slh_public_key_bytes: public_key_size(),
        slh_secret_key_bytes: secret_key_size(),
        slh_signature_bytes: signature_size(),
        secp_public_key_bytes: public_key.serialize().len(),
        secp_secret_key_bytes: 32,
        secp_signature_bytes: signature.as_ref().len(),
    }
}

fn assert_size_expectations(sizes: &SizeSnapshot) {
    assert_eq!(
        sizes.slh_signature_bytes, 3680,
        "bounded SLH signature size must be 3680 bytes"
    );
    assert_eq!(
        sizes.slh_public_key_bytes, 32,
        "bounded SLH public key size must be 32 bytes"
    );
    assert_eq!(
        sizes.slh_secret_key_bytes, 64,
        "bounded SLH secret key size must be 64 bytes"
    );
}

fn criterion_root() -> PathBuf {
    let manifest_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    match env::var_os("CARGO_TARGET_DIR") {
        Some(configured) => {
            let target = PathBuf::from(configured);
            if target.is_absolute() {
                target.join("criterion")
            } else {
                manifest_dir.join(target).join("criterion")
            }
        }
        None => manifest_dir.join("target").join("criterion"),
    }
}

fn estimate_paths(criterion_id: &str) -> [PathBuf; 2] {
    let criterion_root = criterion_root();
    [
        criterion_root
            .join(criterion_id)
            .join("new")
            .join("estimates.json"),
        criterion_root
            .join(criterion_id.replace('/', "_"))
            .join("new")
            .join("estimates.json"),
    ]
}

fn resolve_estimate_path_for_run(
    criterion_id: &str,
    run_started_at: SystemTime,
) -> Result<Option<PathBuf>, String> {
    let min_modified_time = run_started_at
        .checked_sub(ESTIMATE_FRESHNESS_SLACK)
        .unwrap_or(run_started_at);
    let mut latest: Option<(SystemTime, PathBuf)> = None;

    for path in estimate_paths(criterion_id) {
        if !path.exists() {
            continue;
        }
        let modified = fs::metadata(&path)
            .and_then(|metadata| metadata.modified())
            .map_err(|e| format!("failed to read metadata for {}: {e}", path.display()))?;
        if modified < min_modified_time {
            continue;
        }

        match &latest {
            Some((latest_modified, _)) if modified <= *latest_modified => {}
            _ => latest = Some((modified, path)),
        }
    }

    Ok(latest.map(|(_, path)| path))
}

fn read_mean_ns_for_run(
    criterion_id: &str,
    run_started_at: SystemTime,
) -> Result<Option<f64>, String> {
    let Some(path) = resolve_estimate_path_for_run(criterion_id, run_started_at)? else {
        return Ok(None);
    };

    let raw = fs::read_to_string(&path)
        .map_err(|e| format!("failed to read criterion estimate {}: {e}", path.display()))?;
    let parsed: Value = serde_json::from_str(&raw)
        .map_err(|e| format!("failed to parse JSON at {}: {e}", path.display()))?;
    let mean_ns = parsed
        .get("mean")
        .and_then(|mean| mean.get("point_estimate"))
        .and_then(Value::as_f64)
        .ok_or_else(|| format!("missing mean.point_estimate in {}", path.display()))?;
    Ok(Some(mean_ns))
}

fn collect_perf_rows(run_started_at: SystemTime) -> Result<Vec<PerfRow>, String> {
    let mut rows = Vec::new();
    for spec in BENCH_SPECS {
        let Some(mean_ns) = read_mean_ns_for_run(spec.criterion_id, run_started_at)? else {
            eprintln!(
                "Skipping {} (no fresh Criterion estimate from this run; likely filtered out)",
                spec.criterion_id
            );
            continue;
        };
        let latency_ms = mean_ns / 1_000_000.0;
        let throughput_ops_per_sec = if mean_ns > 0.0 {
            1_000_000_000.0 / mean_ns
        } else {
            0.0
        };

        rows.push(PerfRow {
            algorithm: spec.algorithm,
            operation: spec.operation,
            latency_ms,
            throughput_ops_per_sec,
        });
    }
    Ok(rows)
}

fn tps_threshold_for_one_percent_block_time(latency_ms: f64) -> f64 {
    if latency_ms <= 0.0 {
        return f64::INFINITY;
    }
    // Generalized for BLOCK_VERIFY_BUDGET_FRACTION:
    // TPS threshold = (budget_fraction * 1000 ms) / verify_latency_ms.
    (BLOCK_VERIFY_BUDGET_FRACTION * 1_000.0) / latency_ms
}

fn collect_impact_rows(rows: &[PerfRow]) -> Vec<ImpactRow> {
    let mut impacts = Vec::new();
    for row in rows {
        if row.operation != "verify" {
            continue;
        }
        let single = tps_threshold_for_one_percent_block_time(row.latency_ms);
        impacts.push(ImpactRow {
            algorithm: row.algorithm,
            verify_latency_ms: row.latency_ms,
            tps_single_thread: single,
            tps_four_core: single * 4.0,
            tps_eight_core: single * 8.0,
        });
    }
    impacts
}

fn run_command(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8(output.stdout).ok()?;
    let trimmed = stdout.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

fn is_git_worktree_dirty() -> Result<bool, String> {
    let output = Command::new("git")
        .args(["status", "--porcelain", "--untracked-files=no"])
        .output()
        .map_err(|e| format!("failed to execute git status: {e}"))?;
    if !output.status.success() {
        return Err("git status returned a non-zero exit status".to_string());
    }
    let stdout = String::from_utf8(output.stdout)
        .map_err(|e| format!("git status output was not valid UTF-8: {e}"))?;
    Ok(!stdout.trim().is_empty())
}

fn detect_cpu_model() -> String {
    #[cfg(target_os = "macos")]
    {
        if let Some(model) = run_command("sysctl", &["-n", "machdep.cpu.brand_string"]) {
            return model;
        }
        if let Some(model) = run_command("sysctl", &["-n", "hw.model"]) {
            return model;
        }
    }

    #[cfg(target_os = "linux")]
    {
        if let Ok(cpuinfo) = fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if let Some(model) = line.strip_prefix("model name\t: ") {
                    return model.to_string();
                }
            }
        }
    }

    run_command("uname", &["-m"]).unwrap_or_else(|| "unknown".to_string())
}

fn detect_sha_ni() -> String {
    #[cfg(any(target_arch = "x86", target_arch = "x86_64"))]
    {
        if std::is_x86_feature_detected!("sha") {
            "detected".to_string()
        } else {
            "not detected".to_string()
        }
    }

    #[cfg(not(any(target_arch = "x86", target_arch = "x86_64")))]
    {
        "n/a (non-x86 host)".to_string()
    }
}

fn detect_arm_sha2() -> String {
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("sha2") {
            "detected".to_string()
        } else {
            "not detected".to_string()
        }
    }

    #[cfg(not(target_arch = "aarch64"))]
    {
        "n/a (non-aarch64 host)".to_string()
    }
}

fn env_or_unset(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| "unset".to_string())
}

fn runtime_env_knobs_mode() -> String {
    if cfg!(feature = "test-bench-env-knobs") {
        "enabled (test/benchmark opt-in)".to_string()
    } else {
        "ignored (production build)".to_string()
    }
}

fn collect_host_metadata() -> Result<HostMetadata, String> {
    Ok(HostMetadata {
        generated_at_utc: run_command("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"])
            .unwrap_or_else(|| "unknown".to_string()),
        cpu_model: detect_cpu_model(),
        sha_ni: detect_sha_ni(),
        arm_sha2: detect_arm_sha2(),
        rustc_version: run_command("rustc", &["--version"])
            .unwrap_or_else(|| "unknown".to_string()),
        commit_hash: run_command("git", &["rev-parse", "--short=12", "HEAD"])
            .ok_or_else(|| "failed to read git commit hash".to_string())?,
        worktree_dirty_at_start: is_git_worktree_dirty()?,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        runtime_env_knobs: runtime_env_knobs_mode(),
        opt_profile: env_or_unset("SPX_OPT_PROFILE"),
        disable_sha_accel: env_or_unset("SPX_DISABLE_SHA_ACCEL"),
        disable_simd: env_or_unset("SPX_DISABLE_SIMD"),
        fors_threads: env_or_unset("SPX_FORS_THREADS"),
        disable_threads: env_or_unset("SPX_DISABLE_THREADS"),
        enable_arm_sha: env_or_unset("SPX_ENABLE_ARM_SHA"),
        sha_backend: env_or_unset("SPX_SHA_BACKEND"),
    })
}

fn write_report(
    metadata: &HostMetadata,
    sizes: &SizeSnapshot,
    rows: &[PerfRow],
    impacts: &[ImpactRow],
) -> Result<(), String> {
    let mut report = String::new();
    let verify_budget_seconds = BLOCK_TIME_SECONDS * BLOCK_VERIFY_BUDGET_FRACTION;

    writeln!(&mut report, "# Benchmark Report: bounded SLH-DSA-SHA2-128s")
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report).map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "## Host Metadata")
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- Generated (UTC): {}",
        metadata.generated_at_utc
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "- Commit: `{}`", metadata.commit_hash)
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- Worktree Clean At Start: {}",
        if metadata.worktree_dirty_at_start {
            "no"
        } else {
            "yes"
        }
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "- Toolchain: `{}`", metadata.rustc_version)
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "- CPU: {}", metadata.cpu_model)
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "- SHA-NI: {}", metadata.sha_ni)
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "- ARM SHA2: {}", metadata.arm_sha2)
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "- OS/Arch: {}/{}", metadata.os, metadata.arch)
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- Runtime Env Knobs: {}",
        metadata.runtime_env_knobs
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- Optimization Env: `SPX_OPT_PROFILE={}`, `SPX_DISABLE_SHA_ACCEL={}`, `SPX_DISABLE_SIMD={}`, `SPX_FORS_THREADS={}`, `SPX_DISABLE_THREADS={}`, `SPX_ENABLE_ARM_SHA={}`, `SPX_SHA_BACKEND={}`",
        metadata.opt_profile,
        metadata.disable_sha_accel,
        metadata.disable_simd,
        metadata.fors_threads,
        metadata.disable_threads,
        metadata.enable_arm_sha,
        metadata.sha_backend
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report).map_err(|e| format!("failed to build report: {e}"))?;

    writeln!(&mut report, "## Repro Command")
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "- `cargo bench`").map_err(|e| format!("failed to build report: {e}"))?;
    if rows.len() < BENCH_SPECS.len() {
        writeln!(
            &mut report,
            "- Note: collected {} of {} benchmarks in this run (likely due to a filter).",
            rows.len(),
            BENCH_SPECS.len()
        )
        .map_err(|e| format!("failed to build report: {e}"))?;
    }
    writeln!(&mut report).map_err(|e| format!("failed to build report: {e}"))?;

    writeln!(&mut report, "## Size Confirmation")
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "| Algorithm | Public Key (bytes) | Secret Key (bytes) | Signature (bytes) |"
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "|---|---:|---:|---:|")
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "| bounded_slh_dsa_sha2_128s | {} | {} | {} |",
        sizes.slh_public_key_bytes, sizes.slh_secret_key_bytes, sizes.slh_signature_bytes
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "| secp256k1_schnorr | {} | {} | {} |",
        sizes.secp_public_key_bytes, sizes.secp_secret_key_bytes, sizes.secp_signature_bytes
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report).map_err(|e| format!("failed to build report: {e}"))?;

    writeln!(&mut report, "## Latency and Throughput")
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "| Algorithm | Operation | Latency (ms/op) | Throughput (ops/sec) |"
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "|---|---|---:|---:|")
        .map_err(|e| format!("failed to build report: {e}"))?;
    for row in rows {
        writeln!(
            &mut report,
            "| {} | {} | {:.6} | {:.2} |",
            row.algorithm, row.operation, row.latency_ms, row.throughput_ops_per_sec
        )
        .map_err(|e| format!("failed to build report: {e}"))?;
    }
    writeln!(&mut report).map_err(|e| format!("failed to build report: {e}"))?;

    writeln!(&mut report, "## Impact Analysis")
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- Verification budget: {:.3} seconds per {:.0}-second block ({}%).",
        verify_budget_seconds,
        BLOCK_TIME_SECONDS,
        BLOCK_VERIFY_BUDGET_FRACTION * 100.0
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- TPS threshold formula: `TPS > {} / verify_latency_seconds`.",
        BLOCK_VERIFY_BUDGET_FRACTION
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "| Algorithm | Verify Latency (ms/op) | TPS @1-thread | TPS @4-core (ideal) | TPS @8-core (ideal) |"
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "|---|---:|---:|---:|---:|")
        .map_err(|e| format!("failed to build report: {e}"))?;
    for impact in impacts {
        writeln!(
            &mut report,
            "| {} | {:.6} | {:.2} | {:.2} | {:.2} |",
            impact.algorithm,
            impact.verify_latency_ms,
            impact.tps_single_thread,
            impact.tps_four_core,
            impact.tps_eight_core
        )
        .map_err(|e| format!("failed to build report: {e}"))?;
    }
    writeln!(&mut report).map_err(|e| format!("failed to build report: {e}"))?;

    let slh_sign_ms = find_latency_ms(rows, "bounded_slh_dsa_sha2_128s", "sign");
    let slh_verify_ms = find_latency_ms(rows, "bounded_slh_dsa_sha2_128s", "verify");
    let secp_verify_ms = find_latency_ms(rows, "secp256k1_schnorr", "verify");

    writeln!(&mut report, "## Target Check").map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "| Target | Result | Status |")
        .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(&mut report, "|---|---|---|").map_err(|e| format!("failed to build report: {e}"))?;
    match slh_sign_ms {
        Some(ms) => writeln!(
            &mut report,
            "| Signing <= 500 ms | {:.6} ms | {} |",
            ms,
            if ms <= 500.0 { "PASS" } else { "FAIL" }
        )
        .map_err(|e| format!("failed to build report: {e}"))?,
        None => writeln!(
            &mut report,
            "| Signing <= 500 ms | Not measured in this run | N/A |"
        )
        .map_err(|e| format!("failed to build report: {e}"))?,
    }
    match slh_verify_ms {
        Some(ms) => writeln!(
            &mut report,
            "| Verification <= 0.5 ms | {:.6} ms | {} |",
            ms,
            if ms <= 0.5 { "PASS" } else { "FAIL" }
        )
        .map_err(|e| format!("failed to build report: {e}"))?,
        None => writeln!(
            &mut report,
            "| Verification <= 0.5 ms | Not measured in this run | N/A |"
        )
        .map_err(|e| format!("failed to build report: {e}"))?,
    }
    if metadata.sha_ni == "detected" {
        match slh_verify_ms {
            Some(ms) => writeln!(
                &mut report,
                "| Verification with SHA-NI <= 0.1 ms | {:.6} ms | {} |",
                ms,
                if ms <= 0.1 { "PASS" } else { "FAIL" }
            )
            .map_err(|e| format!("failed to build report: {e}"))?,
            None => writeln!(
                &mut report,
                "| Verification with SHA-NI <= 0.1 ms | Not measured in this run | N/A |"
            )
            .map_err(|e| format!("failed to build report: {e}"))?,
        }
    } else {
        writeln!(
            &mut report,
            "| Verification with SHA-NI <= 0.1 ms | Not measured on this host ({}) | N/A |",
            metadata.sha_ni
        )
        .map_err(|e| format!("failed to build report: {e}"))?;
    }
    writeln!(&mut report).map_err(|e| format!("failed to build report: {e}"))?;

    writeln!(&mut report, "## Learnings").map_err(|e| format!("failed to build report: {e}"))?;
    if let Some(ms) = slh_sign_ms {
        if ms <= 500.0 {
            writeln!(
                &mut report,
                "- Bounded SLH-DSA signing is within the wallet UX target."
            )
            .map_err(|e| format!("failed to build report: {e}"))?;
        } else {
            writeln!(
                &mut report,
                "- Bounded SLH-DSA signing is above the wallet UX target and needs optimization."
            )
            .map_err(|e| format!("failed to build report: {e}"))?;
        }
    }
    if let Some(ms) = slh_verify_ms {
        if ms <= 0.5 {
            writeln!(
                &mut report,
                "- Verification is within the 0.5 ms block-validation budget target on this host."
            )
            .map_err(|e| format!("failed to build report: {e}"))?;
        } else {
            writeln!(
                &mut report,
                "- Verification is the primary bottleneck for block-validation budgets on this host."
            )
            .map_err(|e| format!("failed to build report: {e}"))?;
        }
        writeln!(
            &mut report,
            "- At a 1% verify budget on 30-second blocks, bounded SLH-DSA reaches budget saturation near {:.2} TPS single-threaded.",
            tps_threshold_for_one_percent_block_time(ms)
        )
        .map_err(|e| format!("failed to build report: {e}"))?;
    }
    if let (Some(slh_ms), Some(secp_ms)) = (slh_verify_ms, secp_verify_ms) {
        writeln!(
            &mut report,
            "- secp256k1 Schnorr verify is approximately {:.1}x faster than bounded SLH-DSA verify in this environment.",
            slh_ms / secp_ms
        )
        .map_err(|e| format!("failed to build report: {e}"))?;
    }
    if slh_sign_ms.is_none() && slh_verify_ms.is_none() && secp_verify_ms.is_none() {
        writeln!(
            &mut report,
            "- Sign/verify were not part of this filtered run; run `cargo bench` without filters for full learnings."
        )
        .map_err(|e| format!("failed to build report: {e}"))?;
    }
    writeln!(&mut report).map_err(|e| format!("failed to build report: {e}"))?;

    writeln!(&mut report, "## Constraints").map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- This repository is currently configured as a bounded-only profile build, so unbounded SLH and SHA2-vs-SHAKE benchmark comparisons are not included."
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- Reported 4-core and 8-core TPS are idealized linear scaling estimates, not directly measured multicore throughput."
    )
    .map_err(|e| format!("failed to build report: {e}"))?;
    writeln!(
        &mut report,
        "- SHA-NI impact is not measured on this ARM host; an x86 run is required for that measurement."
    )
    .map_err(|e| format!("failed to build report: {e}"))?;

    fs::write(
        Path::new(env!("CARGO_MANIFEST_DIR")).join(REPORT_PATH),
        report,
    )
    .map_err(|e| format!("failed to write {REPORT_PATH}: {e}"))
}

fn write_json_artifact(
    metadata: &HostMetadata,
    sizes: &SizeSnapshot,
    rows: &[PerfRow],
    impacts: &[ImpactRow],
) -> Result<(), String> {
    let verify_budget_seconds = BLOCK_TIME_SECONDS * BLOCK_VERIFY_BUDGET_FRACTION;
    let benchmarks: Vec<Value> = rows
        .iter()
        .map(|row| {
            json!({
                "algorithm": row.algorithm,
                "operation": row.operation,
                "latency_ms": row.latency_ms,
                "throughput_ops_per_sec": row.throughput_ops_per_sec
            })
        })
        .collect();
    let impact_analysis: Vec<Value> = impacts
        .iter()
        .map(|impact| {
            json!({
                "algorithm": impact.algorithm,
                "verify_latency_ms": impact.verify_latency_ms,
                "tps_threshold_1_thread": impact.tps_single_thread,
                "tps_threshold_4_core_ideal": impact.tps_four_core,
                "tps_threshold_8_core_ideal": impact.tps_eight_core
            })
        })
        .collect();

    let artifact = json!({
        "generated_at_utc": metadata.generated_at_utc,
        "commit_hash": metadata.commit_hash,
        "worktree_dirty_at_start": metadata.worktree_dirty_at_start,
        "rustc_version": metadata.rustc_version,
        "host": {
            "cpu_model": metadata.cpu_model,
            "sha_ni": metadata.sha_ni,
            "arm_sha2": metadata.arm_sha2,
            "os": metadata.os,
            "arch": metadata.arch
        },
        "runtime_env_knobs": metadata.runtime_env_knobs,
        "optimization_env": {
            "SPX_OPT_PROFILE": metadata.opt_profile,
            "SPX_DISABLE_SHA_ACCEL": metadata.disable_sha_accel,
            "SPX_DISABLE_SIMD": metadata.disable_simd,
            "SPX_FORS_THREADS": metadata.fors_threads,
            "SPX_DISABLE_THREADS": metadata.disable_threads,
            "SPX_ENABLE_ARM_SHA": metadata.enable_arm_sha,
            "SPX_SHA_BACKEND": metadata.sha_backend
        },
        "sizes": {
            "bounded_slh_dsa_sha2_128s": {
                "public_key_bytes": sizes.slh_public_key_bytes,
                "secret_key_bytes": sizes.slh_secret_key_bytes,
                "signature_bytes": sizes.slh_signature_bytes
            },
            "secp256k1_schnorr": {
                "public_key_bytes": sizes.secp_public_key_bytes,
                "secret_key_bytes": sizes.secp_secret_key_bytes,
                "signature_bytes": sizes.secp_signature_bytes
            }
        },
        "verify_budget": {
            "block_time_seconds": BLOCK_TIME_SECONDS,
            "budget_fraction": BLOCK_VERIFY_BUDGET_FRACTION,
            "budget_seconds": verify_budget_seconds
        },
        "run_scope": {
            "benchmarks_collected": rows.len(),
            "benchmarks_expected": BENCH_SPECS.len()
        },
        "benchmarks": benchmarks,
        "impact_analysis": impact_analysis
    });

    let artifact_path = Path::new(env!("CARGO_MANIFEST_DIR")).join(JSON_ARTIFACT_PATH);
    let pretty = serde_json::to_string_pretty(&artifact)
        .map_err(|e| format!("failed to serialize JSON artifact: {e}"))?;
    fs::write(&artifact_path, pretty)
        .map_err(|e| format!("failed to write {}: {e}", artifact_path.display()))
}

fn write_benchmark_artifacts(
    metadata: &HostMetadata,
    sizes: &SizeSnapshot,
    run_started_at: SystemTime,
) -> Result<(), String> {
    let rows = collect_perf_rows(run_started_at)?;
    let impacts = collect_impact_rows(&rows);

    write_report(metadata, sizes, &rows, &impacts)?;
    write_json_artifact(metadata, sizes, &rows, &impacts)
}

fn configured_criterion() -> Criterion {
    Criterion::default()
        .sample_size(20)
        .warm_up_time(Duration::from_secs(2))
        .measurement_time(Duration::from_secs(8))
        .configure_from_args()
}

fn main() {
    let metadata = collect_host_metadata().unwrap_or_else(|err| {
        panic!("failed to collect benchmark host metadata: {err}");
    });
    if metadata.worktree_dirty_at_start {
        panic!(
            "refusing to generate benchmark artifacts from a dirty worktree; commit or stash tracked changes first"
        );
    }

    let sizes = capture_sizes();
    assert_size_expectations(&sizes);
    let run_started_at = SystemTime::now();

    let mut criterion = configured_criterion();
    benchmark_slh_keygen(&mut criterion);
    benchmark_slh_sign(&mut criterion);
    benchmark_slh_verify(&mut criterion);
    benchmark_secp_keygen(&mut criterion);
    benchmark_secp_sign(&mut criterion);
    benchmark_secp_verify(&mut criterion);
    criterion.final_summary();

    if let Err(err) = write_benchmark_artifacts(&metadata, &sizes, run_started_at) {
        panic!("failed to write benchmark artifacts: {err}");
    }
}
