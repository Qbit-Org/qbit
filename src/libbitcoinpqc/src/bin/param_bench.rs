use bitcoinpqc::{
    generate_keypair, public_key_size, secret_key_size, sign, sign_with_stats, signature_size,
    verify, PqcError,
};
use std::env;
use std::fmt::Write as _;
use std::hint::black_box;
use std::process::Command;
use std::time::Instant;

#[derive(Clone, Copy)]
struct BenchStats {
    mean_ms: f64,
    inner_iters: usize,
    samples: usize,
}

#[derive(Clone, Copy)]
struct Distribution<T> {
    count: usize,
    p50: T,
    p95: T,
    p99: T,
    p999: T,
    max: T,
}

type U64Distribution = Distribution<u64>;
type F64Distribution = Distribution<f64>;

struct SignGrindStats {
    samples: usize,
    cap_exceeded_failures: usize,
    forsc_max_attempts: u32,
    wotsc_max_attempts: u32,
    forsc_attempts: U64Distribution,
    wotsc_total_attempts: U64Distribution,
    wotsc_max_layer_attempts: U64Distribution,
    sign_latency_ms: F64Distribution,
}

fn env_or_default_usize(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .unwrap_or(default)
}

fn env_or_default_usize_at_least(name: &str, default: usize, min: usize) -> usize {
    env_or_default_usize(name, default).max(min)
}

fn env_or_default_f64(name: &str, default: f64) -> f64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse::<f64>().ok().filter(|parsed| parsed.is_finite()))
        .unwrap_or(default)
}

fn env_or_unset(name: &str) -> String {
    env::var(name).unwrap_or_else(|_| "unset".to_string())
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

fn run_command_combined(command: &str, args: &[&str]) -> Option<String> {
    let output = Command::new(command).args(args).output().ok()?;
    let mut text = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if text.is_empty() {
        text = String::from_utf8_lossy(&output.stderr).trim().to_string();
    }
    if text.is_empty() {
        None
    } else {
        Some(text)
    }
}

fn generated_at_utc() -> String {
    run_command("date", &["-u", "+%Y-%m-%dT%H:%M:%SZ"]).unwrap_or_else(|| {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|duration| format!("unix:{}", duration.as_secs()))
            .unwrap_or_else(|_| "unknown".to_string())
    })
}

fn git_commit_sha() -> String {
    env::var("GITHUB_SHA")
        .ok()
        .filter(|value| !value.is_empty())
        .or_else(|| run_command("git", &["rev-parse", "HEAD"]))
        .unwrap_or_else(|| "unknown".to_string())
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
        if let Ok(cpuinfo) = std::fs::read_to_string("/proc/cpuinfo") {
            for line in cpuinfo.lines() {
                if let Some(model) = line.strip_prefix("model name\t: ") {
                    return model.to_string();
                }
                if let Some(model) = line.strip_prefix("Hardware\t: ") {
                    return model.to_string();
                }
                if let Some(model) = line.strip_prefix("Processor\t: ") {
                    return model.to_string();
                }
            }
        }
    }

    #[cfg(target_os = "windows")]
    {
        if let Some(model) = run_command(
            "powershell",
            &[
                "-NoProfile",
                "-Command",
                "(Get-CimInstance Win32_Processor | Select-Object -First 1 -ExpandProperty Name)",
            ],
        ) {
            return model;
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

fn c_compiler_command() -> String {
    env::var("CC").unwrap_or_else(|_| {
        if cfg!(target_os = "windows") {
            "cl".to_string()
        } else {
            "cc".to_string()
        }
    })
}

fn c_compiler_version(command: &str) -> String {
    if cfg!(target_os = "windows") && command == "cl" {
        run_command_combined(command, &[]).unwrap_or_else(|| "unknown".to_string())
    } else {
        run_command_combined(command, &["--version"]).unwrap_or_else(|| "unknown".to_string())
    }
}

fn run_bench<F>(
    target_sample_ms: f64,
    max_inner_iters: usize,
    samples: usize,
    mut op: F,
) -> BenchStats
where
    F: FnMut(),
{
    // Warmup avoids first-run effects when calibrating.
    op();
    let calibrate_start = Instant::now();
    op();
    let calibrate_ms = calibrate_start.elapsed().as_secs_f64() * 1000.0;

    let mut inner_iters = if calibrate_ms > 0.0 {
        (target_sample_ms / calibrate_ms).round() as usize
    } else {
        1
    };
    if inner_iters == 0 {
        inner_iters = 1;
    }
    if inner_iters > max_inner_iters {
        inner_iters = max_inner_iters;
    }

    let mut total_ms = 0.0f64;
    for _ in 0..samples {
        let start = Instant::now();
        for _ in 0..inner_iters {
            op();
        }
        total_ms += start.elapsed().as_secs_f64() * 1000.0 / (inner_iters as f64);
    }

    BenchStats {
        mean_ms: total_ms / (samples as f64),
        inner_iters,
        samples,
    }
}

fn percentile_index(len: usize, percentile: f64) -> usize {
    if len == 0 {
        return 0;
    }
    ((percentile * len as f64).ceil() as usize)
        .saturating_sub(1)
        .min(len - 1)
}

fn distribution_from_sorted<T: Copy>(values: &[T], zero: T) -> Distribution<T> {
    if values.is_empty() {
        return Distribution {
            count: 0,
            p50: zero,
            p95: zero,
            p99: zero,
            p999: zero,
            max: zero,
        };
    }
    let len = values.len();
    Distribution {
        count: len,
        p50: values[percentile_index(len, 0.50)],
        p95: values[percentile_index(len, 0.95)],
        p99: values[percentile_index(len, 0.99)],
        p999: values[percentile_index(len, 0.999)],
        max: values[len - 1],
    }
}

fn u64_distribution(mut values: Vec<u64>) -> U64Distribution {
    values.sort_unstable();
    distribution_from_sorted(&values, 0)
}

fn f64_distribution(mut values: Vec<f64>) -> F64Distribution {
    values.sort_by(|lhs, rhs| lhs.total_cmp(rhs));
    distribution_from_sorted(&values, 0.0)
}

fn grind_message(counter: u64) -> [u8; 32] {
    let mut msg = [0xD7u8; 32];
    msg[..8].copy_from_slice(&counter.to_le_bytes());
    msg[8..16].copy_from_slice(&counter.wrapping_mul(0x9E37_79B9_7F4A_7C15).to_le_bytes());
    for (idx, byte) in msg[16..].iter_mut().enumerate() {
        *byte ^= ((counter >> (idx % 8)) as u8).wrapping_add((idx as u8).wrapping_mul(17));
    }
    msg
}

fn collect_sign_grind_stats(keypair: &bitcoinpqc::KeyPair, samples: usize) -> SignGrindStats {
    let mut forsc_attempts = Vec::with_capacity(samples);
    let mut wotsc_total_attempts = Vec::with_capacity(samples);
    let mut wotsc_max_layer_attempts = Vec::with_capacity(samples);
    let mut sign_latency_ms = Vec::with_capacity(samples);
    let mut forsc_max_attempts = 0u32;
    let mut wotsc_max_attempts = 0u32;
    let mut cap_exceeded_failures = 0usize;

    for i in 0..samples {
        let msg = grind_message(i as u64);
        let start = Instant::now();
        let signed = sign_with_stats(&keypair.secret_key, &msg);
        let elapsed_ms = start.elapsed().as_secs_f64() * 1000.0;

        match signed {
            Ok((signature, stats)) => {
                verify(&keypair.public_key, &msg, &signature)
                    .expect("sign grind corpus signature should verify");
                sign_latency_ms.push(elapsed_ms);
                forsc_attempts.push(stats.forsc_attempts as u64);
                wotsc_total_attempts.push(
                    stats
                        .wotsc_attempts
                        .iter()
                        .map(|attempts| *attempts as u64)
                        .sum(),
                );
                wotsc_max_layer_attempts
                    .push(stats.wotsc_attempts.iter().copied().max().unwrap_or(0) as u64);
                forsc_max_attempts = stats.forsc_max_attempts;
                wotsc_max_attempts = stats.wotsc_max_attempts;
                if stats.limit_exceeded() {
                    cap_exceeded_failures += 1;
                }
                black_box(signature);
            }
            Err(err) if err.error == PqcError::SigningLimitExceeded => {
                panic!("signing cap exceeded in deterministic grind benchmark corpus");
            }
            Err(err) => panic!("sign grind corpus signing failed: {err}"),
        }
    }

    SignGrindStats {
        samples,
        cap_exceeded_failures,
        forsc_max_attempts,
        wotsc_max_attempts,
        forsc_attempts: u64_distribution(forsc_attempts),
        wotsc_total_attempts: u64_distribution(wotsc_total_attempts),
        wotsc_max_layer_attempts: u64_distribution(wotsc_max_layer_attempts),
        sign_latency_ms: f64_distribution(sign_latency_ms),
    }
}

fn throughput_ops_per_sec(latency_ms: f64) -> f64 {
    if latency_ms > 0.0 {
        1000.0 / latency_ms
    } else {
        0.0
    }
}

fn json_escape(value: &str) -> String {
    let mut escaped = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '"' => escaped.push_str("\\\""),
            '\\' => escaped.push_str("\\\\"),
            '\n' => escaped.push_str("\\n"),
            '\r' => escaped.push_str("\\r"),
            '\t' => escaped.push_str("\\t"),
            '\u{08}' => escaped.push_str("\\b"),
            '\u{0c}' => escaped.push_str("\\f"),
            ch if ch <= '\u{1f}' => {
                write!(&mut escaped, "\\u{:04x}", ch as u32)
                    .expect("writing to String cannot fail");
            }
            ch => escaped.push(ch),
        }
    }
    escaped
}

fn json_string(value: &str) -> String {
    format!("\"{}\"", json_escape(value))
}

fn write_string_field(out: &mut String, indent: usize, key: &str, value: &str, comma: bool) {
    write_raw_field(out, indent, key, &json_string(value), comma);
}

fn write_raw_field(out: &mut String, indent: usize, key: &str, value: &str, comma: bool) {
    writeln!(
        out,
        "{}{}: {}{}",
        " ".repeat(indent),
        json_string(key),
        value,
        if comma { "," } else { "" }
    )
    .expect("writing to String cannot fail");
}

fn write_benchmark_entry(
    out: &mut String,
    operation: &str,
    stats: BenchStats,
    throughput_ops_per_sec: f64,
    comma: bool,
) {
    writeln!(out, "    {{").expect("writing to String cannot fail");
    write_string_field(out, 6, "algorithm", "bounded_slh_dsa_sha2_128s", true);
    write_string_field(out, 6, "operation", operation, true);
    write_raw_field(out, 6, "latency_ms", &stats.mean_ms.to_string(), true);
    write_raw_field(
        out,
        6,
        "throughput_ops_per_sec",
        &throughput_ops_per_sec.to_string(),
        true,
    );
    write_raw_field(out, 6, "samples", &stats.samples.to_string(), true);
    write_raw_field(out, 6, "inner_iters", &stats.inner_iters.to_string(), false);
    writeln!(out, "    }}{}", if comma { "," } else { "" }).expect("writing to String cannot fail");
}

fn write_distribution<T: ToString>(
    out: &mut String,
    indent: usize,
    key: &str,
    distribution: Distribution<T>,
    comma: bool,
) {
    writeln!(out, "{}{}: {{", " ".repeat(indent), json_string(key))
        .expect("writing to String cannot fail");
    write_raw_field(
        out,
        indent + 2,
        "count",
        &distribution.count.to_string(),
        true,
    );
    write_raw_field(out, indent + 2, "p50", &distribution.p50.to_string(), true);
    write_raw_field(out, indent + 2, "p95", &distribution.p95.to_string(), true);
    write_raw_field(out, indent + 2, "p99", &distribution.p99.to_string(), true);
    write_raw_field(
        out,
        indent + 2,
        "p99_9",
        &distribution.p999.to_string(),
        true,
    );
    write_raw_field(out, indent + 2, "max", &distribution.max.to_string(), false);
    writeln!(
        out,
        "{}}}{}",
        " ".repeat(indent),
        if comma { "," } else { "" }
    )
    .expect("writing to String cannot fail");
}

fn main() {
    let samples = env_or_default_usize_at_least("PARAM_BENCH_SAMPLES", 5, 1);
    let target_sample_ms = env_or_default_f64("PARAM_BENCH_TARGET_MS", 1500.0);
    let max_inner_iters = env_or_default_usize_at_least("PARAM_BENCH_MAX_INNER", 50, 1);
    let grind_samples = env_or_default_usize_at_least("PARAM_BENCH_GRIND_SAMPLES", 64, 1);

    let mut keygen_counter = 0u64;
    let keygen_stats = run_bench(target_sample_ms, max_inner_iters, samples, || {
        let mut entropy = [0x42u8; 128];
        entropy[..8].copy_from_slice(&keygen_counter.to_le_bytes());
        keygen_counter = keygen_counter.wrapping_add(1);
        let kp = generate_keypair(&entropy).expect("keygen should succeed");
        black_box(kp);
    });

    let mut bench_entropy = [0x24u8; 128];
    bench_entropy[..8].copy_from_slice(&0x5Au64.to_le_bytes());
    let keypair = generate_keypair(&bench_entropy).expect("benchmark keypair generation failed");

    let mut sign_counter = 0u64;
    let sign_stats = run_bench(target_sample_ms, max_inner_iters, samples, || {
        let mut msg = [0xA5u8; 32];
        msg[..8].copy_from_slice(&sign_counter.to_le_bytes());
        sign_counter = sign_counter.wrapping_add(1);
        let sig = sign(&keypair.secret_key, &msg).expect("sign should succeed");
        black_box(sig);
    });

    let mut verify_messages: Vec<[u8; 32]> = Vec::with_capacity(8);
    let mut verify_signatures = Vec::with_capacity(8);
    for i in 0u64..8 {
        let mut msg = [0xC3u8; 32];
        msg[..8].copy_from_slice(&i.to_le_bytes());
        verify_signatures
            .push(sign(&keypair.secret_key, &msg).expect("verify corpus signing failed"));
        verify_messages.push(msg);
    }

    let mut verify_counter = 0usize;
    let verify_stats = run_bench(target_sample_ms, max_inner_iters, samples, || {
        let idx = verify_counter % verify_messages.len();
        verify_counter = verify_counter.wrapping_add(1);
        verify(
            &keypair.public_key,
            &verify_messages[idx],
            &verify_signatures[idx],
        )
        .expect("verify should succeed");
        black_box(idx);
    });
    let sign_grind_stats = collect_sign_grind_stats(&keypair, grind_samples);

    let keygen_ops_per_sec = throughput_ops_per_sec(keygen_stats.mean_ms);
    let sign_ops_per_sec = throughput_ops_per_sec(sign_stats.mean_ms);
    let verify_ops_per_sec = throughput_ops_per_sec(verify_stats.mean_ms);
    let c_compiler = c_compiler_command();
    let mut artifact = String::new();

    writeln!(&mut artifact, "{{").expect("writing to String cannot fail");
    write_raw_field(&mut artifact, 2, "schema_version", "1", true);
    write_string_field(
        &mut artifact,
        2,
        "generated_at_utc",
        &generated_at_utc(),
        true,
    );
    write_string_field(&mut artifact, 2, "commit_sha", &git_commit_sha(), true);

    writeln!(&mut artifact, "  \"github\": {{").expect("writing to String cannot fail");
    write_string_field(
        &mut artifact,
        4,
        "repository",
        &env_or_unset("GITHUB_REPOSITORY"),
        true,
    );
    write_string_field(&mut artifact, 4, "ref", &env_or_unset("GITHUB_REF"), true);
    write_string_field(
        &mut artifact,
        4,
        "head_ref",
        &env_or_unset("GITHUB_HEAD_REF"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "run_id",
        &env_or_unset("GITHUB_RUN_ID"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "run_attempt",
        &env_or_unset("GITHUB_RUN_ATTEMPT"),
        false,
    );
    writeln!(&mut artifact, "  }},").expect("writing to String cannot fail");

    writeln!(&mut artifact, "  \"host\": {{").expect("writing to String cannot fail");
    write_string_field(&mut artifact, 4, "os", env::consts::OS, true);
    write_string_field(&mut artifact, 4, "arch", env::consts::ARCH, true);
    write_string_field(
        &mut artifact,
        4,
        "runner_os",
        &env_or_unset("RUNNER_OS"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "runner_arch",
        &env_or_unset("RUNNER_ARCH"),
        true,
    );
    write_string_field(&mut artifact, 4, "cpu_model", &detect_cpu_model(), true);
    write_string_field(&mut artifact, 4, "sha_ni", &detect_sha_ni(), true);
    write_string_field(&mut artifact, 4, "arm_sha2", &detect_arm_sha2(), false);
    writeln!(&mut artifact, "  }},").expect("writing to String cannot fail");

    writeln!(&mut artifact, "  \"toolchain\": {{").expect("writing to String cannot fail");
    write_string_field(
        &mut artifact,
        4,
        "rustc_version",
        &run_command_combined("rustc", &["--version", "--verbose"])
            .unwrap_or_else(|| "unknown".to_string()),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "cargo_version",
        &run_command_combined("cargo", &["--version"]).unwrap_or_else(|| "unknown".to_string()),
        true,
    );
    write_string_field(&mut artifact, 4, "c_compiler", &c_compiler, true);
    write_string_field(
        &mut artifact,
        4,
        "c_compiler_version",
        &c_compiler_version(&c_compiler),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "cmake_version",
        &run_command_combined("cmake", &["--version"]).unwrap_or_else(|| "unknown".to_string()),
        false,
    );
    writeln!(&mut artifact, "  }},").expect("writing to String cannot fail");

    writeln!(&mut artifact, "  \"backend\": {{").expect("writing to String cannot fail");
    write_string_field(
        &mut artifact,
        4,
        "SPX_OPT_PROFILE",
        &env_or_unset("SPX_OPT_PROFILE"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "SPX_DISABLE_SHA_ACCEL",
        &env_or_unset("SPX_DISABLE_SHA_ACCEL"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "SPX_DISABLE_SIMD",
        &env_or_unset("SPX_DISABLE_SIMD"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "SPX_DISABLE_THREADS",
        &env_or_unset("SPX_DISABLE_THREADS"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "SPX_ENABLE_ARM_SHA",
        &env_or_unset("SPX_ENABLE_ARM_SHA"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "SPX_FORS_THREADS",
        &env_or_unset("SPX_FORS_THREADS"),
        true,
    );
    write_string_field(
        &mut artifact,
        4,
        "SPX_SHA_BACKEND",
        &env_or_unset("SPX_SHA_BACKEND"),
        false,
    );
    writeln!(&mut artifact, "  }},").expect("writing to String cannot fail");

    write_raw_field(
        &mut artifact,
        2,
        "signature_size",
        &signature_size().to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "public_key_size",
        &public_key_size().to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "secret_key_size",
        &secret_key_size().to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "keygen_ms",
        &keygen_stats.mean_ms.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "sign_ms",
        &sign_stats.mean_ms.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "verify_ms",
        &verify_stats.mean_ms.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "keygen_ops_per_sec",
        &keygen_ops_per_sec.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "sign_ops_per_sec",
        &sign_ops_per_sec.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "verify_ops_per_sec",
        &verify_ops_per_sec.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "samples",
        &keygen_stats.samples.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "target_sample_ms",
        &target_sample_ms.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "max_inner_iters",
        &max_inner_iters.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "keygen_inner_iters",
        &keygen_stats.inner_iters.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "sign_inner_iters",
        &sign_stats.inner_iters.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        2,
        "verify_inner_iters",
        &verify_stats.inner_iters.to_string(),
        true,
    );

    writeln!(&mut artifact, "  \"bench_config\": {{").expect("writing to String cannot fail");
    write_raw_field(
        &mut artifact,
        4,
        "samples",
        &keygen_stats.samples.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        4,
        "target_sample_ms",
        &target_sample_ms.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        4,
        "max_inner_iters",
        &max_inner_iters.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        4,
        "grind_samples",
        &grind_samples.to_string(),
        false,
    );
    writeln!(&mut artifact, "  }},").expect("writing to String cannot fail");

    writeln!(&mut artifact, "  \"sign_grind\": {{").expect("writing to String cannot fail");
    write_raw_field(
        &mut artifact,
        4,
        "samples",
        &sign_grind_stats.samples.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        4,
        "cap_exceeded_failures",
        &sign_grind_stats.cap_exceeded_failures.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        4,
        "forsc_max_attempts",
        &sign_grind_stats.forsc_max_attempts.to_string(),
        true,
    );
    write_raw_field(
        &mut artifact,
        4,
        "wotsc_max_attempts",
        &sign_grind_stats.wotsc_max_attempts.to_string(),
        true,
    );
    write_distribution(
        &mut artifact,
        4,
        "forsc_attempts",
        sign_grind_stats.forsc_attempts,
        true,
    );
    write_distribution(
        &mut artifact,
        4,
        "wotsc_total_attempts",
        sign_grind_stats.wotsc_total_attempts,
        true,
    );
    write_distribution(
        &mut artifact,
        4,
        "wotsc_max_layer_attempts",
        sign_grind_stats.wotsc_max_layer_attempts,
        true,
    );
    write_distribution(
        &mut artifact,
        4,
        "sign_latency_ms",
        sign_grind_stats.sign_latency_ms,
        false,
    );
    writeln!(&mut artifact, "  }},").expect("writing to String cannot fail");

    writeln!(&mut artifact, "  \"benchmarks\": [").expect("writing to String cannot fail");
    write_benchmark_entry(
        &mut artifact,
        "keygen",
        keygen_stats,
        keygen_ops_per_sec,
        true,
    );
    write_benchmark_entry(&mut artifact, "sign", sign_stats, sign_ops_per_sec, true);
    write_benchmark_entry(
        &mut artifact,
        "verify",
        verify_stats,
        verify_ops_per_sec,
        false,
    );
    writeln!(&mut artifact, "  ]").expect("writing to String cannot fail");
    writeln!(&mut artifact, "}}").expect("writing to String cannot fail");

    print!("{artifact}");
}
