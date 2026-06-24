use std::env;
use std::path::PathBuf;

fn main() {
    let mut cmake_config = cmake::Config::new(".");
    if env::var_os("CARGO_FEATURE_TEST_HELPERS").is_some() {
        cmake_config.define("BITCOINPQC_ENABLE_TEST_HELPERS", "ON");
    }
    let forsc_max_grind_attempts =
        env::var("BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS").unwrap_or_else(|_| "1835008".to_string());
    let wotsc_max_counter =
        env::var("BITCOINPQC_WOTSC_MAX_COUNTER").unwrap_or_else(|_| "65535".to_string());
    cmake_config.define(
        "BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS",
        forsc_max_grind_attempts,
    );
    cmake_config.define("BITCOINPQC_WOTSC_MAX_COUNTER", wotsc_max_counter);
    if env::var_os("CARGO_FEATURE_TEST_BENCH_ENV_KNOBS").is_some() {
        cmake_config.define("SPX_ENABLE_TEST_BENCH_ENV_KNOBS", "ON");
    }
    let dst = cmake_config.build();

    println!("cargo:rustc-link-search=native={}/lib", dst.display());
    println!("cargo:rustc-link-lib=static=bitcoinpqc");

    println!("cargo:rerun-if-changed=CMakeLists.txt");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=sphincsplus");
    println!("cargo:rerun-if-changed=include/libbitcoinpqc/bitcoinpqc.h");
    println!("cargo:rerun-if-changed=include/libbitcoinpqc/slh_dsa.h");
    println!("cargo:rerun-if-changed=include/libbitcoinpqc/sign_stats.h");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_HELPERS");
    println!("cargo:rerun-if-env-changed=BITCOINPQC_FORSC_MAX_GRIND_ATTEMPTS");
    println!("cargo:rerun-if-env-changed=BITCOINPQC_WOTSC_MAX_COUNTER");
    println!("cargo:rerun-if-env-changed=CARGO_FEATURE_TEST_BENCH_ENV_KNOBS");

    let bindings = bindgen::Builder::default()
        .header("include/libbitcoinpqc/bitcoinpqc.h")
        .clang_arg("-Iinclude")
        .parse_callbacks(Box::new(bindgen::CargoCallbacks::new()))
        .allowlist_function("bitcoin_pqc_.*")
        .allowlist_type("bitcoin_pqc_.*")
        .allowlist_var("BITCOIN_PQC_.*")
        .generate()
        .expect("Unable to generate bindings");

    let out_path = PathBuf::from(env::var("OUT_DIR").unwrap());
    bindings
        .write_to_file(out_path.join("bindings.rs"))
        .expect("Couldn't write bindings!");
}
