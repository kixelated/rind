//! The CPU check names each required feature the CPU lacks, and every
//! operation refuses with the same message.

#[test]
fn check_passes() {
    assert_eq!(rind::cpu::check(), Ok(()));
}

// `RIND_CPU_DISABLE_*` only takes effect with debug assertions.
#[cfg(debug_assertions)]
#[test]
fn missing_feature_is_named() {
    #[cfg(target_arch = "x86_64")]
    const REQUIRED: &[&str] = &[
        "ssse3",
        "popcnt",
        "aes",
        "pclmulqdq",
        "avx",
        "avx2",
        "bmi2",
        "adx",
    ];
    #[cfg(target_arch = "aarch64")]
    const REQUIRED: &[&str] = &["neon", "aes", "pmull", "sha2"];

    // Hashing checks the CPU apart from `Entry`, so each hash family is
    // covered beside an `Entry` operation.
    const OPERATIONS: &[&str] = &["aes-gcm", "sha256", "sha384", "sha512", "sha3-256"];

    // Set in the child process this test spawns once per feature and
    // operation, since the toggle is process-wide and would fail every other
    // test in this one.
    const CHILD: &str = "RIND_TEST_MISSING_CPU_FEATURE";

    // The child reports both refusals as output and lets the operation's
    // panic end it, since a `panic = "abort"` build cannot catch it.
    if let Some(operation) = std::env::var_os(CHILD) {
        println!("check: {}", rind::cpu::check().unwrap_err());
        match operation.to_str().unwrap() {
            "aes-gcm" => drop(rind::aead::AesGcm::new(&[0; 16])),
            "sha256" => drop(rind::hashing::sha2::Sha256Context::new().finish()),
            "sha384" => drop(rind::hashing::sha2::Sha384Context::new().finish()),
            "sha512" => drop(rind::hashing::sha2::Sha512Context::new().finish()),
            "sha3-256" => drop(rind::hashing::sha3::Sha3_256Context::new().finish()),
            other => unreachable!("{other}"),
        }
        return;
    }

    for (feature, operation) in REQUIRED
        .iter()
        .flat_map(|feature| OPERATIONS.iter().map(move |operation| (feature, operation)))
    {
        // valgrind cannot run adx, so this build accepts its absence.
        if *feature == "adx" && option_env!("VALGRIND_BUG_494162").is_some() {
            continue;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "missing_feature_is_named", "--nocapture"])
            .env(CHILD, operation)
            .env(format!("RIND_CPU_DISABLE_{feature}"), "1")
            .output()
            .unwrap();
        let text = format!(
            "{}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );

        let expected = format!(
            "rind requires {feature} CPU support on {}",
            std::env::consts::ARCH
        );
        assert!(!output.status.success(), "{feature} {operation}: {text}");
        assert!(
            text.contains(&format!("check: {expected}\n")),
            "{feature} {operation}: {text}"
        );
        // The panic message follows its `panicked at <location>:` line.
        assert!(
            text.contains(&format!(":\n{expected}\n")),
            "{feature} {operation}: {text}"
        );
    }
}
