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

    // Set in the child process this test spawns once per feature, since the
    // toggle is process-wide and would fail every other test in this one.
    const CHILD: &str = "RIND_TEST_MISSING_CPU_FEATURE";

    // The child reports both refusals as output and lets the operation's
    // panic end it, since a `panic = "abort"` build cannot catch it.
    if std::env::var_os(CHILD).is_some() {
        println!("check: {}", rind::cpu::check().unwrap_err());
        rind::aead::AesGcm::new(&[0; 16]);
        return;
    }

    for feature in REQUIRED {
        // valgrind cannot run adx, so this build accepts its absence.
        if *feature == "adx" && option_env!("VALGRIND_BUG_494162").is_some() {
            continue;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "missing_feature_is_named", "--nocapture"])
            .env(CHILD, "1")
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
        assert!(!output.status.success(), "{feature}: {text}");
        assert!(
            text.contains(&format!("check: {expected}\n")),
            "{feature}: {text}"
        );
        // The panic message follows its `panicked at <location>:` line.
        assert!(
            text.contains(&format!(":\n{expected}\n")),
            "{feature}: {text}"
        );
    }
}
