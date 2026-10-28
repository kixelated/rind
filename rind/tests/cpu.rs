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

    if let Ok(feature) = std::env::var(CHILD) {
        let expected = format!(
            "rind requires {feature} CPU support on {}",
            std::env::consts::ARCH
        );
        assert_eq!(rind::cpu::check().unwrap_err().to_string(), expected);

        let panic = std::panic::catch_unwind(|| {
            rind::aead::AesGcm::new(&[0; 16]);
        })
        .unwrap_err();
        assert_eq!(panic.downcast_ref::<String>(), Some(&expected));
        return;
    }

    for feature in REQUIRED {
        // valgrind cannot run adx, so this build accepts its absence.
        if *feature == "adx" && option_env!("VALGRIND_BUG_494162").is_some() {
            continue;
        }

        let output = std::process::Command::new(std::env::current_exe().unwrap())
            .args(["--exact", "missing_feature_is_named", "--nocapture"])
            .env(CHILD, feature)
            .env(format!("RIND_CPU_DISABLE_{feature}"), "1")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "{feature}: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }
}
