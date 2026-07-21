mod support;

use std::process::Command;

use tempfile::tempdir;

fn noisebench() -> Command {
    Command::new(env!("CARGO_BIN_EXE_noisebench"))
}

#[test]
fn suite_is_the_zero_exit_judge_path() {
    let output = noisebench().args(["suite", "fixtures/"]).output().unwrap();
    assert_eq!(output.status.code(), Some(0));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("4/4 expected outcomes matched"));
}

#[test]
fn audit_preserves_each_nonzero_verdict_exit_code() {
    for (fixture, expected) in [
        ("longitudinal-leak", 2),
        ("low-signal", 3),
        ("invalid-evidence", 4),
    ] {
        let dataset = support::copy_fixture_for_audit(fixture);
        let output = noisebench()
            .args(["audit", dataset.path().to_str().unwrap()])
            .output()
            .unwrap();
        assert_eq!(output.status.code(), Some(expected), "{fixture}");
    }
}

#[test]
fn audit_supported_exits_zero_and_writes_the_report() {
    let dataset = support::copy_fixture_for_audit("exchangeable-control");
    let temp = tempdir().unwrap();
    let report = temp.path().join("report.json");
    let output = noisebench()
        .args([
            "audit",
            dataset.path().to_str().unwrap(),
            "--json",
            report.to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(0));
    let parsed: serde_json::Value =
        serde_json::from_slice(&std::fs::read(report).unwrap()).unwrap();
    assert_eq!(parsed["verdict"], "CLAIM_SUPPORTED");
}

#[test]
fn syntax_errors_use_sysexits_usage_and_help_is_zero() {
    assert_eq!(
        noisebench().arg("nonsense").status().unwrap().code(),
        Some(64)
    );
    assert_eq!(noisebench().arg("--help").status().unwrap().code(), Some(0));
}

#[test]
fn report_write_failures_are_internal_errors() {
    let temp = tempdir().unwrap();
    let output = noisebench()
        .args([
            "audit",
            "fixtures/low-signal",
            "--json",
            temp.path().to_str().unwrap(),
        ])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(70));
    assert!(String::from_utf8(output.stderr)
        .unwrap()
        .starts_with("noisebench: "));
}

#[test]
fn valid_underpowered_evidence_exits_three() {
    let dataset = support::write_valid_dataset();
    let output = noisebench()
        .args(["audit", dataset.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("INSUFFICIENT_THREAT (sample_power_below_minimum)"));
}

#[test]
fn aggregate_power_with_a_per_seed_split_gap_exits_three() {
    let dataset = support::write_aggregate_powered_split_gap_dataset();
    let output = noisebench()
        .args(["audit", dataset.path().to_str().unwrap()])
        .output()
        .unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(String::from_utf8(output.stdout)
        .unwrap()
        .contains("INSUFFICIENT_THREAT (sample_power_below_minimum)"));
}
