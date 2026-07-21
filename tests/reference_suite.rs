mod support;

use std::{collections::BTreeSet, fs, path::Path, sync::OnceLock};

use noisebench::{
    integrity::{load_dataset, seal_dataset, write_canonical_dataset},
    run_suite,
    schema::{Manifest, PrivateLabel, PublicTrace},
    verdict::Verdict,
    SuiteReport,
};

fn suite() -> &'static SuiteReport {
    static SUITE: OnceLock<SuiteReport> = OnceLock::new();
    SUITE.get_or_init(|| run_suite(Path::new("fixtures")).unwrap())
}

#[test]
fn reference_suite_separates_four_evidence_states() {
    let suite = suite();
    assert_eq!(
        suite
            .entries
            .iter()
            .map(|entry| entry.verdict)
            .collect::<Vec<_>>(),
        vec![
            Verdict::ClaimSupported,
            Verdict::InvalidEvidence,
            Verdict::ClaimRejected,
            Verdict::InsufficientThreat,
        ]
    );
    assert!(suite.matches_all_expected());
}

#[test]
fn calibrated_controls_meet_their_stronger_conditions() {
    let suite = suite();
    let supported = &suite
        .entries
        .iter()
        .find(|entry| entry.fixture == "exchangeable-control")
        .unwrap()
        .report;
    let rejected = &suite
        .entries
        .iter()
        .find(|entry| entry.fixture == "longitudinal-leak")
        .unwrap()
        .report;
    let supported_estimates = supported.estimates.as_ref().unwrap();
    assert_eq!(
        supported.control_label.as_deref(),
        Some("SYNTHETIC_CALIBRATION_CONTROL")
    );
    assert!(supported_estimates.bundle_only.upper_bps <= 500);
    assert!(supported_estimates.longitudinal.upper_bps <= 500);
    assert!(supported.power.as_ref().unwrap().shadow_lower_bps >= 1_000);
    let rejected_estimates = rejected.estimates.as_ref().unwrap();
    assert!(rejected_estimates.bundle_only.upper_bps <= 500);
    assert!(rejected_estimates.longitudinal.lower_bps > 500);
    assert!(
        rejected
            .tested_channels
            .contains(&"destination_history".into()),
        "{:#?}",
        rejected.channel_contributions
    );
}

#[test]
fn invalid_fixture_is_one_tamper_of_structurally_valid_evidence() {
    let root = Path::new("fixtures/invalid-evidence");
    let mut manifest: Manifest =
        serde_json::from_slice(&fs::read(root.join("manifest.json")).unwrap()).unwrap();
    let public: Vec<PublicTrace> = fs::read_to_string(root.join("public-traces.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let labels: Vec<PrivateLabel> = fs::read_to_string(root.join("private-labels.jsonl"))
        .unwrap()
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    let observed: BTreeSet<_> = public.iter().map(|trace| trace.seed).collect();
    assert_eq!(
        observed,
        manifest
            .split
            .seeds
            .iter()
            .copied()
            .collect::<BTreeSet<_>>()
    );

    let dir = tempfile::tempdir().unwrap();
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    let loaded = load_dataset(dir.path());
    assert!(loaded.is_ok(), "{loaded:?}");
}
