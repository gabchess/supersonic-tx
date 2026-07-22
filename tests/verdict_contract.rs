mod support;

use noisebench::{
    report::{render_terminal, ReportV1},
    schema::ExpectedFixtureResult,
    statistics::StatisticalEvidence,
    verdict::{assess_dataset, audit_path, ReasonCode, Verdict},
};

#[test]
fn invalid_evidence_precedes_every_statistical_result() {
    let dir = support::write_valid_dataset();
    support::mutate_first_label(dir.path());
    let report = audit_path(dir.path()).unwrap();
    assert_eq!(report.verdict, Verdict::InvalidEvidence);
    assert_eq!(report.primary_reason_code, ReasonCode::ContentHashMismatch);
    assert_eq!(report.exit_code, 4);
}

#[test]
fn supported_copy_is_narrow_and_lists_untested_channels() {
    let report = support::supported_report();
    let text = render_terminal(&report);
    assert_eq!(report.verdict, Verdict::ClaimSupported);
    assert!(text.contains("This is not a claim that the planner is private."));
    assert!(text.contains("RPC and network timing"));
    assert!(text.contains("candidate-conditioned timing, program, asset, and bundle size"));
}

#[test]
fn ordinary_dataset_cannot_self_apply_the_control_label() {
    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, public, labels) = support::valid_dataset(false);
    manifest.producer.configuration =
        serde_json::json!({"control_label": "SYNTHETIC_CALIBRATION_CONTROL"});
    noisebench::integrity::seal_dataset(&mut manifest, &public, &labels).unwrap();
    noisebench::integrity::write_canonical_dataset(dir.path(), &manifest, &public, &labels)
        .unwrap();
    assert_eq!(audit_path(dir.path()).unwrap().control_label, None);
}

#[test]
fn ordinary_audit_rejects_fixture_only_expectations() {
    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, public, labels) = support::valid_dataset(false);
    manifest.expected_fixture_result = Some(ExpectedFixtureResult {
        verdict: "CLAIM_SUPPORTED".into(),
        reason_code: "scoped_claim_supported".into(),
    });
    noisebench::integrity::seal_dataset(&mut manifest, &public, &labels).unwrap();
    noisebench::integrity::write_canonical_dataset(dir.path(), &manifest, &public, &labels)
        .unwrap();
    let report = audit_path(dir.path()).unwrap();
    assert_eq!(report.verdict, Verdict::InvalidEvidence);
    assert_eq!(report.primary_reason_code, ReasonCode::SchemaInvalid);
}

#[test]
fn rejection_precedes_support_and_names_only_confident_channels() {
    let dataset = support::load_valid_dataset();
    let report = assess_dataset(
        &dataset,
        StatisticalEvidence {
            bundle_only: support::estimate(0, -100, 100),
            longitudinal: support::estimate(2_000, 1_500, 2_500),
            shadow: support::estimate(2_500, 2_000, 3_000),
            held_out_actors: 100,
            scoreable_decisions: 1_000,
            channel_contributions: vec![noisebench::statistics::ChannelContribution {
                channel: noisebench::features::FeatureChannel::DestinationHistory,
                full: support::estimate(2_000, 1_500, 2_500),
                ablated: support::estimate(300, 0, 600),
                drop: support::estimate(1_700, 1_000, 2_200),
            }],
        },
    );
    assert_eq!(report.verdict, Verdict::ClaimRejected);
    assert_eq!(
        report.primary_reason_code,
        ReasonCode::LongitudinalClaimExceeded
    );
    assert_eq!(report.tested_channels, vec!["destination_history"]);
}

#[test]
fn straddling_interval_is_insufficient() {
    let dataset = support::load_valid_dataset();
    let report = assess_dataset(
        &dataset,
        StatisticalEvidence {
            bundle_only: support::estimate(500, 100, 900),
            longitudinal: support::estimate(500, 100, 900),
            shadow: support::estimate(2_500, 2_000, 3_000),
            held_out_actors: 100,
            scoreable_decisions: 1_000,
            channel_contributions: Vec::new(),
        },
    );
    assert_eq!(report.verdict, Verdict::InsufficientThreat);
    assert_eq!(
        report.primary_reason_code,
        ReasonCode::ConfidenceInconclusive
    );
}

#[test]
fn coverage_power_and_shadow_fail_before_claim_evaluation() {
    let dir = tempfile::tempdir().unwrap();
    let (_, public, labels) = support::valid_dataset(false);
    let mut manifest = support::manifest(Some(100));
    noisebench::integrity::seal_dataset(&mut manifest, &public, &labels).unwrap();
    noisebench::integrity::write_canonical_dataset(dir.path(), &manifest, &public, &labels)
        .unwrap();
    let report = audit_path(dir.path()).unwrap();
    assert_eq!(report.primary_reason_code, ReasonCode::CoverageBelowMinimum);
    assert_eq!(
        report.reason_codes,
        vec![
            ReasonCode::CoverageBelowMinimum,
            ReasonCode::SamplePowerBelowMinimum,
        ]
    );

    let dataset = support::load_valid_dataset();
    let too_small = StatisticalEvidence {
        bundle_only: support::estimate(2_000, 1_500, 2_500),
        longitudinal: support::estimate(2_000, 1_500, 2_500),
        shadow: support::estimate(2_500, 2_000, 3_000),
        held_out_actors: 99,
        scoreable_decisions: 1_000,
        channel_contributions: Vec::new(),
    };
    assert_eq!(
        assess_dataset(&dataset, too_small).primary_reason_code,
        ReasonCode::SamplePowerBelowMinimum
    );

    let weak_shadow = StatisticalEvidence {
        bundle_only: support::estimate(2_000, 1_500, 2_500),
        longitudinal: support::estimate(2_000, 1_500, 2_500),
        shadow: support::estimate(500, 200, 800),
        held_out_actors: 100,
        scoreable_decisions: 1_000,
        channel_contributions: Vec::new(),
    };
    assert_eq!(
        assess_dataset(&dataset, weak_shadow).primary_reason_code,
        ReasonCode::AttackerSanityFailed
    );
}

#[test]
fn same_level_failures_are_sorted_and_counted() {
    let dataset = support::load_valid_dataset();
    let report = assess_dataset(
        &dataset,
        StatisticalEvidence {
            bundle_only: support::estimate(0, -100, 100),
            longitudinal: support::estimate(0, -100, 100),
            shadow: support::estimate(500, 200, 800),
            held_out_actors: 99,
            scoreable_decisions: 999,
            channel_contributions: Vec::new(),
        },
    );
    assert_eq!(
        report.reason_codes,
        vec![
            ReasonCode::AttackerSanityFailed,
            ReasonCode::SamplePowerBelowMinimum,
        ]
    );
    assert!(render_terminal(&report).contains("1 additional reason"));
}

#[test]
fn channel_contribution_json_uses_the_frozen_flat_shape() {
    let dataset = support::load_valid_dataset();
    let report = assess_dataset(
        &dataset,
        StatisticalEvidence {
            bundle_only: support::estimate(0, -100, 100),
            longitudinal: support::estimate(2_000, 1_500, 2_500),
            shadow: support::estimate(2_500, 2_000, 3_000),
            held_out_actors: 100,
            scoreable_decisions: 1_000,
            channel_contributions: vec![noisebench::statistics::ChannelContribution {
                channel: noisebench::features::FeatureChannel::DestinationHistory,
                full: support::estimate(2_000, 1_500, 2_500),
                ablated: support::estimate(300, 0, 600),
                drop: support::estimate(1_700, 1_000, 2_200),
            }],
        },
    );
    let value = serde_json::to_value(&report.channel_contributions[0]).unwrap();
    assert_eq!(
        value
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>(),
        vec![
            "ablated_point_bps",
            "channel",
            "drop_lower_bps",
            "drop_point_bps",
            "drop_upper_bps",
            "full_point_bps",
        ]
    );
}

#[test]
fn valid_underpowered_dataset_stops_before_model_training() {
    let dir = support::write_valid_dataset();
    let report = audit_path(dir.path()).unwrap();
    assert_eq!(report.verdict, Verdict::InsufficientThreat);
    assert_eq!(
        report.primary_reason_code,
        ReasonCode::SamplePowerBelowMinimum
    );
    assert_eq!(report.exit_code, 3);
}

#[test]
fn aggregate_power_cannot_hide_an_empty_per_seed_split() {
    let dir = support::write_aggregate_powered_split_gap_dataset();
    let report = audit_path(dir.path()).unwrap();
    assert_eq!(report.verdict, Verdict::InsufficientThreat);
    assert_eq!(
        report.primary_reason_code,
        ReasonCode::SamplePowerBelowMinimum
    );
    assert_eq!(report.exit_code, 3);
}

#[test]
fn missing_dataset_stays_an_operational_error() {
    let temp = tempfile::tempdir().unwrap();
    assert!(audit_path(&temp.path().join("missing")).is_err());
}

#[test]
fn report_json_round_trip_preserves_exact_contract() {
    let report = support::supported_report();
    let bytes = serde_json::to_vec(&report).unwrap();
    let decoded: ReportV1 = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(decoded, report);

    let mut value = serde_json::to_value(&report).unwrap();
    value
        .as_object_mut()
        .unwrap()
        .insert("extra".into(), true.into());
    assert!(serde_json::from_value::<ReportV1>(value).is_err());
}
