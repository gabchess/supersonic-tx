mod support;

use noisebench::features::{build_feature_view, FeatureChannel, FeatureMode};

#[test]
fn destination_history_uses_only_prior_public_rows() {
    let dataset = support::two_step_dataset();
    let rows = build_feature_view(&dataset, FeatureMode::Longitudinal { omit: None }).unwrap();
    assert_eq!(
        rows[0]
            .candidate("t-11-0-c-0")
            .feature(rows[0].feature_names(), "destination_frequency"),
        0.0
    );
    assert!(
        rows[1]
            .candidate("t-11-1-c-0")
            .feature(rows[1].feature_names(), "destination_frequency")
            > 0.0
    );
}

#[test]
fn omitting_destination_history_removes_it_before_training() {
    let dataset = support::two_step_dataset();
    let rows = build_feature_view(
        &dataset,
        FeatureMode::Longitudinal {
            omit: Some(FeatureChannel::DestinationHistory),
        },
    )
    .unwrap();
    assert!(!rows[1].feature_names().contains(&"destination_frequency"));
    assert!(!rows[1]
        .feature_names()
        .contains(&"destination_transition_frequency"));
}

#[test]
fn bundle_view_has_no_longitudinal_channel() {
    let dataset = support::two_step_dataset();
    let rows = build_feature_view(&dataset, FeatureMode::BundleOnly).unwrap();
    assert!(rows
        .iter()
        .all(|row| !row.feature_names().contains(&"destination_frequency")));
}

#[test]
fn future_private_labels_do_not_change_prior_feature_rows() {
    let original = support::two_step_dataset();
    let mut changed = support::two_step_dataset();
    let label = changed.labels.get_mut("t-11-1").unwrap();
    label.true_candidate_id = "t-11-1-c-1".into();

    let original_rows =
        build_feature_view(&original, FeatureMode::Longitudinal { omit: None }).unwrap();
    let changed_rows =
        build_feature_view(&changed, FeatureMode::Longitudinal { omit: None }).unwrap();
    assert_eq!(original_rows[0], changed_rows[0]);
}
