mod support;

use noisebench::statistics::{estimate_advantage, estimate_paired_drop, StatisticsError};

#[test]
fn advantage_subtracts_chance_before_actor_macro() {
    let estimate = estimate_advantage(&support::known_predictions(), 100, 7).unwrap();
    assert_eq!(estimate.point_bps, 1_250);
}

#[test]
fn bootstrap_and_channel_drop_are_repeatable() {
    let full = support::full_predictions();
    let ablated = support::ablated_predictions();
    assert_eq!(
        estimate_paired_drop(&full, &ablated, 10_000, 31_337).unwrap(),
        estimate_paired_drop(&full, &ablated, 10_000, 31_337).unwrap()
    );
}

#[test]
fn empty_and_mismatched_evidence_is_rejected() {
    assert!(matches!(
        estimate_advantage(&[], 100, 7),
        Err(StatisticsError::EmptyPredictions)
    ));
    let full = support::full_predictions();
    let mut ablated = support::ablated_predictions();
    ablated.pop();
    assert!(matches!(
        estimate_paired_drop(&full, &ablated, 100, 7),
        Err(StatisticsError::UnpairedPredictions)
    ));
}

#[test]
fn intervals_can_cross_zero() {
    let estimate = estimate_advantage(&support::known_predictions(), 1_000, 9).unwrap();
    assert!(estimate.lower_bps <= 0);
    assert!(estimate.upper_bps >= 0);
}
