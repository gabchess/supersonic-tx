mod support;

use std::collections::BTreeSet;

use noisebench::attackers::{rank_scores, run_attack, run_shadow_sanity, split_actor, Split};

#[test]
fn scaling_is_fit_on_training_candidates_only() {
    let mut data = support::scaling_probe();
    for row in &mut data {
        if split_actor(&row.actor_id, row.seed) == Split::Test {
            for candidate in &mut row.candidates {
                candidate.values[1] += 1_000.0;
            }
        }
    }
    let run = run_attack(&data, &support::manifest(Some(24))).unwrap();
    assert_eq!(run.scaling_sources, BTreeSet::from([Split::Train]));
    assert!((run.scaling_means_by_seed[&11][1] - 0.5).abs() < 1e-12);
}

#[test]
fn exact_scores_use_lexicographic_candidate_tie_break() {
    let ranked = rank_scores(vec![("z".into(), 0.0), ("a".into(), 0.0)]).unwrap();
    assert_eq!(ranked[0].0, "a");
}

#[test]
fn seeded_extreme_ordinal_shadow_is_detectable() {
    let run = run_shadow_sanity(
        &support::large_exchangeable_view(),
        &support::manifest(Some(120)),
    )
    .unwrap();
    assert!(run.test_accuracy >= 0.90, "{}", run.test_accuracy);
}

#[test]
fn actor_splits_are_deterministic_and_disjoint() {
    let actor = "stable-actor";
    assert_eq!(split_actor(actor, 11), split_actor(actor, 11));
    let data = support::large_exchangeable_view();
    for row in data {
        assert_eq!(
            split_actor(&row.actor_id, row.seed),
            split_actor(&row.actor_id, row.seed)
        );
    }
}

#[test]
fn repeated_attack_runs_are_identical() {
    let data = support::large_exchangeable_view();
    let manifest = support::manifest(Some(120));
    assert_eq!(
        run_attack(&data, &manifest).unwrap(),
        run_attack(&data, &manifest).unwrap()
    );
}
