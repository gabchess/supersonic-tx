use noisebench::schema::{parse_strict, Manifest, PrivateLabel, PublicTrace};

const VALID_MANIFEST: &[u8] = br#"{
  "schema":"noisebench/manifest/v1",
  "dataset_id":"fixture",
  "public_trace_schema":"noisebench/public-trace/v1",
  "private_label_schema":"noisebench/private-label/v1",
  "producer":{"name":"noisebench-tests","version":"1","source_commit":null,"configuration":{"count":1,"fixture":true}},
  "observer_profile":"noisebench-observer/v1",
  "feature_version":"noisebench-features/v1",
  "attacker":{"family":"regularized-logistic-ranker/v1","learning_rate_micros":10000,"l2_micros":1000,"training_steps":400,"preprocessing":"train-zscore/v1","tie_break":"candidate-id-lexicographic/v1"},
  "split":{"unit":"actor","train_bps":6000,"validation_bps":2000,"test_bps":2000,"seeds":[11,23,47,71,101]},
  "bootstrap":{"seed":31337,"replicates":10000},
  "coverage":{"expected_decisions":1,"minimum_bps":9500},
  "claim":{"max_advantage_bps":500,"confidence_bps":9500,"channel_contribution_min_drop_bps":500},
  "power":{"minimum_held_out_actors":100,"minimum_scoreable_decisions":1000,"shadow_rule":"seeded-extreme-ordinal/v1","shadow_seed":424242,"shadow_min_advantage_bps":1000},
  "hashes":{"public_sha256":"0000000000000000000000000000000000000000000000000000000000000000","labels_sha256":"0000000000000000000000000000000000000000000000000000000000000000","manifest_sha256":"0000000000000000000000000000000000000000000000000000000000000000","dataset_sha256":"0000000000000000000000000000000000000000000000000000000000000000"},
  "expected_fixture_result":{"verdict":"CLAIM_REJECTED","reason_code":"longitudinal_claim_exceeded"}
}"#;

const VALID_TRACE: &[u8] = br#"{
  "schema":"noisebench/public-trace/v1",
  "trace_id":"t-1","seed":11,"actor_id":"a-1","sequence_index":0,
  "observed_time_bucket":0,
  "bundle":{"program_id":"p","asset_id":"asset"},
  "candidates":[
    {"candidate_id":"c-0","ordinal":0,"destination_id":"d-0","amount_atoms":"10"},
    {"candidate_id":"c-1","ordinal":1,"destination_id":"d-1","amount_atoms":"20"}
  ],
  "refusal":null
}"#;

#[test]
fn exact_v1_manifest_and_scoreable_trace_are_valid() {
    let manifest: Manifest = parse_strict(VALID_MANIFEST).unwrap();
    manifest.validate_v1().unwrap();
    let trace: PublicTrace = parse_strict(VALID_TRACE).unwrap();
    trace.validate_v1(&manifest).unwrap();
    assert_eq!(trace.candidates.len(), 2);
}

#[test]
fn duplicate_and_unknown_keys_are_rejected() {
    assert!(parse_strict::<PrivateLabel>(
        br#"{"schema":"noisebench/private-label/v1","trace_id":"t","trace_id":"x","true_candidate_id":"c"}"#
    )
    .is_err());
    assert!(parse_strict::<PrivateLabel>(
        br#"{"schema":"noisebench/private-label/v1","trace_id":"t","true_candidate_id":"c","extra":1}"#
    )
    .is_err());
}

#[test]
fn scoreable_refusal_and_amount_rules_are_exclusive() {
    let manifest: Manifest = parse_strict(VALID_MANIFEST).unwrap();
    let mut trace: PublicTrace = parse_strict(VALID_TRACE).unwrap();
    trace.refusal = Some(noisebench::schema::Refusal {
        reason_code: "policy".into(),
    });
    assert!(trace.validate_v1(&manifest).is_err());

    let mut trace: PublicTrace = parse_strict(VALID_TRACE).unwrap();
    trace.candidates[0].amount_atoms = "01".into();
    assert!(trace.validate_v1(&manifest).is_err());
}

#[test]
fn private_label_requires_exact_nonempty_fields() {
    let label: PrivateLabel = parse_strict(
        br#"{"schema":"noisebench/private-label/v1","trace_id":"t-1","true_candidate_id":"c-0"}"#,
    )
    .unwrap();
    label.validate_v1().unwrap();
}

#[test]
fn floating_producer_configuration_is_rejected() {
    let bytes = String::from_utf8(VALID_MANIFEST.to_vec())
        .unwrap()
        .replace("\"count\":1", "\"count\":1.5");
    let manifest: Manifest = parse_strict(bytes.as_bytes()).unwrap();
    assert!(manifest.validate_v1().is_err());
}

#[test]
fn producer_configuration_rejects_integers_above_i64() {
    let mut manifest: Manifest = parse_strict(VALID_MANIFEST).unwrap();
    manifest.producer.configuration = serde_json::json!({"too_large": u64::MAX});
    assert!(manifest.validate_v1().is_err());
}
