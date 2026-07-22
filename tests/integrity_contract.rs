mod support;

use noisebench::integrity::{
    address_dataset, load_dataset, seal_dataset, write_canonical_dataset, CoverageStatus,
    IntegrityError,
};

#[test]
fn line_order_does_not_change_the_address() {
    let first = support::valid_dataset(false);
    let second = support::valid_dataset(true);
    assert_eq!(
        address_dataset(&first.0, &first.1, &first.2).unwrap(),
        address_dataset(&second.0, &second.1, &second.2).unwrap()
    );
}

#[test]
fn changed_label_is_invalid_evidence() {
    let dir = support::write_valid_dataset();
    support::mutate_first_label(dir.path());
    assert!(matches!(
        load_dataset(dir.path()),
        Err(IntegrityError::ContentHashMismatch { .. })
    ));
}

#[test]
fn jsonl_records_require_a_final_newline() {
    let dir = support::write_valid_dataset();
    let path = dir.path().join("public-traces.jsonl");
    let mut bytes = std::fs::read(&path).unwrap();
    assert_eq!(bytes.pop(), Some(b'\n'));
    std::fs::write(path, bytes).unwrap();

    assert!(matches!(
        load_dataset(dir.path()),
        Err(IntegrityError::JsonLineNotTerminated)
    ));
}

#[test]
fn unknown_and_low_coverage_are_valid_but_insufficient() {
    for (expected, status) in [
        (None, CoverageStatus::Unknown),
        (Some(100), CoverageStatus::BelowMinimum),
    ] {
        let dir = tempfile::tempdir().unwrap();
        let (_, public, labels) = support::valid_dataset(false);
        let mut manifest = support::manifest(expected);
        seal_dataset(&mut manifest, &public, &labels).unwrap();
        write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
        assert_eq!(load_dataset(dir.path()).unwrap().coverage.status, status);
    }
}

#[test]
fn every_declared_seed_requires_public_evidence() {
    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, mut public, mut labels) = support::valid_dataset(false);
    public.retain(|trace| trace.seed == 11);
    labels.retain(|label| public.iter().any(|trace| trace.trace_id == label.trace_id));
    manifest.coverage.expected_decisions = Some(public.len() as u64);
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    assert!(matches!(
        load_dataset(dir.path()),
        Err(IntegrityError::LinkageInvalid(
            "declared split seed has no public trace"
        ))
    ));
}

#[test]
fn observed_above_expected_is_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let (_, public, labels) = support::valid_dataset(false);
    let mut manifest = support::manifest(Some(1));
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    assert!(matches!(
        load_dataset(dir.path()),
        Err(IntegrityError::CoverageInconsistent)
    ));
}

#[test]
fn label_must_name_a_candidate_in_a_scoreable_trace() {
    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, public, mut labels) = support::valid_dataset(false);
    labels[0].true_candidate_id = "not-a-candidate".into();
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    assert!(matches!(
        load_dataset(dir.path()),
        Err(IntegrityError::LinkageInvalid(_))
    ));
}

#[test]
fn duplicate_trace_ids_and_sequence_gaps_are_invalid() {
    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, mut public, labels) = support::valid_dataset(false);
    public.push(public[0].clone());
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    assert!(matches!(
        load_dataset(dir.path()),
        Err(IntegrityError::LinkageInvalid("duplicate trace id"))
    ));

    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, mut public, labels) = support::valid_dataset(false);
    public[1].sequence_index = 2;
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    assert!(matches!(
        load_dataset(dir.path()),
        Err(IntegrityError::SequenceInvalid)
    ));
}

#[test]
fn refusals_have_no_private_label() {
    let dir = tempfile::tempdir().unwrap();
    let (mut manifest, mut public, labels) = support::valid_dataset(false);
    public[0].candidates.clear();
    public[0].refusal = Some(noisebench::schema::Refusal {
        reason_code: "policy".into(),
    });
    seal_dataset(&mut manifest, &public, &labels).unwrap();
    write_canonical_dataset(dir.path(), &manifest, &public, &labels).unwrap();
    assert!(matches!(
        load_dataset(dir.path()),
        Err(IntegrityError::LinkageInvalid(_))
    ));
}
