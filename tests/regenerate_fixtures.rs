mod support;

#[test]
#[ignore = "writes checked-in reference fixtures"]
fn regenerate_reference_fixtures() {
    if std::env::var_os("NOISEBENCH_REGENERATE").is_none() {
        panic!("set NOISEBENCH_REGENERATE=1 to replace fixtures");
    }
    let first = tempfile::tempdir().unwrap();
    let second = tempfile::tempdir().unwrap();
    support::generate_reference_fixtures(first.path()).unwrap();
    support::generate_reference_fixtures(second.path()).unwrap();
    assert_eq!(
        support::directory_digest(first.path()).unwrap(),
        support::directory_digest(second.path()).unwrap()
    );
    support::generate_reference_fixtures(std::path::Path::new("fixtures")).unwrap();
}
