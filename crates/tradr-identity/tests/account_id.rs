use tradr_identity::AccountId;

#[test]
fn account_id_bytes_for_known_account_matches_expected_sequence() {
    let iss = "https://accounts.google.com";
    let sub = "109876543210987654321";
    let account = AccountId::new(iss, sub);
    let bytes = account.to_bytes();

    let mut expected = Vec::with_capacity(iss.len() + 1 + sub.len());
    expected.extend_from_slice(iss.as_bytes());
    expected.push(0x00);
    expected.extend_from_slice(sub.as_bytes());

    assert_eq!(bytes, expected);
    assert_eq!(bytes[iss.len()], 0x00);
    assert_eq!(bytes.len(), iss.len() + 1 + sub.len());
}

#[test]
fn account_id_bytes_disambiguates_boundary_between_issuer_and_subject() {
    let a = AccountId::new("ab", "c");
    let b = AccountId::new("a", "bc");

    assert_ne!(
        a.to_bytes(),
        b.to_bytes(),
        "omitting the 0x00 separator would allow cross-account collision across the boundary"
    );
    assert_eq!(a.to_bytes(), b"ab\x00c");
    assert_eq!(b.to_bytes(), b"a\x00bc");
}
