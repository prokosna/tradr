//! Supervisor-authored tests for Attestation policy, written before the
//! implementation. Attestation verification is a Critical Module (CLAUDE.md
//! section 6): getting it wrong is impersonation. These cover steps 1 and 3
//! through 6 of docs/05 "What a verifier does"; step 2, the JWKS signature
//! check, is WI-M0-011b and has its own tests.

use sha2::{Digest, Sha256};
use tradr_core::{PublicKeyPoint, TrustTier, UnixTime};
use tradr_identity::{
    AccountId, AttestationError, AttestationPolicy, NonceBinding, ProviderProfile,
    SignatureAlgorithm, VerifiedClaims, classify,
};

const DAY: i64 = 86_400;
const NOW: i64 = 1_800_000_000;

/// RFC 4648 base64url without padding, written here rather than taken from
/// the crate under test. Checked against the RFC's own vectors below.
fn base64url(input: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    let mut out = String::new();
    for chunk in input.chunks(3) {
        let bytes = [
            chunk[0],
            *chunk.get(1).unwrap_or(&0),
            *chunk.get(2).unwrap_or(&0),
        ];
        let n = ((bytes[0] as u32) << 16) | ((bytes[1] as u32) << 8) | bytes[2] as u32;
        for i in 0..chunk.len() + 1 {
            out.push(ALPHABET[((n >> (18 - 6 * i)) & 0x3f) as usize] as char);
        }
    }
    out
}

#[test]
fn the_test_helper_matches_rfc_4648() {
    // A wrong encoder here would make every nonce test agree with itself.
    for (input, expected) in [
        ("", ""),
        ("f", "Zg"),
        ("fo", "Zm8"),
        ("foo", "Zm9v"),
        ("foob", "Zm9vYg"),
        ("fooba", "Zm9vYmE"),
        ("foobar", "Zm9vYmFy"),
    ] {
        assert_eq!(base64url(input.as_bytes()), expected);
    }
    assert_eq!(base64url(&[0xfb, 0xff, 0xbf]), "-_-_", "must be url-safe");
}

fn point(fill: u8) -> PublicKeyPoint {
    let mut bytes = [fill; 65];
    bytes[0] = 0x04;
    match PublicKeyPoint::from_bytes(&bytes) {
        Ok(p) => p,
        Err(e) => panic!("65 bytes must build a point, got {e:?}"),
    }
}

/// The nonce docs/05 step 4 requires, computed independently.
fn verbatim_nonce(identity: &PublicKeyPoint, agreement: &PublicKeyPoint) -> String {
    let mut input = identity.as_bytes().to_vec();
    input.extend_from_slice(agreement.as_bytes());
    base64url(blake3::hash(&input).as_bytes())
}

fn google_profile() -> ProviderProfile {
    ProviderProfile {
        client_id: "test-client".to_string(),
        client_secret: Some("test-secret".to_string()),
        authorization_uri: "https://accounts.google.com/o/oauth2/auth".to_string(),
        token_uri: "https://oauth2.googleapis.com/token".to_string(),
        issuer: "https://accounts.google.com".to_string(),
        client_ids: vec![
            "desktop-client.apps.googleusercontent.com".to_string(),
            "android-client.apps.googleusercontent.com".to_string(),
        ],
        nonce_binding: NonceBinding::Verbatim,
        algorithms: vec![SignatureAlgorithm::Rs256],
        jwks_uri: "https://www.googleapis.com/oauth2/v3/certs".to_string(),
    }
}

fn claims(nonce: String) -> VerifiedClaims {
    VerifiedClaims {
        iss: "https://accounts.google.com".to_string(),
        sub: "our-own-subject".to_string(),
        aud: "desktop-client.apps.googleusercontent.com".to_string(),
        iat: UnixTime::from_secs(NOW),
        nonce,
    }
}

struct Fixture {
    profiles: Vec<ProviderProfile>,
    own: AccountId,
    linked: Vec<AccountId>,
    identity: PublicKeyPoint,
    agreement: PublicKeyPoint,
}

impl Fixture {
    fn new() -> Self {
        Self {
            profiles: vec![google_profile()],
            own: AccountId::new("https://accounts.google.com", "our-own-subject"),
            linked: Vec::new(),
            identity: point(0x11),
            agreement: point(0x22),
        }
    }

    fn policy(&self, ephemeral: bool) -> AttestationPolicy<'_> {
        AttestationPolicy {
            profiles: &self.profiles,
            own_account: &self.own,
            linked_accounts: &self.linked,
            staleness_limit_secs: (30 * DAY) as u64,
            ephemeral_receive: ephemeral,
        }
    }

    fn nonce(&self) -> String {
        verbatim_nonce(&self.identity, &self.agreement)
    }

    fn run(&self, claims: &VerifiedClaims, at: i64) -> Result<TrustTier, AttestationError> {
        classify(
            &self.policy(false),
            claims,
            &self.identity,
            &self.agreement,
            UnixTime::from_secs(at),
        )
    }
}

// --- Step 1: the profile is selected by an exact issuer match -----------

#[test]
fn an_unknown_issuer_is_rejected() {
    let f = Fixture::new();
    let mut c = claims(f.nonce());
    c.iss = "https://accounts.example.com".to_string();

    assert_eq!(f.run(&c, NOW), Err(AttestationError::UnknownIssuer));
}

#[test]
fn an_issuer_is_matched_exactly_and_never_by_prefix_or_case() {
    // A token that could nominate its own verification rules by naming a
    // near-miss issuer would choose which JWKS and which client IDs apply.
    let f = Fixture::new();
    for near_miss in [
        "https://accounts.google.com/",
        "https://accounts.google.com.evil.example",
        "https://Accounts.Google.Com",
        "accounts.google.com",
        "https://accounts.google.co",
        " https://accounts.google.com",
    ] {
        let mut c = claims(f.nonce());
        c.iss = near_miss.to_string();
        assert_eq!(
            f.run(&c, NOW),
            Err(AttestationError::UnknownIssuer),
            "{near_miss:?} must not select the Google profile"
        );
    }
}

#[test]
fn the_issuer_is_checked_before_anything_else() {
    // docs/05: "Nothing else is read first." Every later step depends on
    // which profile is in force, so an unknown issuer must report exactly
    // that even when every other field is also wrong.
    let f = Fixture::new();
    let mut c = claims("not-the-right-nonce".to_string());
    c.iss = "https://accounts.example.com".to_string();
    c.aud = "some-other-client".to_string();
    c.iat = UnixTime::from_secs(NOW - 400 * DAY);

    assert_eq!(f.run(&c, NOW), Err(AttestationError::UnknownIssuer));
}

// --- Step 3: aud is compared against a set ------------------------------

#[test]
fn every_client_id_in_the_profile_is_accepted() {
    // docs/05: aud is the client ID of whichever platform ran the flow, so
    // a desktop device verifying an Android peer sees the Android id.
    // Comparing against one value fails every cross-platform pair while
    // same-platform pairs keep working, which hides its own cause.
    let f = Fixture::new();
    for client_id in &f.profiles[0].client_ids {
        let mut c = claims(f.nonce());
        c.aud = client_id.clone();
        assert!(
            f.run(&c, NOW).is_ok(),
            "{client_id} belongs to the profile and must be accepted"
        );
    }
}

#[test]
fn an_audience_outside_the_profile_is_rejected() {
    let f = Fixture::new();
    for foreign in [
        "someone-elses-client.apps.googleusercontent.com",
        "desktop-client.apps.googleusercontent.com.evil.example",
        "",
    ] {
        let mut c = claims(f.nonce());
        c.aud = foreign.to_string();
        assert_eq!(
            f.run(&c, NOW),
            Err(AttestationError::AudienceNotRecognised),
            "{foreign:?} is not one of the profile's client ids"
        );
    }
}

// --- Step 4: the nonce binds the peer's keys ----------------------------

#[test]
fn the_nonce_must_bind_both_public_keys() {
    // This is the trust root: without it a stolen id_token is replayable
    // with the attacker's own keys, and ADR-0003 stops being true.
    let f = Fixture::new();
    assert!(f.run(&claims(f.nonce()), NOW).is_ok());
}

#[test]
fn a_nonce_binding_different_keys_is_rejected() {
    let f = Fixture::new();
    let other_identity = point(0x33);
    let other_agreement = point(0x44);

    for wrong in [
        verbatim_nonce(&other_identity, &f.agreement),
        verbatim_nonce(&f.identity, &other_agreement),
        verbatim_nonce(&other_identity, &other_agreement),
        // The two keys swapped: concatenation order is part of the binding.
        verbatim_nonce(&f.agreement, &f.identity),
        String::new(),
        "not-base64url".to_string(),
    ] {
        assert_eq!(
            f.run(&claims(wrong.clone()), NOW),
            Err(AttestationError::NonceMismatch),
            "{wrong:?} does not bind this peer's keys"
        );
    }
}

#[test]
fn a_hashed_profile_expects_the_digest_of_the_verbatim_nonce() {
    // docs/05: a provider that stores a digest of the nonce fails step 4
    // outright under the wrong assumption, which is why nonce_binding is a
    // profile field rather than something inferred.
    let f = Fixture::new();
    let mut profile = google_profile();
    profile.nonce_binding = NonceBinding::Hashed;
    let profiles = vec![profile];
    let policy = AttestationPolicy {
        profiles: &profiles,
        own_account: &f.own,
        linked_accounts: &f.linked,
        staleness_limit_secs: (30 * DAY) as u64,
        ephemeral_receive: false,
    };

    let verbatim = f.nonce();
    let hashed = base64url(&Sha256::digest(verbatim.as_bytes()));

    let run = |nonce: String| {
        classify(
            &policy,
            &claims(nonce),
            &f.identity,
            &f.agreement,
            UnixTime::from_secs(NOW),
        )
    };

    assert!(run(hashed).is_ok(), "a hashed profile takes the digest");
    assert_eq!(
        run(verbatim),
        Err(AttestationError::NonceMismatch),
        "a hashed profile must not also accept the verbatim form"
    );
}

// --- Step 5: staleness --------------------------------------------------

#[test]
fn a_recent_attestation_is_accepted() {
    let f = Fixture::new();
    let mut c = claims(f.nonce());
    c.iat = UnixTime::from_secs(NOW - 29 * DAY);
    assert!(f.run(&c, NOW).is_ok());
}

#[test]
fn the_staleness_limit_is_inclusive_at_exactly_the_limit() {
    let f = Fixture::new();
    let mut c = claims(f.nonce());
    c.iat = UnixTime::from_secs(NOW - 30 * DAY);
    assert!(f.run(&c, NOW).is_ok(), "exactly at the limit is not stale");
}

#[test]
fn an_attestation_past_the_limit_is_rejected() {
    let f = Fixture::new();
    let mut c = claims(f.nonce());
    c.iat = UnixTime::from_secs(NOW - 30 * DAY - 1);
    assert_eq!(f.run(&c, NOW), Err(AttestationError::Stale));
}

#[test]
fn an_attestation_issued_in_the_future_is_rejected() {
    // A future iat would otherwise buy unbounded life: the age is negative,
    // so any limit comparison written as a subtraction passes forever.
    let f = Fixture::new();
    let mut c = claims(f.nonce());
    c.iat = UnixTime::from_secs(NOW + 2 * DAY);
    assert_eq!(f.run(&c, NOW), Err(AttestationError::Stale));
}

// --- Step 6: the (iss, sub) pair decides the tier -----------------------

#[test]
fn our_own_account_pair_yields_same_account() {
    let f = Fixture::new();
    assert_eq!(f.run(&claims(f.nonce()), NOW), Ok(TrustTier::SameAccount));
}

#[test]
fn a_linked_account_pair_yields_linked() {
    let mut f = Fixture::new();
    f.linked = vec![AccountId::new(
        "https://accounts.google.com",
        "a-linked-subject",
    )];
    let mut c = claims(f.nonce());
    c.sub = "a-linked-subject".to_string();
    assert_eq!(f.run(&c, NOW), Ok(TrustTier::Linked));
}

#[test]
fn a_matching_subject_under_a_different_issuer_is_not_our_account() {
    // ADR-0010: sub is unique only within an issuer, so identity is the
    // pair. A second profile sharing our subject string must not become us.
    let mut f = Fixture::new();
    let mut other = google_profile();
    other.issuer = "https://login.example.com".to_string();
    f.profiles.push(other);

    let mut c = claims(f.nonce());
    c.iss = "https://login.example.com".to_string();
    c.sub = "our-own-subject".to_string();

    assert_eq!(f.run(&c, NOW), Err(AttestationError::UntrustedAccount));
}

#[test]
fn an_unknown_account_is_rejected_when_not_in_ephemeral_receive_mode() {
    let f = Fixture::new();
    let mut c = claims(f.nonce());
    c.sub = "a-stranger".to_string();
    assert_eq!(f.run(&c, NOW), Err(AttestationError::UntrustedAccount));
}

#[test]
fn an_unknown_account_is_nearby_ephemeral_only_in_ephemeral_receive_mode() {
    let f = Fixture::new();
    let mut c = claims(f.nonce());
    c.sub = "a-stranger".to_string();
    let got = classify(
        &f.policy(true),
        &c,
        &f.identity,
        &f.agreement,
        UnixTime::from_secs(NOW),
    );
    assert_eq!(got, Ok(TrustTier::NearbyEphemeral));
}

#[test]
fn ephemeral_receive_mode_does_not_downgrade_a_trusted_peer() {
    // Turning the mode on widens who is accepted; it must not reclassify a
    // peer that already qualifies for a higher tier. docs/05 lists step 6's
    // cases in precedence order, our own pair first.
    let f = Fixture::new();
    let got = classify(
        &f.policy(true),
        &claims(f.nonce()),
        &f.identity,
        &f.agreement,
        UnixTime::from_secs(NOW),
    );
    assert_eq!(got, Ok(TrustTier::SameAccount));
}

#[test]
fn our_own_account_outranks_the_same_pair_appearing_as_linked() {
    // A degenerate configuration, and the tier must still be the higher of
    // the two rather than whichever check happens to run first.
    let mut f = Fixture::new();
    f.linked = vec![AccountId::new(
        "https://accounts.google.com",
        "our-own-subject",
    )];
    assert_eq!(f.run(&claims(f.nonce()), NOW), Ok(TrustTier::SameAccount));
}

#[test]
fn ephemeral_receive_mode_does_not_excuse_any_earlier_step() {
    // The mode widens step 6 alone. A stale or wrongly bound token must
    // still fail, or turning the mode on would disable verification.
    let f = Fixture::new();
    let at = UnixTime::from_secs(NOW);

    let mut stale = claims(f.nonce());
    stale.iat = UnixTime::from_secs(NOW - 400 * DAY);
    assert_eq!(
        classify(&f.policy(true), &stale, &f.identity, &f.agreement, at),
        Err(AttestationError::Stale)
    );

    let unbound = claims("wrong-nonce".to_string());
    assert_eq!(
        classify(&f.policy(true), &unbound, &f.identity, &f.agreement, at),
        Err(AttestationError::NonceMismatch)
    );
}

#[test]
fn no_rejection_path_returns_a_tier() {
    // TrustTier::Rejected exists for the wire; a failed classification must
    // be an Err, so a caller cannot treat a rejection as a granted tier by
    // forgetting to match on it.
    let f = Fixture::new();
    let mut c = claims(f.nonce());
    c.iss = "https://accounts.example.com".to_string();

    match f.run(&c, NOW) {
        Err(_) => {}
        Ok(tier) => panic!("a rejection must not arrive as Ok({tier:?})"),
    }
}
