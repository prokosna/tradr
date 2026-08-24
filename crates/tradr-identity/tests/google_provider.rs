//! Supervisor-authored tests for WI-M0-008e (DCR-028). Nothing ships with
//! a client ID or a secret: both are configuration, and each deployment
//! registers its own Google project. The audience set is the part that
//! decides whether that deployment's own devices recognise each other.

use tradr_identity::{OAuthClient, Platform, ProviderError, google, oauth_client};

const DESKTOP_ID: &str = "111-desktop.apps.googleusercontent.com";
const ANDROID_ID: &str = "111-android.apps.googleusercontent.com";
const SECRET: &str = "a-configured-secret";
const ISSUER: &str = "https://accounts.google.com";

fn desktop() -> OAuthClient {
    oauth_client(Platform::Desktop, Some(DESKTOP_ID), Some(SECRET), None)
        .expect("an id and a secret are a complete desktop configuration")
}

// --- What a deployer must supply ---

#[test]
fn a_desktop_client_needs_an_id_and_a_secret() {
    let client = desktop();

    assert_eq!(client.client_id, DESKTOP_ID);
    assert_eq!(client.client_secret, Some(SECRET.to_string()));
}

#[test]
fn an_android_client_needs_an_id_and_no_secret() {
    let client = oauth_client(Platform::Android, Some(ANDROID_ID), None, None)
        .expect("an android client has no secret");

    assert_eq!(client.client_id, ANDROID_ID);
    assert_eq!(client.client_secret, None);
}

#[test]
fn nothing_configured_is_not_a_default_but_an_error() {
    assert_eq!(
        oauth_client(Platform::Desktop, None, None, None),
        Err(ProviderError::MissingClientId)
    );
}

#[test]
fn an_empty_value_counts_as_unset() {
    assert_eq!(
        oauth_client(Platform::Desktop, Some(""), Some(SECRET), None),
        Err(ProviderError::MissingClientId)
    );
    assert_eq!(
        oauth_client(Platform::Desktop, Some(DESKTOP_ID), Some(""), None),
        Err(ProviderError::MissingClientSecret)
    );
}

#[test]
fn a_desktop_id_without_its_secret_is_refused_where_the_mistake_was_made() {
    assert_eq!(
        oauth_client(Platform::Desktop, Some(DESKTOP_ID), None, None),
        Err(ProviderError::MissingClientSecret)
    );
}

/// A secret alongside an Android ID means two different clients' values
/// were pasted together, which the token endpoint would report much later
/// and much less clearly.
#[test]
fn a_secret_supplied_for_an_android_client_is_refused() {
    assert_eq!(
        oauth_client(Platform::Android, Some(ANDROID_ID), Some(SECRET), None),
        Err(ProviderError::UnexpectedClientSecret)
    );
}

// --- The audience set ---

#[test]
fn the_audience_set_defaults_to_this_device_alone() {
    assert_eq!(desktop().audiences, vec![DESKTOP_ID.to_string()]);
}

#[test]
fn a_deployment_spanning_two_platforms_lists_both() {
    let both = format!("{DESKTOP_ID},{ANDROID_ID}");
    let client = oauth_client(
        Platform::Desktop,
        Some(DESKTOP_ID),
        Some(SECRET),
        Some(&both),
    )
    .expect("both ids belong to the same project");

    assert_eq!(
        client.audiences,
        vec![DESKTOP_ID.to_string(), ANDROID_ID.to_string()]
    );
}

#[test]
fn surrounding_space_and_empty_entries_are_dropped() {
    let messy = format!("  {DESKTOP_ID} , , {ANDROID_ID}  ,");
    let client = oauth_client(
        Platform::Desktop,
        Some(DESKTOP_ID),
        Some(SECRET),
        Some(&messy),
    )
    .expect("a list a human typed");

    assert_eq!(
        client.audiences,
        vec![DESKTOP_ID.to_string(), ANDROID_ID.to_string()]
    );
}

#[test]
fn a_repeated_audience_appears_once() {
    let doubled = format!("{DESKTOP_ID},{DESKTOP_ID}");
    let client = oauth_client(
        Platform::Desktop,
        Some(DESKTOP_ID),
        Some(SECRET),
        Some(&doubled),
    )
    .expect("a duplicate is a typo, not a conflict");

    assert_eq!(client.audiences.len(), 1);
}

/// A device authenticating as a client its own audience set omits mints
/// Attestations that every peer rejects at step 3, including its own
/// other devices. The configuration is wrong and nothing later says so.
#[test]
fn a_device_absent_from_its_own_audience_set_is_refused() {
    assert_eq!(
        oauth_client(
            Platform::Desktop,
            Some(DESKTOP_ID),
            Some(SECRET),
            Some(ANDROID_ID)
        ),
        Err(ProviderError::ClientIdNotInAudiences)
    );
}

#[test]
fn an_audience_list_that_is_entirely_empty_falls_back_to_this_device() {
    let client = oauth_client(
        Platform::Desktop,
        Some(DESKTOP_ID),
        Some(SECRET),
        Some("  , ,"),
    )
    .expect("an empty list is an unset list");

    assert_eq!(client.audiences, vec![DESKTOP_ID.to_string()]);
}

// --- What the profile carries, and what it refuses to take from configuration ---

#[test]
fn the_profile_accepts_exactly_the_configured_audiences() {
    let both = format!("{DESKTOP_ID},{ANDROID_ID}");
    let client = oauth_client(
        Platform::Desktop,
        Some(DESKTOP_ID),
        Some(SECRET),
        Some(&both),
    )
    .expect("configuration");
    let profile = google(client);

    assert_eq!(
        profile.client_ids,
        vec![DESKTOP_ID.to_string(), ANDROID_ID.to_string()]
    );
    assert_eq!(profile.client_id, DESKTOP_ID);
    assert_eq!(profile.client_secret, Some(SECRET.to_string()));
}

/// The issuer, the key set, the nonce binding and the permitted
/// algorithms are a trust decision compiled in, never a setting: a
/// deployer chooses which client speaks for them, not how a peer's token
/// is verified.
#[test]
fn nothing_a_peer_is_verified_against_comes_from_configuration() {
    let profile = google(desktop());

    assert_eq!(profile.issuer, ISSUER);
    assert_eq!(
        profile.jwks_uri,
        "https://www.googleapis.com/oauth2/v3/certs"
    );
    assert_eq!(
        profile.nonce_binding,
        tradr_identity::NonceBinding::Verbatim
    );
    assert_eq!(
        profile.algorithms,
        vec![tradr_identity::SignatureAlgorithm::Rs256]
    );
    assert!(profile.authorization_uri.starts_with("https://"));
    assert!(profile.token_uri.starts_with("https://"));
}

#[test]
fn the_id_a_device_uses_is_always_one_it_accepts() {
    for client in [
        desktop(),
        oauth_client(Platform::Android, Some(ANDROID_ID), None, None).expect("android"),
    ] {
        let profile = google(client);
        assert!(
            profile.client_ids.contains(&profile.client_id),
            "{} is not in its own accepted set",
            profile.client_id
        );
    }
}
