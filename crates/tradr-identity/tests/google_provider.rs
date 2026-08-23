//! Supervisor-authored tests for WI-M0-008a, written before the
//! implementation. docs/05 "Provider profiles" and "OAuth client
//! configuration": this is the only value in the codebase that names a
//! provider, and an override that replaced the audience set instead of
//! extending it would split an account into halves that reject each other.

use tradr_identity::{
    OAuthOverride, Platform, ProviderError, ProviderProfile, google, oauth_override,
};

const DESKTOP_ID: &str = "475695468283-shsoa7f59bdbta9jlubfs49jonv1m7ng.apps.googleusercontent.com";
const ANDROID_ID: &str = "475695468283-v4q25lmqo6kjova3crhiutnl59jnrckk.apps.googleusercontent.com";
const ISSUER: &str = "https://accounts.google.com";
const OTHER_ID: &str = "999-someone-elses.apps.googleusercontent.com";

fn desktop() -> ProviderProfile {
    google(Platform::Desktop, None)
}

fn overridden() -> ProviderProfile {
    google(
        Platform::Desktop,
        Some(OAuthOverride {
            client_id: OTHER_ID.to_string(),
            client_secret: "an-overriding-secret".to_string(),
        }),
    )
}

// --- What the shipped profile says ---

#[test]
fn google_is_named_by_its_exact_issuer_string() {
    assert_eq!(desktop().issuer, ISSUER);
}

#[test]
fn both_platform_client_ids_are_accepted_whichever_platform_this_is() {
    for platform in [Platform::Desktop, Platform::Android] {
        let profile = google(platform, None);
        assert!(
            profile
                .client_ids
                .iter()
                .any(|id| id.as_str() == DESKTOP_ID)
        );
        assert!(
            profile
                .client_ids
                .iter()
                .any(|id| id.as_str() == ANDROID_ID)
        );
    }
}

#[test]
fn each_platform_authenticates_as_its_own_client() {
    assert_eq!(google(Platform::Desktop, None).client_id, DESKTOP_ID);
    assert_eq!(google(Platform::Android, None).client_id, ANDROID_ID);
}

/// The id a device authenticates with must be one a peer accepts, or every
/// Attestation it mints fails step 3 against every other device.
#[test]
fn the_id_a_device_uses_is_always_one_it_accepts() {
    for profile in [
        google(Platform::Desktop, None),
        google(Platform::Android, None),
        overridden(),
    ] {
        assert!(
            profile.client_ids.contains(&profile.client_id),
            "{} is not in its own accepted set",
            profile.client_id
        );
    }
}

#[test]
fn only_the_desktop_client_carries_a_secret() {
    assert!(google(Platform::Desktop, None).client_secret.is_some());

    assert_eq!(google(Platform::Android, None).client_secret, None);
}

#[test]
fn the_endpoints_the_flow_needs_are_https_and_present() {
    let profile = desktop();

    for uri in [
        &profile.authorization_uri,
        &profile.token_uri,
        &profile.jwks_uri,
    ] {
        assert!(uri.starts_with("https://"), "{uri} is not https");
    }
}

#[test]
fn google_reflects_the_nonce_verbatim_and_signs_with_rs256_alone() {
    let profile = desktop();

    assert_eq!(
        profile.nonce_binding,
        tradr_identity::NonceBinding::Verbatim
    );
    assert_eq!(
        profile.algorithms,
        vec![tradr_identity::SignatureAlgorithm::Rs256]
    );
}

// --- What an override changes, and what it must not ---

#[test]
fn an_override_extends_the_accepted_set_rather_than_replacing_it() {
    let profile = overridden();

    assert!(profile.client_ids.iter().any(|id| id.as_str() == OTHER_ID));
    assert!(
        profile
            .client_ids
            .iter()
            .any(|id| id.as_str() == DESKTOP_ID)
    );
    assert!(
        profile
            .client_ids
            .iter()
            .any(|id| id.as_str() == ANDROID_ID)
    );
}

#[test]
fn an_override_is_the_client_this_device_authenticates_as() {
    let profile = overridden();

    assert_eq!(profile.client_id, OTHER_ID);
    assert_eq!(
        profile.client_secret,
        Some("an-overriding-secret".to_string())
    );
}

#[test]
fn an_override_changes_nothing_a_peer_is_verified_against() {
    let default = desktop();
    let profile = overridden();

    assert_eq!(profile.issuer, default.issuer);
    assert_eq!(profile.jwks_uri, default.jwks_uri);
    assert_eq!(profile.nonce_binding, default.nonce_binding);
    assert_eq!(profile.algorithms, default.algorithms);
}

#[test]
fn an_override_naming_a_default_client_does_not_double_it() {
    let profile = google(
        Platform::Desktop,
        Some(OAuthOverride {
            client_id: ANDROID_ID.to_string(),
            client_secret: "s".to_string(),
        }),
    );

    let count = profile
        .client_ids
        .iter()
        .filter(|id| *id == ANDROID_ID)
        .count();
    assert_eq!(count, 1);
}

// --- Reading the pair out of the environment ---

#[test]
fn neither_variable_set_is_no_override() {
    assert_eq!(oauth_override(None, None), Ok(None));
}

#[test]
fn both_variables_set_is_an_override() {
    assert_eq!(
        oauth_override(Some("an-id"), Some("a-secret")),
        Ok(Some(OAuthOverride {
            client_id: "an-id".to_string(),
            client_secret: "a-secret".to_string(),
        }))
    );
}

/// Half a pair is refused where the mistake was made. Google's token
/// endpoint rejects it too, but as a failed exchange with nothing in it
/// naming the cause.
#[test]
fn an_id_without_its_secret_is_refused() {
    assert_eq!(
        oauth_override(Some("an-id"), None),
        Err(ProviderError::HalfOverridden)
    );
}

#[test]
fn a_secret_without_its_id_is_refused() {
    assert_eq!(
        oauth_override(None, Some("a-secret")),
        Err(ProviderError::HalfOverridden)
    );
}

#[test]
fn an_empty_value_counts_as_unset() {
    assert_eq!(oauth_override(Some(""), Some("")), Ok(None));

    assert_eq!(
        oauth_override(Some(""), Some("a-secret")),
        Err(ProviderError::HalfOverridden)
    );
}
