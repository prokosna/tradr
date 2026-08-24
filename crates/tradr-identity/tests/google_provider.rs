//! Supervisor-authored tests for WI-M0-008f (DCR-029). One string names
//! every OAuth client in a deployment and is identical on every device;
//! each build looks itself up in it. The failure this shape exists to
//! catch is a list that omits a platform, which the old per-device
//! configuration could only surface as a rejected peer much later.

use tradr_identity::{OAuthClient, Platform, ProviderError, google, oauth_client};

const DESKTOP_ID: &str = "111-desktop.apps.googleusercontent.com";
const ANDROID_ID: &str = "111-android.apps.googleusercontent.com";
const SECRET: &str = "a-configured-secret";
const BOTH: &str =
    "desktop:111-desktop.apps.googleusercontent.com,android:111-android.apps.googleusercontent.com";

fn desktop() -> OAuthClient {
    oauth_client(Platform::Desktop, Some(BOTH), Some(SECRET)).expect("a complete deployment")
}

// --- One string, and every device finds itself in it ---

#[test]
fn a_device_authenticates_as_the_client_matching_its_own_platform() {
    assert_eq!(desktop().client_id, DESKTOP_ID);

    let android = oauth_client(Platform::Android, Some(BOTH), None).expect("android has no secret");
    assert_eq!(android.client_id, ANDROID_ID);
}

#[test]
fn every_id_in_the_list_is_accepted_whichever_device_reads_it() {
    let expected = vec![DESKTOP_ID.to_string(), ANDROID_ID.to_string()];

    assert_eq!(desktop().audiences, expected);
    assert_eq!(
        oauth_client(Platform::Android, Some(BOTH), None)
            .expect("android")
            .audiences,
        expected
    );
}

#[test]
fn the_id_a_device_uses_is_always_one_it_accepts() {
    for client in [
        desktop(),
        oauth_client(Platform::Android, Some(BOTH), None).expect("android"),
    ] {
        let profile = google(client);
        assert!(profile.client_ids.contains(&profile.client_id));
    }
}

// --- The list a deployment forgot to finish ---

/// The whole point of the shape. A deployment naming only its desktop
/// client is a valid desktop-only deployment, and its desktop devices
/// start; an Android build refuses at startup rather than being rejected
/// by a peer after both ends are already set up.
#[test]
fn a_build_the_list_does_not_name_refuses_to_start() {
    let desktop_only = format!("desktop:{DESKTOP_ID}");

    assert!(oauth_client(Platform::Desktop, Some(&desktop_only), Some(SECRET)).is_ok());

    assert_eq!(
        oauth_client(Platform::Android, Some(&desktop_only), None),
        Err(ProviderError::PlatformNotConfigured)
    );
}

#[test]
fn a_list_naming_a_platform_twice_is_refused() {
    let doubled = format!("desktop:{DESKTOP_ID},desktop:{ANDROID_ID}");

    assert_eq!(
        oauth_client(Platform::Desktop, Some(&doubled), Some(SECRET)),
        Err(ProviderError::DuplicatePlatform("desktop".to_string()))
    );
}

#[test]
fn no_list_at_all_is_not_a_default_but_an_error() {
    assert_eq!(
        oauth_client(Platform::Desktop, None, Some(SECRET)),
        Err(ProviderError::MissingClientIds)
    );
    assert_eq!(
        oauth_client(Platform::Desktop, Some("   "), Some(SECRET)),
        Err(ProviderError::MissingClientIds)
    );
}

// --- Shapes a human types ---

#[test]
fn surrounding_space_and_empty_entries_are_dropped() {
    let messy = format!("  desktop : {DESKTOP_ID} , , android:{ANDROID_ID} ,");
    let client = oauth_client(Platform::Desktop, Some(&messy), Some(SECRET)).expect("a typed list");

    assert_eq!(client.client_id, DESKTOP_ID);
    assert_eq!(
        client.audiences,
        vec![DESKTOP_ID.to_string(), ANDROID_ID.to_string()]
    );
}

#[test]
fn a_platform_label_is_matched_without_regard_to_case() {
    let shouted = format!("DESKTOP:{DESKTOP_ID},Android:{ANDROID_ID}");
    let client =
        oauth_client(Platform::Desktop, Some(&shouted), Some(SECRET)).expect("a typed list");

    assert_eq!(client.client_id, DESKTOP_ID);
}

#[test]
fn an_entry_carrying_no_label_is_malformed() {
    let bare = format!("{DESKTOP_ID},android:{ANDROID_ID}");

    assert!(matches!(
        oauth_client(Platform::Desktop, Some(&bare), Some(SECRET)),
        Err(ProviderError::MalformedClientIds(_))
    ));
}

#[test]
fn an_entry_carrying_no_id_is_malformed() {
    let empty = format!("desktop:,android:{ANDROID_ID}");

    assert!(matches!(
        oauth_client(Platform::Desktop, Some(&empty), Some(SECRET)),
        Err(ProviderError::MalformedClientIds(_))
    ));
}

/// Adding iOS must not break the devices that predate it. An unknown
/// label contributes its ID to the accepted set and nothing else, so an
/// existing desktop device verifies an iOS peer after a restart rather
/// than after a rebuild.
#[test]
fn a_platform_this_build_does_not_know_still_joins_the_accepted_set() {
    let with_ios = format!("{BOTH},ios:111-ios.apps.googleusercontent.com");
    let client =
        oauth_client(Platform::Desktop, Some(&with_ios), Some(SECRET)).expect("configured");

    assert_eq!(client.client_id, DESKTOP_ID);
    assert!(
        client
            .audiences
            .iter()
            .any(|id| id == "111-ios.apps.googleusercontent.com")
    );
}

#[test]
fn a_repeated_id_under_different_labels_appears_once_in_the_set() {
    let same = format!("desktop:{DESKTOP_ID},ios:{DESKTOP_ID}");
    let client = oauth_client(Platform::Desktop, Some(&same), Some(SECRET)).expect("configured");

    assert_eq!(client.audiences, vec![DESKTOP_ID.to_string()]);
}

// --- The secret, which is the only per-device value ---

#[test]
fn a_desktop_build_without_its_secret_is_refused_at_startup() {
    assert_eq!(
        oauth_client(Platform::Desktop, Some(BOTH), None),
        Err(ProviderError::MissingClientSecret)
    );
    assert_eq!(
        oauth_client(Platform::Desktop, Some(BOTH), Some("")),
        Err(ProviderError::MissingClientSecret)
    );
}

/// A secret on an Android build means two clients' settings were pasted
/// together. Google issues none for that client type.
#[test]
fn a_secret_supplied_to_an_android_build_is_refused() {
    assert_eq!(
        oauth_client(Platform::Android, Some(BOTH), Some(SECRET)),
        Err(ProviderError::UnexpectedClientSecret)
    );
}

// --- What configuration may not reach ---

#[test]
fn nothing_a_peer_is_verified_against_comes_from_configuration() {
    let profile = google(desktop());

    assert_eq!(profile.issuer, "https://accounts.google.com");
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
