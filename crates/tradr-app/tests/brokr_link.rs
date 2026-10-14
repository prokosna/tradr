use std::collections::HashMap;
use std::sync::Mutex;

use tradr_app::brokr::{
    BrokrLink, BrokrLinkError, BrokrSettings, JoinToken, save_join_token, save_settings,
    stored_link,
};
use tradr_core::{SecretStore, SecretStoreError, StorageLevel};

#[derive(Default)]
struct MemorySecrets {
    slots: Mutex<HashMap<String, Vec<u8>>>,
}

impl SecretStore for MemorySecrets {
    fn store(&self, slot: &str, secret: &[u8]) -> Result<(), SecretStoreError> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .insert(slot.to_string(), secret.to_vec());
        Ok(())
    }

    fn load(&self, slot: &str) -> Result<Option<Vec<u8>>, SecretStoreError> {
        Ok(self
            .slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .get(slot)
            .cloned())
    }

    fn remove(&self, slot: &str) -> Result<(), SecretStoreError> {
        self.slots
            .lock()
            .unwrap_or_else(|p| p.into_inner())
            .remove(slot);
        Ok(())
    }

    fn level(&self) -> StorageLevel {
        StorageLevel::File
    }
}

#[test]
fn parse_hand_written_link() {
    let link =
        BrokrLink::parse("tradr://brokr?url=http://host.example:8780&token=abc-DEF_1.2").unwrap();
    assert_eq!(link.url(), "http://host.example:8780");
    assert_eq!(link.token().as_str(), "abc-DEF_1.2");
}

#[test]
fn to_link_then_parse_round_trip() {
    let token_raw = "a b&c=d+e%f#g/é";
    let address = "http://host.example:8780";
    let link = BrokrLink::new(address.to_string(), JoinToken::new(token_raw.to_string()));
    let written = link.to_link();

    assert!(!written.contains(' '));
    assert!(!written.contains('#'));
    assert!(!written.contains(token_raw));

    let parsed = BrokrLink::parse(&written).unwrap();
    assert_eq!(parsed.url(), address);
    assert_eq!(parsed.token().as_str(), token_raw);
}

#[test]
fn to_link_exact_format() {
    let link = BrokrLink::new(
        "http://host.example:8780".to_string(),
        JoinToken::new("abc".to_string()),
    );
    assert_eq!(
        link.to_link(),
        "tradr://brokr?url=http%3A%2F%2Fhost.example%3A8780&token=abc"
    );
}

#[test]
fn parse_accepts_surrounding_whitespace() {
    let raw = "  \t tradr://brokr?url=http://host.example:8780&token=abc \n\r\n";
    let link = BrokrLink::parse(raw).unwrap();
    assert_eq!(link.url(), "http://host.example:8780");
    assert_eq!(link.token().as_str(), "abc");
}

#[test]
fn parse_accepts_case_insensitive_prefix() {
    let raw = "TRADR://BROKR?url=http://host.example:8780&token=abc";
    let link = BrokrLink::parse(raw).unwrap();
    assert_eq!(link.url(), "http://host.example:8780");
    assert_eq!(link.token().as_str(), "abc");
}

#[test]
fn parse_ignores_unknown_query_pairs() {
    let raw = "tradr://brokr?v=2&url=http://host.example:8780&token=abc&extra=xyz";
    let link = BrokrLink::parse(raw).unwrap();
    assert_eq!(link.url(), "http://host.example:8780");
    assert_eq!(link.token().as_str(), "abc");
}

#[test]
fn parse_refuses_non_brokr_scheme() {
    assert_eq!(
        BrokrLink::parse("https://host/?url=a&token=b"),
        Err(BrokrLinkError::NotABrokrLink)
    );
}

#[test]
fn parse_refuses_path() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr/x?url=a&token=b"),
        Err(BrokrLinkError::NotABrokrLink)
    );
}

#[test]
fn parse_refuses_missing_query_question_mark() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr"),
        Err(BrokrLinkError::NotABrokrLink)
    );
}

#[test]
fn parse_refuses_multibyte_prefix() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr\u{e9}"),
        Err(BrokrLinkError::NotABrokrLink)
    );
    assert_eq!(
        BrokrLink::parse("tradr://brok\u{e9}?url=a&token=b"),
        Err(BrokrLinkError::NotABrokrLink)
    );
    assert_eq!(
        BrokrLink::parse("\u{e9}"),
        Err(BrokrLinkError::NotABrokrLink)
    );
}

#[test]
fn parse_refuses_hash_character() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr?url=a#b&token=c"),
        Err(BrokrLinkError::NotABrokrLink)
    );
}

#[test]
fn parse_refuses_missing_url() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr?token=b"),
        Err(BrokrLinkError::MissingAddress)
    );
}

#[test]
fn parse_refuses_empty_url() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr?url=&token=b"),
        Err(BrokrLinkError::MissingAddress)
    );
}

#[test]
fn parse_refuses_missing_token() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr?url=a"),
        Err(BrokrLinkError::MissingToken)
    );
}

#[test]
fn parse_refuses_empty_token() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr?url=a&token="),
        Err(BrokrLinkError::MissingToken)
    );
}

#[test]
fn parse_refuses_repeated_url() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr?url=a&url=b&token=c"),
        Err(BrokrLinkError::RepeatedAddress)
    );
}

#[test]
fn parse_refuses_repeated_token() {
    assert_eq!(
        BrokrLink::parse("tradr://brokr?url=a&token=b&token=c"),
        Err(BrokrLinkError::RepeatedToken)
    );
}

#[test]
fn debug_does_not_reveal_token() {
    let link = BrokrLink::new(
        "http://host.example:8780".to_string(),
        JoinToken::new("s3cret-token-value".to_string()),
    );
    let debug_output = format!("{link:?}");
    assert!(!debug_output.contains("s3cret-token-value"));
}

#[test]
fn error_display_messages() {
    assert_eq!(
        BrokrLinkError::NotABrokrLink.to_string(),
        "This is not a Brokr link. A Brokr link starts with tradr://brokr?"
    );
    assert_eq!(
        BrokrLinkError::MissingAddress.to_string(),
        "The link has no Brokr address."
    );
    assert_eq!(
        BrokrLinkError::MissingToken.to_string(),
        "The link has no join token."
    );
    assert_eq!(
        BrokrLinkError::RepeatedAddress.to_string(),
        "The link gives the Brokr address more than once."
    );
    assert_eq!(
        BrokrLinkError::RepeatedToken.to_string(),
        "The link gives the join token more than once."
    );
}

#[test]
fn stored_link_lifecycle() {
    let temp = tempfile::tempdir().unwrap();
    let secrets = MemorySecrets::default();

    let empty = stored_link(temp.path(), &secrets).unwrap();
    assert_eq!(empty, None);

    save_settings(
        temp.path(),
        &BrokrSettings {
            url: "http://host.example:8780".to_string(),
        },
    )
    .unwrap();
    let only_settings = stored_link(temp.path(), &secrets).unwrap();
    assert_eq!(only_settings, None);

    save_join_token(&secrets, &JoinToken::new("secret-token-123".to_string())).unwrap();
    let both = stored_link(temp.path(), &secrets)
        .unwrap()
        .expect("both stored");
    assert_eq!(both.url(), "http://host.example:8780");
    assert_eq!(both.token().as_str(), "secret-token-123");

    let parsed = BrokrLink::parse(&both.to_link()).unwrap();
    assert_eq!(parsed.url(), both.url());
    assert_eq!(parsed.token().as_str(), both.token().as_str());
}
