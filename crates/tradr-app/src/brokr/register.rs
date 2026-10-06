use tradr_core::{DomainTag, KeyStore, LinkSecret, PublicIdentity};
use tradr_identity::AccountId;

use super::api::{BrokrApi, BrokrError, RegisterRequest, Session};

const SIGNATURE_LEN: usize = 64;

pub(super) fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn decode_hex(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) || !s.is_ascii() {
        return None;
    }
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).ok())
        .collect()
}

/// Registers this device with the Brokr and answers the session token. The
/// Brokr receives tags derived from the account and Link Secrets, never the
/// account itself (invariant I3).
pub async fn register(
    api: &dyn BrokrApi,
    key_store: &dyn KeyStore,
    identity: &PublicIdentity,
    own_account: &AccountId,
    link_secrets: &[LinkSecret],
    join_token: &str,
) -> Result<Session, BrokrError> {
    let info = api.info().await?;
    let salt = decode_hex(&info.account_salt)
        .ok_or_else(|| BrokrError::Malformed("account_salt is not hex".to_string()))?;

    let challenge = api.challenge().await?;
    let nonce = decode_hex(&challenge.nonce)
        .ok_or_else(|| BrokrError::Malformed("nonce is not hex".to_string()))?;

    let signature = key_store
        .sign(DomainTag::BrokrChallenge, &nonce)
        .map_err(BrokrError::Key)?;
    if signature.as_bytes().len() != SIGNATURE_LEN {
        return Err(BrokrError::Malformed(
            "signature is not 64 raw bytes".to_string(),
        ));
    }

    let mut account_hasher = blake3::Hasher::new();
    account_hasher.update(&own_account.to_bytes());
    account_hasher.update(&salt);

    let request = RegisterRequest {
        device_id: identity.device_id().to_string(),
        identity_pub: encode_hex(identity.identity_pub().as_bytes()),
        join_token: join_token.to_string(),
        account_tag: encode_hex(account_hasher.finalize().as_bytes()),
        link_tags: link_secrets
            .iter()
            .map(|secret| encode_hex(blake3::hash(secret.as_bytes()).as_bytes()))
            .collect(),
        nonce: challenge.nonce,
        signature: encode_hex(signature.as_bytes()),
    };
    api.register(request).await
}
