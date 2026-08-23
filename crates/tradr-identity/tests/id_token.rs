//! Supervisor-authored tests for id_token signature verification, written
//! before the implementation. docs/05 step 2, a Critical Module: a verifier
//! that trusts a token's own `alg` header is the classic JWT failure. Tokens
//! here are minted with `rsa` directly, never through the crate under test,
//! so a broken verifier cannot agree with itself.

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use hmac::{Hmac, Mac};
use rsa::pkcs1v15::SigningKey;
use rsa::pkcs8::DecodePrivateKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, RsaPublicKey};
use sha2::Sha256;
use tradr_identity::{
    Jwk, NonceBinding, ProviderProfile, SignatureAlgorithm, TokenError, VerifiedClaims,
    verify_id_token,
};

/// A fixed 2048-bit key, so the suite is fast and deterministic. Generating
/// one per run would cost about a second each and prove nothing extra.
const TEST_KEY_PEM: &str = r#"-----BEGIN PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDYQ+qgF0T16c2x
yXBPU0I36ACKWEjOYpixQ1gz7x4MPcpmod8Yrjl7neTIfUVsmKT5brnzJ64kcKT8
b4zmtJ090gHN3Fa7L/RIiIAw+7xm1s1hrStLMDT5GZcQJ7gmtciuM4a2BoxOi3Cp
vxtN2SSsu4AumW1qOE81KD0K9+yodMTiUXRQHdM8BcWqz7MwLdFSNzTp0gWch3HV
/ApthIScsNrFXt0tGxMUZ5PGxrOBl7ToRSZmerdEuWUibv62uxGD8uTmjADTwx0u
IVJoI6ky8SBsP4tswRFmVM3yR9HkygjqnCK2bkJrEIO+hvgh0taZshYCRg5BKJBp
I+UAvpqjAgMBAAECggEBANHTw3ckXJJEEIDoswEkBOF9Rdj0o18rJn8GmjN5UywJ
X7GIaI7nq3oWzf0AHjWpPJeOKPiUjU9pw4nxKUJGBzIN6hY0LCpd8qPVXJsqA7e7
vXWBsLm4wgzWGU1hXDiis1zhPViqrcMfY2Yut20mu4CkQ0/zKMegbqliqydTONiO
+hMaKig1naMoSUn5UO2GDtTHocqDSTWa6TOI7o0mEtBqKkKdXrsulnzptCWNYpc9
IzZVurQZ8QG2PCB0oTpze3r1/aUMAwqE4P3h8kHEhDaHNDaDEfIiJTsojDoChMEf
wOHcwRtF4oDFCp1aI2c3XKSCYLKDFvQ8AeyTs5VKgkECgYEA5EI+9iXKa2+MXQZ6
4VZ5ks31Pk/fHs7z53RY2D4cG6ehK8Fhnd8b3J9wmoMPQySE6DamfXGk7mwqdERb
jJ/kxowc4g2fVW9WY5kcTbtPp0qgx3xRoIEb7ErVY3zzf5KLwR47mCYn93aLWnRp
Q6ZHUXH1KAnvjIfoxBROJ0SFuhECgYEA8oyFU53ZmidDB/3eO6bFSf7bXH3sWSnJ
0QEkB3HDOLkqeGEIWH9XxVnqwSDcZ807Z4mfCtSHC/pCaA075o7sTKpSF2JRkeGS
EH5G1/BZjzenRlaKPTEePisWYwxTwT19stxF/ViQ9fBHTsEZQ+iyLcQ1yVqIspH/
3SyLNdw+tXMCgYBCM/SO7+cFwhSz5m09bhdUvOekawYLqXqUZupdzaXZX4Ufa7ck
UtGB67x9FAYZMz5ZG4CuYYe0nyqxDiJ/ZuCztW+rIMhVvzUPLhlHckxn+P0o3qXO
J6QxpIK/mD4HgjmGiX4/YtG0tG02jwz40gFdXe/87OTNnZ2lQT5ppTYkAQKBgQCF
iZw2JygQ2SDsm3bpPK5OSQSY7bNce8djTM97UcT7y+Z4FGQ15RZ7zz+SSPdQJwxX
ustXeR9JFuXMx8x86Z9rrjI4MadbO+fhMMTsSqXkVe3AqhC+E/bkn3BZ5AWQ1LwJ
54CZNVPKNBnuYB3653iB/g7m5vNv7TYDnWyfoLzdxQKBgQC6EYvHMd8ol9WgpRXk
/F7ZcA5/6eUGkI1Z4l8nfnlylCUGp49v5hGY+i2z64/c5/VNF/NM9x9s1eFU2wwt
7GmF4b+pYDjQYFAIyK82trfgO+w3w7Gicmxo4Qw3By0IPG/+LskehuEz7Bw7EVKL
MH1PaxeOz3eaTQVEUUg5TNv80g==
-----END PRIVATE KEY-----"#;

const KID: &str = "test-key-1";
const ISS: &str = "https://accounts.google.com";
const AUD: &str = "desktop-client.apps.googleusercontent.com";

fn private_key() -> RsaPrivateKey {
    match RsaPrivateKey::from_pkcs8_pem(TEST_KEY_PEM) {
        Ok(k) => k,
        Err(e) => panic!("the embedded test key must parse, got {e}"),
    }
}

/// The JWKS entry a provider would publish for the key above.
fn published_key() -> Jwk {
    let public = RsaPublicKey::from(&private_key());
    Jwk {
        kid: KID.to_string(),
        algorithm: SignatureAlgorithm::Rs256,
        modulus: public.n().to_bytes_be(),
        exponent: public.e().to_bytes_be(),
    }
}

fn profile() -> ProviderProfile {
    ProviderProfile {
        issuer: ISS.to_string(),
        client_ids: vec![AUD.to_string()],
        nonce_binding: NonceBinding::Verbatim,
        algorithms: vec![SignatureAlgorithm::Rs256],
    }
}

fn payload_json() -> String {
    format!(
        r#"{{"iss":"{ISS}","sub":"peer-subject","aud":"{AUD}","iat":1800000000,"nonce":"a-nonce"}}"#
    )
}

/// Mints a token signed with the real key, under whatever header is given.
fn signed_token(header_json: &str, payload_json: &str) -> String {
    let input = format!("{}.{}", B64.encode(header_json), B64.encode(payload_json));
    let signing_key = SigningKey::<Sha256>::new(private_key());
    let signature = signing_key.sign(input.as_bytes());
    format!("{}.{}", input, B64.encode(signature.to_bytes()))
}

fn valid_token() -> String {
    signed_token(
        &format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{KID}"}}"#),
        &payload_json(),
    )
}

fn verify(token: &str) -> Result<VerifiedClaims, TokenError> {
    verify_id_token(&profile(), &[published_key()], token)
}

// --- The happy path -----------------------------------------------------

#[test]
fn a_correctly_signed_token_verifies_and_yields_its_claims() {
    let Ok(claims) = verify(&valid_token()) else {
        panic!("a token signed by the published key must verify");
    };
    assert_eq!(claims.iss, ISS);
    assert_eq!(claims.sub, "peer-subject");
    assert_eq!(claims.aud, AUD);
    assert_eq!(claims.iat.as_secs(), 1_800_000_000);
    assert_eq!(claims.nonce, "a-nonce");
}

// --- The token does not choose how it is verified -----------------------

#[test]
fn a_token_declaring_alg_none_is_rejected() {
    // The signature is absent entirely. A verifier that reads `alg` and
    // dispatches on it accepts this.
    let header = format!(r#"{{"alg":"none","typ":"JWT","kid":"{KID}"}}"#);
    let token = format!("{}.{}.", B64.encode(&header), B64.encode(payload_json()));

    assert_eq!(
        verify(&token),
        Err(TokenError::AlgorithmNotPermitted("none".to_string()))
    );
}

#[test]
fn a_token_declaring_hs256_is_rejected_even_with_a_valid_mac() {
    // Algorithm confusion. The MAC below is genuinely correct under the
    // provider's own public modulus, which is public, so anyone can build
    // this token. A verifier that dispatches on `alg` accepts it and the
    // attacker owns every account.
    let header = format!(r#"{{"alg":"HS256","typ":"JWT","kid":"{KID}"}}"#);
    let input = format!("{}.{}", B64.encode(&header), B64.encode(payload_json()));
    let modulus = RsaPublicKey::from(&private_key()).n().to_bytes_be();
    let Ok(mut mac) = <Hmac<Sha256> as Mac>::new_from_slice(&modulus) else {
        panic!("hmac accepts a key of any length");
    };
    mac.update(input.as_bytes());
    let token = format!("{}.{}", input, B64.encode(mac.finalize().into_bytes()));

    assert_eq!(
        verify(&token),
        Err(TokenError::AlgorithmNotPermitted("HS256".to_string()))
    );
}

#[test]
fn an_algorithm_outside_the_profile_is_rejected_even_when_it_is_a_real_one() {
    for alg in ["RS512", "PS256", "ES256", "HS512", ""] {
        let header = format!(r#"{{"alg":"{alg}","typ":"JWT","kid":"{KID}"}}"#);
        let token = signed_token(&header, &payload_json());
        assert_eq!(
            verify(&token),
            Err(TokenError::AlgorithmNotPermitted(alg.to_string())),
            "{alg} is not in the profile and must be refused"
        );
    }
}

#[test]
fn a_profile_that_permits_nothing_accepts_nothing() {
    // The membership test against `profile.algorithms` is the whole rule,
    // and with one algorithm in the enum it is invisible unless a profile
    // that does not list it is tried. This token is otherwise perfect.
    let empty = ProviderProfile {
        algorithms: Vec::new(),
        ..profile()
    };

    assert_eq!(
        verify_id_token(&empty, &[published_key()], &valid_token()),
        Err(TokenError::AlgorithmNotPermitted("RS256".to_string()))
    );
}

#[test]
fn the_algorithm_is_checked_before_the_signature() {
    // A token with a rejected `alg` and a signature that is also garbage
    // must report the algorithm, not the signature. Otherwise the two
    // checks could be reordered without any test noticing, and the order
    // is what closes the confusion attack.
    let header = format!(r#"{{"alg":"HS256","typ":"JWT","kid":"{KID}"}}"#);
    let token = format!(
        "{}.{}.{}",
        B64.encode(&header),
        B64.encode(payload_json()),
        B64.encode([0u8; 32])
    );

    assert_eq!(
        verify(&token),
        Err(TokenError::AlgorithmNotPermitted("HS256".to_string()))
    );
}

// --- kid selects among the profile's keys, and nothing else -------------

#[test]
fn an_unknown_key_id_is_rejected() {
    let header = r#"{"alg":"RS256","typ":"JWT","kid":"some-other-key"}"#;
    let token = signed_token(header, &payload_json());

    assert_eq!(
        verify(&token),
        Err(TokenError::UnknownKeyId("some-other-key".to_string()))
    );
}

#[test]
fn a_token_with_no_key_id_is_rejected() {
    // Not "try every key": a provider publishes several, and picking one by
    // trial turns a wrong guess into a signature check the attacker gets to
    // repeat against each.
    let header = r#"{"alg":"RS256","typ":"JWT"}"#;
    let token = signed_token(header, &payload_json());

    assert!(matches!(verify(&token), Err(TokenError::Malformed(_))));
}

#[test]
fn a_token_signed_by_a_different_key_under_a_known_id_is_rejected() {
    // The kid names a key we hold; the signature was made with another. The
    // kid must not be treated as evidence about who signed.
    let mut rng = rand::thread_rng();
    let Ok(other) = RsaPrivateKey::new(&mut rng, 2048) else {
        panic!("generating a second key must succeed");
    };
    let header = format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{KID}"}}"#);
    let input = format!("{}.{}", B64.encode(&header), B64.encode(payload_json()));
    let signature = SigningKey::<Sha256>::new(other).sign(input.as_bytes());
    let token = format!("{}.{}", input, B64.encode(signature.to_bytes()));

    assert_eq!(verify(&token), Err(TokenError::SignatureInvalid));
}

// --- The signature covers what it is supposed to cover ------------------

#[test]
fn a_tampered_payload_is_rejected() {
    let token = valid_token();
    let mut parts: Vec<&str> = token.split('.').collect();
    let forged = B64.encode(payload_json().replace("peer-subject", "someone-else"));
    parts[1] = &forged;

    assert_eq!(verify(&parts.join(".")), Err(TokenError::SignatureInvalid));
}

#[test]
fn a_tampered_signature_is_rejected() {
    let token = valid_token();
    let Some((rest, signature)) = token.rsplit_once('.') else {
        panic!("a token has three segments");
    };
    let Ok(mut bytes) = B64.decode(signature) else {
        panic!("our own signature must decode");
    };
    bytes[0] ^= 0xff;

    assert_eq!(
        verify(&format!("{rest}.{}", B64.encode(bytes))),
        Err(TokenError::SignatureInvalid)
    );
}

// --- Shape -------------------------------------------------------------

#[test]
fn a_token_without_exactly_three_segments_is_rejected() {
    let valid = valid_token();
    let Some((two_parts, _)) = valid.rsplit_once('.') else {
        panic!("a token has three segments");
    };
    for candidate in [
        "",
        "onlyonesegment",
        two_parts,
        &format!("{valid}.extra"),
        "..",
    ] {
        assert!(
            matches!(verify(candidate), Err(TokenError::Malformed(_))),
            "{candidate:?} is not a three-segment token"
        );
    }
}

#[test]
fn a_segment_that_is_not_base64url_is_rejected() {
    let valid = valid_token();
    let parts: Vec<&str> = valid.split('.').collect();
    for i in 0..3 {
        let mut broken = parts.clone();
        broken[i] = "not*valid*base64url";
        assert!(
            matches!(verify(&broken.join(".")), Err(TokenError::Malformed(_))),
            "segment {i} is not decodable and the token must be refused"
        );
    }
}

#[test]
fn padded_base64_is_rejected() {
    // JWT is base64url without padding. Accepting both spellings would give
    // one token two encodings, which anything that compares tokens as
    // strings would then disagree about.
    let header = format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{KID}"}}"#);
    let padded = base64::engine::general_purpose::URL_SAFE.encode(&header);
    if !padded.ends_with('=') {
        return;
    }
    let token = format!(
        "{}.{}.{}",
        padded,
        B64.encode(payload_json()),
        B64.encode([0u8; 8])
    );

    assert!(matches!(verify(&token), Err(TokenError::Malformed(_))));
}

// --- Claims ------------------------------------------------------------

#[test]
fn an_audience_given_as_an_array_is_rejected() {
    // DCR-021: RFC 7519 permits either shape, and this design accepts one,
    // so step 3's comparison has a single meaning.
    let payload =
        format!(r#"{{"iss":"{ISS}","sub":"s","aud":["{AUD}"],"iat":1800000000,"nonce":"n"}}"#);
    let header = format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{KID}"}}"#);

    assert!(matches!(
        verify(&signed_token(&header, &payload)),
        Err(TokenError::Malformed(_))
    ));
}

#[test]
fn a_missing_claim_is_rejected_rather_than_defaulted() {
    // A defaulted claim is a claim an attacker did not have to supply.
    let header = format!(r#"{{"alg":"RS256","typ":"JWT","kid":"{KID}"}}"#);
    for omitted in ["iss", "sub", "aud", "iat", "nonce"] {
        let full = payload_json();
        let payload = strip_claim(&full, omitted);
        assert!(
            matches!(
                verify(&signed_token(&header, &payload)),
                Err(TokenError::Malformed(_))
            ),
            "a token with no {omitted} must be refused"
        );
    }
}

/// Removes one claim from the fixture payload, leaving valid JSON.
fn strip_claim(payload: &str, name: &str) -> String {
    let Some(value) = serde_json_value(payload, name) else {
        panic!("the fixture must contain {name}");
    };
    payload
        .replace(&format!(r#""{name}":{value},"#), "")
        .replace(&format!(r#","{name}":{value}"#), "")
}

/// Finds a claim's raw JSON text without parsing the document, so the test
/// helper does not depend on a JSON library agreeing with the implementation.
fn serde_json_value(payload: &str, name: &str) -> Option<String> {
    let key = format!(r#""{name}":"#);
    let start = payload.find(&key)? + key.len();
    let rest = &payload[start..];
    let end = rest.find([',', '}']).unwrap_or(rest.len());
    Some(rest[..end].to_string())
}
