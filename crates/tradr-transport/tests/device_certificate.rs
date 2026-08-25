//! Supervisor-authored tests for WI-M1-002b, written before the
//! implementation. The certificate is where a QUIC peer first states which
//! Device Key it holds, and docs/05 makes the `SubjectPublicKeyInfo` the
//! only place that claim appears. A builder that puts the key anywhere
//! else, or a reader that takes it from anywhere else, breaks pinning.

use p256::ecdsa::signature::{Signer, Verifier};
use p256::ecdsa::{Signature as EcdsaSignature, SigningKey, VerifyingKey};
use p256::elliptic_curve::sec1::ToEncodedPoint;
use p256::{PublicKey, SecretKey};
use tradr_core::{
    Backing, DeviceId, DomainTag, KeyStore, KeyStoreError, PublicIdentity, PublicKeyPoint,
    SharedSecret, Signature, SoftwareReason,
};
use tradr_transport::certificate::{CertificateError, build_self_signed, identity_point};

/// A `KeyStore` over fixed P-256 scalars. `tradr-transport` may not
/// dev-depend on `tradr-identity`, since `ci/layer-deps.sh` scans every
/// section of a manifest, and that is the right shape regardless: a test
/// reaching for the other implementation is a test that can agree with it.
struct TestKeyStore {
    identity_key: SigningKey,
    agreement_key: SecretKey,
}

impl TestKeyStore {
    fn with_scalars(identity: [u8; 32], agreement: [u8; 32]) -> Self {
        Self {
            identity_key: SigningKey::from_slice(&identity).expect("a fixed valid P-256 scalar"),
            agreement_key: SecretKey::from_slice(&agreement).expect("a fixed valid P-256 scalar"),
        }
    }

    fn uncompressed_identity(&self) -> Vec<u8> {
        self.identity_key
            .verifying_key()
            .to_encoded_point(false)
            .as_bytes()
            .to_vec()
    }

    fn compressed_identity(&self) -> Vec<u8> {
        self.identity_key
            .verifying_key()
            .to_encoded_point(true)
            .as_bytes()
            .to_vec()
    }
}

impl KeyStore for TestKeyStore {
    fn public_identity(&self) -> Result<PublicIdentity, KeyStoreError> {
        let identity_pub = PublicKeyPoint::from_bytes(&self.uncompressed_identity())
            .expect("p256 writes an uncompressed point in 65 bytes");
        let agreement_point = self.agreement_key.public_key().to_encoded_point(false);
        let agreement_pub = PublicKeyPoint::from_bytes(agreement_point.as_bytes())
            .expect("p256 writes an uncompressed point in 65 bytes");
        let digest = blake3::hash(identity_pub.as_bytes());
        Ok(PublicIdentity::new(
            identity_pub,
            agreement_pub,
            DeviceId::from_identity_digest(digest.as_bytes()),
        ))
    }

    fn sign(&self, domain: DomainTag, message: &[u8]) -> Result<Signature, KeyStoreError> {
        let payload = domain
            .payload(message)
            .map_err(KeyStoreError::DomainSeparation)?;
        let raw: EcdsaSignature = self
            .identity_key
            .try_sign(payload.as_ref())
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
        let normalized = raw.normalize_s().unwrap_or(raw);
        Ok(Signature::from_bytes(normalized.to_bytes().to_vec()))
    }

    fn agree(&self, peer_public: &PublicKeyPoint) -> Result<SharedSecret, KeyStoreError> {
        let peer = PublicKey::from_sec1_bytes(peer_public.as_bytes())
            .map_err(|e| KeyStoreError::Backend(Box::new(e)))?;
        let shared =
            p256::ecdh::diffie_hellman(self.agreement_key.to_nonzero_scalar(), peer.as_affine());
        Ok(SharedSecret::from_bytes(shared.raw_secret_bytes().to_vec()))
    }

    fn backing(&self) -> Backing {
        Backing::Software(SoftwareReason::PlatformHasNoSecureElement)
    }
}

fn device_a() -> TestKeyStore {
    TestKeyStore::with_scalars([0x11; 32], [0x22; 32])
}

fn device_b() -> TestKeyStore {
    TestKeyStore::with_scalars([0x33; 32], [0x44; 32])
}

// The three children of Certificate, in RFC 5280's order.
const CERT_TBS: usize = 0;
const CERT_SIGNATURE_ALGORITHM: usize = 1;
const CERT_SIGNATURE_VALUE: usize = 2;

// The seven children a TBSCertificate has when it carries a version and
// no optional field after the key, which is what docs/05 settles on.
const TBS_VERSION: usize = 0;
const TBS_SERIAL: usize = 1;
const TBS_SIGNATURE_ALGORITHM: usize = 2;
const TBS_ISSUER: usize = 3;
const TBS_VALIDITY: usize = 4;
const TBS_SUBJECT: usize = 5;
const TBS_SPKI: usize = 6;
const TBS_CHILDREN: usize = 7;

// Written out as bytes rather than built from an encoder, so an OID typo
// in the implementation cannot be reproduced by the test that checks it.
const ID_EC_PUBLIC_KEY: &[u8] = &[0x06, 0x07, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x02, 0x01];
const PRIME256V1: &[u8] = &[0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07];
const SECP384R1: &[u8] = &[0x06, 0x05, 0x2b, 0x81, 0x04, 0x00, 0x22];
const RSA_ENCRYPTION: &[u8] = &[
    0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01,
];
const NULL_PARAMETER: &[u8] = &[0x05, 0x00];

// AlgorithmIdentifier for ecdsa-with-SHA256. RFC 5758 requires the
// parameters field to be absent, so the whole structure is twelve bytes
// and a NULL parameter would make it fourteen.
const ECDSA_WITH_SHA_256: &[u8] = &[
    0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
];

// EXPLICIT [0] wrapping INTEGER 2, which is how a v3 certificate spells
// its version.
const VERSION_V3: &[u8] = &[0xa0, 0x03, 0x02, 0x01, 0x02];

// INTEGER 1: the constant serial DCR-039 settles on.
const SERIAL_NUMBER: &[u8] = &[0x02, 0x01, 0x01];

const NOT_BEFORE: &[u8] = b"200101000000Z";
const NOT_AFTER: &[u8] = b"99991231235959Z";

const UTC_TIME: u8 = 0x17;
const GENERALIZED_TIME: u8 = 0x18;
const BIT_STRING: u8 = 0x03;
const SEQUENCE: u8 = 0x30;

// Splits one DER element into its tag, its body, and the bytes after it.
// Hand-rolled rather than taken from a parser crate, so a certificate is
// measured against the encoding rules and not against whichever library
// the implementation happened to choose.
fn split(bytes: &[u8]) -> (u8, &[u8], &[u8]) {
    let (&tag, rest) = bytes.split_first().expect("a DER element has a tag");
    let (&first, rest) = rest.split_first().expect("a DER element has a length");
    let (len, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7f);
        assert!(
            (1..=2).contains(&count),
            "a certificate's lengths fit in two bytes"
        );
        let (head, tail) = rest.split_at(count);
        let len = head
            .iter()
            .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
        (len, tail)
    };
    let (body, after) = rest.split_at(len);
    (tag, body, after)
}

// Every child of a constructed element, each as its own complete
// encoding, so a child can be compared or replaced exactly as it appears
// on the wire.
fn children(element: &[u8]) -> Vec<&[u8]> {
    let (_, body, _) = split(element);
    let mut out = Vec::new();
    let mut rest = body;
    while !rest.is_empty() {
        let (_, _, after) = split(rest);
        let taken = rest.len() - after.len();
        out.push(&rest[..taken]);
        rest = after;
    }
    out
}

// Wraps `body` in a DER tag and a definite length.
fn tlv(tag: u8, body: &[u8]) -> Vec<u8> {
    let len = body.len();
    assert!(len < 0x10000, "a certificate is far shorter than this");
    let mut out = vec![tag];
    if len < 0x80 {
        out.push(u8::try_from(len).expect("below 0x80"));
    } else if len < 0x100 {
        out.push(0x81);
        out.push(u8::try_from(len).expect("below 0x100"));
    } else {
        out.push(0x82);
        out.push(u8::try_from(len >> 8).expect("below 0x100"));
        out.push(u8::try_from(len & 0xff).expect("masked to a byte"));
    }
    out.extend_from_slice(body);
    out
}

// Assembles a SubjectPublicKeyInfo from an algorithm OID, its parameter
// and a public key point, so a certificate carrying a curve or a point
// encoding the design refuses can be built without asking the encoder
// under test to build something it should refuse.
fn spki(algorithm_oid: &[u8], parameter: &[u8], point: &[u8]) -> Vec<u8> {
    let mut algorithm = algorithm_oid.to_vec();
    algorithm.extend_from_slice(parameter);
    let mut body = tlv(SEQUENCE, &algorithm);
    let mut key_bits = vec![0x00];
    key_bits.extend_from_slice(point);
    body.extend_from_slice(&tlv(BIT_STRING, &key_bits));
    tlv(SEQUENCE, &body)
}

// The signatureValue BIT STRING over `tbs`: the raw r || s a `KeyStore`
// returns, re-encoded as the DER ECDSA-Sig-Value X.509 requires.
fn signature_value(store: &TestKeyStore, tbs: &[u8]) -> Vec<u8> {
    let raw = store
        .sign(DomainTag::CertificateTbs, tbs)
        .expect("a TBSCertificate begins with the byte its separation requires");
    let der = EcdsaSignature::from_slice(raw.as_bytes())
        .expect("a KeyStore returns 64 bytes of r || s")
        .to_der();
    let mut bits = vec![0x00];
    bits.extend_from_slice(der.as_bytes());
    tlv(BIT_STRING, &bits)
}

// Rebuilds `certificate` around a different SubjectPublicKeyInfo and
// signs the result with `store`. Re-signing is what makes a rejection
// attributable: it can only have come from the key the certificate
// carries, never from a signature left behind by the bytes it replaced.
fn resigned_with_spki(certificate: &[u8], new_spki: &[u8], store: &TestKeyStore) -> Vec<u8> {
    let outer = children(certificate);
    let mut tbs_body = Vec::new();
    for (index, child) in children(outer[CERT_TBS]).iter().enumerate() {
        if index == TBS_SPKI {
            tbs_body.extend_from_slice(new_spki);
        } else {
            tbs_body.extend_from_slice(child);
        }
    }
    let tbs = tlv(SEQUENCE, &tbs_body);
    let signature = signature_value(store, &tbs);
    let mut body = tbs;
    body.extend_from_slice(outer[CERT_SIGNATURE_ALGORITHM]);
    body.extend_from_slice(&signature);
    tlv(SEQUENCE, &body)
}

// The ECDSA signature inside a signatureValue BIT STRING, whose leading
// body byte counts unused bits and is zero for a whole number of bytes.
fn ecdsa_signature(signature_value: &[u8]) -> EcdsaSignature {
    let (_, body, _) = split(signature_value);
    assert_eq!(body[0], 0x00, "a signature occupies whole bytes");
    EcdsaSignature::from_der(&body[1..]).expect("X.509 carries a DER ECDSA-Sig-Value")
}

fn certificate(store: &TestKeyStore) -> Vec<u8> {
    build_self_signed(store).expect("a working store must yield a certificate")
}

#[test]
fn the_identity_point_reads_back_out_of_the_certificate_it_built() {
    let store = device_a();
    let der = certificate(&store);
    let held = store
        .public_identity()
        .expect("a fixed store exposes its identity")
        .identity_pub()
        .clone();

    let read = identity_point(&der).expect("its own certificate must parse");

    assert_eq!(read, held);
}

#[test]
fn the_subject_public_key_info_is_the_identity_point_and_nothing_else() {
    // Pins the encoding, not merely the value. docs/05 makes the SPKI the
    // one place identity appears, so what a peer parses has to be the
    // uncompressed point under id-ecPublicKey and prime256v1 exactly.
    let store = device_a();
    let der = certificate(&store);
    let outer = children(&der);
    let tbs = children(outer[CERT_TBS]);

    assert_eq!(
        tbs[TBS_SPKI],
        spki(ID_EC_PUBLIC_KEY, PRIME256V1, &store.uncompressed_identity()).as_slice()
    );
}

#[test]
fn the_self_signature_covers_the_tbs_bytes_exactly() {
    // Nothing may be prepended: `DomainTag::CertificateTbs` requires the
    // separation the structure already carries instead of adding one, and
    // a signature over anything but these bytes fails every peer.
    let store = device_a();
    let der = certificate(&store);
    let outer = children(&der);
    let signature = ecdsa_signature(outer[CERT_SIGNATURE_VALUE]);
    let key = VerifyingKey::from_sec1_bytes(&store.uncompressed_identity())
        .expect("the store's own point is a P-256 point");

    assert!(key.verify(outer[CERT_TBS], &signature).is_ok());
}

#[test]
fn the_self_signature_fails_over_tbs_bytes_that_were_altered() {
    // Proves the test above can fail. A verifier that accepted anything
    // would pass it while proving nothing about which bytes were signed.
    let store = device_a();
    let der = certificate(&store);
    let outer = children(&der);
    let signature = ecdsa_signature(outer[CERT_SIGNATURE_VALUE]);
    let key = VerifyingKey::from_sec1_bytes(&store.uncompressed_identity())
        .expect("the store's own point is a P-256 point");
    let mut altered = outer[CERT_TBS].to_vec();
    let last = altered.len() - 1;
    altered[last] ^= 0x01;

    assert!(key.verify(&altered, &signature).is_err());
}

#[test]
fn both_signature_algorithm_fields_name_ecdsa_with_sha_256() {
    let der = certificate(&device_a());
    let outer = children(&der);
    let tbs = children(outer[CERT_TBS]);

    assert_eq!(outer[CERT_SIGNATURE_ALGORITHM], ECDSA_WITH_SHA_256);
    assert_eq!(tbs[TBS_SIGNATURE_ALGORITHM], ECDSA_WITH_SHA_256);
}

#[test]
fn two_devices_carry_byte_identical_subjects_issuers_and_serials() {
    // Decision 19 made checkable rather than asserted. The inequality on
    // the key is what gives the equalities their meaning: without it, two
    // identical certificates would satisfy every line below.
    let a = certificate(&device_a());
    let b = certificate(&device_b());
    let outer_a = children(&a);
    let outer_b = children(&b);
    let tbs_a = children(outer_a[CERT_TBS]);
    let tbs_b = children(outer_b[CERT_TBS]);

    assert_ne!(tbs_a[TBS_SPKI], tbs_b[TBS_SPKI]);
    assert_eq!(tbs_a[TBS_ISSUER], tbs_b[TBS_ISSUER]);
    assert_eq!(tbs_a[TBS_SUBJECT], tbs_b[TBS_SUBJECT]);
    assert_eq!(tbs_a[TBS_ISSUER], tbs_a[TBS_SUBJECT]);
    assert_eq!(tbs_a[TBS_SERIAL], SERIAL_NUMBER);
    assert_eq!(tbs_b[TBS_SERIAL], SERIAL_NUMBER);
}

#[test]
fn the_certificate_is_v3_and_carries_no_extensions() {
    let der = certificate(&device_a());
    let outer = children(&der);
    let tbs = children(outer[CERT_TBS]);

    assert_eq!(tbs.len(), TBS_CHILDREN);
    assert_eq!(tbs[TBS_VERSION], VERSION_V3);
}

#[test]
fn the_validity_window_is_fixed_and_never_expires() {
    // Decision 20: a window nothing reads, so that no clock decides
    // whether a connection is allowed. The encoding is pinned because
    // RFC 5280 splits it at 2050, and a builder that used one form for
    // both dates would produce a certificate a strict peer refuses.
    let der = certificate(&device_a());
    let outer = children(&der);
    let tbs = children(outer[CERT_TBS]);
    let validity = children(tbs[TBS_VALIDITY]);

    assert_eq!(validity[0], tlv(UTC_TIME, NOT_BEFORE).as_slice());
    assert_eq!(validity[1], tlv(GENERALIZED_TIME, NOT_AFTER).as_slice());
}

#[test]
fn a_compressed_point_is_refused() {
    let store = device_a();
    let der = certificate(&store);
    let point = store.compressed_identity();
    let hostile = resigned_with_spki(&der, &spki(ID_EC_PUBLIC_KEY, PRIME256V1, &point), &store);

    assert!(matches!(
        identity_point(&hostile),
        Err(CertificateError::NotUncompressedPoint)
    ));
}

#[test]
fn a_certificate_naming_another_curve_is_refused() {
    let store = device_a();
    let der = certificate(&store);
    let point = store.uncompressed_identity();
    let hostile = resigned_with_spki(&der, &spki(ID_EC_PUBLIC_KEY, SECP384R1, &point), &store);

    assert!(matches!(
        identity_point(&hostile),
        Err(CertificateError::NotP256)
    ));
}

#[test]
fn a_certificate_naming_another_algorithm_is_refused() {
    let store = device_a();
    let der = certificate(&store);
    let point = store.uncompressed_identity();
    let hostile = resigned_with_spki(&der, &spki(RSA_ENCRYPTION, NULL_PARAMETER, &point), &store);

    assert!(matches!(
        identity_point(&hostile),
        Err(CertificateError::NotP256)
    ));
}

#[test]
fn a_certificate_naming_another_algorithm_over_p256_is_refused() {
    // Isolates the algorithm check from the curve check. The test above
    // carries a NULL parameter, which the curve check refuses on its own,
    // so a reader that had dropped the algorithm check entirely would
    // still pass it. Naming prime256v1 here leaves the algorithm OID as
    // the only thing wrong.
    let store = device_a();
    let der = certificate(&store);
    let point = store.uncompressed_identity();
    let hostile = resigned_with_spki(&der, &spki(RSA_ENCRYPTION, PRIME256V1, &point), &store);

    assert!(matches!(
        identity_point(&hostile),
        Err(CertificateError::NotP256)
    ));
}

#[test]
fn a_point_that_is_not_on_the_curve_is_refused() {
    let store = device_a();
    let der = certificate(&store);
    let mut point = store.uncompressed_identity();
    let last = point.len() - 1;
    point[last] ^= 0x01;
    let hostile = resigned_with_spki(&der, &spki(ID_EC_PUBLIC_KEY, PRIME256V1, &point), &store);

    assert!(matches!(
        identity_point(&hostile),
        Err(CertificateError::PointNotOnCurve)
    ));
}

#[test]
fn truncated_der_is_refused_at_every_prefix_length() {
    let der = certificate(&device_a());

    for length in 0..der.len() {
        assert!(
            identity_point(&der[..length]).is_err(),
            "a {length}-byte prefix of a certificate parsed"
        );
    }
}

#[test]
fn a_trailing_byte_after_the_certificate_is_refused() {
    // A parser that stops at the outer length and ignores what follows
    // accepts two spellings of one certificate, which is what makes a
    // certificate comparable by bytes stop being safe.
    let mut der = certificate(&device_a());
    der.push(0x00);

    assert!(identity_point(&der).is_err());
}

#[test]
fn a_peers_device_id_derives_from_the_certificate_it_presented() {
    // The join WI-M1-002a exists for. The verifier in WI-M1-003 holds a
    // peer's certificate and nothing else, and has to arrive at the same
    // DeviceId that peer computes for itself.
    let store = device_b();
    let der = certificate(&store);

    let point = identity_point(&der).expect("a well-formed certificate must parse");
    let derived = DeviceId::from_identity_digest(blake3::hash(point.as_bytes()).as_bytes());

    assert_eq!(
        derived,
        store
            .public_identity()
            .expect("a fixed store exposes its identity")
            .device_id()
    );
}
