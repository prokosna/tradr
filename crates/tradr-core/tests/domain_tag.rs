//! Supervisor-authored tests for domain separation, written first.
//! `DomainTag` decides what every identity-key signature is over, and
//! docs/05's defence against cross-protocol signature reuse rests on the
//! six contexts being disjoint. That was an argument in prose; these tests
//! are what make it a property. Pure, so no `KeyStore` is involved.

use tradr_core::{DomainTag, Separation};

// --- The set itself -----------------------------------------------------

#[test]
fn the_closed_set_is_the_six_contexts_docs_05_lists() {
    assert_eq!(DomainTag::ALL.len(), 6);

    for tag in [
        DomainTag::KeyBind,
        DomainTag::Hello,
        DomainTag::BrokrChallenge,
        DomainTag::Revoke,
        DomainTag::CertificateTbs,
        DomainTag::TlsCertificateVerify,
    ] {
        assert!(
            DomainTag::ALL.contains(&tag),
            "{tag:?} is a DomainTag but is missing from ALL, so every \
             property proved over ALL silently excludes it"
        );
    }
}

// --- Separation shapes --------------------------------------------------

#[test]
fn the_four_tagged_contexts_prepend_their_docs_05_byte_strings() {
    assert_eq!(
        DomainTag::KeyBind.separation(),
        Separation::Prepended(b"tradr-keybind-v1")
    );
    assert_eq!(
        DomainTag::Hello.separation(),
        Separation::Prepended(b"tradr-hello-v1")
    );
    assert_eq!(
        DomainTag::BrokrChallenge.separation(),
        Separation::Prepended(b"tradr-brokr-v1")
    );
    assert_eq!(
        DomainTag::Revoke.separation(),
        Separation::Prepended(b"tradr-revoke-v1")
    );
}

#[test]
fn a_certificate_tbs_requires_ders_sequence_byte_and_prepends_nothing() {
    assert_eq!(
        DomainTag::CertificateTbs.separation(),
        Separation::Required(&[0x30])
    );
}

#[test]
fn tls_certificate_verify_requires_rfc_8446s_own_preamble() {
    // RFC 8446 section 4.4.3: sixty-four spaces, then the context string.
    // Truncated at "TLS 1.3, " so one tag covers the client and server
    // spellings, which that specification already separates.
    let Separation::Required(required) = DomainTag::TlsCertificateVerify.separation() else {
        panic!("TlsCertificateVerify must require a prefix, never prepend one");
    };

    assert_eq!(required.len(), 64 + b"TLS 1.3, ".len());
    assert!(required[..64].iter().all(|b| *b == 0x20));
    assert_eq!(&required[64..], b"TLS 1.3, ");
}

// --- The disjointness docs/05 rests on ----------------------------------

// The bytes an attacker would have to make one context produce in order to
// replay a signature as another. Built from the tag alone, so it is what
// every implementation signs, whichever way it happens to be written.
fn signed_prefix(tag: DomainTag) -> &'static [u8] {
    match tag.separation() {
        Separation::Prepended(bytes) | Separation::Required(bytes) => bytes,
    }
}

#[test]
fn every_context_separates_on_at_least_one_byte() {
    for tag in DomainTag::ALL {
        assert!(
            !signed_prefix(*tag).is_empty(),
            "{tag:?} separates on no bytes at all, so it is not separated"
        );
    }
}

#[test]
fn one_byte_tells_a_structural_context_from_every_other_one() {
    // docs/05's table, and only what it claims: the four tagged contexts
    // share 0x74 and are told apart from each other by the whole prefix.
    // What a single byte has to settle is tagged against structural.
    let mut structural = Vec::new();

    for tag in DomainTag::ALL {
        let first = signed_prefix(*tag)[0];
        match tag.separation() {
            Separation::Prepended(_) => assert_eq!(
                first, 0x74,
                "{tag:?} prepends a string that does not begin with `tradr-`"
            ),
            Separation::Required(_) => structural.push((tag, first)),
        }
    }

    assert_eq!(structural.len(), 2, "docs/05 names two structural contexts");
    for (tag, first) in &structural {
        assert_ne!(
            *first, 0x74,
            "{tag:?} accepts a message a tagged context could have produced"
        );
    }
    assert_ne!(
        structural[0].1, structural[1].1,
        "the two structural contexts share a first byte, so one message \
         could be well formed for both"
    );
}

#[test]
fn no_contexts_separator_is_a_prefix_of_another() {
    for a in DomainTag::ALL {
        for b in DomainTag::ALL {
            if a == b {
                continue;
            }
            let (pa, pb) = (signed_prefix(*a), signed_prefix(*b));
            let shortest = pa.len().min(pb.len());
            assert_ne!(
                &pa[..shortest],
                &pb[..shortest],
                "{a:?} and {b:?} share a common separator prefix"
            );
        }
    }
}

// --- payload(): the one place the policy lives --------------------------

#[test]
fn a_prepended_tag_yields_tag_followed_by_the_message() {
    let payload = DomainTag::Hello
        .payload(b"nonce")
        .expect("a prepended tag imposes no condition on its message");

    assert_eq!(payload.as_ref(), b"tradr-hello-v1nonce");
}

#[test]
fn a_prepended_tag_accepts_an_empty_message() {
    let payload = DomainTag::Revoke
        .payload(b"")
        .expect("an empty message is still a message");

    assert_eq!(payload.as_ref(), b"tradr-revoke-v1");
}

#[test]
fn a_required_tag_yields_the_message_untouched() {
    // The certificate must be signed over exactly the bytes X.509 fixed;
    // anything added or removed here makes the signature verify against
    // nothing a peer will ever reconstruct.
    let tbs = [0x30u8, 0x82, 0x01, 0x0a, 0xff, 0x00];

    let payload = DomainTag::CertificateTbs
        .payload(&tbs)
        .expect("a DER SEQUENCE carries its own separation");

    assert_eq!(payload.as_ref(), &tbs);
}

#[test]
fn a_required_tag_refuses_a_message_lacking_its_prefix() {
    for tag in [DomainTag::CertificateTbs, DomainTag::TlsCertificateVerify] {
        assert!(
            tag.payload(b"anything at all").is_err(),
            "{tag:?} must refuse a message that does not carry its separation"
        );
        assert!(
            tag.payload(b"").is_err(),
            "{tag:?} must refuse an empty message"
        );
    }
}

#[test]
fn a_required_tag_refuses_a_message_carrying_only_part_of_its_prefix() {
    // Sixty-three spaces rather than sixty-four. A length check that
    // compares what it has rather than what it needs passes this.
    let mut nearly = vec![0x20u8; 63];
    nearly.extend_from_slice(b"TLS 1.3, server CertificateVerify");

    assert!(
        DomainTag::TlsCertificateVerify.payload(&nearly).is_err(),
        "a truncated preamble must be refused, not padded or tolerated"
    );
}

#[test]
fn a_required_tag_refuses_every_other_contexts_message() {
    // The attack docs/05 names, tried in the direction the new tags open:
    // a caller that can pick the tag must not be able to get a signature
    // over another context's bytes out of one that prepends nothing.
    for required in [DomainTag::CertificateTbs, DomainTag::TlsCertificateVerify] {
        for other in DomainTag::ALL {
            if other == &required {
                continue;
            }
            let Separation::Prepended(bytes) = other.separation() else {
                continue;
            };
            let mut message = bytes.to_vec();
            message.extend_from_slice(b"borrowed");

            assert!(
                required.payload(&message).is_err(),
                "{required:?} signed a message shaped like {other:?}"
            );
        }
    }
}

#[test]
fn a_required_tag_accepts_a_message_that_is_exactly_its_prefix() {
    // Not a useful message, but the boundary: the check is over the
    // prefix, and a message of exactly that length carries it in full.
    let Separation::Required(required) = DomainTag::TlsCertificateVerify.separation() else {
        panic!("TlsCertificateVerify must require a prefix");
    };

    let payload = DomainTag::TlsCertificateVerify
        .payload(required)
        .expect("a message equal to its own required prefix carries it");

    assert_eq!(payload.as_ref(), required);
}

#[test]
fn the_payload_of_a_required_tag_borrows_rather_than_copying() {
    // A megabyte certificate is not the case, but a signer handed a
    // borrowed message must not be the reason a copy of it exists.
    let tbs = [0x30u8; 128];

    let payload = DomainTag::CertificateTbs
        .payload(&tbs)
        .expect("a DER SEQUENCE carries its own separation");

    assert!(matches!(payload, std::borrow::Cow::Borrowed(_)));
}
