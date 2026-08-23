//! Holds a Provider Profile's JWKS between verifications and decides when
//! a device may go fetch a fresh document. docs/05 "The token never
//! chooses how it is verified", the refetch-budget paragraphs (DCR-022).
//! No I/O: the composition root fetches, this type only decides whether
//! it may.

use std::time::Duration;

use tradr_core::Monotonic;

use crate::id_token::Jwk;
use crate::jwks::{JwksError, parse_jwks};

/// docs/05: the floor between refetches, bounding a peer sending random
/// `kid` values to twelve outbound requests an hour from each device it
/// reaches, while still picking up a legitimate rotation within one.
const REFETCH_FLOOR: Duration = Duration::from_secs(5 * 60);

/// A Provider Profile's JWKS, held between verifications. Bound to a
/// `jwks_uri` at construction so a document can never be installed into
/// the wrong provider's cache, and rate-limits refetches so an unknown
/// `kid` cannot be turned into unbounded outbound traffic by a peer.
pub struct JwksCache {
    jwks_uri: String,
    keys: Vec<Jwk>,
    last_claim: Option<Monotonic>,
}

impl JwksCache {
    /// Builds an empty cache bound to `jwks_uri`.
    pub fn new(jwks_uri: &str) -> Self {
        Self {
            jwks_uri: jwks_uri.to_string(),
            keys: Vec::new(),
            last_claim: None,
        }
    }

    /// The `jwks_uri` this cache was built with.
    pub fn jwks_uri(&self) -> &str {
        &self.jwks_uri
    }

    /// The currently cached keys.
    pub fn keys(&self) -> &[Jwk] {
        &self.keys
    }

    /// Parses `document` and replaces the cached set with the result. On
    /// any error the cached set is left exactly as it was: a refetch can
    /// only ever add to what a device can verify, never take it away, and
    /// offline verification is what keeps Tier 0 serverless.
    pub fn install(&mut self, document: &[u8]) -> Result<(), JwksError> {
        let parsed = parse_jwks(document)?;
        self.keys = parsed;
        Ok(())
    }

    /// Answers whether the caller may go fetch a fresh document because
    /// `kid` is not among the cached keys. Granting is what spends the
    /// budget, so a caller asking twice is refused the second time. The
    /// budget belongs to the whole cache, not to `kid`, or a peer sending
    /// random `kid` values would drive one outbound fetch each.
    pub fn claim_refetch_for(&mut self, kid: &str, now: Monotonic) -> bool {
        if self.keys.iter().any(|k| k.kid == kid) {
            return false;
        }
        if let Some(last) = self.last_claim
            && now.duration_since(last) < REFETCH_FLOOR
        {
            return false;
        }
        self.last_claim = Some(now);
        true
    }
}
