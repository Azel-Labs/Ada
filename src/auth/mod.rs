//! Bearer-session authentication ported from the existing backend.
use std::{
    collections::HashMap,
    sync::Arc,
    time::{Duration, Instant},
};

use axum::{
    extract::FromRequestParts,
    http::{header, request::Parts},
};
use jsonwebtoken::jwk::{AlgorithmParameters, KeyAlgorithm, KeyOperations, PublicKeyUse};
use jsonwebtoken::{
    Algorithm, DecodingKey, Validation, decode, decode_header, errors::ErrorKind, jwk::JwkSet,
};
use secrecy::ExposeSecret;
use serde::Deserialize;
use tokio::sync::RwLock;

mod config;
mod error;
use axum::{
    Router,
    extract::{Request, State},
    middleware::{self, Next},
    response::Response,
};
pub use config::AuthConfig;
pub use error::AuthError;
use futures_util::StreamExt;

const MAX_BEARER_TOKEN_BYTES: usize = 16 * 1024;
const MAX_JWKS_BYTES: usize = 1024 * 1024;
const MAX_USER_ID_BYTES: usize = 128;

#[derive(Clone)]
pub struct JwtVerifier {
    inner: Arc<VerifierInner>,
}

struct VerifierInner {
    issuer: String,
    authorized_parties: Vec<String>,
    audience: Option<String>,
    key_source: KeySource,
}

enum KeySource {
    Static(DecodingKey),
    Jwks {
        client: reqwest::Client,
        url: reqwest::Url,
        ttl: Duration,
        cache: RwLock<JwksCache>,
    },
}

struct JwksCache {
    keys: HashMap<String, DecodingKey>,
    expires_at: Instant,
    last_refresh: Option<Instant>,
}

#[derive(Debug, Deserialize)]
struct Claims {
    sub: String,
    // Clerk native sessions can omit azp because they have no browser Origin.
    azp: Option<String>,
    #[allow(dead_code)]
    sid: Option<String>,
    #[allow(dead_code)]
    exp: u64,
    #[allow(dead_code)]
    nbf: u64,
    #[allow(dead_code)]
    iss: String,
}

#[derive(Debug, Clone)]
pub struct User {
    user_id: String,
}

impl User {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.user_id
    }
}

#[derive(Debug, thiserror::Error)]
enum VerifyError {
    #[error("invalid session token")]
    Invalid,
    #[error("verification keys unavailable")]
    Unavailable(#[source] anyhow::Error),
}

impl JwtVerifier {
    /// Create a JWT verifier with a static RSA key or a bounded JWKS client.
    ///
    /// # Errors
    /// Returns an error for invalid configuration, malformed RSA keys or client initialization.
    pub fn new(config: &AuthConfig) -> anyhow::Result<Self> {
        config.validate()?;
        let key_source = if let Some(pem) = &config.jwt_key {
            let normalized = pem.expose_secret().replace("\\n", "\n");
            KeySource::Static(
                DecodingKey::from_rsa_pem(normalized.as_bytes())
                    .map_err(|error| anyhow::anyhow!("invalid AUTH_JWT_KEY: {error}"))?,
            )
        } else {
            KeySource::Jwks {
                client: reqwest::Client::builder()
                    .no_proxy()
                    .redirect(reqwest::redirect::Policy::none())
                    .connect_timeout(Duration::from_secs(5))
                    .timeout(Duration::from_secs(10))
                    .build()?,
                url: config.jwks_url.clone(),
                ttl: Duration::from_secs(config.jwks_cache_seconds),
                cache: RwLock::new(JwksCache {
                    keys: HashMap::new(),
                    expires_at: Instant::now(),
                    last_refresh: None,
                }),
            }
        };

        Ok(Self {
            inner: Arc::new(VerifierInner {
                issuer: config.issuer.clone(),
                authorized_parties: config.authorized_parties.clone(),
                audience: config.audience.clone(),
                key_source,
            }),
        })
    }

    async fn verify(&self, token: &str) -> Result<User, VerifyError> {
        if token.is_empty() || token.len() > MAX_BEARER_TOKEN_BYTES {
            return Err(VerifyError::Invalid);
        }
        let header = decode_header(token).map_err(|_| VerifyError::Invalid)?;
        if header.alg != Algorithm::RS256 {
            return Err(VerifyError::Invalid);
        }

        let key = match &self.inner.key_source {
            KeySource::Static(key) => key.clone(),
            KeySource::Jwks { .. } => {
                let kid = header.kid.as_deref().ok_or(VerifyError::Invalid)?;
                self.jwks_key(kid, false).await?
            }
        };

        let claims = match self.decode_claims(token, &key) {
            Ok(claims) => claims,
            Err(error)
                if matches!(error.kind(), ErrorKind::InvalidSignature)
                    && matches!(self.inner.key_source, KeySource::Jwks { .. }) =>
            {
                let kid = header.kid.as_deref().ok_or(VerifyError::Invalid)?;
                let refreshed = self.jwks_key(kid, true).await?;
                self.decode_claims(token, &refreshed)
                    .map_err(|_| VerifyError::Invalid)?
            }
            Err(_) => return Err(VerifyError::Invalid),
        };

        // This verifier accepts explicit Bearer tokens only, never cookies.
        // Enforce the origin allowlist whenever Clerk includes an origin claim.
        if claims.azp.as_ref().is_some_and(|azp| {
            !self
                .inner
                .authorized_parties
                .iter()
                .any(|party| party == azp)
        }) || !valid_user_id(&claims.sub)
        {
            return Err(VerifyError::Invalid);
        }

        Ok(User {
            user_id: claims.sub,
        })
    }

    fn decode_claims(
        &self,
        token: &str,
        key: &DecodingKey,
    ) -> Result<Claims, jsonwebtoken::errors::Error> {
        let mut validation = Validation::new(Algorithm::RS256);
        validation.set_issuer(&[self.inner.issuer.as_str()]);
        validation.set_required_spec_claims(&["exp", "nbf", "iss", "sub"]);
        validation.validate_nbf = true;
        validation.leeway = 5;
        if let Some(audience) = &self.inner.audience {
            validation.set_audience(&[audience.as_str()]);
        } else {
            validation.validate_aud = false;
        }
        decode::<Claims>(token, key, &validation).map(|data| data.claims)
    }

    #[expect(
        clippy::too_many_lines,
        reason = "Keep the JWKS refresh transaction and its cache lock in one scope"
    )]
    async fn jwks_key(&self, kid: &str, force_refresh: bool) -> Result<DecodingKey, VerifyError> {
        if kid.is_empty() || kid.len() > 256 {
            return Err(VerifyError::Invalid);
        }
        let KeySource::Jwks {
            client,
            url,
            ttl,
            cache,
        } = &self.inner.key_source
        else {
            return Err(VerifyError::Invalid);
        };

        if !force_refresh {
            let current = cache.read().await;
            if current.expires_at > Instant::now()
                && let Some(key) = current.keys.get(kid)
            {
                return Ok(key.clone());
            }
        }

        let mut current = cache.write().await;
        if !force_refresh
            && current.expires_at > Instant::now()
            && let Some(key) = current.keys.get(kid)
        {
            return Ok(key.clone());
        }

        // Coalesce unknown-kid and bad-signature refreshes; never serve expired keys.
        if current
            .last_refresh
            .is_some_and(|last| last.elapsed() < Duration::from_secs(5))
        {
            if current.expires_at > Instant::now() {
                return current.keys.get(kid).cloned().ok_or(VerifyError::Invalid);
            }
            return Err(VerifyError::Unavailable(anyhow::anyhow!(
                "JWKS refresh cooling down"
            )));
        }
        current.last_refresh = Some(Instant::now());
        let response = client
            .get(url.clone())
            .send()
            .await
            .and_then(reqwest::Response::error_for_status)
            .map_err(|error| VerifyError::Unavailable(error.into()))?;
        if response
            .content_length()
            .is_some_and(|length| length > MAX_JWKS_BYTES as u64)
        {
            return Err(VerifyError::Unavailable(anyhow::anyhow!(
                "JWKS response exceeds size limit"
            )));
        }
        let mut body = Vec::new();
        let mut stream = response.bytes_stream();
        while let Some(chunk) = stream.next().await {
            let chunk = chunk.map_err(|error| VerifyError::Unavailable(error.into()))?;
            if chunk.len() > MAX_JWKS_BYTES.saturating_sub(body.len()) {
                return Err(VerifyError::Unavailable(anyhow::anyhow!(
                    "JWKS response exceeds size limit"
                )));
            }
            body.extend_from_slice(&chunk);
        }
        let jwks: JwkSet = serde_json::from_slice(&body)
            .map_err(|error| VerifyError::Unavailable(error.into()))?;
        if jwks.keys.len() > 128 {
            return Err(VerifyError::Unavailable(anyhow::anyhow!(
                "too many JWKS keys"
            )));
        }
        let mut keys = HashMap::with_capacity(jwks.keys.len());
        for jwk in &jwks.keys {
            let Some(key_id) = jwk.common.key_id.as_ref() else {
                continue;
            };
            if key_id.is_empty()
                || key_id.len() > 256
                || !matches!(jwk.algorithm, AlgorithmParameters::RSA(_))
                || jwk
                    .common
                    .key_algorithm
                    .is_some_and(|alg| alg != KeyAlgorithm::RS256)
                || jwk
                    .common
                    .public_key_use
                    .as_ref()
                    .is_some_and(|usage| *usage != PublicKeyUse::Signature)
                || jwk
                    .common
                    .key_operations
                    .as_ref()
                    .is_some_and(|ops| !ops.contains(&KeyOperations::Verify))
            {
                continue;
            }
            let Ok(key) = DecodingKey::from_jwk(jwk) else {
                continue;
            };
            if keys.insert(key_id.clone(), key).is_some() {
                return Err(VerifyError::Unavailable(anyhow::anyhow!(
                    "duplicate JWKS key ID"
                )));
            }
        }
        current.keys = keys;
        current.expires_at = Instant::now() + *ttl;
        current.keys.get(kid).cloned().ok_or(VerifyError::Invalid)
    }
}

/// Protect all application routes after Oak decryption. Call once after merging routes.
pub fn protect(router: Router, verifier: JwtVerifier) -> Router {
    router.layer(middleware::from_fn_with_state(verifier, require_user))
}

async fn require_user(
    State(verifier): State<JwtVerifier>,
    mut request: Request,
    next: Next,
) -> Result<Response, AuthError> {
    let mut headers = request.headers().get_all(header::AUTHORIZATION).iter();
    let header = headers
        .next()
        .and_then(|value| value.to_str().ok())
        .ok_or(AuthError::Unauthorized)?;
    if headers.next().is_some() {
        return Err(AuthError::Unauthorized);
    }
    let (scheme, token) = header.split_once(' ').ok_or(AuthError::Unauthorized)?;
    if !scheme.eq_ignore_ascii_case("Bearer")
        || token.is_empty()
        || token.len() > MAX_BEARER_TOKEN_BYTES
        || token.bytes().any(|byte| byte.is_ascii_whitespace())
    {
        return Err(AuthError::Unauthorized);
    }
    let user = verifier.verify(token).await.map_err(|error| match error {
        VerifyError::Invalid => AuthError::Unauthorized,
        VerifyError::Unavailable(_) => {
            tracing::warn!("JWT verification keys unavailable");
            AuthError::Unavailable
        }
    })?;
    if let Some(value) = request.headers_mut().get_mut(header::AUTHORIZATION) {
        value.set_sensitive(true);
    }
    request.extensions_mut().insert(user);
    Ok(next.run(request).await)
}

/// Reuse the authenticated identity in handlers without another JWT verification.
impl<S: Send + Sync> FromRequestParts<S> for User {
    type Rejection = AuthError;
    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<User>()
            .cloned()
            .ok_or(AuthError::Unauthorized)
    }
}

fn valid_user_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= MAX_USER_ID_BYTES
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::valid_user_id;

    #[test]
    fn accepts_valid_user_ids() {
        assert!(valid_user_id("user_2abcDEF-123"));
    }

    #[test]
    fn rejects_invalid_user_ids() {
        assert!(!valid_user_id(""));
        assert!(!valid_user_id("user_123\nspoofed"));
    }
}
