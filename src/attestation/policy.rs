//! Public, untrusted policy delivery. Acceptance is exclusively client-side.
use axum::{
    body::Body,
    http::{HeaderValue, Response, StatusCode},
};
use std::{
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const URL: &str = "https://github.com/Azel-Labs/Ada/releases/download/ada-policy/policy-envelope.json";
const MAX_BYTES: usize = 2 * 1024 * 1024;
struct Cached {
    fetched: Instant,
    bytes: Vec<u8>,
}
static CACHE: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();

async fn load() -> anyhow::Result<Vec<u8>> {
    let mut cache = CACHE.get_or_init(|| Mutex::new(None)).lock().await;
    if let Some(cached) = &*cache
        && cached.fetched.elapsed() < Duration::from_secs(30)
    {
        return Ok(cached.bytes.clone());
    }
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(3))
        .https_only(true)
        .build()?;
    let mut response = client
        .get(URL)
        .header("Accept", "application/json")
        .send()
        .await?
        .error_for_status()?;
    anyhow::ensure!(
        response
            .content_length()
            .is_none_or(|n| n <= MAX_BYTES as u64),
        "policy size limit"
    );
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        anyhow::ensure!(bytes.len() + chunk.len() <= MAX_BYTES, "policy size limit");
        bytes.extend_from_slice(&chunk);
    }
    anyhow::ensure!(!bytes.is_empty(), "empty policy");
    *cache = Some(Cached {
        fetched: Instant::now(),
        bytes: bytes.clone(),
    });
    Ok(bytes)
}

/// Fetch the public signed policy without a session, credentials or private data.
/// CORS permits any frontend to retrieve it; the signature decides acceptance.
pub async fn get() -> Response<Body> {
    let result = tokio::time::timeout(Duration::from_secs(12), load()).await;
    let (status, bytes) = match result {
        Ok(Ok(bytes)) => (StatusCode::OK, bytes),
        _ => (StatusCode::SERVICE_UNAVAILABLE, Vec::new()),
    };
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    response
}
