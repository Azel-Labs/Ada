//! Public, untrusted policy delivery. Acceptance is exclusively client-side.
use axum::{
    body::Body,
    http::{HeaderValue, Response, StatusCode},
};
use std::{
    io::Read,
    sync::OnceLock,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const RELEASE_URL: &str = "https://api.github.com/repos/Azel-Labs/Ada/releases/tags/ada-policy";
const ASSET_BASE_URL: &str = "https://api.github.com/repos/Azel-Labs/Ada/releases/assets/";
const SEED_PATH: &str = "/run/ada/policy-envelope.json";
const MAX_BYTES: usize = 2 * 1024 * 1024;
// Two API requests per refresh stay below GitHub's unauthenticated rate limit.
const REFRESH_INTERVAL: Duration = Duration::from_mins(5);

#[derive(serde::Deserialize)]
struct Release {
    assets: Vec<Asset>,
}

#[derive(serde::Deserialize)]
struct Asset {
    id: u64,
    name: String,
    state: String,
    size: u64,
}

struct Cached {
    fetched: Instant,
    bytes: Vec<u8>,
}
static CACHE: OnceLock<Mutex<Option<Cached>>> = OnceLock::new();

async fn load() -> anyhow::Result<Vec<u8>> {
    let mut cache = CACHE.get_or_init(|| Mutex::new(None)).lock().await;
    if cache.is_none() {
        let seed = tokio::task::spawn_blocking(|| -> anyhow::Result<Vec<u8>> {
            let mut bytes = Vec::new();
            std::fs::File::open(SEED_PATH)?
                .take(MAX_BYTES as u64 + 1)
                .read_to_end(&mut bytes)?;
            anyhow::ensure!(
                !bytes.is_empty() && bytes.len() <= MAX_BYTES,
                "policy seed size limit"
            );
            Ok(bytes)
        })
        .await?;
        if let Ok(bytes) = seed {
            *cache = Some(Cached {
                fetched: Instant::now() - REFRESH_INTERVAL,
                bytes,
            });
        }
    }
    if let Some(cached) = &mut *cache {
        if cached.fetched.elapsed() >= REFRESH_INTERVAL {
            // Serve the signed snapshot immediately while one refresh runs.
            // Failed refreshes keep the snapshot and wait before retrying.
            cached.fetched = Instant::now();
            tokio::spawn(async {
                match download().await {
                    Ok(bytes) => {
                        *CACHE.get().expect("policy cache initialized").lock().await =
                            Some(Cached {
                                fetched: Instant::now(),
                                bytes,
                            });
                    }
                    Err(error) => log_download_error(&error),
                }
            });
        }
        return Ok(cached.bytes.clone());
    }
    let bytes = download().await?;
    *cache = Some(Cached {
        fetched: Instant::now(),
        bytes: bytes.clone(),
    });
    Ok(bytes)
}

async fn download() -> anyhow::Result<Vec<u8>> {
    tokio::time::timeout(Duration::from_secs(10), fetch()).await?
}

async fn fetch() -> anyhow::Result<Vec<u8>> {
    let client = reqwest::Client::builder()
        .user_agent("Ada-policy-delivery")
        .timeout(Duration::from_secs(10))
        .redirect(reqwest::redirect::Policy::limited(3))
        .https_only(true)
        .build()?;
    let metadata = client
        .get(RELEASE_URL)
        .header("Accept", "application/vnd.github+json")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?
        .error_for_status()?;
    let release: Release = serde_json::from_slice(&read_bounded(metadata).await?)?;
    let mut assets = release
        .assets
        .into_iter()
        .filter(|asset| asset.name == "policy-envelope.json");
    let asset = assets
        .next()
        .ok_or_else(|| anyhow::anyhow!("policy release asset missing"))?;
    anyhow::ensure!(
        assets.next().is_none()
            && asset.id > 0
            && asset.state == "uploaded"
            && asset.size > 0
            && asset.size <= MAX_BYTES as u64,
        "invalid policy release asset"
    );
    // Build the URL from a numeric ID; never follow a metadata-supplied URL.
    let response = client
        .get(format!("{ASSET_BASE_URL}{}", asset.id))
        .header("Accept", "application/octet-stream")
        .header("X-GitHub-Api-Version", "2022-11-28")
        .send()
        .await?
        .error_for_status()?;
    let bytes = read_bounded(response).await?;
    anyhow::ensure!(
        bytes.len() as u64 == asset.size,
        "policy asset size mismatch"
    );
    // These are still untrusted bytes. The client authenticates the policy and
    // enforces expiration, release approval and rollback protection as before.
    Ok(bytes)
}

async fn read_bounded(mut response: reqwest::Response) -> anyhow::Result<Vec<u8>> {
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
    Ok(bytes)
}

/// Fetch the public signed policy without a session, credentials or private data.
/// CORS permits any frontend to retrieve it; the signature decides acceptance.
pub async fn get() -> Response<Body> {
    let result = tokio::time::timeout(Duration::from_secs(12), load()).await;
    let (status, bytes) = match result {
        Ok(Ok(bytes)) => (StatusCode::OK, bytes),
        Ok(Err(error)) => {
            log_download_error(&error);
            (StatusCode::SERVICE_UNAVAILABLE, Vec::new())
        }
        Err(_) => {
            tracing::warn!("Signed policy download timed out");
            (StatusCode::SERVICE_UNAVAILABLE, Vec::new())
        }
    };
    let mut response = Response::new(Body::from(bytes));
    *response.status_mut() = status;
    let headers = response.headers_mut();
    headers.insert("content-type", HeaderValue::from_static("application/json"));
    headers.insert("access-control-allow-origin", HeaderValue::from_static("*"));
    headers.insert("cache-control", HeaderValue::from_static("no-store"));
    response
}

fn log_download_error(error: &anyhow::Error) {
    let status = error
        .downcast_ref::<reqwest::Error>()
        .and_then(reqwest::Error::status)
        .map(|status| status.as_u16());
    tracing::warn!(upstream_status = ?status, "Signed policy refresh failed; client policy validation remains required");
}
