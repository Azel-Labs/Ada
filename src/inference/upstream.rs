//! NEAR AI's verified, encrypted client. No alternate inference transport.
use anyhow::{Context, Result, ensure};
use eventsource_stream::Eventsource;
use futures_util::{Stream, StreamExt};
use nearai_inference_sdk::{
    AttestationVerificationResult, DeploymentProvenanceStatus, GatewayTlsBinding,
    GatewayVerificationOptions, GpuEvidenceRequirement, InferenceClient, InferenceClientOptions,
    InferenceError, ModelAttestationPolicy, ModelVerificationOptions, SigningAlgo, SigningIdentity,
    VerifiedCompletionAttestation, VerifiedCompletionResult,
};
use serde_json::Value;
use std::{
    collections::HashMap,
    pin::Pin,
    sync::{Arc, OnceLock},
    time::{Duration, Instant},
};

pub(crate) mod proof;
mod provenance;
pub(crate) use proof::VerifiedInference;

const MAX_BODY: usize = 64 * 1024 * 1024;
const PREFLIGHT_TIMEOUT: Duration = Duration::from_mins(2);
const RECEIPT_TIMEOUT: Duration = Duration::from_secs(30);

pub struct StreamResponse {
    pub status_code: u16,
    pub headers: HashMap<String, String>,
    pub body: Pin<Box<dyn Stream<Item = Result<axum::body::Bytes>> + Send>>,
}

/// Filled only after the SDK verifies the completed encrypted transcript.
pub(crate) type CompletionProof = Arc<OnceLock<VerifiedInference>>;

pub struct InferenceBackend {
    options: InferenceClientOptions,
    timeout: Duration,
    slots: Arc<tokio::sync::Semaphore>,
}

fn client_options(origin: &str, credential: String) -> Result<InferenceClientOptions> {
    let url = reqwest::Url::parse(origin)?;
    ensure!(
        url.scheme() == "https"
            && url.host_str().is_some()
            && url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none(),
        "NEARAI_BASE_URL must be an HTTPS API base URL"
    );
    ensure!(!credential.trim().is_empty(), "NEARAI_API_KEY is required");
    Ok(InferenceClientOptions {
        api_key: Some(credential),
        base_url: origin.to_owned(),
        e2ee: true,
        signing_algo: SigningAlgo::Ed25519,
        gateway_verification: GatewayVerificationOptions {
            deployment: Some(Arc::new(provenance::ApprovedDeployment::gateway())),
            include_spki_fingerprint: true,
            ..Default::default()
        },
        model_verification: ModelVerificationOptions {
            deployment: Some(Arc::new(provenance::ApprovedDeployment::model())),
            policy: Some(ModelAttestationPolicy {
                gpu_evidence: GpuEvidenceRequirement::Required,
                ..Default::default()
            }),
            ..Default::default()
        },
        // Each completion owns a fresh client. This cache only joins verify()
        // to send() for that one request; no evidence is reused across requests.
        attestation_cache_ttl: PREFLIGHT_TIMEOUT,
        response_cache_ttl: Duration::from_mins(2),
        max_response_bytes: MAX_BODY,
        max_receipt_cache_bytes: 256 * 1024 * 1024,
        max_cache_entries: 128,
        ..Default::default()
    })
}

impl InferenceBackend {
    /// Construct the SDK client without contacting the provider during boot.
    /// # Errors
    /// Rejects an insecure endpoint, empty credential or invalid SDK configuration.
    pub fn new(origin: &str, credential: String, timeout: Duration) -> Result<Self> {
        let options = client_options(origin, credential)?;
        InferenceClient::with_options(options.clone()).map_err(sdk_error)?;
        Ok(Self {
            options,
            timeout,
            slots: Arc::new(tokio::sync::Semaphore::new(8)),
        })
    }

    async fn send(
        &self,
        body: &[u8],
        streaming: bool,
    ) -> Result<(
        nearai_inference_sdk::InferenceResponse,
        AttestationVerificationResult,
        String,
        InferenceClient,
    )> {
        let request = request_body(body, streaming)?;
        let model = request["model"]
            .as_str()
            .context("model required")?
            .to_owned();
        let client = InferenceClient::with_options(self.options.clone()).map_err(sdk_error)?;
        let mut request = client.chat_request(request).map_err(sdk_error)?;
        *request.timeout_mut() = Some(self.timeout);
        // Nonces are generated after this point. Bound their age at dispatch
        // with a monotonic clock, rather than a timestamp supplied by the peer.
        let preflight_started = Instant::now();
        let attestation = tokio::time::timeout(PREFLIGHT_TIMEOUT, client.verify(&model))
            .await
            .context("NEAR attestation deadline exceeded")?
            .map_err(sdk_error)?;
        // Require the SDK's verified match with the actual TLS evidence peer.
        ensure!(
            matches!(
                attestation.gateway.tls_binding,
                GatewayTlsBinding::Attested { .. }
            ),
            "NEAR gateway omitted attested TLS binding"
        );
        ensure!(
            !attestation.models.is_empty(),
            "NEAR model attestation required"
        );
        // The pinned SDK applies its default TCB policy (UpToDate or OutOfDate).
        // Preserve its verified status/advisories in the completion evidence.
        for evidence in std::iter::once(&attestation.gateway.evidence)
            .chain(attestation.models.iter().map(|model| &model.evidence))
        {
            ensure!(
                evidence.signer.signing_algo == SigningAlgo::Ed25519,
                "NEAR signer algorithm rejected"
            );
        }
        ensure!(
            attestation.gateway.evidence.deployment_provenance
                == DeploymentProvenanceStatus::Verified
                && attestation
                    .models
                    .iter()
                    .all(|model| model.evidence.deployment_provenance
                        == DeploymentProvenanceStatus::Verified),
            "NEAR software provenance required"
        );
        // NEAR replicas may share a model key. The SDK verifies every candidate,
        // pins the selected key for E2EE and verifies the response's signer.
        // A shared signer does not identify one particular serving instance.
        ensure!(
            preflight_started.elapsed() < PREFLIGHT_TIMEOUT,
            "NEAR evidence expired before inference dispatch"
        );
        let response = tokio::time::timeout(self.timeout, client.send(request))
            .await
            .context("NEAR request deadline exceeded")?
            .map_err(sdk_error)?;
        ensure!(
            response.status.is_success(),
            "NEAR inference returned HTTP {}",
            response.status.as_u16()
        );
        Ok((response, attestation, model, client))
    }

    pub(crate) async fn stream(&self, body: &[u8]) -> Result<(StreamResponse, CompletionProof)> {
        let permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .context("inference transport busy")?;
        let (response, attestation, model, client) = self.send(body, true).await?;
        ensure!(
            response
                .headers
                .get("content-type")
                .and_then(|v| v.to_str().ok())
                .and_then(|v| v.split(';').next())
                .is_some_and(|v| v.trim().eq_ignore_ascii_case("text/event-stream")),
            "NEAR inference did not return SSE"
        );
        let proof = Arc::new(OnceLock::new());
        let completed = proof.clone();
        let origin = client.base_url().to_owned();
        let verify = move |id: String| async move {
            let _permit = permit;
            let result = verified_response(&client, &id).await?;
            matches_preflight(&attestation, &result)?;
            let verified = VerifiedInference::new(&origin, model, &attestation, &result);
            completed
                .set(verified)
                .map_err(|_| anyhow::anyhow!("duplicate completion proof"))
        };
        Ok((
            StreamResponse {
                status_code: response.status.as_u16(),
                headers: HashMap::from([("content-type".into(), "text/event-stream".into())]),
                body: authenticated_stream(response.body, self.timeout, verify),
            },
            proof,
        ))
    }

    pub(crate) async fn complete(&self, body: &[u8]) -> Result<Value> {
        let _permit = self
            .slots
            .clone()
            .try_acquire_owned()
            .context("inference transport busy")?;
        let (response, attestation, _, client) = self.send(body, false).await?;
        let bytes = tokio::time::timeout(self.timeout, response.bytes())
            .await
            .context("NEAR response deadline exceeded")?
            .map_err(sdk_error)?;
        ensure!(bytes.len() <= 1024 * 1024, "vision response exceeds limit");
        let value: Value = serde_json::from_slice(&bytes)?;
        let id = value["id"]
            .as_str()
            .filter(|id| !id.is_empty())
            .context("completion ID missing")?;
        let result = verified_response(&client, id).await?;
        matches_preflight(&attestation, &result)?;
        Ok(value)
    }
}

fn request_body(body: &[u8], streaming: bool) -> Result<Value> {
    ensure!(body.len() <= MAX_BODY, "inference request exceeds limit");
    let value: Value = serde_json::from_slice(body)?;
    ensure!(value.is_object(), "inference body must be an object");
    ensure!(
        value["model"]
            .as_str()
            .is_some_and(|v| !v.is_empty() && v.len() <= 512),
        "model required"
    );
    ensure!(
        value["stream"].as_bool() == Some(streaming),
        "unexpected inference stream mode"
    );
    // Routing belongs to the SDK; do not forward old Phala provider overrides.
    ensure!(
        value.get("provider").is_none(),
        "provider overrides are unsupported"
    );
    Ok(value)
}

fn signer_identity(signer: &SigningIdentity) -> (String, String) {
    let address = signer.signing_address.to_ascii_lowercase();
    (
        signer.signing_algo.to_string(),
        address.strip_prefix("0x").unwrap_or(&address).to_owned(),
    )
}

fn matches_preflight(
    preflight: &AttestationVerificationResult,
    result: &VerifiedCompletionResult,
) -> Result<()> {
    let matches = match &result.attestation {
        VerifiedCompletionAttestation::Gateway(gateway) => gateway == &preflight.gateway,
        VerifiedCompletionAttestation::Model(model) => {
            preflight.models.contains(model)
                && signer_identity(&model.evidence.signer)
                    == signer_identity(&result.signature.signer)
        }
        VerifiedCompletionAttestation::Direct(_) => false,
    };
    ensure!(
        matches,
        "completion evidence differs from verified preflight"
    );
    Ok(())
}

async fn verified_response(client: &InferenceClient, id: &str) -> Result<VerifiedCompletionResult> {
    tokio::time::timeout(RECEIPT_TIMEOUT, async {
        for attempt in 0..3 {
            match client.verify_response(id).await {
                Ok(result) => return Ok(result),
                Err(error) if error.retryable() && attempt < 2 => {
                    tokio::time::sleep(Duration::from_millis(250 * (attempt + 1))).await;
                }
                Err(error) => return Err(sdk_error(error)),
            }
        }
        unreachable!("bounded signature retries return")
    })
    .await
    .context("NEAR signature verification deadline exceeded")?
}

#[allow(
    clippy::needless_pass_by_value,
    reason = "map_err consumes and redacts the SDK error"
)]
fn sdk_error(error: InferenceError) -> anyhow::Error {
    // Never expose provider error bodies, request URLs or prompt contents.
    if let InferenceError::Verification(
        nearai_inference_sdk::VerificationError::TcbStatusNotAllowed {
            actual,
            accepted,
            advisory_ids,
        },
    ) = &error
    {
        return anyhow::anyhow!(
            "NEAR inference failed ({}; actual {actual:?}; accepted {accepted:?}; Intel advisories {advisory_ids:?})",
            error.code()
        );
    }
    if let InferenceError::Api(nearai_inference_sdk::ApiError::HttpStatus { resource, status }) =
        &error
    {
        return anyhow::anyhow!(
            "NEAR inference failed ({}; {resource}; HTTP {status})",
            error.code()
        );
    }
    anyhow::anyhow!("NEAR inference failed ({})", error.code())
}

fn authenticated_stream<F, Fut>(
    body: nearai_inference_sdk::ByteStream,
    timeout: Duration,
    verify: F,
) -> Pin<Box<dyn Stream<Item = Result<axum::body::Bytes>> + Send>>
where
    F: FnOnce(String) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = Result<()>> + Send,
{
    fn check(condition: bool, message: &'static str) -> Result<()> {
        ensure!(condition, message);
        Ok(())
    }

    Box::pin(async_stream::try_stream! {
        let mut events = body.eventsource();
        let deadline = tokio::time::Instant::now() + timeout;
        let mut id: Option<String> = None;
        let mut done = false;
        let mut total = 0usize;
        while let Some(event) = tokio::time::timeout_at(deadline, events.next()).await
            .context("NEAR stream deadline exceeded")? {
            let event = event.map_err(|_| anyhow::anyhow!("NEAR encrypted stream failed"))?;
            check(event.event.is_empty() || event.event == "message", "unexpected inference event")?;
            check(!done, "inference data after completion marker")?;
            if event.data.trim() == "[DONE]" { done = true; continue; }
            total = total.checked_add(event.data.len()).context("response exceeds limit")?;
            check(total <= MAX_BODY, "response exceeds limit")?;
            let value: Value = serde_json::from_str(&event.data).context("invalid inference event")?;
            check(value.get("error").is_none(), "inference stream failed")?;
            if let Some(current) = value.get("id").and_then(Value::as_str) {
                check(!current.is_empty() && current.len() <= 512, "invalid completion ID")?;
                check(id.as_ref().is_none_or(|id| id == current), "completion ID changed")?;
                id = Some(current.to_owned());
            }
            yield axum::body::Bytes::from(format!("data: {value}\n\n"));
        }
        // Receipt registration happens at EOF, after the SDK's last yielded chunk.
        check(done, "inference stream truncated")?;
        verify(id.context("completion ID missing")?).await?;
        yield axum::body::Bytes::from_static(b"data: [DONE]\n\n");
    })
}

// Also used by usage accounting, with its own credential and HTTP client.
pub(crate) async fn bounded_body(response: reqwest::Response, limit: usize) -> Result<Vec<u8>> {
    let mut body = response.bytes_stream();
    let mut bytes = Vec::new();
    while let Some(chunk) = body.next().await {
        let chunk = chunk?;
        ensure!(
            chunk.len() <= limit.saturating_sub(bytes.len()),
            "response exceeds limit"
        );
        bytes.extend_from_slice(&chunk);
    }
    Ok(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};

    const CHUNK: &[u8] = b"data: {\"id\":\"chat-1\",\"choices\":[]}\n\n";
    const DONE: &[u8] = b"data: [DONE]\n\n";

    #[tokio::test]
    async fn terminal_marker_waits_for_sdk_eof_and_signature() {
        let eof = Arc::new(AtomicBool::new(false));
        let observed = eof.clone();
        let body = Box::pin(async_stream::stream! {
            yield Ok(axum::body::Bytes::from_static(CHUNK));
            yield Ok(axum::body::Bytes::from_static(DONE));
            observed.store(true, Ordering::SeqCst);
        });
        let (finish, wait) = tokio::sync::oneshot::channel();
        let mut stream = authenticated_stream(body, Duration::from_secs(1), move |id| async move {
            assert_eq!(id, "chat-1");
            assert!(eof.load(Ordering::SeqCst));
            wait.await?;
            Ok(())
        });
        assert!(!stream.next().await.unwrap().unwrap().ends_with(DONE));
        assert!(
            tokio::time::timeout(Duration::from_millis(10), stream.next())
                .await
                .is_err()
        );
        finish.send(()).unwrap();
        assert_eq!(stream.next().await.unwrap().unwrap().as_ref(), DONE);
        assert!(stream.next().await.is_none());
    }

    #[tokio::test]
    async fn invalid_signature_or_truncated_body_never_completes() {
        for suffix in [
            Some(Ok(axum::body::Bytes::from_static(DONE))),
            None,
            Some(Err(InferenceError::Api(
                nearai_inference_sdk::ApiError::CompletionNotFound,
            ))),
        ] {
            let body = Box::pin(futures_util::stream::iter(
                std::iter::once(Ok(axum::body::Bytes::from_static(CHUNK))).chain(suffix),
            ));
            let mut stream = authenticated_stream(body, Duration::from_secs(1), |_| async {
                anyhow::bail!("invalid signature")
            });
            let mut failed = false;
            while let Some(result) = stream.next().await {
                match result {
                    Ok(bytes) => assert!(!bytes.ends_with(DONE)),
                    Err(_) => failed = true,
                }
            }
            assert!(failed);
        }
    }

    #[tokio::test]
    async fn completion_id_changes_are_rejected_before_receipt_fetch() {
        let body = Box::pin(futures_util::stream::iter([
            Ok(axum::body::Bytes::from_static(CHUNK)),
            Ok(axum::body::Bytes::from_static(
                b"data: {\"id\":\"chat-2\",\"choices\":[]}\n\n",
            )),
            Ok(axum::body::Bytes::from_static(DONE)),
        ]));
        let mut stream = authenticated_stream(body, Duration::from_secs(1), |_| async {
            panic!("must reject before receipt fetch")
        });
        assert!(stream.next().await.unwrap().is_ok());
        assert!(stream.next().await.unwrap().is_err());
        assert!(stream.next().await.is_none());
    }

    #[test]
    fn provider_security_is_mandatory() {
        assert!(client_options("http://cloud-api.near.ai/v1", "test".into()).is_err());
        let options = client_options("https://cloud-api.near.ai/v1", "test".into()).unwrap();
        assert!(options.e2ee && options.gateway_verification.include_spki_fingerprint);
        assert!(options.gateway_verification.deployment.is_some());
        assert!(options.model_verification.deployment.is_some());
        assert!(options.gateway_verification.policy.is_none());
        let model = options.model_verification.policy.unwrap();
        assert!(model.accepted_tcb_statuses.is_none());
        assert_eq!(model.gpu_evidence, GpuEvidenceRequirement::Required);
        assert!(
            request_body(
                br#"{"model":"a","stream":true,"provider":{"aci_verified":false}}"#,
                true
            )
            .is_err()
        );
    }
}
