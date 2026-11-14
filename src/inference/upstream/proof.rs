//! Serialize SDK-verified facts for Ada's signed completion envelope.
use nearai_inference_sdk::{
    AttestationVerificationResult, DeploymentProvenanceStatus, GatewayTlsBinding,
    GpuEvidenceStatus, TcbStatus, VerifiedAttestationEvidence, VerifiedCompletionResult,
};
use serde_json::{Value, json};

pub(crate) struct VerifiedInference {
    pub model_id: String,
    pub origin: String,
    pub established_at: u64,
    pub completed_at: u64,
    pub tcb_up_to_date: bool,
    pub evidence: Value,
}

impl VerifiedInference {
    pub(super) fn new(
        origin: &str,
        model: String,
        preflight: &AttestationVerificationResult,
        completion: &VerifiedCompletionResult,
    ) -> Self {
        let gateway_tls = match &preflight.gateway.tls_binding {
            GatewayTlsBinding::Attested { spki_fingerprint } => {
                json!({"spki_sha256":spki_fingerprint})
            }
            GatewayTlsBinding::None => Value::Null,
        };
        Self {
            model_id: model,
            origin: origin.to_owned(),
            established_at: preflight.verified_at / 1000,
            completed_at: crate::attestation::evidence::now_secs(),
            tcb_up_to_date: std::iter::once(&preflight.gateway.evidence)
                .chain(preflight.models.iter().map(|model| &model.evidence))
                .all(|evidence| evidence.tcb_status == TcbStatus::UpToDate),
            evidence: json!({
                "schema":"ada.nearai-inference.v1",
                "basis":"sdk_verified_claims",
                "sdk_revision":"14b29f67b63b97bf63678296e095ddfcc8f5ba74",
                "image_provenance_policy": {
                    "digest":super::provenance::policy_digest(),
                    "coverage":"required_gateway_and_model_launcher_images",
                    "required_gateway_image":"nearaidev/cloud-api",
                    "required_model_image":"nearaidev/compose-manager-launcher",
                    "supporting_images_covered":false,
                    "approval":"publisher_workflow",
                    "runtime_loaded_images_covered":false,
                },
                "verified_at_ms":preflight.verified_at,
                "acceptance_policy":{
                    "tcb_policy":"nearai_sdk_default",
                    "accepted_tcb_statuses":["UpToDate", "OutOfDate"],
                    "intel_advisories":"reported_by_sdk",
                    "signing_algorithm":"ed25519",
                    "fresh_preflight_per_completion":true,
                    "maximum_preflight_age_at_dispatch_seconds":super::PREFLIGHT_TIMEOUT.as_secs(),
                    "unique_model_signers_required":false,
                    "all_model_candidates_verified":true,
                    "response_signer_policy":"nearai_sdk_selected_preflight_signer",
                    "individual_serving_instance_identified":false,
                    "os_boot_measurements_approved":false,
                    "launch_configuration_approved":false,
                },
                "gateway":{"evidence":evidence(&preflight.gateway.evidence), "tls_binding":gateway_tls},
                "models":preflight.models.iter().map(|model| json!({
                    "evidence":evidence(&model.evidence),
                    "signing_public_key":model.signing_public_key,
                    "gpu_attested":model.gpu_evidence == GpuEvidenceStatus::Verified,
                })).collect::<Vec<_>>(),
                "transport":{
                    "e2ee":true, "gateway_tls_pinned":true,
                    "same_connection_for_evidence_and_inference":false,
                },
                "completion":{
                    "id":completion.id, "signature_kind":completion.signature_kind(),
                    "signer":completion.signature.signer,
                    "signed_text":completion.signature.signed_text,
                    "signature":completion.signature.signature,
                    "covers":"exact_encrypted_request_and_response_bytes",
                    "linked_gateway_model_receipt":false,
                },
            }),
        }
    }
}

fn evidence(value: &VerifiedAttestationEvidence) -> Value {
    json!({
        "signer":value.signer, "tcb_status":value.tcb_status, "advisory_ids":value.advisory_ids,
        "app_compose":value.deployment.app_compose,
        "os_image_hash":value.deployment.runtime_measurements.os_image_hash,
        "compose_hash":value.deployment.runtime_measurements.compose_hash,
        "deployment_provenance_verified":value.deployment_provenance == DeploymentProvenanceStatus::Verified,
    })
}
