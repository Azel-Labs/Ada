//! Authenticate the required gateway or model-launcher image against its NEAR publisher.
//! Provider releases may change; repository/workflow/issuer policy may not.
use async_trait::async_trait;
use nearai_inference_sdk::{
    DeploymentVerifier, ImageProvenancePolicy, MeasuredDeployment, VerificationError,
    fetch_image_provenance, verify_image_provenance,
};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    sync::LazyLock,
    time::{Duration, Instant},
};
use tokio::sync::Mutex;

const POLICY: &str = include_str!("nearai-publishers.json");
const GATEWAY: &str = "nearaidev/cloud-api";
const MODEL: &str = "nearaidev/compose-manager-launcher";
const CACHE_TTL: Duration = Duration::from_hours(1);
const CACHE_LIMIT: usize = 128;

static POLICIES: LazyLock<BTreeMap<String, ImageProvenancePolicy>> = LazyLock::new(|| {
    serde_json::from_str(POLICY).expect("compiled NEAR publisher policy must be valid")
});
type Image = (String, String);
static VERIFIED: LazyLock<Mutex<BTreeMap<Image, Instant>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

pub(super) fn policy_digest() -> String {
    format!("sha256:{}", hex::encode(Sha256::digest(POLICY.as_bytes())))
}

pub(super) struct ApprovedDeployment {
    required_image: &'static str,
}

impl ApprovedDeployment {
    pub(super) const fn gateway() -> Self {
        Self {
            required_image: GATEWAY,
        }
    }

    pub(super) const fn model() -> Self {
        Self {
            required_image: MODEL,
        }
    }

    // The SDK has already authenticated the original app_compose bytes. Parsing
    // them here selects images; it must not replace the SDK's measurement check.
    fn check_images(&self, app_compose: &str) -> Result<BTreeSet<Image>, VerificationError> {
        require(app_compose.len() <= 1024 * 1024)?;
        let app: serde_json::Value = serde_json::from_str(app_compose).map_err(rejected)?;
        let compose = app["docker_compose_file"].as_str().ok_or_else(rejection)?;
        let mut value: serde_yaml_ng::Value = serde_yaml_ng::from_str(compose).map_err(rejected)?;
        value.apply_merge().map_err(rejected)?;
        require(value.is_mapping() && value.get("include").is_none())?;
        let services = value
            .get("services")
            .and_then(serde_yaml_ng::Value::as_mapping)
            .ok_or_else(rejection)?;
        require(!services.is_empty() && services.len() <= 64)?;
        let mut required_present = false;
        let mut images = BTreeSet::new();
        for (name, service) in services {
            require(name.as_str().is_some() && service.is_mapping())?;
            let image = service
                .get("image")
                .and_then(serde_yaml_ng::Value::as_str)
                .ok_or_else(rejection)?;
            // Only literal references can establish the required image's identity.
            // Supporting services and variable defaults are outside this build-proof scope.
            if image.contains('$') {
                continue;
            }
            let image = image.strip_prefix("docker.io/").unwrap_or(image);
            let (name, digest) = image.split_once('@').unwrap_or((image, ""));
            // A tag alongside a digest is only a label. The exact digest is mandatory.
            let repository = name
                .split_once(':')
                .map_or(name, |(repository, _)| repository);
            if repository != self.required_image {
                continue;
            }
            require(service.get("build").is_none() && service.get("extends").is_none())?;
            let hash = digest.strip_prefix("sha256:").ok_or_else(rejection)?;
            require(
                hash.len() == 64
                    && hash
                        .bytes()
                        .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                    && POLICIES.contains_key(repository),
            )?;
            required_present |= repository == self.required_image;
            images.insert((repository.to_owned(), digest.to_owned()));
        }
        require(required_present)?;
        Ok(images)
    }
}

#[async_trait]
impl DeploymentVerifier for ApprovedDeployment {
    async fn verify(&self, deployment: &MeasuredDeployment) -> Result<(), VerificationError> {
        for (repository, digest) in self.check_images(&deployment.app_compose)? {
            verify_image(&repository, &digest).await?;
        }
        Ok(())
    }
}

async fn verify_image(repository: &str, digest: &str) -> Result<(), VerificationError> {
    let policy = POLICIES.get(repository).ok_or_else(rejection)?;
    let key = (repository.to_owned(), digest.to_owned());
    // Serialize misses to coalesce repeated gateway/model candidates. Fresh quote
    // verification still occurs in the SDK; only successful build proofs cache.
    let mut cache = VERIFIED.lock().await;
    cache.retain(|_, verified_at| verified_at.elapsed() < CACHE_TTL);
    if cache.contains_key(&key) {
        return Ok(());
    }
    let signed_digest = signed_image_digest(repository, digest)?;
    tokio::time::timeout(Duration::from_secs(30), async {
        let bundles = fetch_image_provenance(&policy.repository, &signed_digest, None)
            .await
            .map_err(|source| VerificationError::ImageProvenanceRequestFailed {
                image_repository: repository.to_owned(),
                digest: digest.to_owned(),
                source: Box::new(source),
            })?;
        verify_image_provenance(&bundles, &signed_digest, policy).await
    })
    .await
    .map_err(rejected)??;
    if cache.len() >= CACHE_LIMIT {
        let oldest = cache
            .iter()
            .min_by_key(|(_, time)| **time)
            .map(|(key, _)| key.clone());
        if let Some(oldest) = oldest {
            cache.remove(&oldest);
        }
    }
    cache.insert(key, Instant::now());
    Ok(())
}

// NEAR's production launcher is pinned to a platform manifest, while its
// GitHub build proof signs the containing OCI index. These are original index
// bytes from the registry, not an approval: its computed digest must still pass
// the SDK's Sigstore verification with the existing publisher policy.
const LAUNCHER_INDEX: &[u8] = include_bytes!("nearai-launcher-index.json");

fn signed_image_digest(repository: &str, digest: &str) -> Result<String, VerificationError> {
    if repository != MODEL {
        return Ok(digest.to_owned());
    }
    let index: serde_json::Value = serde_json::from_slice(LAUNCHER_INDEX).map_err(rejected)?;
    require(index["schemaVersion"] == 2)?;
    require(index["mediaType"] == "application/vnd.oci.image.index.v1+json")?;
    let manifests = index["manifests"].as_array().ok_or_else(rejection)?;
    if manifests.iter().any(|manifest| {
        manifest["digest"].as_str() == Some(digest)
            && manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
            && manifest["platform"]["os"] == "linux"
            && manifest["platform"]["architecture"] == "amd64"
    }) {
        return Ok(format!(
            "sha256:{}",
            hex::encode(Sha256::digest(LAUNCHER_INDEX))
        ));
    }
    Ok(digest.to_owned())
}

fn rejection() -> VerificationError {
    VerificationError::DeploymentProvenanceRejected
}

fn rejected<T>(_: T) -> VerificationError {
    rejection()
}

fn require(condition: bool) -> Result<(), VerificationError> {
    if condition { Ok(()) } else { Err(rejection()) }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn launcher_child_requires_the_signed_parent_index() {
        let child = "sha256:079a14b41deb11e0e27f9b69648e8b3d89bd6fb9ccf6071643b8f447fa415085";
        assert_eq!(
            signed_image_digest(MODEL, child).unwrap(),
            "sha256:91fdff3cfa3543d72656b2368c7d8a0a83d95a0f1087378c897aa1537acdba56"
        );
        assert_eq!(signed_image_digest(GATEWAY, child).unwrap(), child);
        let other = "sha256:0000000000000000000000000000000000000000000000000000000000000000";
        assert_eq!(signed_image_digest(MODEL, other).unwrap(), other);
        let evidence = "sha256:c3e4bbb110835c63ed355bba05b9dbd6b127f44d1b509c32025f79c6a622e1f2";
        assert_eq!(signed_image_digest(MODEL, evidence).unwrap(), evidence);
    }

    #[derive(serde::Deserialize)]
    struct PublishedBuild {
        image: String,
        digest: String,
        bundle: serde_json::Value,
    }

    fn fixtures() -> Vec<PublishedBuild> {
        serde_json::from_str(include_str!("testdata/nearai-provenance.json")).unwrap()
    }

    fn measured(compose: &str) -> MeasuredDeployment {
        MeasuredDeployment {
            app_compose: serde_json::json!({"docker_compose_file":compose}).to_string(),
            runtime_measurements: Default::default(),
        }
    }

    #[tokio::test]
    async fn published_versions_verify_without_release_pins() {
        // Real public production bundles exercise the SDK's complete signature,
        // certificate, transparency-log, digest and source-identity verification.
        let mut gateway_commits = BTreeSet::new();
        for build in fixtures() {
            let policy = &POLICIES[&build.image];
            assert!(policy.commit.is_none());
            let verified =
                verify_image_provenance(&[build.bundle.to_string()], &build.digest, policy)
                    .await
                    .unwrap();
            let verifier = match build.image.as_str() {
                GATEWAY => {
                    gateway_commits.insert(verified.commit);
                    ApprovedDeployment::gateway()
                }
                MODEL => ApprovedDeployment::model(),
                _ => continue,
            };
            let compose = format!(
                "services:\n  app:\n    image: docker.io/{}:prod@{}\n",
                build.image, build.digest
            );
            assert!(
                verifier
                    .check_images(&measured(&compose).app_compose)
                    .unwrap()
                    .contains(&(build.image, build.digest))
            );
        }
        assert_eq!(
            gateway_commits.len(),
            2,
            "different signed source commits must pass"
        );
    }

    #[test]
    fn rejects_unknown_unpinned_or_incomplete_deployments() {
        let builds = fixtures();
        let gateway = builds.iter().find(|b| b.image == GATEWAY).unwrap();
        let accepted = format!(
            "services:\n  app:\n    image: {}@{}\n",
            gateway.image, gateway.digest
        );
        let verifier = ApprovedDeployment::gateway();
        for compose in [
            "services: {}".to_owned(),
            "services:\n  app:\n    build: .\n".to_owned(),
            "services:\n  app:\n    image: nearaidev/cloud-api:prod\n".to_owned(),
            format!(
                "services:\n  app:\n    image: attacker/cloud-api@{}\n",
                gateway.digest
            ),
            accepted.replace(&gateway.digest, "sha256:1234"),
            accepted.replace(&gateway.digest, &format!("sha256:{}", "g".repeat(64))),
            format!("{accepted}include: another-compose.yml\n"),
            accepted.replace("image:", "extends: unknown\n    image:"),
            accepted.replace("nearaidev/cloud-api", "${IMAGE:-nearaidev/cloud-api}"),
        ] {
            assert!(
                verifier
                    .check_images(&measured(&compose).app_compose)
                    .is_err()
            );
        }
        // Other containers and unresolved defaults do not receive build approval.
        let supporting = format!(
            "{accepted}  sidecar:\n    image: alpine:latest\n  manager:\n    image: ${{MANAGER_IMAGE:-example/manager:latest}}\n"
        );
        assert_eq!(
            verifier
                .check_images(&measured(&supporting).app_compose)
                .unwrap(),
            BTreeSet::from([(gateway.image.clone(), gateway.digest.clone())])
        );
        // A new digest can be selected, but is never approved without its signed proof.
        assert!(
            verifier
                .check_images(
                    &measured(
                        &accepted.replace(&gateway.digest, &format!("sha256:{}", "0".repeat(64)),)
                    )
                    .app_compose
                )
                .is_ok()
        );
        // An approved gateway build is not an approved model deployment.
        assert!(
            ApprovedDeployment::model()
                .check_images(&measured(&accepted).app_compose)
                .is_err()
        );
    }

    #[tokio::test]
    async fn rejects_changed_signature_digest_and_source() {
        let builds = fixtures();
        let build = &builds[0];
        let bundles = [build.bundle.to_string()];
        let policy = &POLICIES[&build.image];
        for field in ["repository", "workflow", "ref", "issuer"] {
            let mut wrong_source = policy.clone();
            match field {
                "repository" => wrong_source.repository = "attacker/cloud-api".to_owned(),
                "workflow" => wrong_source.workflow = ".github/workflows/other.yml".to_owned(),
                "ref" => wrong_source.git_ref = Some("refs/heads/untrusted".to_owned()),
                _ => wrong_source.issuer = "https://attacker.invalid".to_owned(),
            }
            assert!(
                verify_image_provenance(&bundles, &build.digest, &wrong_source)
                    .await
                    .is_err(),
                "must reject changed {field}"
            );
        }
        assert!(
            verify_image_provenance(&bundles, &format!("sha256:{}", "0".repeat(64)), policy)
                .await
                .is_err()
        );
        let mut tampered = build.bundle.clone();
        tampered["dsseEnvelope"]["signatures"][0]["sig"] = serde_json::json!("AAAA");
        assert!(
            verify_image_provenance(&[tampered.to_string()], &build.digest, policy)
                .await
                .is_err()
        );
    }
}
