// SPDX-License-Identifier: BSD-3-Clause
use crate::CardError;
use ed25519_dalek::{Signature, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

pub const ENGINE_ID: &str =
    "rquickjs=0.14.0;rquickjs-core=0.14.0;rquickjs-sys=0.14.0;quickjs-ng=0.16.2;bytecode=le";
pub const HOST_ABI: u32 = 2;
pub(crate) const MAX_PACKAGE: usize = 64 * 1024;
pub(crate) const MAX_DESCRIPTOR: usize = 4096;
const DOMAIN: &[u8] = b"ramflux-card-signed-descriptor-v2\0";
/// Fixed lexicographic field order, ASCII bindings and u32 integers give canonical JSON.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageDescriptor {
    pub app_id: String,
    pub bytecode_sha256: String,
    pub catalog: String,
    pub catalog_sha256: String,
    pub engine: String,
    pub host_abi: u32,
    pub package_id: String,
    pub security_epoch: u32,
    pub version: u32,
}
/// Release-pinned host configuration. Never populate this policy from a package or peer.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AcceptancePolicy {
    pub app_id: String,
    pub package_id: String,
    pub minimum_epoch: u32,
    pub minimum_version: u32,
    pub exact_descriptor_sha256: Option<String>,
}
/// Only authenticated, policy-accepted bytes can reach the unsafe engine loader.
#[derive(Clone)]
pub struct SignedPackage {
    pub(crate) bytecode: Vec<u8>,
}
impl PackageDescriptor {
    /// Canonical descriptor bytes; signing always uses this representation.
    /// # Errors
    /// Rejects oversized/invalid descriptor identities and digests.
    pub fn canonical_bytes(&self) -> Result<Vec<u8>, CardError> {
        if !identity(&self.app_id)
            || !identity(&self.package_id)
            || !digest_string(&self.bytecode_sha256)
            || !digest_string(&self.catalog_sha256)
            || self.security_epoch == 0
            || self.version == 0
            || self.engine.len() > 256
            || self.catalog.len() > 64
        {
            return Err(CardError::Admission("descriptor fields"));
        }
        Ok(serde_json::to_vec(self)?)
    }
}
impl SignedPackage {
    /// Authenticate descriptor, engine/catalog bindings, bytes and host rollback policy.
    /// # Errors
    /// Rejects unsigned, noncanonical, obsolete, mismatched or oversized packages.
    pub fn verify(
        bytecode: &[u8],
        descriptor: &[u8],
        signature: &[u8; 64],
        trusted_key: &[u8; 32],
        policy: &AcceptancePolicy,
    ) -> Result<Self, CardError> {
        if bytecode.is_empty() || bytecode.len() > MAX_PACKAGE {
            return Err(CardError::Limit("package"));
        }
        crate::spec::preflight(descriptor, MAX_DESCRIPTOR)?;
        let parsed: PackageDescriptor = serde_json::from_slice(descriptor)?;
        if parsed.canonical_bytes()? != descriptor {
            return Err(CardError::Admission("noncanonical descriptor"));
        }
        if !identity(&policy.app_id)
            || !identity(&policy.package_id)
            || policy.minimum_epoch == 0
            || policy.minimum_version == 0
            || policy.exact_descriptor_sha256.as_ref().is_some_and(|v| !digest_string(v))
        {
            return Err(CardError::Admission("host policy"));
        }
        if parsed.app_id != policy.app_id
            || parsed.package_id != policy.package_id
            || parsed.catalog != "rf-card/v1"
            || parsed.catalog_sha256 != catalog_digest()
            || parsed.engine != ENGINE_ID
            || parsed.host_abi != HOST_ABI
        {
            return Err(CardError::Admission("package bindings"));
        }
        if (parsed.security_epoch, parsed.version) < (policy.minimum_epoch, policy.minimum_version)
        {
            return Err(CardError::Admission("release floor"));
        }
        if policy.exact_descriptor_sha256.as_ref().is_some_and(|v| *v != sha256(descriptor)) {
            return Err(CardError::Admission("exact release"));
        }
        if parsed.bytecode_sha256 != sha256(bytecode) {
            return Err(CardError::Admission("bytecode digest"));
        }
        let key = VerifyingKey::from_bytes(trusted_key).map_err(|_| CardError::Signature)?;
        key.verify_strict(&signing_message(descriptor), &Signature::from_bytes(signature))
            .map_err(|_| CardError::Signature)?;
        Ok(Self { bytecode: bytecode.to_vec() })
    }
}
pub(crate) fn signing_message(descriptor: &[u8]) -> Vec<u8> {
    let mut message = DOMAIN.to_vec();
    message.extend_from_slice(descriptor);
    message
}
#[must_use]
pub fn catalog_digest() -> String {
    sha256(include_bytes!("../catalog.json"))
}
pub(crate) fn sha256(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn digest_string(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}
fn identity(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        CardSession,
        compiler::compile_and_sign,
        runtime::tests::{artifact, fixture, guard, release},
    };
    use ed25519_dalek::{Signer, SigningKey};
    #[test]
    fn rejects_signed_old_releases_and_wrong_bindings_before_load() {
        let _guard = guard();
        let key = SigningKey::from_bytes(&[7; 32]);
        let current = artifact(include_str!("../library/form.js"));
        let mut old_release = release();
        old_release.version = 1;
        let old = compile_and_sign(include_bytes!("../library/form.js"), &key, &old_release)
            .expect("test: genuine old form package");
        let policy = release().policy();
        assert!(
            matches!(
                SignedPackage::verify(
                    &old.bytecode,
                    &old.descriptor,
                    &old.signature,
                    &old.public_key,
                    &policy
                ),
                Err(CardError::Admission("release floor"))
            ),
            "old valid signature must not bypass host floor"
        );
        let accepted = SignedPackage::verify(
            &current.bytecode,
            &current.descriptor,
            &current.signature,
            &current.public_key,
            &policy,
        )
        .expect("test: current release accepted");
        let (_session, _) =
            CardSession::open(fixture(), accepted).expect("test: current genuine form renders");
        let descriptor: PackageDescriptor =
            serde_json::from_slice(&current.descriptor).expect("test: descriptor");
        for field in ["catalog", "catalog_digest", "abi", "engine", "app", "package"] {
            let mut wrong = descriptor.clone();
            match field {
                "catalog" => wrong.catalog = "another/v1".into(),
                "catalog_digest" => wrong.catalog_sha256 = "0".repeat(64),
                "abi" => wrong.host_abi += 1,
                "engine" => wrong.engine = "different-engine".into(),
                "app" => wrong.app_id = "org.other".into(),
                _ => wrong.package_id = "other-package".into(),
            }
            let bytes = wrong.canonical_bytes().expect("test: canonical mismatched descriptor");
            let sig = key.sign(&signing_message(&bytes)).to_bytes();
            assert!(
                matches!(
                    SignedPackage::verify(
                        &current.bytecode,
                        &bytes,
                        &sig,
                        &current.public_key,
                        &policy
                    ),
                    Err(CardError::Admission("package bindings"))
                ),
                "wrong {field} must fail before loader"
            );
        }
        let mut exact = policy;
        exact.exact_descriptor_sha256 = Some(sha256(&current.descriptor));
        assert!(
            SignedPackage::verify(
                &current.bytecode,
                &current.descriptor,
                &current.signature,
                &current.public_key,
                &exact
            )
            .is_ok(),
            "host can pin one exact bundled descriptor"
        );
        exact.exact_descriptor_sha256 = Some("0".repeat(64));
        assert!(
            matches!(
                SignedPackage::verify(
                    &current.bytecode,
                    &current.descriptor,
                    &current.signature,
                    &current.public_key,
                    &exact
                ),
                Err(CardError::Admission("exact release"))
            ),
            "different release digest must fail"
        );
    }
    #[test]
    fn rejects_noncanonical_descriptor_encoding() {
        let current = artifact(include_str!("../library/form.js"));
        let mut noncanonical = current.descriptor.clone();
        noncanonical.push(b' ');
        assert!(
            matches!(
                SignedPackage::verify(
                    &current.bytecode,
                    &noncanonical,
                    &current.signature,
                    &current.public_key,
                    &release().policy()
                ),
                Err(CardError::Admission("noncanonical descriptor"))
            ),
            "alternate encodings must not enter signature admission"
        );
    }
    #[test]
    fn engine_descriptor_matches_the_locked_dependency_graph() {
        let lock = include_str!("../../../Cargo.lock");
        for name in ["rquickjs", "rquickjs-core", "rquickjs-sys"] {
            assert!(
                lock.contains(&format!("name = \"{name}\"\nversion = \"0.14.0\"")),
                "signed engine pin differs from Cargo.lock for {name}"
            );
            assert!(
                ENGINE_ID.contains(&format!("{name}=0.14.0")),
                "signed engine descriptor omits {name}"
            );
        }
    }
}
