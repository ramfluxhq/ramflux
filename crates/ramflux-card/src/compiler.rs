// SPDX-License-Identifier: BSD-3-Clause
//! Offline release tooling, shared with real-engine tests; not an application API.
use crate::{
    AcceptancePolicy, CardError, ENGINE_ID, HOST_ABI, PackageDescriptor,
    package::{MAX_PACKAGE, catalog_digest, sha256, signing_message},
};
use ed25519_dalek::{Signer, SigningKey};
use serde::{Deserialize, Serialize};
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PackageRelease {
    pub app_id: String,
    pub package_id: String,
    pub security_epoch: u32,
    pub version: u32,
}
pub struct CompiledPackage {
    pub bytecode: Vec<u8>,
    pub descriptor: Vec<u8>,
    pub signature: [u8; 64],
    pub public_key: [u8; 32],
}
impl PackageRelease {
    #[must_use]
    pub fn policy(&self) -> AcceptancePolicy {
        AcceptancePolicy {
            app_id: self.app_id.clone(),
            package_id: self.package_id.clone(),
            minimum_epoch: self.security_epoch,
            minimum_version: self.version,
            exact_descriptor_sha256: None,
        }
    }
}
/// Compile one project-owned bundle, construct its descriptor and sign the release.
/// # Errors
/// Returns compiler, resource or descriptor errors. No untrusted source entry exists in the runtime.
pub fn compile_and_sign(
    source: &[u8],
    key: &SigningKey,
    release: &PackageRelease,
) -> Result<CompiledPackage, CardError> {
    if source.is_empty() || source.len() > MAX_PACKAGE {
        return Err(CardError::Limit("compiler source"));
    }
    let bytecode = crate::engine_compiler::compile(source, "rf-library")?;
    if bytecode.len() > MAX_PACKAGE {
        return Err(CardError::Limit("compiled package"));
    }
    let descriptor = PackageDescriptor {
        app_id: release.app_id.clone(),
        bytecode_sha256: sha256(&bytecode),
        catalog: "rf-card/v1".into(),
        catalog_sha256: catalog_digest(),
        engine: ENGINE_ID.into(),
        host_abi: HOST_ABI,
        package_id: release.package_id.clone(),
        security_epoch: release.security_epoch,
        version: release.version,
    }
    .canonical_bytes()?;
    let signature = key.sign(&signing_message(&descriptor)).to_bytes();
    Ok(CompiledPackage {
        bytecode,
        descriptor,
        signature,
        public_key: key.verifying_key().to_bytes(),
    })
}
