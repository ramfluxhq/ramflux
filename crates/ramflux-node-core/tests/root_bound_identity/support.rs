// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use ramflux_crypto::*;
use ramflux_node_core::*;
use ramflux_protocol::{
    DeviceSetStatus, PrincipalKind, SignedDeviceSetEntry, SignedDeviceSetRecord, encode_base64url,
};
pub type TestResult = Result<(), Box<dyn std::error::Error>>;
pub struct Fixture {
    pub root: IdentityRoot,
    pub device: DeviceBranch,
    pub x: X25519KeyPair,
    pub request: IdentityRegisterRequest,
}
impl Fixture {
    pub fn new() -> Result<Self, Box<dyn std::error::Error>> {
        let root = create_identity_root("alice", [11; 32]);
        let device = create_device_branch("alice", "alice-device", 1, [12; 32]);
        let x = X25519KeyPair::from_seed([14; 32]);
        let proof = authorize_device_branch_v2(
            &root,
            &device,
            BranchAuthorization {
                audience: IDENTITY_BIND_AUDIENCE,
                capability_scope: vec![IDENTITY_BIND_CAPABILITY.into()],
                issued_at: 1000,
                expires_at: 2000,
                principal_kind: PrincipalKind::HeadlessAi,
                agreement_identity_public_key: x.public,
            },
        )?;
        let keys = device_key_commitments(
            &encode_base64url(device.signing_key.verifying_key().to_bytes()),
            &encode_base64url(x.public),
        )?;
        let record = sign_device_set(
            &root,
            DeviceSetSigningInput {
                principal_kind: PrincipalKind::HeadlessAi,
                device_set_epoch: 1,
                devices: vec![SignedDeviceSetEntry {
                    device_id: device.device_id.clone(),
                    device_epoch: 1,
                    signing_key_commitment: keys.0,
                    agreement_key_commitment: keys.1,
                    status: DeviceSetStatus::Active,
                    revoked_at: None,
                }],
            },
        )?;
        let request = IdentityRegisterRequest {
            root_public_key: encode_base64url(root.signing_key.verifying_key().to_bytes()),
            principal_commitment: identity_root_commitment(&root.signing_key.verifying_key()),
            branch_public_key: encode_base64url(device.signing_key.verifying_key().to_bytes()),
            device_set: Some(record),
            proof,
            target_delivery_id: "target".into(),
            gateway_id: "gateway".into(),
            session_id: "session".into(),
            push_alias_hash: None,
            now: 1100,
            registration_pow: None,
            source_ip_hash: None,
        };
        Ok(Self { root, device, x, request })
    }
    pub fn record(
        &self,
        epoch: u64,
        status: DeviceSetStatus,
    ) -> Result<SignedDeviceSetRecord, CryptoError> {
        let mut entries =
            self.request.device_set.as_ref().map_or_else(Vec::new, |set| set.devices.clone());
        for entry in &mut entries {
            entry.status = status;
            entry.revoked_at = if status == DeviceSetStatus::Revoked { Some(1200) } else { None };
        }
        sign_device_set(
            &self.root,
            DeviceSetSigningInput {
                principal_kind: PrincipalKind::HeadlessAi,
                device_set_epoch: epoch,
                devices: entries,
            },
        )
    }
    pub fn bundle(&self) -> Result<PrekeyBundle, CryptoError> {
        create_prekey_bundle(
            &self.device,
            &self.x,
            "signed:1",
            &X25519KeyPair::from_seed([15; 32]),
            None,
            None,
        )
    }
    pub fn publish(&self, record: SignedDeviceSetRecord) -> DeviceSetPublishRequest {
        DeviceSetPublishRequest { root_public_key: self.request.root_public_key.clone(), record }
    }
}
