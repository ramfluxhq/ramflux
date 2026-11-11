// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Durable public discovery evidence, indexed by hash/key instead of rewriting history.
use crate::SdkError;
use ramflux_crypto::custody::{NodeKeyBinding, VerifiedNodeRecord, verify_node_identity_record};
use ramflux_protocol::custody::{Envelope, NodeIdentityRecord};
use std::{
    fs,
    io::{Read, Write},
    path::{Path, PathBuf},
};

#[derive(Clone)]
pub(super) struct NodePins {
    root: PathBuf,
    node_id: String,
    public: String,
}
fn invalid() -> SdkError {
    SdkError::CustodySetupInvalid
}
fn read<T: for<'de> serde::Deserialize<'de> + serde::Serialize>(
    path: &Path,
    limit: usize,
) -> Result<T, SdkError> {
    let mut bytes = Vec::new();
    fs::File::open(path)?.take((limit + 1) as u64).read_to_end(&mut bytes)?;
    Ok(ramflux_protocol::custody::decode(&bytes, limit)?)
}
fn create(path: &Path, bytes: &[u8]) -> Result<(), SdkError> {
    match crate::platform::fs::create_new_owner_only_io(path) {
        Ok(mut file) => {
            file.write_all(bytes)?;
            file.sync_all()?;
            Ok(())
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
            if fs::read(path)? != bytes {
                return Err(invalid());
            }
            Ok(())
        }
        Err(e) => Err(e.into()),
    }
}
impl NodePins {
    pub(super) fn new(root: &Path, node_id: &str, public: &str) -> Result<Self, SdkError> {
        let id = ramflux_crypto::blake3_256_base64url(
            "ramflux.identity.node_pin_path.v1",
            node_id.as_bytes(),
        );
        let root = root.join("custody_network").join(id);
        fs::create_dir_all(&root)?;
        for name in ["history", "keys", "publics"] {
            fs::create_dir_all(root.join(name))?;
        }
        Ok(Self { root, node_id: node_id.into(), public: public.into() })
    }
    pub(super) fn current_hash(&self) -> Result<Option<String>, SdkError> {
        let _lock = self.lock()?;
        let head = self.root.join("head.json");
        if head.try_exists()? { Ok(Some(read(&head, 1024)?)) } else { Ok(None) }
    }
    pub(super) fn observe(
        &self,
        record: &Envelope<NodeIdentityRecord>,
        now: u64,
    ) -> Result<VerifiedNodeRecord, SdkError> {
        let next = verify_node_identity_record(record, &self.node_id, &self.public, now)?;
        let _lock = self.lock()?;
        let mut known = std::collections::BTreeMap::new();
        let mut publics = std::collections::BTreeMap::new();
        let entries: Vec<_> = next.key_bindings().collect();
        for (id, binding) in &entries {
            let public = &binding.public_key;
            let path = self.root.join("keys").join(id);
            if path.try_exists()? {
                known.insert((*id).to_owned(), read::<NodeKeyBinding>(&path, 4096)?);
            }
            let path = self.root.join("publics").join(public);
            if path.try_exists()? {
                publics.insert((*public).clone(), read::<String>(&path, 1024)?);
            }
        }
        let head = self.root.join("head.json");
        if head.try_exists()? {
            let hash: String = read(&head, 1024)?;
            let old = self.history(&hash, now)?;
            old.verify_successor(&next, |id| known.get(id).cloned(), |p| publics.get(p).cloned())?;
        }
        create(
            &self.root.join("history").join(next.hash()),
            &ramflux_protocol::canonical_json_bytes(record)?,
        )?;
        for (id, binding) in entries {
            let public = &binding.public_key;
            create(&self.root.join("keys").join(id), &serde_json::to_vec(&binding)?)?;
            create(&self.root.join("publics").join(public), &serde_json::to_vec(&id)?)?;
        }
        let temp = self.root.join(format!(
            ".head-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        create(&temp, &serde_json::to_vec(next.hash())?)?;
        fs::rename(temp, head)?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(next)
    }
    fn history(&self, hash: &str, now: u64) -> Result<VerifiedNodeRecord, SdkError> {
        let bytes = ramflux_protocol::decode_base64url(hash).map_err(|_| invalid())?;
        if bytes.len() != 32 || ramflux_protocol::encode_base64url(bytes) != hash {
            return Err(invalid());
        }
        let record: Envelope<NodeIdentityRecord> =
            read(&self.root.join("history").join(hash), 512 * 1024)?;
        let record = verify_node_identity_record(&record, &self.node_id, &self.public, now)?;
        if record.hash() != hash {
            return Err(invalid());
        }
        Ok(record)
    }
    fn lock(&self) -> Result<fs::File, SdkError> {
        let lock = crate::platform::fs::open_owner_only_read_write(&self.root.join(".pins.lock"))?;
        crate::platform::fs::lock_exclusive(&lock)?;
        Ok(lock)
    }
}

impl NodePins {
    pub(super) fn observe_peer(
        &self,
        publication: &ramflux_protocol::custody::Publication,
        device: &ramflux_protocol::custody::DeviceRef,
        bundle: &serde_json::Value,
        custodian: Option<&ramflux_protocol::custody::Publication>,
        now: u64,
    ) -> Result<(), SdkError> {
        let verified = verify_authority(publication, custodian, now)?;
        // Verified native forks are security evidence in their own right. Attempt to persist both
        // native fences before checking device authorization or accompanying bundle material,
        // all of which may independently reject this publication.
        let authority_result = self.observe_authority(&verified);
        let custodian_result = custodian
            .map(|human| {
                verify_authority(human, None, now).and_then(|human| self.observe_authority(&human))
            })
            .transpose();
        authority_result?;
        custodian_result?;
        let cert = verified.authorize(device, "message", now)?;
        let bytes = ramflux_protocol::canonical_json_bytes(bundle)?;
        let bundle: ramflux_crypto::PrekeyBundle =
            ramflux_protocol::custody::decode(&bytes, 64 * 1024)?;
        if bundle.device_id != device.device_id
            || bundle.device_epoch != device.device_epoch
            || bundle.device_identity_ed25519_public != cert.branch_signing_public_key
            || ramflux_protocol::encode_base64url(bundle.identity_key)
                != cert.agreement_identity_public_key
            || bundle.identity_key != bundle.device_agreement_x25519_public
            || bundle.identity_commitment != publication.record.body.principal_id
        {
            return Err(invalid());
        }
        ramflux_crypto::verify_prekey_bundle(
            &ramflux_crypto::verifying_key_from_base64url(&cert.branch_signing_public_key)?,
            &bundle,
        )?;
        Ok(())
    }
}
#[derive(Default, serde::Serialize, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct PeerPins {
    pins: ramflux_crypto::custody::AuthorityPins,
    accepted: Option<ramflux_protocol::custody::Envelope<ramflux_protocol::custody::DeviceSet>>,
    #[serde(default, skip_serializing_if = "super::layer_declaration::DeclarationPins::is_empty")]
    message_layers: super::layer_declaration::DeclarationPins,
}
impl NodePins {
    fn observe_authority(
        &self,
        verified: &ramflux_crypto::custody::VerifiedRecord,
    ) -> Result<(), SdkError> {
        use ramflux_crypto::custody::PinOutcome;
        let _lock = self.lock()?;
        let path = self.root.join(format!("peer-{}.json", verified.envelope().body.account_anchor));
        let mut state: PeerPins =
            if path.try_exists()? { read(&path, 8 * 1024 * 1024)? } else { PeerPins::default() };
        let record = verified.envelope();
        let native_head = ramflux_protocol::custody::object_hash(record)?;
        let mut message_layers = state.message_layers.clone();
        let declaration_result = message_layers.observe_roster(
            &record.body.account_anchor,
            &record.body.devices,
            record.body.device_set_epoch,
            &native_head,
        );
        let outcome = state.pins.observe_with_previous(verified, state.accepted.as_ref())?;
        if outcome == PinOutcome::Advanced {
            state.accepted = Some(verified.envelope().clone());
        }
        if matches!(outcome, PinOutcome::Fenced(_)) {
            self.persist_peer_state(&path, &state)?;
            declaration_result?;
            return Err(SdkError::CustodyForkFenced);
        }
        declaration_result?;
        state.message_layers = message_layers;
        self.persist_peer_state(&path, &state)?;
        super::store::require_current_authority(&state.pins, verified)?;
        Ok(())
    }
    fn persist_peer_state(&self, path: &Path, state: &PeerPins) -> Result<(), SdkError> {
        let temp = self.root.join(format!(
            ".peer-{}",
            ramflux_protocol::encode_base64url(ramflux_crypto::random_32()?)
        ));
        let bytes = serde_json::to_vec(&state)?;
        if bytes.len() > 8 * 1024 * 1024 {
            return Err(invalid());
        }
        create(&temp, &bytes)?;
        fs::rename(temp, path)?;
        fs::File::open(&self.root)?.sync_all()?;
        Ok(())
    }
}
pub(crate) fn verify_authority(
    publication: &ramflux_protocol::custody::Publication,
    custodian: Option<&ramflux_protocol::custody::Publication>,
    now: u64,
) -> Result<ramflux_crypto::custody::VerifiedRecord, SdkError> {
    let human = custodian
        .map(|p| {
            ramflux_crypto::custody::verify_record(&p.record, now, p.compacted_ids.as_deref(), None)
        })
        .transpose()?;
    Ok(ramflux_crypto::custody::verify_record(
        &publication.record,
        now,
        publication.compacted_ids.as_deref(),
        human.as_ref(),
    )?)
}

pub(super) fn log_unbound(root: &Path) -> Result<(), SdkError> {
    let path = root.join("custody_network").join("unbound-connections.log");
    let mut file = crate::platform::fs::open_owner_only_append(&path)?;
    writeln!(file, "{} no_channel_binding explicit_client_opt_in", super::network::now()?)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};
    use crate::custody::{BranchCredentials, load_account};
    use ramflux_protocol::custody::{DeviceRef, Publication, SignedLayerDeclaration, decode_epoch};

    fn successor(
        prior: &Publication,
        primary: &ramflux_crypto::custody::SelfSigningKey,
        declaration: Option<SignedLayerDeclaration>,
        issued_at: u64,
    ) -> TestResult<Publication> {
        let mut body = prior.record.body.clone();
        body.previous_record_hash = Some(ramflux_protocol::custody::object_hash(&prior.record)?);
        body.device_set_epoch = body.device_set_epoch.checked_add(1).ok_or("epoch overflow")?;
        body.issued_at = issued_at;
        body.devices[0].message_layer = declaration;
        Ok(Publication { record: primary.sign_record(body)?, compacted_ids: None })
    }

    fn signed_declaration(
        branch: &BranchCredentials,
        device: DeviceRef,
        sequence: u64,
        issued_at: u64,
        expires_at: u64,
    ) -> TestResult<SignedLayerDeclaration> {
        Ok(super::super::layer_declaration::candidate(
            &branch.signing,
            device,
            ramflux_protocol::custody::MESSAGE_LAYER_FLOOR,
            sequence,
            issued_at,
            expires_at,
        )?)
    }

    fn peer_path(pins: &NodePins, anchor: &str) -> PathBuf {
        pins.root.join(format!("peer-{anchor}.json"))
    }

    #[test]
    fn legacy_peer_pin_bytes_decode_and_reencode_identically() -> TestResult {
        // Exact pre-message_layers PeerPins serialization from the prior SDK version.
        const LEGACY: &[u8] = br#"{"pins":{"accounts":{}},"accepted":null}"#;
        let state: PeerPins = ramflux_protocol::custody::decode(LEGACY, 8 * 1024 * 1024)?;
        assert!(state.message_layers.is_empty());
        assert_eq!(serde_json::to_vec(&state)?, LEGACY);
        Ok(())
    }

    #[tokio::test]
    async fn layer_update_rejects_rollback() -> TestResult {
        let fixture = Fixture::new("layer-pin-real-wire").await?;
        let now = crate::custody::network_now()?;
        let id = fixture.client.account_db()?.local_account_id.clone();
        let account = load_account(&fixture.root.0, &id, now)?;
        let original = fixture.manifest.custody.as_ref().ok_or("native manifest")?;
        let original_publication = original.publication.clone();
        let device = original.devices[0].device_ref.clone();
        let bundle = original.devices[0].prekey_bundle.clone();
        let primary = fixture.vault.primary_for_public_key(
            &account.record().body.master_certificate.body.self_signing_public_key,
        )?;
        let (_, branch) = account.credentials(fixture.vault.as_ref(), &device.device_id, now)?;

        // Sequence two is genuinely branch-signed and endorsed by a higher native head.
        let issued_at = now + 10;
        let expires_at = issued_at + 2;
        let declaration = signed_declaration(&branch, device.clone(), 2, issued_at, expires_at)?;
        let first =
            successor(&original_publication, &primary, Some(declaration.clone()), issued_at)?;
        let pins = NodePins::new(&fixture.root.0, "layer-peer", "unused")?;
        pins.observe_peer(&first, &device, &bundle, None, issued_at)?;
        let path = peer_path(&pins, &device.account_anchor);
        let first_bytes = fs::read(&path)?;
        let state: PeerPins = read(&path, 8 * 1024 * 1024)?;
        assert_eq!(
            serde_json::to_value(&state.message_layers)?["devices"][0]["declaration_sequence"],
            2
        );

        // A controlled time after expiry reopens the actual peer file and keeps its floor.
        let post_expiry_now = expires_at + 1;
        let reopened = NodePins::new(&fixture.root.0, "layer-peer", "unused")?;
        reopened.observe_peer(&first, &device, &bundle, None, post_expiry_now)?;
        let state: PeerPins = read(&path, 8 * 1024 * 1024)?;
        assert_eq!(
            serde_json::to_value(&state.message_layers)?["devices"][0]["declaration_sequence"],
            2
        );

        // A later endorsed head refreshes the same declaration pin after expiry.
        let refreshed =
            successor(&first, &primary, Some(declaration.clone()), post_expiry_now + 1)?;
        reopened.observe_peer(&refreshed, &device, &bundle, None, post_expiry_now + 1)?;
        let state: PeerPins = read(&path, 8 * 1024 * 1024)?;
        assert_eq!(
            serde_json::to_value(&state.message_layers)?["devices"][0]["native_epoch"],
            refreshed.record.body.device_set_epoch
        );

        // A historical restore is refused without changing the durable accepted state.
        let before_refusal = fs::read(&path)?;
        assert!(matches!(
            reopened.observe_peer(
                &original_publication,
                &device,
                &bundle,
                None,
                post_expiry_now + 1
            ),
            Err(SdkError::Crypto(ramflux_crypto::CryptoError::IdentityAuthority(
                "custody epoch rollback"
            )))
        ));
        assert_eq!(fs::read(&path)?, before_refusal);

        // A valid lower sequence is independently refused, also without a partial native pin.
        let lower = signed_declaration(
            &branch,
            device.clone(),
            1,
            post_expiry_now + 2,
            post_expiry_now + 3,
        )?;
        let lower_head = successor(&refreshed, &primary, Some(lower), post_expiry_now + 2)?;
        assert!(matches!(
            reopened.observe_peer(&lower_head, &device, &bundle, None, post_expiry_now + 2),
            Err(SdkError::CustodyForkFenced)
        ));
        assert_eq!(fs::read(&path)?, before_refusal);

        // Withdrawal retains the sequence; equal-sequence reappearance is not a renewal.
        let withdrawn = successor(&refreshed, &primary, None, post_expiry_now + 3)?;
        reopened.observe_peer(&withdrawn, &device, &bundle, None, post_expiry_now + 3)?;
        let before_refusal = fs::read(&path)?;
        let reappeared = successor(&withdrawn, &primary, Some(declaration), post_expiry_now + 4)?;
        assert!(matches!(
            reopened.observe_peer(&reappeared, &device, &bundle, None, post_expiry_now + 4),
            Err(SdkError::CustodyForkFenced)
        ));
        assert_eq!(fs::read(&path)?, before_refusal);
        let state: PeerPins = read(&path, 8 * 1024 * 1024)?;
        assert_eq!(serde_json::to_value(&state.message_layers)?["devices"][0]["present"], false);
        assert_eq!(
            serde_json::to_value(&state.message_layers)?["devices"][0]["native_epoch"],
            withdrawn.record.body.device_set_epoch
        );
        assert_eq!(
            decode_epoch(withdrawn.record.body.device_set_epoch)?,
            decode_epoch(state.accepted.as_ref().ok_or("accepted head")?.body.device_set_epoch)?
        );
        assert_ne!(first_bytes, before_refusal);
        Ok(())
    }

    #[tokio::test]
    async fn native_fork_fence_persists_before_declaration_rejection() -> TestResult {
        let fixture = Fixture::new("layer-pin-fork-fence").await?;
        let now = crate::custody::network_now()?;
        let id = fixture.client.account_db()?.local_account_id.clone();
        let account = load_account(&fixture.root.0, &id, now)?;
        let native = fixture.manifest.custody.as_ref().ok_or("native manifest")?;
        let device = native.devices[0].device_ref.clone();
        let bundle = native.devices[0].prekey_bundle.clone();
        let primary = fixture.vault.primary_for_public_key(
            &account.record().body.master_certificate.body.self_signing_public_key,
        )?;
        let (_, branch) = account.credentials(fixture.vault.as_ref(), &device.device_id, now)?;
        let issued_at = now + 10;
        let declaration =
            signed_declaration(&branch, device.clone(), 2, issued_at, issued_at + 60)?;
        let accepted =
            successor(&native.publication, &primary, Some(declaration.clone()), issued_at)?;
        let pins = NodePins::new(&fixture.root.0, "fork-peer", "unused")?;
        pins.observe_peer(&accepted, &device, &bundle, None, issued_at)?;
        let path = peer_path(&pins, &device.account_anchor);

        // Same signed epoch, different valid head. Declaration pinning detects the fork too;
        // AuthorityPins evidence must reach disk before that refusal is returned.
        let mut fork_body = accepted.record.body.clone();
        fork_body.profile.display_name.push_str(" fork");
        let fork = Publication { record: primary.sign_record(fork_body)?, compacted_ids: None };
        assert!(matches!(
            pins.observe_peer(&fork, &device, &bundle, None, issued_at),
            Err(SdkError::CustodyForkFenced)
        ));
        let durable: PeerPins = read(&path, 8 * 1024 * 1024)?;
        let range = decode_epoch(accepted.record.body.device_set_epoch)?.0;
        assert!(durable.pins.conflict_evidence(&device.account_anchor, range).is_some());
        let fenced_bytes = fs::read(&path)?;

        // Reopening and replaying the formerly accepted head remains fenced.
        let reopened = NodePins::new(&fixture.root.0, "fork-peer", "unused")?;
        assert!(matches!(
            reopened.observe_peer(&accepted, &device, &bundle, None, issued_at),
            Err(SdkError::CustodyForkFenced)
        ));
        assert_eq!(fs::read(&path)?, fenced_bytes);
        Ok(())
    }

    #[tokio::test]
    async fn verified_peer_fork_is_fenced_before_each_material_rejection() -> TestResult {
        let fixture = Fixture::new("layer-pin-fork-before-material").await?;
        let now = crate::custody::network_now()?;
        let id = fixture.client.account_db()?.local_account_id.clone();
        let account = load_account(&fixture.root.0, &id, now)?;
        let native = fixture.manifest.custody.as_ref().ok_or("native manifest")?;
        let device = native.devices[0].device_ref.clone();
        let bundle = native.devices[0].prekey_bundle.clone();
        let primary = fixture.vault.primary_for_public_key(
            &account.record().body.master_certificate.body.self_signing_public_key,
        )?;
        let (_, branch) = account.credentials(fixture.vault.as_ref(), &device.device_id, now)?;
        let issued_at = now + 10;
        let declaration =
            signed_declaration(&branch, device.clone(), 2, issued_at, issued_at + 120)?;
        let accepted = successor(&native.publication, &primary, Some(declaration), issued_at)?;

        for cause in
            ["bad-prekey-signature", "bad-bundle", "unauthorized-device", "bad-declaration"]
        {
            let pins = NodePins::new(&fixture.root.0, &format!("fork-{cause}"), "unused")?;
            pins.observe_peer(&accepted, &device, &bundle, None, issued_at)?;
            let path = peer_path(&pins, &device.account_anchor);

            let mut fork_body = accepted.record.body.clone();
            fork_body.profile.display_name.push_str(cause);
            if cause == "bad-declaration" {
                fork_body.devices[0].message_layer = Some(signed_declaration(
                    &branch,
                    device.clone(),
                    1,
                    issued_at,
                    issued_at + 120,
                )?);
            }
            let fork = Publication { record: primary.sign_record(fork_body)?, compacted_ids: None };
            let mut rejected_device = device.clone();
            let mut rejected_bundle = bundle.clone();
            match cause {
                "bad-prekey-signature" => {
                    rejected_bundle["signature_by_device_identity"] =
                        serde_json::json!(ramflux_protocol::encode_base64url([0; 64]));
                }
                "bad-bundle" => rejected_bundle = serde_json::json!({"unexpected": true}),
                "unauthorized-device" => rejected_device.device_id.push_str("-unauthorized"),
                "bad-declaration" => {}
                _ => unreachable!(),
            }

            assert!(
                matches!(
                    pins.observe_peer(
                        &fork,
                        &rejected_device,
                        &rejected_bundle,
                        None,
                        issued_at + 1
                    ),
                    Err(SdkError::CustodyForkFenced)
                ),
                "verified fork was not fenced before {cause} could return"
            );
            let durable: PeerPins = read(&path, 8 * 1024 * 1024)?;
            let range = decode_epoch(accepted.record.body.device_set_epoch)?.0;
            assert!(durable.pins.conflict_evidence(&device.account_anchor, range).is_some());
            let fenced_bytes = fs::read(&path)?;

            let reopened = NodePins::new(&fixture.root.0, &format!("fork-{cause}"), "unused")?;
            assert!(
                matches!(
                    reopened.observe_peer(&accepted, &device, &bundle, None, issued_at + 1),
                    Err(SdkError::CustodyForkFenced)
                ),
                "replay after {cause} did not retain the durable fence"
            );
            assert_eq!(fs::read(&path)?, fenced_bytes);
        }
        Ok(())
    }
}
