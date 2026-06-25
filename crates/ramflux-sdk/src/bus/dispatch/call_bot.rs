// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

pub(crate) fn dispatch_call_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account_mut(state, account_id)?;
    match request.method.as_str() {
        "call.invite" => {
            let body: LocalBusCallInviteRequest = serde_json::from_value(request.body.clone())?;
            let opaque_payload = ramflux_protocol::decode_base64url(&body.opaque_offer_base64)
                .map_err(|error| SdkError::LocalBus(format!("invalid call offer: {error}")))?;
            let signal = OpaqueCallSignal { call_id: body.call_id.clone(), opaque_payload };
            let relay = ramflux_sync::relay_opaque_call_signal(&signal);
            ramflux_sync::assert_srtp_relay_has_no_media_key(&relay)?;
            let record = LocalCallRecord {
                call_id: body.call_id.clone(),
                target_id: body.target_id,
                state: "invited".to_owned(),
                relay,
                turn_allocation_id: format!("turn_alloc_{}", body.call_id),
                node_sees_sdp: false,
                relay_holds_media_key: false,
            };
            account.calls.insert(body.call_id, record.clone());
            Ok(local_bus_ok(serde_json::to_value(record)?))
        }
        "call.answer" => {
            let body: LocalBusCallAnswerRequest = serde_json::from_value(request.body.clone())?;
            let opaque_payload = ramflux_protocol::decode_base64url(&body.opaque_answer_base64)
                .map_err(|error| SdkError::LocalBus(format!("invalid call answer: {error}")))?;
            let record = account
                .calls
                .get_mut(&body.call_id)
                .ok_or_else(|| SdkError::LocalBus(format!("call not found: {}", body.call_id)))?;
            let signal = OpaqueCallSignal { call_id: body.call_id, opaque_payload };
            record.relay = ramflux_sync::relay_opaque_call_signal(&signal);
            ramflux_sync::assert_srtp_relay_has_no_media_key(&record.relay)?;
            "answered".clone_into(&mut record.state);
            Ok(local_bus_ok(serde_json::to_value(record)?))
        }
        "call.hangup" => {
            let body: LocalBusCallHangupRequest = serde_json::from_value(request.body.clone())?;
            let record = account
                .calls
                .get_mut(&body.call_id)
                .ok_or_else(|| SdkError::LocalBus(format!("call not found: {}", body.call_id)))?;
            "hung_up".clone_into(&mut record.state);
            Ok(local_bus_ok(serde_json::to_value(record)?))
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

pub(crate) fn dispatch_bot_bus_request(
    request: &LocalBusFrame,
    state: &mut LocalBusDaemonState,
) -> Result<LocalBusDispatchResult, SdkError> {
    let account_id = request_account_id(request)?;
    let account = local_bus_account_mut(state, account_id)?;
    match request.method.as_str() {
        "bot.trust.add" => {
            let body: LocalBusBotTrustAddRequest = serde_json::from_value(request.body.clone())?;
            bot_trust_add(account, body)
        }
        "bot.install" => {
            let body: LocalBusBotInstallRequest = serde_json::from_value(request.body.clone())?;
            bot_install(account, body)
        }
        "bot.list" => Ok(local_bus_ok(serde_json::json!({
            "bots": account.bots.values().collect::<Vec<_>>(),
        }))),
        "bot.revoke" => {
            let body: LocalBusBotRevokeRequest = serde_json::from_value(request.body.clone())?;
            bot_revoke(account, &body)
        }
        other => Err(SdkError::LocalBus(format!("unsupported local bus method: {other}"))),
    }
}

fn bot_trust_add(
    account: &mut LocalBusAccountState,
    body: LocalBusBotTrustAddRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    if body.trust_source != "local_pin" {
        return Err(SdkError::CapabilityDenied(
            "bot trust source is not locally authoritative".to_owned(),
        ));
    }
    let pin = BotTrustPinRecord {
        bot_identity_commitment: body.bot_identity_commitment,
        bot_public_key: body.bot_public_key,
        signing_key_id: body.signing_key_id,
        trust_source: body.trust_source,
        pinned_at: now_unix_timestamp(),
    };
    account.client.account_db()?.upsert_bot_trust_pin(&pin)?;
    Ok(local_bus_ok(serde_json::to_value(LocalBotTrustPinRecord {
        bot_identity_commitment: pin.bot_identity_commitment,
        bot_public_key: pin.bot_public_key,
        signing_key_id: pin.signing_key_id,
        trust_source: pin.trust_source,
        pinned_at: pin.pinned_at,
    })?))
}

fn bot_install(
    account: &mut LocalBusAccountState,
    body: LocalBusBotInstallRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    if account.client.account_db()?.bot_install_revoked(&body.manifest.bot_identity_commitment)? {
        return Err(SdkError::CapabilityDenied("bot identity is revoked".to_owned()));
    }
    let trusted = account
        .client
        .account_db()?
        .bot_trust_pin(&body.manifest.bot_identity_commitment)?
        .ok_or_else(|| SdkError::CapabilityDenied("trusted bot pin missing".to_owned()))?;
    let now = now_unix_timestamp();
    let manifest_hash = verify_bot_manifest(&body.manifest, &trusted.bot_public_key, now)?;
    let device = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let installer_public_key =
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes());
    verify_bot_install_grant(
        &body.manifest,
        &body.install_grant,
        &installer_public_key,
        &device.device_id,
        now,
    )?;
    let expected_members = bot_manifest_required_consents(&body.manifest);
    let consent_set = body.consent_member_ids.iter().cloned().collect::<BTreeSet<_>>();
    if !expected_members.is_subset(&consent_set) {
        return Err(SdkError::CapabilityDenied("bot group consent missing".to_owned()));
    }
    let record = persist_verified_bot_install(account, body, trusted, &manifest_hash, now)?;
    Ok(local_bus_ok(serde_json::to_value(record)?))
}

fn persist_verified_bot_install(
    account: &mut LocalBusAccountState,
    body: LocalBusBotInstallRequest,
    trusted: BotTrustPinRecord,
    manifest_hash: &str,
    now: i64,
) -> Result<LocalBotRecord, SdkError> {
    let requested_scopes = body.install_grant.scope.clone();
    let manifest_scopes = body
        .manifest
        .permissions
        .iter()
        .chain(body.manifest.capabilities.iter())
        .cloned()
        .collect::<Vec<_>>();
    let grant_hash = bot_install_grant_hash(&body.install_grant)?;
    let manifest_body = ramflux_protocol::canonical_json_bytes(&body.manifest)?;
    let grant_body = ramflux_protocol::canonical_json_bytes(&body.install_grant)?;
    account.client.account_db()?.upsert_bot_manifest_cache(
        manifest_hash,
        &body.manifest,
        &manifest_body,
        now,
    )?;
    account.client.account_db()?.upsert_bot_install_grant(
        &body.install_grant,
        &grant_hash,
        &grant_body,
        &body.consent_member_ids,
        now,
    )?;
    let bot_id = body.manifest.bot_identity_commitment.clone();
    let revocation_targets =
        ramflux_sync::bot_revocation_targets(&bot_id).into_iter().collect::<Vec<_>>();
    let record = LocalBotRecord {
        bot_id: bot_id.clone(),
        manifest: body.manifest,
        install_grant: body.install_grant,
        bot_manifest_hash: manifest_hash.to_owned(),
        grant_hash,
        requested_scopes,
        manifest_scopes,
        consent_member_ids: body.consent_member_ids,
        actor_type: "bot".to_owned(),
        operation_origin: "bot_actor".to_owned(),
        trust_source: trusted.trust_source,
        state: "installed".to_owned(),
        revocation_targets,
        revocation_event_id: None,
    };
    account.bots.insert(bot_id, record.clone());
    Ok(record)
}

fn bot_revoke(
    account: &mut LocalBusAccountState,
    body: &LocalBusBotRevokeRequest,
) -> Result<LocalBusDispatchResult, SdkError> {
    let now = now_unix_timestamp();
    let revocation = sign_local_bot_revocation(account, &body.bot_id, now)?;
    let record = account
        .bots
        .get_mut(&body.bot_id)
        .ok_or_else(|| SdkError::LocalBus(format!("bot not found: {}", body.bot_id)))?;
    "revoked".clone_into(&mut record.state);
    record.revocation_targets =
        ramflux_sync::bot_revocation_targets(&body.bot_id).into_iter().collect();
    record.revocation_event_id = Some(revocation.event_id.clone());
    account.client.account_db()?.revoke_bot_install_grant(
        &body.bot_id,
        now,
        &revocation.event_id,
    )?;
    account.client.append_event(
        &revocation.event_id,
        "bot.install_revoked",
        &serde_json::to_vec(&revocation)?,
    )?;
    Ok(local_bus_ok(serde_json::to_value(record)?))
}

#[derive(Clone, Debug, serde::Serialize)]
struct LocalBotRevocationSigningBody {
    bot_identity_commitment: String,
    event_type: String,
    revoked_by_device_id: String,
    created_at: i64,
}

#[derive(Clone, Debug, serde::Serialize)]
struct LocalBotRevocationTombstone {
    event_id: String,
    event_type: String,
    bot_identity_commitment: String,
    revoked_by_device_id: String,
    created_at: i64,
    signature: String,
}

fn sign_local_bot_revocation(
    account: &LocalBusAccountState,
    bot_id: &str,
    created_at: i64,
) -> Result<LocalBotRevocationTombstone, SdkError> {
    let device = account.client.device_branch.as_ref().ok_or(SdkError::IdentityRootMissing)?;
    let body = LocalBotRevocationSigningBody {
        bot_identity_commitment: bot_id.to_owned(),
        event_type: "bot.install_revoked".to_owned(),
        revoked_by_device_id: device.device_id.clone(),
        created_at,
    };
    let signature = ramflux_crypto::sign_with_device_branch(device, &body)?;
    Ok(LocalBotRevocationTombstone {
        event_id: format!("bot.install_revoked:{bot_id}:{created_at}"),
        event_type: body.event_type,
        bot_identity_commitment: body.bot_identity_commitment,
        revoked_by_device_id: body.revoked_by_device_id,
        created_at,
        signature,
    })
}

fn bot_install_grant_hash(grant: &ramflux_protocol::BotInstallGrant) -> Result<String, SdkError> {
    Ok(ramflux_protocol::hash_base64url(
        ramflux_protocol::domain::BOT_INSTALL_GRANT,
        &ramflux_protocol::canonical_json_bytes(&bot_install_grant_signing_body(grant))?,
    ))
}

pub(crate) fn hydrate_local_bot_records(
    account: &mut LocalBusAccountState,
) -> Result<(), SdkError> {
    for stored in account.client.account_db()?.installed_bots()? {
        let manifest: ramflux_protocol::BotManifest =
            serde_json::from_slice(&stored.manifest_body)?;
        let install_grant: ramflux_protocol::BotInstallGrant =
            serde_json::from_slice(&stored.grant_body)?;
        let revocation_targets =
            ramflux_sync::bot_revocation_targets(&stored.bot_identity_commitment)
                .into_iter()
                .collect::<Vec<_>>();
        account.bots.insert(
            stored.bot_identity_commitment.clone(),
            LocalBotRecord {
                bot_id: stored.bot_identity_commitment,
                manifest,
                install_grant,
                bot_manifest_hash: stored.bot_manifest_hash,
                grant_hash: stored.grant_hash,
                requested_scopes: stored.scope,
                manifest_scopes: Vec::new(),
                consent_member_ids: stored.consent_member_ids,
                actor_type: stored.actor_type,
                operation_origin: "bot_actor".to_owned(),
                trust_source: stored.trust_source,
                state: stored.state,
                revocation_targets,
                revocation_event_id: stored.revocation_event_id,
            },
        );
    }
    Ok(())
}

fn bot_manifest_required_consents(manifest: &ramflux_protocol::BotManifest) -> BTreeSet<String> {
    manifest
        .permissions
        .iter()
        .chain(manifest.capabilities.iter())
        .filter_map(|scope| {
            scope.strip_prefix("group:consent:").or_else(|| scope.strip_prefix("group:invite:"))
        })
        .map(ToOwned::to_owned)
        .collect()
}

#[cfg(test)]
#[allow(clippy::expect_used, clippy::panic, clippy::too_many_lines)]
mod tests {
    use super::*;

    const ACCOUNT_ID: &str = "acct_bot";
    const PRINCIPAL_ID: &str = "principal_bot_installer";
    const DEVICE_ID: &str = "device_bot_installer";
    const NOW: i64 = 1_760_000_000;
    const FUTURE_EXPIRES_AT: i64 = 4_000_000_000;

    fn temp_root(test_name: &str) -> PathBuf {
        let nanos = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_nanos();
        std::env::temp_dir()
            .join(format!("ramflux-sdk-bot-{test_name}-{}-{nanos}", std::process::id()))
    }

    fn gateway_config() -> GatewaySessionConfig {
        GatewaySessionConfig::quic(GatewayQuicEndpointConfig {
            bind_addr: "127.0.0.1:0".parse().expect("bind addr"),
            gateway_addr: "127.0.0.1:1".parse().expect("gateway addr"),
            server_name: "ramflux-gateway".to_owned(),
            ca_cert: PathBuf::from("ca.pem"),
            principal_id: PRINCIPAL_ID.to_owned(),
            device_id: DEVICE_ID.to_owned(),
            target_delivery_id: "target_bot_installer".to_owned(),
            prekey_http_url: None,
        })
    }

    fn test_state(test_name: &str) -> (LocalBusDaemonState, PathBuf) {
        let root = temp_root(test_name);
        let mut client = RamfluxClient::new();
        client.create_identity_root(PRINCIPAL_ID, [0x61; 32]);
        client.create_device_branch(PRINCIPAL_ID, DEVICE_ID, 1, [0x62; 32]);
        client.open_account_index(&root).expect("open index");
        client.create_account(ACCOUNT_ID, "principal_commitment_bot").expect("create account");
        client.set_active_account(ACCOUNT_ID).expect("active account");
        client.unlock_account(ACCOUNT_ID, b"bot-account-secret").expect("unlock account");
        let state = LocalBusDaemonState {
            config: LocalBusConfig::new(root.join("rfd.sock"), root.clone()),
            accounts: BTreeMap::from([(
                ACCOUNT_ID.to_owned(),
                LocalBusAccountState::disconnected(client, gateway_config()),
            )]),
            active_account_id: Some(ACCOUNT_ID.to_owned()),
            attended_accounts: BTreeSet::new(),
            subscribers: BTreeMap::new(),
        };
        (state, root)
    }

    fn request(method: &str, body: serde_json::Value) -> LocalBusFrame {
        LocalBusFrame::request("req", Some(ACCOUNT_ID.to_owned()), "bot", method, body)
    }

    fn bot_device(seed: [u8; 32]) -> DeviceBranch {
        ramflux_crypto::create_device_branch("bot_principal", "bot_device", 1, seed)
    }

    fn public_key(device: &DeviceBranch) -> String {
        ramflux_protocol::encode_base64url(device.signing_key.verifying_key().to_bytes())
    }

    fn unsigned_manifest() -> ramflux_protocol::BotManifest {
        ramflux_protocol::BotManifest {
            schema: ramflux_protocol::domain::BOT_MANIFEST.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::BOT_MANIFEST.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "bot-key-1".to_owned(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "outer-signature-placeholder".to_owned(),
            },
            bot_identity_commitment: "bot_idc_b2".to_owned(),
            actor_type: ramflux_protocol::ActorType::Bot,
            display_name: "Build Bot".to_owned(),
            manifest_version: "1.0.0".to_owned(),
            home_node: "bots.example.test".to_owned(),
            capabilities: vec!["message:send".to_owned()],
            permissions: vec![
                "conversation:read:mentioned_context".to_owned(),
                "group:invite:member_a".to_owned(),
            ],
            owner_identity_commitment: "owner_idc".to_owned(),
            hosting_model: ramflux_protocol::HostingModel::Federated,
            a2ui_profiles: vec!["ramflux.a2ui.v1".to_owned()],
            safety_disclosure: ramflux_protocol::SafetyDisclosure {
                disclosure_version: 1,
                disclosure_text: "Hosted bot can read messages sent to it.".to_owned(),
                hosting_model: ramflux_protocol::HostingModel::Federated,
                key_custody_class: ramflux_protocol::KeyCustodyClass::FederatedOperatorKey,
                operator_identity_commitment: Some("operator_idc".to_owned()),
                operator_display_name: Some("Operator".to_owned()),
                can_read_dm_plaintext: true,
                can_read_group_messages_when_member: true,
                tee_attestation_hash: None,
                disclosure_hash: "disclosure_hash".to_owned(),
            },
            created_at: NOW,
            expires_at: Some(FUTURE_EXPIRES_AT),
            signature_by_bot_identity: String::new(),
            optional_signature_by_home_node: None,
            optional_signature_by_directory: None,
        }
    }

    fn signed_manifest(bot: &DeviceBranch) -> ramflux_protocol::BotManifest {
        let mut manifest = unsigned_manifest();
        manifest.signature_by_bot_identity =
            ramflux_crypto::sign_with_device_branch(bot, &bot_manifest_signing_body(&manifest))
                .expect("sign manifest");
        manifest
    }

    fn signed_grant(
        installer: &DeviceBranch,
        manifest: &ramflux_protocol::BotManifest,
    ) -> ramflux_protocol::BotInstallGrant {
        let mut grant = ramflux_protocol::BotInstallGrant {
            schema: ramflux_protocol::domain::BOT_INSTALL_GRANT.to_owned(),
            version: 1,
            domain: ramflux_protocol::domain::BOT_INSTALL_GRANT.to_owned(),
            ext: ramflux_protocol::Ext::default(),
            signed: ramflux_protocol::SignedFields {
                signing_key_id: "installer-key-1".to_owned(),
                signature_alg: ramflux_protocol::SignatureAlg::Ed25519,
                signature: "outer-signature-placeholder".to_owned(),
            },
            grant_id: "grant_bot_b2".to_owned(),
            bot_identity_commitment: manifest.bot_identity_commitment.clone(),
            bot_manifest_hash: bot_manifest_hash(manifest).expect("manifest hash"),
            installer_identity: PRINCIPAL_ID.to_owned(),
            installer_device_id: DEVICE_ID.to_owned(),
            scope: vec!["conversation:read:mentioned_context".to_owned()],
            conversation_id: Some("conversation_bot_b2".to_owned()),
            group_id: Some("group_bot_b2".to_owned()),
            expires_at: FUTURE_EXPIRES_AT,
            signature_by_installer_device: String::new(),
        };
        grant.signature_by_installer_device = ramflux_crypto::sign_with_device_branch(
            installer,
            &bot_install_grant_signing_body(&grant),
        )
        .expect("sign grant");
        grant
    }

    fn trust_pin(state: &mut LocalBusDaemonState, bot: &DeviceBranch) {
        let body = serde_json::json!({
            "bot_identity_commitment": "bot_idc_b2",
            "bot_public_key": public_key(bot),
            "signing_key_id": "bot-key-1",
            "trust_source": "local_pin",
        });
        dispatch_bot_bus_request(&request("bot.trust.add", body), state).expect("trust pin");
    }

    fn install_body(
        manifest: &ramflux_protocol::BotManifest,
        grant: &ramflux_protocol::BotInstallGrant,
        consent_member_ids: &[String],
    ) -> serde_json::Value {
        serde_json::json!({
            "manifest": manifest,
            "install_grant": grant,
            "consent_member_ids": consent_member_ids,
        })
    }

    #[test]
    fn bot_pin_then_signed_install_persists_and_rehydrates() {
        let (mut state, root) = test_state("install_rehydrate");
        let bot = bot_device([0x71; 32]);
        trust_pin(&mut state, &bot);
        let installer = state.accounts[ACCOUNT_ID].client.device_branch.clone().expect("device");
        let manifest = signed_manifest(&bot);
        let grant = signed_grant(&installer, &manifest);
        let install_response = dispatch_bot_bus_request(
            &request("bot.install", install_body(&manifest, &grant, &["member_a".to_owned()])),
            &mut state,
        )
        .expect("install")
        .response_body;
        let record: LocalBotRecord = serde_json::from_value(install_response).expect("record");
        assert_eq!(record.actor_type, "bot");
        assert_eq!(record.operation_origin, "bot_actor");
        assert_eq!(record.trust_source, "local_pin");
        assert_eq!(record.requested_scopes, grant.scope);

        let mut restored_client = RamfluxClient::new();
        restored_client.create_identity_root(PRINCIPAL_ID, [0x61; 32]);
        restored_client.create_device_branch(PRINCIPAL_ID, DEVICE_ID, 1, [0x62; 32]);
        restored_client.open_account_index(&root).expect("open restored index");
        restored_client.unlock_account(ACCOUNT_ID, b"bot-account-secret").expect("unlock restored");
        let mut restored = LocalBusAccountState::disconnected(restored_client, gateway_config());
        hydrate_local_bot_records(&mut restored).expect("hydrate bots");
        assert!(restored.bots.contains_key("bot_idc_b2"));
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bot_install_rejects_missing_pin_bad_signature_or_missing_consent() {
        let (mut state, root) = test_state("negative_install");
        let bot = bot_device([0x72; 32]);
        let installer = state.accounts[ACCOUNT_ID].client.device_branch.clone().expect("device");
        let manifest = signed_manifest(&bot);
        let grant = signed_grant(&installer, &manifest);
        assert!(
            dispatch_bot_bus_request(
                &request("bot.install", install_body(&manifest, &grant, &["member_a".to_owned()]),),
                &mut state,
            )
            .is_err()
        );

        trust_pin(&mut state, &bot);
        let mut tampered = manifest.clone();
        tampered.display_name = "Tampered Bot".to_owned();
        assert!(
            dispatch_bot_bus_request(
                &request("bot.install", install_body(&tampered, &grant, &["member_a".to_owned()]),),
                &mut state,
            )
            .is_err()
        );
        assert!(
            dispatch_bot_bus_request(
                &request("bot.install", install_body(&manifest, &grant, &[])),
                &mut state,
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn bot_revoke_writes_tombstone_and_blocks_reinstall() {
        let (mut state, root) = test_state("revoke");
        let bot = bot_device([0x73; 32]);
        trust_pin(&mut state, &bot);
        let installer = state.accounts[ACCOUNT_ID].client.device_branch.clone().expect("device");
        let manifest = signed_manifest(&bot);
        let grant = signed_grant(&installer, &manifest);
        dispatch_bot_bus_request(
            &request("bot.install", install_body(&manifest, &grant, &["member_a".to_owned()])),
            &mut state,
        )
        .expect("install");
        let revoked = dispatch_bot_bus_request(
            &request("bot.revoke", serde_json::json!({ "bot_id": "bot_idc_b2" })),
            &mut state,
        )
        .expect("revoke")
        .response_body;
        let record: LocalBotRecord = serde_json::from_value(revoked).expect("revoked record");
        assert_eq!(record.state, "revoked");
        assert!(record.revocation_event_id.is_some());
        assert!(
            dispatch_bot_bus_request(
                &request("bot.install", install_body(&manifest, &grant, &["member_a".to_owned()]),),
                &mut state,
            )
            .is_err()
        );
        let _ = std::fs::remove_dir_all(root);
    }
}
