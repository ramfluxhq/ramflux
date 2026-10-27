// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub const EVENT: &str = "ramflux.event.v1";
pub const ENVELOPE: &str = "ramflux.envelope.v1";
pub const OBJECT: &str = "ramflux.object.v1";
pub const CHUNK_PLAIN: &str = "ramflux.chunk.plain.v1";
pub const CHUNK_CIPHER: &str = "ramflux.chunk.cipher.v1";
pub const OBJECT_CHUNK_ID: &str = "ramflux.object_chunk_id.v1";
pub const OBJECT_MANIFEST: &str = "ramflux.object_manifest.v1";
pub const OBJECT_CHUNK_REQUEST: &str = "ramflux.object_chunk_request.v1";
pub const SIGNED_REQUEST: &str = "ramflux.signed_request.v1";
pub const DEVICE_PROOF: &str = "ramflux.device_proof.v1";
pub const HOME_NODE_MIGRATION_PROOF: &str = "ramflux.home_node_migration_proof.v1";
pub const IDENTITY_DELETION_PROOF: &str = "ramflux.identity_deletion_proof.v1";
pub const IDENTITY_DELETION_PROOF_DELETED_METADATA_LEAF: &str =
    "ramflux.identity_deletion_proof.deleted_metadata_leaf.v1";
pub const IDENTITY_DELETION_PROOF_DELETED_METADATA_PARENT: &str =
    "ramflux.identity_deletion_proof.deleted_metadata_parent.v1";
pub const IDENTITY_DELETION_PROOF_DELETED_METADATA_EMPTY: &str =
    "ramflux.identity_deletion_proof.deleted_metadata_empty.v1";
pub const IDENTITY_DELETION_PROOF_RETAINED_SUMMARY: &str =
    "ramflux.identity_deletion_proof.retained_summary.v1";
pub const IDENTITY_DELETION_PROOF_TOMBSTONE: &str = "ramflux.identity_deletion_proof.tombstone.v1";
pub const ACK: &str = "ramflux.ack.v1";
pub const NACK: &str = "ramflux.nack.v1";
pub const CURSOR: &str = "ramflux.cursor.v1";
pub const IDENTITY_EVENT: &str = "ramflux.identity_event.v1";
pub const BRANCH_PROOF_V2: &str = "ramflux.branch_proof.v2";
pub const IDENTITY_PROFILE: &str = "ramflux.identity.profile.v1";
pub const SIGNED_DEVICE_SET_V2: &str = "ramflux.identity.signed_device_set.v2";
pub const SIGNED_DEVICE_SET: &str = "ramflux.identity.signed_device_set.v1";
pub const DEVICE_SIGNING_KEY_COMMITMENT: &str = "ramflux.identity.device_signing_key.v1";
pub const DEVICE_AGREEMENT_KEY_COMMITMENT: &str = "ramflux.identity.device_agreement_key.v1";
pub const BRANCH_PROOF: &str = "ramflux.branch_proof.v1";
pub const FRIEND_EVENT: &str = "ramflux.friend_event.v1";
pub const GROUP_EVENT: &str = "ramflux.group_event.v1";
pub const CONVERSATION_EVENT: &str = "ramflux.conversation_event.v1";
pub const MESSAGE_EVENT: &str = "ramflux.message_event.v1";
pub const NOTIFICATION_WAKE: &str = "ramflux.notification_wake.v1";
pub const MCP_GRANT: &str = "ramflux.mcp_grant.v1";
pub const BOT_MANIFEST: &str = "ramflux.bot_manifest.v1";
pub const BOT_EVENT: &str = "ramflux.bot_event.v1";
pub const BOT_INSTALL_GRANT: &str = "ramflux.bot_install_grant.v1";
pub const A2I_CONTROL: &str = "ramflux.a2i_control.v1";
pub const A2UI_SURFACE: &str = "ramflux.a2ui_surface.v1";
pub const A2UI_SURFACE_HASH: &str = "ramflux.a2ui.surface_hash.v1";
pub const A2UI_FINAL_COMPONENT: &str = "ramflux.a2ui.final_component.v1";
pub const A2UI_FINAL_TEXT: &str = "ramflux.a2ui.final_text.v1";
pub const A2UI_ACTION_ARGS: &str = "ramflux.a2ui.action_args.v1";
pub const SURFACE_CARRIER: &str = "ramflux.surface.carrier.v2";
pub const PUSH_ALIAS: &str = "ramflux.push_alias.v1";
pub const FEDERATION_HANDSHAKE: &str = "ramflux.federation_handshake.v1";
pub const X3DH_PREKEY_BUNDLE: &str = "ramflux.x3dh.prekey_bundle.v1";
pub const X3DH_INITIAL_SECRET: &str = "ramflux.x3dh.initial_secret.v1";
pub const DM_RATCHET_ROOT: &str = "ramflux.dm_ratchet.root.v1";
pub const DM_RATCHET_CHAIN: &str = "ramflux.dm_ratchet.chain.v1";
pub const DM_RATCHET_MESSAGE: &str = "ramflux.dm_ratchet.message.v1";
pub const DM_RATCHET_HEADER: &str = "ramflux.dm_ratchet.header.v1";
pub const DM_RATCHET_SKIPPED_KEY: &str = "ramflux.dm_ratchet.skipped_key.v1";
pub const GROUP_SENDER_KEY_DISTRIBUTION: &str = "ramflux.group_sender_key.distribution.v1";
pub const GROUP_SENDER_KEY_CHAIN: &str = "ramflux.group_sender_key.chain.v1";
pub const GROUP_SENDER_KEY_MESSAGE: &str = "ramflux.group_sender_key.message.v1";
pub const COMMITTING_AEAD: &str = "ramflux.committing_aead.v1";
pub const COMMITTING_AEAD_HEADER: &str = "ramflux.committing_aead.header.v1";
pub const COMMITTING_AEAD_AD: &str = "ramflux.committing_aead.ad.v1";
pub const FRANKING_OPENING: &str = "ramflux.franking_opening.v1";
pub const FRANKING_NODE_TAG: &str = "ramflux.franking.node_tag.v1";
pub const KEY_VERIFICATION_SAFETY_NUMBER: &str = "ramflux.safety_number.v1";
pub const KEY_VERIFICATION_DEVICE_SET: &str = "ramflux.device_set.v1";
pub const REGISTRATION_POW: &str = "ramflux.registration_pow.v1";
pub const REGISTRATION_TRUST_TIER: &str = "ramflux.registration_trust_tier.v1";

pub const TASK_EVENT: &str = "ramflux.task_event.v1";

// Reserved custody labels do not activate a wire format or verifier.
pub const CUSTODY_MASTER_CERTIFICATE: &str = "ramflux.identity.master_certificate.v1";
pub const SIGNED_DEVICE_SET_V3: &str = "ramflux.identity.signed_device_set.v3";
pub const CUSTODY_BRANCH_CERTIFICATE: &str = "ramflux.identity.branch_certificate.v1";
pub const BRANCH_PROOF_V3: &str = "ramflux.identity.branch_proof.v3";
pub const CUSTODY_DELEGATION: &str = "ramflux.identity.delegation.v1";
pub const CUSTODY_GROUP_DELEGATION: &str = "ramflux.identity.group_delegation.v1";
pub const CUSTODY_ERASURE_ACK: &str = "ramflux.identity.erasure_ack.v1";
pub const CUSTODY_LEGACY_BINDING: &str = "ramflux.identity.legacy_binding.v1";
pub const CONTACT_REQUEST_V2: &str = "ramflux.identity.contact_request.v2";
pub const CUSTODY_RELAY_ACCEPTANCE: &str = "ramflux.identity.relay_acceptance.v1";
pub const CUSTODY_TRANSFER_BINDING: &str = "ramflux.identity.transfer_binding.v1";
pub const CUSTODY_REVOKED_CHECKPOINT: &str = "ramflux.identity.revoked_devices.checkpoint.v1";
pub const CUSTODY_NODE_RECORD: &str = "ramflux.identity.node_record.v1";
pub const CUSTODY_TIME_ATTESTATION: &str = "ramflux.identity.time_attestation.v1";
pub const CUSTODY_MASTER_SEED: &str = "ramflux.identity.master.v1";
pub const CUSTODY_OBJECT_HASH: &str = "ramflux.identity.custody.object_hash.v1";
pub const CUSTODY_SECTION_HASH: &str = "ramflux.identity.custody.section_hash.v1";
pub const CUSTODY_SAFETY_NUMBER: &str = "ramflux.identity.safety_number.v2";
pub const CUSTODY_PAIRING_TRANSCRIPT: &str = "ramflux.identity.pairing_transcript.v1";
pub const CUSTODY_PAIRING_COMMITMENT: &str = "ramflux.identity.pairing.commitment.v1";
pub const CUSTODY_PAIRING_SAS: &str = "ramflux.identity.pairing.sas.v1";
pub const CUSTODY_PAIRING_CONFIRM_INITIATOR: &str = "ramflux.identity.pairing.confirm.initiator.v1";
pub const CUSTODY_PAIRING_CONFIRM_RESPONDER: &str = "ramflux.identity.pairing.confirm.responder.v1";
pub const CUSTODY_PAIRING_CHANNEL_INITIATOR: &str = "ramflux.identity.pairing.channel.initiator.v1";
pub const CUSTODY_PAIRING_CHANNEL_RESPONDER: &str = "ramflux.identity.pairing.channel.responder.v1";
pub const CUSTODY_PAIRING_EMOJI_SUITE: &str = "ramflux.identity.pairing.sas_emoji.v1";
pub const CUSTODY_TRANSFER_HPKE_INFO: &str = "ramflux.identity.transfer.hpke_info.v1";
pub const CUSTODY_TRANSFER_AAD: &str = "ramflux.identity.transfer.aad.v1";
pub const CUSTODY_TRANSFER_HPKE: &str = "ramflux.identity.transfer.hpke.v1";
pub const CUSTODY_TRANSFER_PAYLOAD: &str = "ramflux.identity.transfer.payload.v1";
pub const CUSTODY_TRANSFER_HPKE_SUITE: &str = "ramflux.identity.transfer.hpke_suite.v1";
pub const CUSTODY_BRANCH_EXPORTER: &str = "EXPERIMENTAL-ramflux.identity.branch_proof.exporter.v3";
pub const CUSTODY_REVOKED_LIST: &str = "ramflux.identity.revoked_devices.list.v1";
pub const CUSTODY_TIME_PROBE: &str = "ramflux.identity.time_probe.v1";

pub const HOME_PREPARE: &str = "ramflux.identity.home_prepare.v1";
pub const HOME_ROUTE_OFFER: &str = "ramflux.identity.home_route_offer.v1";
pub const HOME_AUTHORIZATION: &str = "ramflux.identity.home_authorization.v1";
pub const HOME_GENESIS: &str = "ramflux.identity.home_genesis.v1";
pub const HOME_CONTROL: &str = "ramflux.identity.home_control.v1";
pub const HOME_RECEIPT: &str = "ramflux.identity.home_receipt.v1";
pub const HOME_COMMIT: &str = "ramflux.identity.home_commit.v1";
pub const HOME_COMMIT_DELIVERY: &str = "ramflux.identity.home_commit_delivery.v1";
pub const HOME_ADMISSION_ATTESTATION: &str = "ramflux.identity.home_admission_attestation.v1";
pub const HOME_NONCOMMIT_FENCE: &str = "ramflux.identity.home_noncommit_fence.v1";
pub const HOME_RECORD_HASH: &str = "ramflux.identity.home_record_hash.v1";
pub const HOME_DELIVERY_MAP: &str = "ramflux.identity.home_delivery_map.v1";

pub const ALL: [&str; 112] = [
    EVENT,
    TASK_EVENT,
    ENVELOPE,
    OBJECT,
    CHUNK_PLAIN,
    CHUNK_CIPHER,
    OBJECT_CHUNK_ID,
    OBJECT_MANIFEST,
    OBJECT_CHUNK_REQUEST,
    SIGNED_REQUEST,
    DEVICE_PROOF,
    HOME_NODE_MIGRATION_PROOF,
    IDENTITY_DELETION_PROOF,
    IDENTITY_DELETION_PROOF_DELETED_METADATA_LEAF,
    IDENTITY_DELETION_PROOF_DELETED_METADATA_PARENT,
    IDENTITY_DELETION_PROOF_DELETED_METADATA_EMPTY,
    IDENTITY_DELETION_PROOF_RETAINED_SUMMARY,
    IDENTITY_DELETION_PROOF_TOMBSTONE,
    ACK,
    NACK,
    CURSOR,
    IDENTITY_EVENT,
    BRANCH_PROOF,
    BRANCH_PROOF_V2,
    SIGNED_DEVICE_SET,
    SIGNED_DEVICE_SET_V2,
    IDENTITY_PROFILE,
    DEVICE_SIGNING_KEY_COMMITMENT,
    DEVICE_AGREEMENT_KEY_COMMITMENT,
    FRIEND_EVENT,
    GROUP_EVENT,
    CONVERSATION_EVENT,
    MESSAGE_EVENT,
    NOTIFICATION_WAKE,
    MCP_GRANT,
    BOT_MANIFEST,
    BOT_EVENT,
    BOT_INSTALL_GRANT,
    A2I_CONTROL,
    A2UI_SURFACE,
    A2UI_SURFACE_HASH,
    A2UI_ACTION_ARGS,
    A2UI_FINAL_COMPONENT,
    A2UI_FINAL_TEXT,
    SURFACE_CARRIER,
    PUSH_ALIAS,
    FEDERATION_HANDSHAKE,
    X3DH_PREKEY_BUNDLE,
    X3DH_INITIAL_SECRET,
    DM_RATCHET_ROOT,
    DM_RATCHET_CHAIN,
    DM_RATCHET_MESSAGE,
    DM_RATCHET_HEADER,
    DM_RATCHET_SKIPPED_KEY,
    GROUP_SENDER_KEY_DISTRIBUTION,
    GROUP_SENDER_KEY_CHAIN,
    GROUP_SENDER_KEY_MESSAGE,
    COMMITTING_AEAD,
    COMMITTING_AEAD_HEADER,
    COMMITTING_AEAD_AD,
    FRANKING_OPENING,
    FRANKING_NODE_TAG,
    KEY_VERIFICATION_SAFETY_NUMBER,
    KEY_VERIFICATION_DEVICE_SET,
    REGISTRATION_POW,
    REGISTRATION_TRUST_TIER,
    CUSTODY_MASTER_CERTIFICATE,
    SIGNED_DEVICE_SET_V3,
    CUSTODY_BRANCH_CERTIFICATE,
    BRANCH_PROOF_V3,
    CUSTODY_DELEGATION,
    CUSTODY_GROUP_DELEGATION,
    CUSTODY_ERASURE_ACK,
    CUSTODY_LEGACY_BINDING,
    CONTACT_REQUEST_V2,
    CUSTODY_RELAY_ACCEPTANCE,
    CUSTODY_TRANSFER_BINDING,
    CUSTODY_REVOKED_CHECKPOINT,
    CUSTODY_NODE_RECORD,
    CUSTODY_TIME_ATTESTATION,
    CUSTODY_MASTER_SEED,
    CUSTODY_OBJECT_HASH,
    CUSTODY_SECTION_HASH,
    CUSTODY_SAFETY_NUMBER,
    CUSTODY_PAIRING_TRANSCRIPT,
    CUSTODY_PAIRING_COMMITMENT,
    CUSTODY_PAIRING_SAS,
    CUSTODY_PAIRING_CONFIRM_INITIATOR,
    CUSTODY_PAIRING_CONFIRM_RESPONDER,
    CUSTODY_PAIRING_CHANNEL_INITIATOR,
    CUSTODY_PAIRING_CHANNEL_RESPONDER,
    CUSTODY_PAIRING_EMOJI_SUITE,
    CUSTODY_TRANSFER_HPKE_INFO,
    CUSTODY_TRANSFER_AAD,
    CUSTODY_TRANSFER_HPKE,
    CUSTODY_TRANSFER_PAYLOAD,
    CUSTODY_TRANSFER_HPKE_SUITE,
    CUSTODY_BRANCH_EXPORTER,
    CUSTODY_REVOKED_LIST,
    CUSTODY_TIME_PROBE,
    HOME_PREPARE,
    HOME_ROUTE_OFFER,
    HOME_AUTHORIZATION,
    HOME_GENESIS,
    HOME_CONTROL,
    HOME_RECEIPT,
    HOME_COMMIT,
    HOME_COMMIT_DELIVERY,
    HOME_ADMISSION_ATTESTATION,
    HOME_NONCOMMIT_FENCE,
    HOME_RECORD_HASH,
    HOME_DELIVERY_MAP,
];

#[cfg(test)]
mod tests {
    #[test]
    fn registered_domains_are_unique_and_include_a2ui_arguments() {
        let unique = super::ALL.into_iter().collect::<std::collections::BTreeSet<_>>();
        assert_eq!(unique.len(), super::ALL.len());
        assert!(unique.contains(super::A2UI_ACTION_ARGS));
        assert_eq!(super::A2UI_ACTION_ARGS, "ramflux.a2ui.action_args.v1");
    }
    #[test]
    fn registered_domains_are_prefix_free_and_custody_labels_share_the_identity_namespace() {
        for (index, left) in super::ALL.iter().enumerate() {
            assert!(!left.as_bytes().contains(&0), "domain contains a frame separator");
            for right in &super::ALL[index + 1..] {
                assert!(
                    !left.starts_with(right) && !right.starts_with(left),
                    "ambiguous domains: {left} / {right}"
                );
            }
        }
        for label in &super::ALL[66..] {
            assert!(
                label.starts_with("ramflux.identity.") || *label == super::CUSTODY_BRANCH_EXPORTER
            );
        }
        assert_eq!(
            super::CUSTODY_BRANCH_EXPORTER,
            "EXPERIMENTAL-ramflux.identity.branch_proof.exporter.v3"
        );
        assert_eq!(super::CUSTODY_PAIRING_TRANSCRIPT, "ramflux.identity.pairing_transcript.v1");
    }
}
