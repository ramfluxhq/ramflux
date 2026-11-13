// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Consume only source-authenticated AEAD transport on a refused durable frame; no body effects.
use super::{
    GatewayInboxEntry, HeadUse, RamfluxClient, SdkError, associated_data_from_outer, decode,
    refuse_received_outer_fields, report,
};

impl RamfluxClient {
    pub(super) fn commit_authenticated_refused_transport(
        &self,
        entry: &GatewayInboxEntry,
        local: &str,
    ) -> Result<(), SdkError> {
        self.authenticated_envelope_sender(HeadUse::NewAuthorization, entry)?;
        refuse_received_outer_fields(&entry.envelope)?;
        let packet = decode(&entry.envelope)?;
        report::refuse_payload_outer_mismatch(&entry.envelope, &packet)?;
        let local_device = self.local_device_identity(local)?;
        let remote = self.authenticated_device_identity(HeadUse::NewAuthorization, entry)?;
        let group_peer = self
            .account_db()?
            .pinned_group_root_metadata(&entry.envelope.source_principal_id, remote.device_id())?
            .iter()
            .any(|root| root == remote.root_commitment());
        if remote.root_commitment() != self.own_account_anchor()?
            && !self.friend_link_peer_is_accepted(remote.root_commitment())?
            && !group_peer
        {
            return Ok(());
        }
        let (mut session, bundle) =
            self.recv_pair_session(&local_device, &remote, &entry.envelope.envelope_id, &packet)?;
        let aad = associated_data_from_outer(
            &entry.envelope,
            &entry.envelope.source_device_id,
            local,
            &bundle,
        )?;
        let _decrypted =
            zeroize::Zeroizing::new(session.decrypt_with_franking_keys(&packet.ciphertext, &aad)?);
        // AEAD authenticates transport ownership even when C or the application frame is invalid.
        // Do not derive a conversation, remember a collapse scope, execute a reset or retain bytes.
        self.commit_bootstrap_sequence(
            &local_device,
            &remote,
            packet.x3dh.as_ref(),
            &session.session_id,
        )?;
        self.persist_pair(&local_device, &remote, &bundle, &session)?;
        self.confirm_pair(&local_device, &remote, &session, false, packet.x3dh.is_some())?;
        Ok(())
    }
}
