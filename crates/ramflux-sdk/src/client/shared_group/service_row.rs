// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One timeline service row for each creator-signed group change.
//!
//! `service_events` is the accepted log. Every member projects that log, including a device whose
//! first snapshot already contains changes it never saw. Transport re-signing replaces the issuer
//! and leaves the log, and therefore the event identity, unchanged.
use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::group_state::{
    GroupServiceChange, GroupServiceEvent, GroupServiceOrder, GroupStateActor, GroupStateChange,
};
use ramflux_protocol::message as g;
use ramflux_storage::{DirectMessageWrite, MessageMetadata};

use crate::{RamfluxClient, SdkError};

use super::invalid;

impl RamfluxClient {
    /// Message-timeline order for a mapped change, or a clock order that stays out of that timeline.
    ///
    /// # Errors
    /// Rejects an exhausted message sequence, an author that is not the signing device,
    /// or a clock that cannot be represented.
    pub(crate) fn service_order_for_change(
        &self,
        previous: &VerifiedGroupState,
        change: &GroupStateChange,
        actor: &GroupStateActor,
    ) -> Result<GroupServiceOrder, SdkError> {
        let mapped = matches!(
            change,
            GroupStateChange::SetName { .. }
                | GroupStateChange::Add { .. }
                | GroupStateChange::Remove { .. }
        );
        if !mapped || ramflux_crypto::change_already_applied(previous.view(), change) {
            return Ok(GroupServiceOrder::from_clock(
                previous.view().epoch.saturating_add(1),
                crate::time::now_unix_timestamp(),
            )?);
        }
        let identity = self.allocate_generated_identity(
            &previous.view().conversation_id,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        let author =
            identity.author.as_ref().ok_or_else(|| invalid("group service author missing"))?;
        if author.account_anchor != actor.identity.root_commitment
            || author.device_id != actor.identity.device_id
            || author.device_epoch == 0
        {
            return Err(invalid("group service author differs from the signing device"));
        }
        Ok(GroupServiceOrder::from_allocated(
            author.device_epoch,
            identity.device_sequence,
            identity.hlc,
        )?)
    }

    /// Project the signed change log in `next`.
    ///
    /// The timeline is that log. Replay of the same bytes is a no-op. A shorter log that is a
    /// prefix of the accepted log is refused, because that rewinds a stored change. Any other
    /// verified log replaces rows it does not contain, so two devices that adopt the same
    /// snapshot keep the same service history. A different body under the same derived id is
    /// `ReplayMismatch`.
    ///
    /// # Errors
    /// Rejects a rewound log, an invalid signed event, or a storage conflict.
    pub(crate) fn project_accepted_group_service(
        &self,
        previous: Option<&VerifiedGroupState>,
        next: &VerifiedGroupState,
    ) -> Result<(), SdkError> {
        if let Some(previous) = previous {
            let old = previous.snapshot().service_events.as_slice();
            let new = next.snapshot().service_events.as_slice();
            if rewinds_accepted_log(old, new) {
                return Err(invalid("group service event log rewrote an accepted change"));
            }
        }
        self.account_db()?.join_write(|| self.write_service_log(next))
    }

    fn write_service_log(&self, next: &VerifiedGroupState) -> Result<(), SdkError> {
        let mut kept = std::collections::BTreeSet::new();
        for event in &next.snapshot().service_events {
            let identity = service_identity(next, event)?;
            let message_id = ramflux_protocol::encode_base64url(&identity.id);
            let exact = Self::encode_generated_inner(
                identity.clone(),
                &g::Content { value: Some(g::content::Value::Service(service_for_event(event))) },
            )?;
            self.store_group_service_row(next, event, &identity, &exact)?;
            kept.insert(message_id);
        }
        self.drop_service_rows_outside(next, &kept)
    }

    fn drop_service_rows_outside(
        &self,
        next: &VerifiedGroupState,
        kept: &std::collections::BTreeSet<String>,
    ) -> Result<(), SdkError> {
        let conversation = next.view().conversation_id.clone();
        let rows = self.account_db()?.direct_messages(&conversation)?;
        for row in rows {
            if row.deleted
                || kept.contains(&row.message_id)
                || !body_is_service(&row.encrypted_body)
            {
                continue;
            }
            self.account_db()?.drop_replaced_service_projection(&conversation, &row.message_id)?;
        }
        Ok(())
    }

    fn store_group_service_row(
        &self,
        state: &VerifiedGroupState,
        event: &GroupServiceEvent,
        identity: &g::EventIdentity,
        exact: &[u8],
    ) -> Result<(), SdkError> {
        let message_id = ramflux_protocol::encode_base64url(&identity.id);
        let sender = state
            .view()
            .members
            .iter()
            .find(|member| {
                member.identity.root_commitment == event.author_root
                    && member.identity.device_id == event.author_device
            })
            .map_or_else(
                || event.author_root.clone(),
                |member| member.identity.principal_id.clone(),
            );
        let created_at = i64::try_from(event.hlc_ms / 1000).unwrap_or(state.snapshot().issued_at);
        let db = self.account_db()?;
        db.join_write(|| {
            if db.message_is_deleted(&message_id)? {
                return Ok(());
            }
            if let Some(existing) = db.direct_message_by_id(&message_id)? {
                let stored = db.message_content(&message_id)?;
                if existing.conversation_id != identity.conversation_id
                    || stored.as_deref() != Some(exact)
                {
                    return Err(SdkError::ReplayMismatch);
                }
                return Ok(());
            }
            let metadata = MessageMetadata::default();
            db.send_direct_message_at_with_metadata(DirectMessageWrite {
                conversation_id: &identity.conversation_id,
                message_id: &message_id,
                sender_id: &sender,
                encrypted_body: exact,
                metadata: &metadata,
                created_at,
            })?;
            db.store_message_content(&identity.conversation_id, &message_id, exact)?;
            db.persist_message_actor_state(
                &message_id,
                &format!("routed/generated-identity/{message_id}"),
                identity,
            )?;
            let local = self.owned_device_identity()?;
            if identity.author.as_ref().is_some_and(|author| {
                author.account_anchor == local.root_commitment()
                    && author.device_id == local.device_id()
            }) {
                db.mark_generated_message_owned(&message_id, &local)?;
            }
            self.journal_generated_receive_updates(exact)
        })
    }
}

/// A strict shorter prefix drops an accepted change. A divergent log is a replacement.
fn rewinds_accepted_log(old: &[GroupServiceEvent], new: &[GroupServiceEvent]) -> bool {
    new.len() < old.len()
        && new.iter().zip(old.iter()).all(|(next_event, old_event)| next_event == old_event)
}

fn body_is_service(body: &[u8]) -> bool {
    matches!(
        RamfluxClient::decode_generated_inner(body).ok().and_then(|(_, content)| content.value),
        Some(g::content::Value::Service(_))
    )
}

#[cfg(test)]
impl RamfluxClient {
    /// Chat rows only. Service projections remain visible through [`Self::direct_messages`].
    ///
    /// # Errors
    /// Returns an error when the conversation cannot be read.
    pub(crate) fn direct_chat_messages(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<ramflux_storage::DirectMessageRecord>, SdkError> {
        let rows = self.direct_messages(conversation_id)?;
        Ok(rows.into_iter().filter(|row| !body_is_service(&row.encrypted_body)).collect())
    }

    /// Live service projections in timeline order, as message id and exact stored bytes.
    ///
    /// # Errors
    /// Returns an error when the conversation cannot be read.
    pub(crate) fn service_projection_pin(
        &self,
        conversation_id: &str,
    ) -> Result<Vec<(String, Vec<u8>)>, SdkError> {
        let mut rows = Vec::new();
        for row in self.direct_messages(conversation_id)? {
            if !row.deleted && body_is_service(&row.encrypted_body) {
                rows.push((row.message_id, row.encrypted_body));
            }
        }
        rows.sort();
        Ok(rows)
    }
}

fn service_for_event(event: &GroupServiceEvent) -> g::Service {
    match &event.change {
        GroupServiceChange::SetName { name } => {
            service(g::ServiceAction::ServiceNameChanged, Vec::new(), Some(name.clone()))
        }
        GroupServiceChange::Add { root_commitment, device_id } => service(
            g::ServiceAction::ServiceMemberAdded,
            vec![subject(root_commitment, device_id)],
            None,
        ),
        GroupServiceChange::Remove { root_commitment, device_id } => service(
            g::ServiceAction::ServiceMemberRemoved,
            vec![subject(root_commitment, device_id)],
            None,
        ),
    }
}

fn subject(root: &str, device: &str) -> g::QualifiedDevice {
    g::QualifiedDevice {
        account_anchor: root.to_owned(),
        device_id: device.to_owned(),
        device_epoch: 0,
    }
}

fn service(
    action: g::ServiceAction,
    subjects: Vec<g::QualifiedDevice>,
    text: Option<String>,
) -> g::Service {
    g::Service {
        action: action as i32,
        subjects,
        text,
        target: None,
        native_authority_proof: Vec::new(),
    }
}

fn service_identity(
    state: &VerifiedGroupState,
    event: &GroupServiceEvent,
) -> Result<g::EventIdentity, SdkError> {
    let author = g::QualifiedDevice {
        account_anchor: event.author_root.clone(),
        device_id: event.author_device.clone(),
        device_epoch: event.device_epoch,
    };
    let conversation = state.view().conversation_id.clone();
    let id = g::identity::derive(&author, &conversation, event.device_sequence)
        .map_err(|_| invalid("group service identity"))?;
    let identity = g::EventIdentity {
        id: id.to_vec(),
        conversation_id: conversation,
        author: Some(author),
        device_sequence: event.device_sequence,
        hlc: event.hlc().map_err(|_| invalid("group service identity"))?,
        group_id: Some(state.view().group_id.clone()),
        group_epoch: Some(event.group_epoch),
    };
    g::identity::verify(&identity).map_err(|_| invalid("group service identity"))?;
    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client::native_test_support::{Fixture, TestResult};
    use ramflux_protocol::SharedGroupRole;

    const GROUP: &str = "service-row-group";
    const THREAD: &str = "service-row-thread";
    const JUMP_GROUP: &str = "service-jump-group";
    const JUMP_THREAD: &str = "service-jump-thread";

    fn lease(source: &Fixture) -> TestResult<crate::custody::PrimarySigningLease> {
        Ok(source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("test: native owner")?
            .group_primary(source.vault.as_ref())?)
    }

    fn change(source: &Fixture, change: GroupStateChange) -> TestResult<VerifiedGroupState> {
        let primary = lease(source)?;
        Ok(source.client.shared_group_change_with_primary(
            GROUP,
            &source.config.target_delivery_id,
            change,
            Some(&primary),
        )?)
    }

    fn service_rows(
        client: &RamfluxClient,
    ) -> TestResult<Vec<crate::client::typed_read_model::MessageView>> {
        service_rows_in(client, THREAD)
    }

    fn service_rows_in(
        client: &RamfluxClient,
        thread: &str,
    ) -> TestResult<Vec<crate::client::typed_read_model::MessageView>> {
        let page = client.generated_message_view_page(thread, None, 100)?;
        Ok(page.messages.into_iter().filter(|row| row.kind == "service").collect())
    }

    fn action(row: &crate::client::typed_read_model::MessageView) -> Option<i32> {
        match row.content.as_ref().and_then(|content| content.value.as_ref()) {
            Some(g::content::Value::Service(service)) => Some(service.action),
            _ => None,
        }
    }

    fn rows_with(
        rows: &[crate::client::typed_read_model::MessageView],
        kind: g::ServiceAction,
    ) -> Vec<&crate::client::typed_read_model::MessageView> {
        rows.iter().filter(|row| action(row) == Some(kind as i32)).collect()
    }

    #[tokio::test(flavor = "current_thread")]
    async fn accepted_group_changes_write_one_service_row_in_message_order() -> TestResult {
        match crate::client::native_test_support::watchdog::within(body()).await {
            Ok(result) => result,
            Err(elapsed) => Err(elapsed.into()),
        }
    }

    struct Scenario {
        owner: Fixture,
        peer: Fixture,
        added: VerifiedGroupState,
        renamed: VerifiedGroupState,
        before_sequence: u64,
        before_hlc: u64,
        after_sequence: u64,
        after_hlc: u64,
    }

    async fn prepare() -> TestResult<Scenario> {
        let owner = Fixture::with_device("service-row-owner", "phone").await?;
        let peer = Fixture::with_device("service-row-peer", "phone").await?;
        owner.accept_peer(&peer)?;
        peer.accept_peer(&owner)?;
        {
            let primary = lease(&owner)?;
            owner.client.shared_group_create_with_primary(
                GROUP,
                THREAD,
                Some("Checklist".into()),
                &owner.config.target_delivery_id,
                Some(&primary),
            )?;
        }
        let added = change(
            &owner,
            GroupStateChange::Add {
                member: peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        let before = owner.client.allocate_generated_identity(
            THREAD,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        let renamed = change(&owner, GroupStateChange::SetName { name: "Renamed".into() })?;
        let after = owner.client.allocate_generated_identity(
            THREAD,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        Ok(Scenario {
            owner,
            peer,
            added,
            renamed,
            before_sequence: before.device_sequence,
            before_hlc: before.hlc,
            after_sequence: after.device_sequence,
            after_hlc: after.hlc,
        })
    }

    async fn body() -> TestResult {
        let scenario = prepare().await?;
        let name = assert_owner_timeline(&scenario)?;
        assert_peer_rename(&scenario, &name)?;
        assert_prefix_rejects_a_shorter_log(&scenario)?;
        assert_role_change_writes_no_row(&scenario)?;
        assert_remove(&scenario)?;
        assert_late_device_keeps_every_signed_change().await?;
        Ok(())
    }

    fn assert_owner_timeline(
        scenario: &Scenario,
    ) -> TestResult<crate::client::typed_read_model::MessageView> {
        let owner_rows = service_rows(&scenario.owner.client)?;
        let name_rows = rows_with(&owner_rows, g::ServiceAction::ServiceNameChanged);
        assert_eq!(name_rows.len(), 1, "test: owner rename writes one name row");
        let name = name_rows[0].clone();
        assert_eq!(
            name.device_sequence.0,
            scenario.before_sequence + 1,
            "test: name row takes the next message sequence"
        );
        assert_eq!(
            scenario.after_sequence,
            name.device_sequence.0 + 1,
            "test: the following message takes the sequence after the name row"
        );
        let name_hlc = (name.hlc_ms << 16) | name.hlc_logical;
        assert!(
            name_hlc > scenario.before_hlc,
            "test: name row is ordered after the preceding allocation"
        );
        assert!(
            scenario.after_hlc > name_hlc,
            "test: the following allocation is ordered after the name row"
        );
        assert_eq!(
            name.content
                .as_ref()
                .and_then(|content| match content.value.as_ref() {
                    Some(g::content::Value::Service(service)) => service.text.clone(),
                    _ => None,
                })
                .as_deref(),
            Some("Renamed"),
            "test: name row carries the new group name"
        );
        assert!(name.is_own, "test: the signing device owns the name row");
        assert_eq!(
            rows_with(&owner_rows, g::ServiceAction::ServiceMemberAdded).len(),
            1,
            "test: member add writes one service row"
        );
        Ok(name)
    }

    fn assert_peer_rename(
        scenario: &Scenario,
        name: &crate::client::typed_read_model::MessageView,
    ) -> TestResult {
        assert!(scenario.peer.client.accept_shared_group_state(
            &scenario.added,
            &scenario.peer.config.target_delivery_id
        )?);
        let peer_rows = service_rows(&scenario.peer.client)?;
        let peer_added = rows_with(&peer_rows, g::ServiceAction::ServiceMemberAdded);
        assert_eq!(peer_added.len(), 1, "test: the first snapshot projects the signed add");
        let owner_rows = service_rows(&scenario.owner.client)?;
        let owner_added = rows_with(&owner_rows, g::ServiceAction::ServiceMemberAdded);
        assert_eq!(
            peer_added.first().map(|row| row.id.as_str()),
            owner_added.first().map(|row| row.id.as_str()),
            "test: both devices share the add event id"
        );
        assert!(scenario.peer.client.accept_shared_group_state(
            &scenario.renamed,
            &scenario.peer.config.target_delivery_id
        )?);
        let peer_rows = service_rows(&scenario.peer.client)?;
        let peer_name = rows_with(&peer_rows, g::ServiceAction::ServiceNameChanged);
        assert_eq!(peer_name.len(), 1, "test: peer rename writes one name row");
        assert_eq!(peer_name[0].id, name.id, "test: both devices share the signed event id");
        assert_eq!(
            peer_name[0].device_sequence, name.device_sequence,
            "test: both devices share the sequence"
        );
        assert_eq!(peer_name[0].hlc_ms, name.hlc_ms, "test: both devices share the physical clock");
        assert_eq!(
            peer_name[0].hlc_logical, name.hlc_logical,
            "test: both devices share the logical clock"
        );
        assert!(!peer_name[0].is_own, "test: a peer does not own the signer's row");
        assert!(!scenario.peer.client.accept_shared_group_state(
            &scenario.renamed,
            &scenario.peer.config.target_delivery_id
        )?);
        assert_eq!(
            rows_with(&service_rows(&scenario.peer.client)?, g::ServiceAction::ServiceNameChanged)
                .len(),
            1,
            "test: replaying the rename does not duplicate the row"
        );
        Ok(())
    }

    fn assert_prefix_rejects_a_shorter_log(scenario: &Scenario) -> TestResult {
        let before = service_rows(&scenario.owner.client)?.len();
        let error = scenario
            .owner
            .client
            .project_accepted_group_service(Some(&scenario.renamed), &scenario.added);
        match error {
            Err(SdkError::InboundRejected(reason)) => {
                assert!(
                    reason.contains("rewrote an accepted change"),
                    "test: shorter log refusal names the rewrite: {reason}"
                );
            }
            other => {
                return Err(
                    format!("test: a shorter service log must be refused, got {other:?}").into()
                );
            }
        }
        assert_eq!(
            service_rows(&scenario.owner.client)?.len(),
            before,
            "test: the refusal writes nothing"
        );
        Ok(())
    }

    fn assert_role_change_writes_no_row(scenario: &Scenario) -> TestResult {
        let before = service_rows(&scenario.owner.client)?.len();
        let role = change(
            &scenario.owner,
            GroupStateChange::SetRole {
                root_commitment: scenario
                    .peer
                    .client
                    .owned_device_identity()?
                    .root_commitment()
                    .to_owned(),
                device_id: scenario.peer.client.owned_device_identity()?.device_id().to_owned(),
                role: SharedGroupRole::Admin,
            },
        )?;
        assert_eq!(
            service_rows(&scenario.owner.client)?.len(),
            before,
            "test: a role change writes no service row"
        );
        assert!(
            scenario
                .peer
                .client
                .accept_shared_group_state(&role, &scenario.peer.config.target_delivery_id)?
        );
        assert_eq!(
            rows_with(&service_rows(&scenario.peer.client)?, g::ServiceAction::ServiceNameChanged)
                .len(),
            1,
            "test: accepting a role change keeps the single name row"
        );
        Ok(())
    }

    fn assert_remove(scenario: &Scenario) -> TestResult {
        let removed = change(
            &scenario.owner,
            GroupStateChange::Remove {
                root_commitment: scenario
                    .peer
                    .client
                    .owned_device_identity()?
                    .root_commitment()
                    .to_owned(),
                device_id: scenario.peer.client.owned_device_identity()?.device_id().to_owned(),
            },
        )?;
        let owner_rows_after_remove = service_rows(&scenario.owner.client)?;
        let owner_removed =
            rows_with(&owner_rows_after_remove, g::ServiceAction::ServiceMemberRemoved);
        assert_eq!(owner_removed.len(), 1, "test: member remove writes one service row");
        let owner_id = owner_removed[0].id.clone();
        assert!(
            scenario
                .peer
                .client
                .accept_shared_group_state(&removed, &scenario.peer.config.target_delivery_id)?
        );
        let peer_rows_after_remove = service_rows(&scenario.peer.client)?;
        let peer_removed =
            rows_with(&peer_rows_after_remove, g::ServiceAction::ServiceMemberRemoved);
        assert_eq!(peer_removed.len(), 1, "test: peer remove writes one service row");
        assert_eq!(peer_removed[0].id, owner_id, "test: both devices share the remove event id");
        assert!(
            !scenario
                .peer
                .client
                .accept_shared_group_state(&removed, &scenario.peer.config.target_delivery_id)?
        );
        assert_eq!(
            rows_with(
                &service_rows(&scenario.peer.client)?,
                g::ServiceAction::ServiceMemberRemoved
            )
            .len(),
            1,
            "test: replaying the remove does not duplicate the row"
        );
        Ok(())
    }

    async fn assert_late_device_keeps_every_signed_change() -> TestResult {
        let owner = Fixture::with_device("service-jump-owner", "phone").await?;
        let peer = Fixture::with_device("service-jump-peer", "phone").await?;
        let late = Fixture::with_device("service-jump-late", "phone").await?;
        owner.accept_peer(&peer)?;
        peer.accept_peer(&owner)?;
        owner.accept_peer(&late)?;
        late.accept_peer(&owner)?;
        {
            let primary = lease(&owner)?;
            owner.client.shared_group_create_with_primary(
                JUMP_GROUP,
                JUMP_THREAD,
                Some("Checklist".into()),
                &owner.config.target_delivery_id,
                Some(&primary),
            )?;
        }
        let added = change_in(
            &owner,
            JUMP_GROUP,
            GroupStateChange::Add {
                member: peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        let renamed =
            change_in(&owner, JUMP_GROUP, GroupStateChange::SetName { name: "Renamed".into() })?;
        let restored =
            change_in(&owner, JUMP_GROUP, GroupStateChange::SetName { name: "Checklist".into() })?;
        let final_state = change_in(
            &owner,
            JUMP_GROUP,
            GroupStateChange::Add {
                member: late.client.owned_group_actor(&late.config.target_delivery_id)?.identity,
                role: SharedGroupRole::Member,
            },
        )?;
        for state in [&added, &renamed, &restored, &final_state] {
            assert!(peer.client.accept_shared_group_state(state, &peer.config.target_delivery_id)?);
        }
        let branch = peer.client.device_branch.as_ref().ok_or("test: peer branch")?;
        let actor = peer.client.owned_group_actor(&peer.config.target_delivery_id)?;
        let resigned = ramflux_crypto::resign_group_state_snapshot(branch, &actor, &final_state)?;
        assert_ne!(
            resigned.snapshot().issuer.identity.root_commitment,
            final_state.snapshot().issuer.identity.root_commitment,
            "test: forwarding replaces the transport issuer"
        );
        assert_eq!(
            resigned.snapshot().service_events,
            final_state.snapshot().service_events,
            "test: forwarding keeps the creator-signed log"
        );
        assert_eq!(
            resigned.snapshot().state_hash,
            final_state.snapshot().state_hash,
            "test: forwarding keeps the creator state hash"
        );
        assert!(late.client.accept_shared_group_state(&resigned, &late.config.target_delivery_id)?);
        assert_jumped_and_forwarded_rows(&owner, &peer, &late, &final_state, &resigned)
    }

    fn assert_jumped_and_forwarded_rows(
        owner: &Fixture,
        peer: &Fixture,
        late: &Fixture,
        final_state: &VerifiedGroupState,
        resigned: &VerifiedGroupState,
    ) -> TestResult {
        let owner_ids = ordered_ids(&service_rows_in(&owner.client, JUMP_THREAD)?);
        let peer_ids = ordered_ids(&service_rows_in(&peer.client, JUMP_THREAD)?);
        let late_rows = service_rows_in(&late.client, JUMP_THREAD)?;
        let late_ids = ordered_ids(&late_rows);
        assert_eq!(owner_ids.len(), 4, "test: add, rename, rename-back and late add");
        assert_eq!(peer_ids, owner_ids, "test: a sequential peer shares every signed id");
        assert_eq!(late_ids, owner_ids, "test: one jumped snapshot projects the whole log");
        let names = rows_with(&late_rows, g::ServiceAction::ServiceNameChanged);
        assert_eq!(names.len(), 2, "test: rename-back is a second name row, not a cancellation");
        let texts = name_texts(&names)?;
        assert!(texts.contains(&"Renamed"), "test: the intermediate rename survives the jump");
        assert!(texts.contains(&"Checklist"), "test: the rename back is its own row");
        let owner_device = owner.client.owned_device_identity()?;
        for row in &names {
            let author = row.author.as_ref().ok_or("test: name row author")?;
            assert_eq!(author.account_anchor, owner_device.root_commitment());
            assert_eq!(author.device_id, owner_device.device_id());
            assert_ne!(
                author.account_anchor,
                resigned.snapshot().issuer.identity.root_commitment,
                "test: the row author is the allocating device, not the forwarder"
            );
        }
        let renamed_event = final_state
            .snapshot()
            .service_events
            .iter()
            .find(|event| {
                matches!(&event.change, GroupServiceChange::SetName { name } if name == "Renamed")
            })
            .ok_or("test: signed rename event")?;
        let forwarder = g::QualifiedDevice {
            account_anchor: resigned.snapshot().issuer.identity.root_commitment.clone(),
            device_id: resigned.snapshot().issuer.identity.device_id.clone(),
            device_epoch: renamed_event.device_epoch,
        };
        let derived = g::identity::derive(&forwarder, JUMP_THREAD, renamed_event.device_sequence)
            .map_err(|error| format!("test: forwarder derive: {error}"))?;
        let forwarder_id = ramflux_protocol::encode_base64url(derived);
        let renamed_row = names
            .iter()
            .find(|row| {
                row.content.as_ref().is_some_and(|content| {
                    matches!(
                        content.value.as_ref(),
                        Some(g::content::Value::Service(service))
                            if service.text.as_deref() == Some("Renamed")
                    )
                })
            })
            .ok_or("test: renamed row")?;
        assert_ne!(
            forwarder_id, renamed_row.id,
            "test: the forwarder's own sequence is a different event id"
        );
        assert!(!late.client.accept_shared_group_state(resigned, &late.config.target_delivery_id)?);
        assert_eq!(
            ordered_ids(&service_rows_in(&late.client, JUMP_THREAD)?),
            late_ids,
            "test: replaying the forwarded snapshot does not duplicate rows"
        );
        Ok(())
    }

    fn change_in(
        source: &Fixture,
        group: &str,
        change: GroupStateChange,
    ) -> TestResult<VerifiedGroupState> {
        let primary = lease(source)?;
        Ok(source.client.shared_group_change_with_primary(
            group,
            &source.config.target_delivery_id,
            change,
            Some(&primary),
        )?)
    }

    fn ordered_ids(rows: &[crate::client::typed_read_model::MessageView]) -> Vec<String> {
        let mut rows: Vec<&crate::client::typed_read_model::MessageView> = rows.iter().collect();
        rows.sort_by_key(|row| (row.hlc_ms, row.hlc_logical, row.device_sequence.0));
        rows.into_iter().map(|row| row.id.clone()).collect()
    }

    fn name_texts<'a>(
        rows: &[&'a crate::client::typed_read_model::MessageView],
    ) -> TestResult<Vec<&'a str>> {
        let mut texts = Vec::new();
        for row in rows {
            let text = row
                .content
                .as_ref()
                .and_then(|content| match content.value.as_ref() {
                    Some(g::content::Value::Service(service)) => service.text.as_deref(),
                    _ => None,
                })
                .ok_or("test: name row text")?;
            texts.push(text);
        }
        Ok(texts)
    }
}
