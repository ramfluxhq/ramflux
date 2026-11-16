// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! One timeline service row for an accepted group-state snapshot.
//!
//! The signed `service_order` is the message ordering key. Every member reconstructs the same
//! event identity from it. A snapshot that does not change the name or the membership writes no row.
use std::collections::BTreeSet;

use ramflux_crypto::VerifiedGroupState;
use ramflux_protocol::group_state::{
    GroupServiceOrder, GroupStateActor, GroupStateChange, SharedGroupState,
};
use ramflux_protocol::message as g;
use ramflux_storage::{DirectMessageWrite, MessageMetadata};

use crate::{RamfluxClient, SdkError};

use super::invalid;

/// `validate_service` refuses more subjects than this. A jump past the cap is an error.
const MAX_SERVICE_SUBJECTS: usize = 64;

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

    /// Write the one service row for `next` when it differs from `previous` in a mapped way.
    ///
    /// Replay of the same bytes is a no-op. A different body under the same derived id is
    /// `ReplayMismatch`.
    ///
    /// # Errors
    /// Rejects an invalid signed order, more than 64 subjects, or a storage conflict.
    pub(crate) fn project_accepted_group_service(
        &self,
        previous: &VerifiedGroupState,
        next: &VerifiedGroupState,
    ) -> Result<(), SdkError> {
        let Some(service) = service_for_delta(previous.view(), next.view())? else {
            return Ok(());
        };
        let identity = service_identity(next)?;
        let exact = Self::encode_generated_inner(
            identity.clone(),
            &g::Content { value: Some(g::content::Value::Service(service)) },
        )?;
        self.store_group_service_row(next, &identity, &exact)
    }

    fn store_group_service_row(
        &self,
        state: &VerifiedGroupState,
        identity: &g::EventIdentity,
        exact: &[u8],
    ) -> Result<(), SdkError> {
        let message_id = ramflux_protocol::encode_base64url(&identity.id);
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
                sender_id: &state.snapshot().issuer.identity.principal_id,
                encrypted_body: exact,
                metadata: &metadata,
                created_at: state.snapshot().issued_at,
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

/// One snapshot has one signed order. A jump that changes several categories records the
/// highest-priority one: the name, then additions, then removals.
fn service_for_delta(
    previous: &SharedGroupState,
    next: &SharedGroupState,
) -> Result<Option<g::Service>, SdkError> {
    if previous.name != next.name {
        return Ok(Some(service(
            g::ServiceAction::ServiceNameChanged,
            Vec::new(),
            Some(next.name.clone().unwrap_or_default()),
        )));
    }
    let previous_ids = member_ids(previous);
    let next_ids = member_ids(next);
    let added = members_only(next, &previous_ids)?;
    if !added.is_empty() {
        return Ok(Some(service(g::ServiceAction::ServiceMemberAdded, added, None)));
    }
    let removed = members_only(previous, &next_ids)?;
    if !removed.is_empty() {
        return Ok(Some(service(g::ServiceAction::ServiceMemberRemoved, removed, None)));
    }
    Ok(None)
}

fn member_ids(state: &SharedGroupState) -> BTreeSet<(&str, &str)> {
    state
        .members
        .iter()
        .map(|member| {
            (member.identity.root_commitment.as_str(), member.identity.device_id.as_str())
        })
        .collect()
}

fn members_only(
    state: &SharedGroupState,
    other: &BTreeSet<(&str, &str)>,
) -> Result<Vec<g::QualifiedDevice>, SdkError> {
    let mut subjects: Vec<g::QualifiedDevice> = state
        .members
        .iter()
        .filter(|member| {
            !other.contains(&(
                member.identity.root_commitment.as_str(),
                member.identity.device_id.as_str(),
            ))
        })
        .map(|member| g::QualifiedDevice {
            account_anchor: member.identity.root_commitment.clone(),
            device_id: member.identity.device_id.clone(),
            device_epoch: 0,
        })
        .collect();
    if subjects.len() > MAX_SERVICE_SUBJECTS {
        return Err(invalid("group service subjects exceed the row limit"));
    }
    subjects.sort_by(|left, right| {
        (&left.account_anchor, &left.device_id).cmp(&(&right.account_anchor, &right.device_id))
    });
    Ok(subjects)
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

fn service_identity(state: &VerifiedGroupState) -> Result<g::EventIdentity, SdkError> {
    let snapshot = state.snapshot();
    let order = &snapshot.service_order;
    let author = g::QualifiedDevice {
        account_anchor: snapshot.issuer.identity.root_commitment.clone(),
        device_id: snapshot.issuer.identity.device_id.clone(),
        device_epoch: order.device_epoch,
    };
    let conversation = state.view().conversation_id.clone();
    let id = g::identity::derive(&author, &conversation, order.device_sequence)
        .map_err(|_| invalid("group service identity"))?;
    let identity = g::EventIdentity {
        id: id.to_vec(),
        conversation_id: conversation,
        author: Some(author),
        device_sequence: order.device_sequence,
        hlc: order.hlc()?,
        group_id: Some(state.view().group_id.clone()),
        group_epoch: Some(state.view().epoch),
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
        let page = client.generated_message_view_page(THREAD, None, 100)?;
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
        assert_role_change_writes_no_row(&scenario)?;
        assert_remove(&scenario)?;
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
        assert_eq!(
            service_rows(&scenario.peer.client)?.len(),
            0,
            "test: the first snapshot has no earlier state to diff"
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
}
