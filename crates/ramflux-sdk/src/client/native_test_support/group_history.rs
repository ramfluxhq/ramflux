// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Own-root group history cannot manufacture authority or roll back a signed membership head.
use super::*;
use crate::SdkError;
use ramflux_protocol::{GroupStateChange, SharedGroupRole, message as g};

const GROUP: &str = "native-history-group";
const THREAD: &str = "native-history-thread";
struct Case {
    source: Fixture,
    target: Fixture,
    peer: Fixture,
    state: ramflux_crypto::VerifiedGroupState,
}
impl Case {
    async fn new() -> TestResult<Self> {
        let mut source = Fixture::with_device("group-history-owner", "phone").await?;
        let target = source.enroll_sibling("group-history-target", "laptop").await?;
        let peer = Fixture::with_device("group-history-peer", "phone").await?;
        source.accept_peer(&peer)?;
        target.accept_peer(&peer)?;
        let primary = source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("native account")?
            .group_primary(source.vault.as_ref())?;
        source.client.shared_group_create_with_primary(
            GROUP,
            THREAD,
            Some("Signed name".into()),
            &source.config.target_delivery_id,
            Some(&primary),
        )?;
        let state = source.client.shared_group_change_with_primary(
            GROUP,
            &source.config.target_delivery_id,
            GroupStateChange::Add {
                member: peer.client.owned_group_actor(&peer.config.target_delivery_id)?.identity,
                role: SharedGroupRole::Member,
            },
            Some(&primary),
        )?;
        Ok(Self { source, target, peer, state })
    }
    fn capture(&self) -> TestResult<String> {
        let identity = self.source.client.allocate_generated_identity(
            THREAD,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        let owner = ramflux_protocol::encode_base64url(&identity.id);
        self.source.client.encrypt_generated_group_inner(
            GROUP,
            &self.source.config.device_id,
            identity,
            &g::Message { text: "historical group message".into(), ..Default::default() },
        )?;
        Ok(owner)
    }
    fn packet(&self) -> TestResult<ramflux_protocol::Envelope> {
        let plan = self
            .source
            .client
            .prepare_authored_history(&self.source.config)?
            .ok_or("history plan")?;
        let (_, packet) = self
            .source
            .client
            .seal_authored_history(
                &self.source.config,
                plan,
                self.source.material_for(&self.target)?,
            )?
            .ok_or("sealed history")?;
        Ok(packet)
    }
    fn accept_state(&self) -> TestResult {
        self.target
            .client
            .accept_shared_group_state(&self.state, &self.target.config.target_delivery_id)?;
        Ok(())
    }
}

#[tokio::test(flavor = "current_thread")]
async fn native_group_history_keeps_equal_device_labels_under_distinct_roots() -> TestResult {
    watchdog::within(async {
        let mut case = Case::new().await?;
        case.accept_state()?;
        let owner = case.capture()?;
        let packet = case.packet()?;
        case.target.receive(packet.clone(), 1).await?;
        case.target.receive(packet, 1).await?;
        assert_ne!(
            case.source.client.owned_device_identity()?,
            case.peer.client.owned_device_identity()?
        );
        let view = case.target.client.generated_message_detail(THREAD, &owner)?;
        assert_eq!(view.message.text.as_deref(), Some("historical group message"));
        assert_eq!(case.target.client.direct_chat_messages(THREAD)?.len(), 1);
        assert_eq!(
            case.target
                .client
                .account_db()?
                .shared_group_state(GROUP)?
                .ok_or("state")?
                .view()
                .epoch,
            2
        );
        assert_eq!(
            case.target
                .client
                .account_db()?
                .client_record("conversation", THREAD)?
                .ok_or("thread")?["title"],
            "Signed name"
        );
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn own_group_context_cannot_supply_missing_independent_native_authority() -> TestResult {
    watchdog::within(async {
        let mut case = Case::new().await?;
        let owner = case.capture()?;
        let packet = case.packet()?;
        let error = case.target.receive(packet, 1).await.err().ok_or("missing independent group authority accepted")?;
        assert!(matches!(error.downcast_ref::<SdkError>(), Some(SdkError::GeneratedRefused { code: crate::GeneratedRefusalCode::Authority, reason }) if reason == "generated group: verified native group state required"), "unexpected refusal: {error}");
        assert!(case.target.client.account_db()?.shared_group_state(GROUP)?.is_none());
        assert!(case.target.client.account_db()?.message_content(&owner)?.is_none());
        assert_eq!(case.target.client.direct_messages(THREAD)?.len(), 0);
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn stale_own_group_context_preserves_current_signed_removal() -> TestResult {
    watchdog::within(async {
        let mut case = Case::new().await?;
        case.accept_state()?;
        let owner = case.capture()?;
        let packet = case.packet()?;
        let primary = case
            .source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("native account")?
            .group_primary(case.source.vault.as_ref())?;
        let latest = case.source.client.shared_group_change_with_primary(
            GROUP,
            &case.source.config.target_delivery_id,
            GroupStateChange::Remove {
                root_commitment: case.peer.client.own_account_anchor()?,
                device_id: case.peer.config.device_id.clone(),
            },
            Some(&primary),
        )?;
        case.target
            .client
            .accept_shared_group_state(&latest, &case.target.config.target_delivery_id)?;
        let before =
            case.target.client.account_db()?.shared_group_state(GROUP)?.ok_or("current state")?;
        case.target.receive(packet.clone(), 1).await?;
        case.target.receive(packet, 1).await?;
        let after =
            case.target.client.account_db()?.shared_group_state(GROUP)?.ok_or("retained state")?;
        assert_eq!(
            after.snapshot(),
            before.snapshot(),
            "stale copied context changed signed authority"
        );
        let peer = case.peer.client.owned_device_identity()?;
        assert!(after.view().effective_role(peer.root_commitment(), peer.device_id()).is_none());
        assert_eq!(
            case.target.client.generated_message_detail(THREAD, &owner)?.message.text.as_deref(),
            Some("historical group message")
        );
        Ok(())
    })
    .await?
}

#[tokio::test(flavor = "current_thread")]
async fn own_device_history_import_skips_group_message_below_joined_epoch() -> TestResult {
    watchdog::within(async {
        let mut source = Fixture::with_device("group-floor-owner", "phone").await?;
        let target = source.enroll_sibling("group-floor-target", "laptop").await?;
        let primary = source
            .client
            .born_v3_account
            .as_ref()
            .ok_or("native account")?
            .group_primary(source.vault.as_ref())?;
        source.client.shared_group_create_with_primary(
            GROUP,
            THREAD,
            Some("Floor".into()),
            &source.config.target_delivery_id,
            Some(&primary),
        )?;
        // The message is authored at epoch one, before the laptop joins the group.
        let identity = source.client.allocate_generated_identity(
            THREAD,
            crate::client::generated_identity::now_ms(),
            false,
        )?;
        let owner = ramflux_protocol::encode_base64url(&identity.id);
        source.client.encrypt_generated_group_inner(
            GROUP,
            &source.config.device_id,
            identity,
            &g::Message { text: "message before the join".into(), ..Default::default() },
        )?;
        let joined = source.client.shared_group_change_with_primary(
            GROUP,
            &source.config.target_delivery_id,
            GroupStateChange::Add {
                member: target
                    .client
                    .owned_group_actor(&target.config.target_delivery_id)?
                    .identity,
                role: SharedGroupRole::Member,
            },
            Some(&primary),
        )?;
        target.client.accept_shared_group_state(&joined, &target.config.target_delivery_id)?;
        let plan = source.client.prepare_authored_history(&source.config)?.ok_or("history plan")?;
        let (_, packet) = source
            .client
            .seal_authored_history(&source.config, plan, source.material_for(&target)?)?
            .ok_or("sealed history")?;
        let mut target = target;
        let refusal = target.receive(packet, 1).await;
        assert!(refusal.is_err(), "a group message below the joined epoch must be refused");
        assert!(target.client.account_db()?.message_content(&owner)?.is_none());
        assert_eq!(target.client.direct_chat_messages(THREAD)?.len(), 0);
        Ok(())
    })
    .await?
}
