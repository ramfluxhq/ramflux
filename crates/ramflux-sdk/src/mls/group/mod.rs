// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! SDK group engine. Decisions take the caller's `now_ms` and do not read a clock.

mod apply;
mod attach;
mod commit;
mod events;
mod host;
mod join;
mod post;
pub(crate) mod session;
mod store;
mod tokens;

use std::path::PathBuf;

use ramflux_mls::Mls;
use serde_json::Value;

use self::events::GroupEvent;
use self::store::{HistoryRow, PendingRow, Store};
use self::tokens::QuotaView;
use crate::mls::{MlsRuntime, SqlMlsKv};
use crate::{RamfluxClient, SdkError};

/// Borrowed account handles for one group operation.
pub(crate) struct Parts<'a> {
    pub mls: &'a Mls<SqlMlsKv>,
    pub store: &'a Store,
    pub root: PathBuf,
}

pub(crate) struct GroupEngine<'a> {
    client: &'a RamfluxClient,
    runtime: &'a MlsRuntime,
}

pub(crate) struct CreateResult {
    pub group_id: [u8; 32],
    pub epoch: u64,
}

pub(crate) enum JoinOutcome {
    Joined { group_id: [u8; 32] },
    Pending { request_id: String, reason: String, expires_at: u64 },
    Refused { reason: String, params: Value },
}

pub(crate) enum SendState {
    Sent { log_seq: u64 },
    Queued { reason: String },
    DelayedPrivacy { send_after: u64, delay_s: u64 },
    Uploading,
    RateLimited { bucket: &'static str, retry_after_s: Option<u64> },
    Failed { reason: String },
}

pub(crate) struct GroupInfo {
    pub group_id: [u8; 32],
    pub name: String,
    pub epoch: u64,
    pub leaf_count: u32,
    pub member: bool,
    pub approval: bool,
    pub warnings: Vec<String>,
    pub quota: QuotaView,
}

pub(crate) struct InviteRecord {
    pub invite_id: [u8; 16],
    pub link: String,
    pub max_uses: u32,
    pub expires_at: u64,
    pub revoked: bool,
}

impl<'a> GroupEngine<'a> {
    pub(crate) fn new(client: &'a RamfluxClient, runtime: &'a MlsRuntime) -> Self {
        Self { client, runtime }
    }

    fn store_handle(&self) -> Result<Store, SdkError> {
        Ok(Store::open(self.client.account_db()?.mls_kv()))
    }

    pub(crate) async fn create(&self, name: &str, approval: bool, now_ms: u64) -> Result<CreateResult, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        commit::create(self.client, &parts, name, approval, now_ms).await
    }

    pub(crate) async fn invite_put(
        &self,
        group_id: &[u8; 32],
        max_uses: u32,
        ttl_ms: u64,
        now_ms: u64,
    ) -> Result<InviteRecord, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        commit::invite_put(&parts, group_id, max_uses, ttl_ms, now_ms).await
    }

    pub(crate) async fn invite_revoke(
        &self,
        group_id: &[u8; 32],
        invite_id: &[u8; 16],
        now_ms: u64,
    ) -> Result<(), SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        let _ = now_ms;
        commit::invite_revoke(&parts, group_id, invite_id).await
    }

    pub(crate) fn invite_list(&self, group_id: &[u8; 32]) -> Result<Vec<InviteRecord>, SdkError> {
        commit::invite_list(&self.store_handle()?, group_id)
    }

    pub(crate) async fn join_invite(&self, link: &str, now_ms: u64) -> Result<JoinOutcome, SdkError> {
        let store = self.store_handle()?;
        join::join_invite(self.client, self.runtime.mls(), &store, link, now_ms).await
    }

    pub(crate) async fn join_own_device(&self, group_id: &[u8; 32], now_ms: u64) -> Result<JoinOutcome, SdkError> {
        let store = self.store_handle()?;
        join::join_member_kind(
            self.client,
            self.runtime.mls(),
            &store,
            group_id,
            ramflux_crypto::large_group::JoinKind::OwnDevice,
            now_ms,
        )
        .await
    }

    pub(crate) async fn rejoin(&self, group_id: &[u8; 32], now_ms: u64) -> Result<JoinOutcome, SdkError> {
        let store = self.store_handle()?;
        join::join_member_kind(
            self.client,
            self.runtime.mls(),
            &store,
            group_id,
            ramflux_crypto::large_group::JoinKind::Rejoin,
            now_ms,
        )
        .await
    }

    pub(crate) async fn welcome_poll(&self, group_id: &[u8; 32], now_ms: u64) -> Result<JoinOutcome, SdkError> {
        let store = self.store_handle()?;
        join::welcome_poll(self.client, self.runtime.mls(), &store, group_id, now_ms).await
    }

    pub(crate) async fn post_text(&self, group_id: &[u8; 32], text: &str, now_ms: u64) -> Result<SendState, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        post::post_text(&parts, group_id, text, now_ms).await
    }

    pub(crate) async fn post_card(&self, group_id: &[u8; 32], card_json: &str, now_ms: u64) -> Result<SendState, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        post::post_card(&parts, group_id, card_json, now_ms).await
    }

    pub(crate) async fn post_attachments(
        &self,
        group_id: &[u8; 32],
        files: &[&[u8]],
        now_ms: u64,
    ) -> Result<SendState, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        post::post_attachments(&parts, group_id, files, now_ms).await
    }

    pub(crate) async fn submit_application(
        &self,
        group_id: &[u8; 32],
        bytes: &[u8],
        now_ms: u64,
    ) -> Result<SendState, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        post::submit_application(&parts, group_id, bytes, now_ms).await
    }

    pub(crate) async fn delete_own(&self, group_id: &[u8; 32], post_id: &str, now_ms: u64) -> Result<SendState, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        post::delete_own(&parts, group_id, post_id, now_ms).await
    }

    pub(crate) async fn load_attachment(
        &self,
        group_id: &[u8; 32],
        blob_ref: &[u8; 32],
        now_ms: u64,
    ) -> Result<Vec<u8>, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        post::load_attachment(&parts, group_id, blob_ref, now_ms).await
    }

    pub(crate) async fn apply(&self, group_id: &[u8; 32], now_ms: u64) -> Result<Vec<GroupEvent>, SdkError> {
        let store = self.store_handle()?;
        let parts = Parts { mls: self.runtime.mls(), store: &store, root: join::data_root(self.client)? };
        apply::apply(&parts, group_id, now_ms).await
    }

    #[allow(clippy::unused_self)]
    pub(crate) fn member_live(&self, group_id: &[u8; 32]) -> bool {
        session::member_live(group_id)
    }

    pub(crate) fn history(&self, group_id: &[u8; 32]) -> Result<Vec<HistoryRow>, SdkError> {
        let store = self.store_handle()?;
        let group = commit::load_group(&store, group_id)?;
        commit::require_member(&group)?;
        store.history(group_id)
    }

    pub(crate) fn info(&self, group_id: &[u8; 32], now_ms: u64) -> Result<GroupInfo, SdkError> {
        let store = self.store_handle()?;
        let group = commit::load_group(&store, group_id)?;
        commit::require_member(&group)?;
        let wallet = store.wallet(group_id)?;
        let quota = tokens::quota_view(&group, &wallet, now_ms);
        Ok(GroupInfo {
            group_id: group.group_id,
            name: group.name,
            epoch: group.epoch,
            leaf_count: group.leaf_count,
            member: group.member,
            approval: group.approval,
            warnings: group.warnings,
            quota,
        })
    }

    pub(crate) fn mark_read(&self, group_id: &[u8; 32], log_seq: u64) -> Result<GroupEvent, SdkError> {
        let store = self.store_handle()?;
        let mut group = commit::load_group(&store, group_id)?;
        commit::require_member(&group)?;
        if log_seq > group.read_log_seq {
            group.read_log_seq = log_seq;
            store.put_group_merged(&group)?;
        }
        let unread = group.log_seq.saturating_sub(group.read_log_seq);
        Ok(events::read_event(&group.group_id, group.read_log_seq, unread, 0))
    }

    pub(crate) fn pending_joins(&self) -> Result<Vec<PendingRow>, SdkError> {
        self.store_handle()?.pending()
    }
}

pub(crate) fn rate_limited_state(detail: &str) -> SendState {
    let mut parts = detail.split(':');
    let bucket = match parts.next() {
        Some("commit") => "commit",
        Some("open") => "open",
        Some("attach") => "attach",
        _ => "post",
    };
    let retry_after_s = parts.next().and_then(|text| text.parse().ok());
    SendState::RateLimited { bucket, retry_after_s }
}

pub(crate) fn send_state_of(result: Result<u64, SdkError>) -> SendState {
    match result {
        Ok(log_seq) => SendState::Sent { log_seq },
        Err(error) => match &error {
            SdkError::Mls { code, detail } if *code == "rate_limited" => rate_limited_state(detail),
            SdkError::Mls { code, .. } if *code == "not_member" || *code == "bad_request" || *code == "unauthorized" => {
                SendState::Failed { reason: error.to_string() }
            }
            _ => SendState::Queued { reason: error.to_string() },
        },
    }
}
