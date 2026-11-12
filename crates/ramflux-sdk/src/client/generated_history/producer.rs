// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Outgoing own-root history producer: durable transfer rows and exact-byte page chains.
//! A page carries only first-hand retained evidence; nothing is re-signed or fabricated.
use super::{RamfluxClient, SdkError, g};
use crate::client::identity_authority::NativeOperation;
use prost::Message as _;
use ramflux_crypto::RootQualifiedDeviceRef;
use serde::{Deserialize, Serialize};

/// Durable per-target transfer row. It never holds message content.
pub(super) const TRANSFER: &str = "history-out/transfer/";
/// Sealed in-flight page; bound to every item owner so any erasure invalidates the whole page.
pub(super) const PAGE: &str = "history/page/out/";
/// The receiver's chain bound; see `history_chain::transcript`.
pub(crate) const MAX_PAGE_ITEMS: usize = 32;
/// Local soft budget for exact item bytes, below the Inner wire bound, leaving room for the
/// page header, Control framing and the event identity.
pub(crate) const MAX_PAGE_ITEM_BYTES: usize = g::validation::MAX_INNER_BYTES - 16 * 1024;
/// A receiver forgets an idle transfer after 60 seconds and then only admits page zero.
/// The producer restarts its chain (never its item cursor) after twice that window.
pub(super) const RESTART_AFTER_IDLE_SECS: i64 = 120;

#[derive(Clone, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub(crate) struct Cursor {
    pub(crate) conversation: String,
    pub(crate) created_at: i64,
    pub(crate) message: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct InFlight {
    pub(crate) page: u64,
    pub(crate) previous: Vec<u8>,
    pub(crate) digest: Vec<u8>,
    pub(crate) after: Cursor,
    /// Authenticated references: the exact owners whose retained evidence the page carries.
    pub(crate) owners: Vec<String>,
    pub(crate) skipped: u64,
    /// Binds the cached sealed envelope to this record across restarts.
    pub(crate) envelope_id: String,
    pub(crate) payload_hash: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct Outgoing {
    pub(crate) transfer_id: Vec<u8>,
    pub(crate) target: String,
    pub(crate) target_epoch: u64,
    pub(crate) next_page: u64,
    pub(crate) last_digest: Vec<u8>,
    pub(crate) cursor: Option<Cursor>,
    pub(crate) in_flight: Option<InFlight>,
    pub(crate) last_submit_at: i64,
    pub(crate) next_at: i64,
    pub(crate) attempts: u32,
    pub(crate) exported: u64,
    pub(crate) skipped: u64,
    pub(crate) done: bool,
}

/// One page built from the local store, before sealing.
pub(crate) struct BuiltPage {
    pub(crate) conversation: String,
    pub(crate) page: g::HistoryPage,
    pub(crate) owners: Vec<String>,
    pub(crate) after: Cursor,
    pub(crate) skipped: u64,
}

pub(super) fn refused(reason: &str) -> SdkError {
    SdkError::GeneratedRefused {
        code: crate::error::GeneratedRefusalCode::Content,
        reason: reason.into(),
    }
}

fn random_transfer_id() -> Result<Vec<u8>, SdkError> {
    let mut bytes = [0_u8; 32];
    getrandom::fill(&mut bytes).map_err(|_| SdkError::CustodyRandomUnavailable)?;
    Ok(bytes.to_vec())
}

pub(super) fn transfer_key(target: &RootQualifiedDeviceRef) -> String {
    format!("{TRANSFER}{}", target.storage_key())
}

pub(super) fn page_key(target: &str) -> String {
    format!("{PAGE}{target}")
}

impl Outgoing {
    pub(super) fn new(
        target: &RootQualifiedDeviceRef,
        target_epoch: u64,
    ) -> Result<Self, SdkError> {
        Ok(Self {
            transfer_id: random_transfer_id()?,
            target: target.storage_key().into(),
            target_epoch,
            next_page: 0,
            last_digest: vec![0; 32],
            cursor: None,
            in_flight: None,
            last_submit_at: 0,
            next_at: 0,
            attempts: 0,
            exported: 0,
            skipped: 0,
            done: false,
        })
    }

    /// Restart the digest chain at page zero while keeping the durable item cursor.
    pub(super) fn restart_chain(&mut self) -> Result<(), SdkError> {
        self.transfer_id = random_transfer_id()?;
        self.next_page = 0;
        self.last_digest = vec![0; 32];
        self.in_flight = None;
        Ok(())
    }

    pub(super) fn chain_expired(&self, now: i64) -> bool {
        self.next_page > 0 && now.saturating_sub(self.last_submit_at) >= RESTART_AFTER_IDLE_SECS
    }
}

impl RamfluxClient {
    /// Current sync epoch of an own-root sibling, or `None` when it is not admitted.
    pub(super) fn history_target_epoch(
        &self,
        target: &RootQualifiedDeviceRef,
    ) -> Result<Option<u64>, SdkError> {
        let local = self.owned_device_identity()?;
        if target == &local || target.root_commitment() != local.root_commitment() {
            return Ok(None);
        }
        let now = crate::custody::network_now()?;
        let Some(authority) = self.current_custody_authority(target.root_commitment(), now)? else {
            return Err(SdkError::InboundPending("history target authority unavailable".into()));
        };
        Ok(authority
            .envelope()
            .body
            .devices
            .iter()
            .find(|entry| entry.device_id == target.device_id())
            .filter(|entry| {
                authority
                    .authorize(
                        &ramflux_protocol::custody::DeviceRef {
                            account_anchor: target.root_commitment().into(),
                            device_id: target.device_id().into(),
                            device_epoch: entry.device_epoch,
                        },
                        "sync",
                        now,
                    )
                    .is_ok()
            })
            .map(|entry| entry.device_epoch))
    }

    /// Durably start one history transfer to an admitted own-root sibling (the importing
    /// device). Returns `false` while an unfinished transfer to that target already exists:
    /// the receiver admits a single chain per source.
    /// # Errors
    /// Refuses the local device, a foreign root and a target without native Sync authority.
    pub(crate) fn stage_generated_history_transfer(
        &self,
        target: &RootQualifiedDeviceRef,
    ) -> Result<bool, SdkError> {
        self.require_native_operation(&self.owned_device_identity()?, NativeOperation::Sync)?;
        let epoch = self
            .history_target_epoch(target)?
            .ok_or_else(|| refused("history transport requires an admitted own-root sibling"))?;
        self.require_native_operation(target, NativeOperation::Sync)?;
        let db = self.account_db()?;
        let key = transfer_key(target);
        db.write_transaction(|| {
            if db.load_actor_state::<Outgoing>(&key)?.is_some_and(|row| !row.done) {
                return Ok(false);
            }
            db.remove_actor_state(&page_key(target.storage_key()))?;
            db.persist_actor_state(&key, &Outgoing::new(target, epoch)?)?;
            Ok(true)
        })
    }

    /// Start the native history transfer to one named own device (the importing device).
    /// The account's history courier then delivers the pages; progress is durable.
    /// # Errors
    /// Refuses an unknown device, the local device and a device without Sync authority.
    pub fn start_generated_history_transfer(
        &self,
        target_device_id: &str,
    ) -> Result<bool, SdkError> {
        let root = self.own_account_anchor()?;
        let target = self.device_identity_for_root(&root, target_device_id)?;
        self.stage_generated_history_transfer(&target)
    }

    /// Start a transfer to every admitted own-root sibling. Returns the number started.
    /// # Errors
    /// Returns authority and storage errors; an account without siblings starts nothing.
    pub fn start_generated_history_transfers(&self) -> Result<usize, SdkError> {
        let local = self.owned_device_identity()?;
        let now = crate::custody::network_now()?;
        let Some(authority) = self.current_custody_authority(local.root_commitment(), now)? else {
            return Ok(0);
        };
        let mut started = 0;
        for entry in &authority.envelope().body.devices {
            if entry.device_id == local.device_id() {
                continue;
            }
            let target =
                self.device_identity_for_root(local.root_commitment(), &entry.device_id)?;
            if self.history_target_epoch(&target)?.is_some()
                && self.stage_generated_history_transfer(&target)?
            {
                started += 1;
            }
        }
        Ok(started)
    }

    /// Build the next page strictly after `cursor`. Pages are homogeneous per conversation,
    /// hold at most 32 items and stay inside the exact-item byte budget. Rows without
    /// exportable first-hand evidence (legacy, deleted, retired, oversized) are skipped and
    /// counted, never forwarded as attested content.
    /// # Errors
    /// Returns storage errors and digest/encoding failures; evidence failures only skip a row.
    pub(crate) fn build_generated_history_page(
        &self,
        transfer_id: &[u8],
        page: u64,
        previous: &[u8],
        cursor: Option<&Cursor>,
    ) -> Result<Option<BuiltPage>, SdkError> {
        let db = self.account_db()?;
        let mut rows = db
            .all_direct_messages()?
            .into_iter()
            .map(|row| {
                (
                    Cursor {
                        conversation: row.conversation_id,
                        created_at: row.created_at,
                        message: row.message_id,
                    },
                    row.deleted,
                )
            })
            .filter(|(position, _)| cursor.is_none_or(|cursor| position > cursor))
            .collect::<Vec<_>>();
        rows.sort();
        let mut items = Vec::new();
        let mut owners = Vec::new();
        let mut exact = Vec::<Vec<u8>>::new();
        let (mut bytes, mut skipped) = (0_usize, 0_u64);
        let mut after = None;
        let mut conversation = None::<String>;
        for (position, deleted) in rows {
            if conversation.as_ref().is_some_and(|current| current != &position.conversation)
                || items.len() == MAX_PAGE_ITEMS
            {
                break;
            }
            let item = if deleted { None } else { self.exportable_history_item(&position)? };
            let Some(item) = item else {
                skipped += 1;
                after = Some(position);
                continue;
            };
            let encoded = item.encode_to_vec();
            if encoded.len() > MAX_PAGE_ITEM_BYTES {
                skipped += 1;
                after = Some(position);
                continue;
            }
            if bytes + encoded.len() > MAX_PAGE_ITEM_BYTES {
                break;
            }
            bytes += encoded.len();
            conversation = Some(position.conversation.clone());
            owners.push(position.message.clone());
            items.push(item);
            exact.push(encoded);
            after = Some(position);
        }
        let Some(after) = after else { return Ok(None) };
        let Some(conversation) = conversation else {
            // Only skipped rows remained; the caller still advances its durable cursor.
            return Ok(Some(BuiltPage {
                conversation: String::new(),
                page: g::HistoryPage::default(),
                owners,
                after,
                skipped,
            }));
        };
        let exact = exact.iter().map(Vec::as_slice).collect::<Vec<_>>();
        let digest = g::history_chain::digest(transfer_id, page, previous, &exact)
            .map_err(|_| refused("history page transcript out of bounds"))?;
        Ok(Some(BuiltPage {
            conversation,
            page: g::HistoryPage {
                transfer_id: transfer_id.to_vec(),
                page,
                previous_page_digest: previous.to_vec(),
                items,
                page_digest: digest.to_vec(),
            },
            owners,
            after,
            skipped,
        }))
    }

    fn exportable_history_item(&self, row: &Cursor) -> Result<Option<g::HistoryItem>, SdkError> {
        let Ok(id) = ramflux_protocol::decode_base64url(&row.message) else { return Ok(None) };
        if id.len() != 32 {
            return Ok(None);
        }
        match self.export_generated_history_item(&id) {
            Ok(item) => {
                let inner = g::Inner::decode(item.exact_inner.as_slice())
                    .map_err(|_| refused("stored history Inner malformed"))?;
                // The exported item must still belong to the row's conversation.
                Ok(inner
                    .identity
                    .is_some_and(|identity| identity.conversation_id == row.conversation)
                    .then_some(item))
            }
            Err(SdkError::HistoryEvidence(_) | SdkError::GeneratedRefused { .. }) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Encode a built page as the exact own-history Control Inner and prove that the
    /// receiver's exact-byte verifier accepts those bytes before anything is sealed.
    /// # Errors
    /// Refuses a page whose encoded bytes do not verify to the same page.
    pub(crate) fn encode_generated_history_page(
        &self,
        built: &BuiltPage,
    ) -> Result<(g::EventIdentity, Vec<u8>), SdkError> {
        let identity = self.allocate_generated_identity(
            &built.conversation,
            crate::client::generated_identity::now_ms(),
            true,
        )?;
        let control = crate::client::generated_control::control_from_payload(
            g::control::Payload::OwnHistory(built.page.clone()),
        )?;
        let inner = Self::encode_generated_inner(
            identity.clone(),
            &g::Content { value: Some(g::content::Value::Control(control)) },
        )?;
        let scanned = g::validation::scan_inner(&inner)
            .map_err(|_| refused("history Control Inner malformed"))?;
        let verified = g::history_chain::verify_control(scanned.body)
            .map_err(|_| refused("history page exact-item digest mismatch"))?;
        if verified != built.page {
            return Err(refused("history page does not survive exact encoding"));
        }
        Ok((identity, inner))
    }
}
