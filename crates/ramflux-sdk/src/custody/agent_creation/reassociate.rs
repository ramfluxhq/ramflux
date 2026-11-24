// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Move one desktop's agent inventory onto the human account created by a fresh pairing.
//!
//! The pairing protocol is unchanged. After that ceremony is installed, this journal copies the
//! completed publishing records, rebind inventory and agent metadata, points each agent at the new
//! local human id, and freezes a new rebind plan. Agent ids, anchors and vault references stay.
//! An open journal refuses activation, cleanup and a second inventory.

use super::rebind::{RebindBinding, RebindEntry};
use super::rebind_plan::is_rebind;
use super::rebind_send::prepare_rebind_request;
use super::state::AgentCreationState;
use super::store::{AgentCreationRecord, AgentCreationStore, write_json_atomic};
use crate::SdkError;
use crate::custody::pairing::install_store::{self, Install};
use crate::custody::{self, load_account, load_data_account, retarget_agent_custodian};
use ramflux_protocol::custody::{
    DeviceRef, DeviceSet, Envelope, decode_register_plan, object_hash,
};
use ramflux_protocol::decode_base64url;
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs;
use std::io::{ErrorKind, Read};
use std::path::{Path, PathBuf};

const SCHEMA: &str = "ramflux.agent_reassociation.v1";
const MAX_AGENTS: usize = 256;
const MAX_FILES: usize = 2_048;
const MAX_FILE_BYTES: u64 = 64 * 1024;
const MAX_JOURNAL_BYTES: u64 = 256 * 1024;
const MAX_ACCOUNTS: usize = 1_024;
const DIR_NAME: &str = "agent_reassociation";

/// What the caller locks before the file phases run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Settlement {
    pub source: String,
    pub destination: String,
    pub agents: Vec<String>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Planned,
    Moving,
    Pointers,
    Suspended,
    Plans,
    Complete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Journal {
    schema: String,
    phase: Phase,
    operation_id: String,
    source_account_id: String,
    destination_account_id: String,
    source_anchor: String,
    destination_anchor: String,
    desktop: DeviceRef,
    agents: Vec<String>,
    files: Vec<String>,
    unresolved: Vec<String>,
}

struct HumanRow {
    id: String,
    anchor: String,
}

/// Write the planned journal, or return the open one that already names `human`.
///
/// `Ok(None)` when this account has nothing to move and no open journal. Ambiguous inventories
/// and a destination that already has agent files are refused and write nothing.
///
/// # Errors
/// `reassociation_ambiguous` when more than one human inventory shares the anchor.
/// `reassociation_conflict` when the destination already holds agent files. I/O and corrupt
/// journals pass through.
pub(crate) fn plan_reassociation(
    root: &Path,
    human: &str,
    source_unlocked: &dyn Fn(&str) -> bool,
) -> Result<Option<Settlement>, SdkError> {
    custody::valid_id(human)?;
    if let Some(journal) = open_journal_for(root, human)? {
        return Ok(Some(settlement_of(&journal)));
    }
    let Some(draft) = discover(root, human, source_unlocked)? else {
        return Ok(None);
    };
    let journal = Journal {
        schema: SCHEMA.to_owned(),
        phase: Phase::Planned,
        operation_id: draft.operation_id,
        source_account_id: draft.source,
        destination_account_id: draft.destination,
        source_anchor: draft.anchor.clone(),
        destination_anchor: draft.anchor,
        desktop: draft.desktop,
        agents: draft.agents,
        files: draft.files,
        unresolved: Vec::new(),
    };
    check_journal(&journal)?;
    save_journal(root, &journal)?;
    Ok(Some(settlement_of(&journal)))
}

/// Run every remaining phase of the open journal that names `human`.
///
/// `Ok(false)` leaves the journal open (the caller must not advance or activate). `Ok(true)`
/// means there is no open journal for this account.
///
/// # Errors
/// A ceremony that no longer matches the installed marker, or a destination file that is
/// missing, is `reassociation_conflict`. A destination file that exists but no longer matches
/// the source is the repair plan written after the copy: the source stays, and the advance
/// continues. Nothing already copied is deleted on the conflict path.
pub(crate) fn advance_reassociation(root: &Path, human: &str, now: u64) -> Result<bool, SdkError> {
    release_completed_sources(root, human)?;
    let Some(mut journal) = open_journal_for(root, human)? else {
        return Ok(true);
    };
    require_same_ceremony(root, &journal)?;
    if journal.phase == Phase::Planned {
        journal.phase = Phase::Moving;
        save_journal(root, &journal)?;
    }
    if journal.phase == Phase::Moving {
        copy_files(root, &journal)?;
        journal.phase = Phase::Pointers;
        save_journal(root, &journal)?;
    }
    if journal.phase == Phase::Pointers {
        retarget_all(root, &journal)?;
        journal.phase = Phase::Suspended;
        save_journal(root, &journal)?;
    }
    if journal.phase == Phase::Suspended {
        let store = AgentCreationStore::open(root, &journal.destination_account_id)?;
        suspend_destination(&store, &mut journal)?;
        save_journal(root, &journal)?;
        journal.phase = Phase::Plans;
        save_journal(root, &journal)?;
    }
    if journal.phase == Phase::Plans {
        match freeze_plans(root, &journal, now) {
            Ok(()) => {}
            Err(SdkError::PairingCode("PublicationPending")) => return Ok(false),
            Err(error) => return Err(error),
        }
        journal.phase = Phase::Complete;
        save_journal(root, &journal)?;
    }
    if journal.phase == Phase::Complete {
        remove_source_files(root, &journal)?;
        return Ok(true);
    }
    Ok(false)
}

/// Whether an open journal still owns this creation store.
///
/// # Errors
/// A corrupt journal is `CustodySetupInvalid`.
pub(crate) fn store_is_fenced(store: &AgentCreationStore) -> Result<bool, SdkError> {
    Ok(open_journal_for(store.root(), store.human_account_id()?)?.is_some())
}

/// Delete source copies named by a finished journal for `human`.
///
/// An open journal is left untouched. A crash after the journal is marked complete resumes here:
/// the finished journal is not an open one, and the copy is removed only when the bytes match.
/// Bytes that diverged after the copy (the frozen repair plan) are left on the source.
///
/// # Errors
/// `reassociation_conflict` when a journaled destination file is missing. I/O failures pass
/// through.
pub(crate) fn release_completed_sources(root: &Path, human: &str) -> Result<(), SdkError> {
    custody::valid_id(human)?;
    let entries = match fs::read_dir(journal_dir(root)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(SdkError::CustodyVaultUnavailable),
    };
    let mut seen = 0usize;
    for entry in entries {
        let entry = entry.map_err(|_| SdkError::CustodyVaultUnavailable)?;
        seen = seen.saturating_add(1);
        if seen > MAX_ACCOUNTS {
            return Err(SdkError::CustodySetupInvalid);
        }
        release_one(root, human, &entry)?;
    }
    Ok(())
}

fn release_one(root: &Path, human: &str, entry: &fs::DirEntry) -> Result<(), SdkError> {
    let name = entry.file_name();
    let Some(destination) = name.to_str().and_then(|text| text.strip_suffix(".json")) else {
        return Ok(());
    };
    let Some(journal) = load_journal(root, destination)? else {
        return Ok(());
    };
    if journal.phase == Phase::Complete
        && (journal.source_account_id == human || journal.destination_account_id == human)
    {
        remove_source_files(root, &journal)?;
    }
    Ok(())
}

/// Binding forced while `agent_account_id` is named by an open journal.
///
/// # Errors
/// A corrupt journal is `CustodySetupInvalid`.
pub(crate) fn fenced_agent_binding(
    root: &Path,
    agent_account_id: &str,
) -> Result<Option<RebindBinding>, SdkError> {
    custody::valid_id(agent_account_id)?;
    for journal in open_journals(root)? {
        if journal.agents.iter().any(|id| id == agent_account_id) {
            return Ok(Some(RebindBinding::RebindPending));
        }
    }
    Ok(None)
}

/// Whether a fresh plan can name the stored agent head.
///
/// An in-flight publication, or a complete copy that is not the stored head, is not ready.
///
/// # Errors
/// Store and authority read failures pass through.
pub(crate) fn fresh_plan_ready(
    root: &Path,
    store: &AgentCreationStore,
    agent_account_id: &str,
) -> Result<bool, SdkError> {
    if unresolved_ids(store)?.iter().any(|id| id == agent_account_id) {
        return Ok(false);
    }
    let Some(record) = newest_complete(store, agent_account_id)? else {
        return Ok(false);
    };
    authority_matches(root, agent_account_id, &record)
}

/// Whether the owner still has to approve this binding's current plan.
///
/// A missing request id still needs a plan. A frozen plan with no decision is sent again.
/// A publishing or decided request is not sent as a new approval.
///
/// # Errors
/// A corrupt request file is `CustodySetupInvalid`.
pub(crate) fn rebind_awaits_owner(
    store: &AgentCreationStore,
    entry: &RebindEntry,
) -> Result<bool, SdkError> {
    if entry.binding != RebindBinding::RebindPending {
        return Ok(false);
    }
    let Some(request_id) = &entry.request_id else {
        return Ok(true);
    };
    let Some(record) = store.load(request_id)? else {
        return Ok(true);
    };
    Ok(record.state == AgentCreationState::AuthorizationPending && record.decision_b64.is_none())
}

struct Draft {
    source: String,
    destination: String,
    anchor: String,
    operation_id: String,
    desktop: DeviceRef,
    agents: Vec<String>,
    files: Vec<String>,
}

fn settlement_of(journal: &Journal) -> Settlement {
    Settlement {
        source: journal.source_account_id.clone(),
        destination: journal.destination_account_id.clone(),
        agents: journal.agents.clone(),
    }
}

fn discover(
    root: &Path,
    human: &str,
    source_unlocked: &dyn Fn(&str) -> bool,
) -> Result<Option<Draft>, SdkError> {
    if journal_destination_exists(root, human)? {
        return Ok(None);
    }
    let rows = human_rows(root)?;
    let Some(here) = rows.iter().find(|row| row.id == human) else {
        return Ok(None);
    };
    let files = move_files(root, human)?;
    if files.is_empty() {
        discover_destination(root, human, here, &rows, source_unlocked)
    } else {
        discover_source(root, human, here, &rows, &files, source_unlocked)
    }
}

fn discover_source(
    root: &Path,
    human: &str,
    here: &HumanRow,
    rows: &[HumanRow],
    files: &[String],
    source_unlocked: &dyn Fn(&str) -> bool,
) -> Result<Option<Draft>, SdkError> {
    if !source_unlocked(human) {
        return Ok(None);
    }
    let mut destinations = Vec::new();
    for row in rows.iter().filter(|row| row.id != human && row.anchor == here.anchor) {
        if move_files(root, &row.id)?.is_empty()
            && let Some(install) = fresh_enroll(root, &row.id, &here.anchor)?
        {
            destinations.push((row.id.clone(), install));
        }
    }
    let Some((destination, install)) = only_one(destinations)? else {
        return Ok(None);
    };
    draft_from(root, human, &destination, here.anchor.clone(), &install, files.to_vec())
}

fn discover_destination(
    root: &Path,
    human: &str,
    here: &HumanRow,
    rows: &[HumanRow],
    source_unlocked: &dyn Fn(&str) -> bool,
) -> Result<Option<Draft>, SdkError> {
    let Some(install) = fresh_enroll(root, human, &here.anchor)? else {
        return Ok(None);
    };
    let mut sources = Vec::new();
    for row in rows.iter().filter(|row| row.id != human && row.anchor == here.anchor) {
        let files = move_files(root, &row.id)?;
        if !files.is_empty() {
            sources.push((row.id.clone(), files));
        }
    }
    if sources.len() > 1 {
        return Err(SdkError::AgentCreationRefused("reassociation_ambiguous"));
    }
    let Some((source, files)) = sources.pop() else {
        return Ok(None);
    };
    if !source_unlocked(&source) {
        return Ok(None);
    }
    draft_from(root, &source, human, here.anchor.clone(), &install, files)
}

fn draft_from(
    root: &Path,
    source: &str,
    destination: &str,
    anchor: String,
    install: &Install,
    files: Vec<String>,
) -> Result<Option<Draft>, SdkError> {
    if journal_destination_exists(root, destination)? || !move_files(root, destination)?.is_empty()
    {
        return Err(SdkError::AgentCreationRefused("reassociation_conflict"));
    }
    let store = AgentCreationStore::open(root, source)?;
    Ok(Some(Draft {
        source: source.to_owned(),
        destination: destination.to_owned(),
        anchor,
        operation_id: install.operation_id.clone(),
        desktop: install.recipient_ref.clone(),
        agents: agent_ids(&store)?,
        files,
    }))
}

fn only_one(mut found: Vec<(String, Install)>) -> Result<Option<(String, Install)>, SdkError> {
    if found.len() > 1 {
        return Err(SdkError::AgentCreationRefused("reassociation_ambiguous"));
    }
    Ok(found.pop())
}

fn fresh_enroll(root: &Path, account_id: &str, anchor: &str) -> Result<Option<Install>, SdkError> {
    let Some(install) = install_store::read_installed(root, account_id)? else {
        return Ok(None);
    };
    let fresh = install.state == "installed"
        && install.recipient_mode == "new"
        && install.install_purpose == "enroll"
        && install.full_transfer.is_none()
        && install.account_anchor == anchor
        && install.recipient_ref.account_anchor == anchor;
    Ok(fresh.then_some(install))
}

fn require_same_ceremony(root: &Path, journal: &Journal) -> Result<(), SdkError> {
    let Some(install) = install_store::read_installed(root, &journal.destination_account_id)?
    else {
        return Err(SdkError::AgentCreationRefused("reassociation_conflict"));
    };
    if ceremony_continues(&install, journal) {
        Ok(())
    } else {
        Err(SdkError::AgentCreationRefused("reassociation_conflict"))
    }
}

/// The enroll that opened the journal, or a later authority refresh of that same device.
/// A directory refresh replaces the enroll marker; it must not strand a journal already in
/// progress. A different device, anchor, or enroll operation still conflicts.
fn ceremony_continues(install: &Install, journal: &Journal) -> bool {
    let same_device = install.state == "installed"
        && install.account_anchor == journal.destination_anchor
        && install.recipient_ref.account_anchor == journal.desktop.account_anchor
        && install.recipient_ref.device_id == journal.desktop.device_id
        && install.full_transfer.is_none();
    if !same_device {
        return false;
    }
    match install.install_purpose.as_str() {
        "enroll" => {
            install.recipient_mode == "new"
                && install.operation_id == journal.operation_id
                && install.recipient_ref == journal.desktop
        }
        "authority_refresh" => install.recipient_mode == "existing",
        _ => false,
    }
}

fn human_rows(root: &Path) -> Result<Vec<HumanRow>, SdkError> {
    let dir = root.join("custody_accounts");
    let entries = match fs::read_dir(&dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(SdkError::CustodyVaultUnavailable),
    };
    let mut rows = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if rows.len() >= MAX_ACCOUNTS {
            return Err(SdkError::CustodySetupInvalid);
        }
        if let Some(row) = one_row(root, &entry)? {
            rows.push(row);
        }
    }
    Ok(rows)
}

fn one_row(root: &Path, entry: &fs::DirEntry) -> Result<Option<HumanRow>, SdkError> {
    if !entry.file_type().map_err(|_| SdkError::CustodyVaultUnavailable)?.is_dir() {
        return Ok(None);
    }
    let Some(id) = entry.file_name().into_string().ok() else {
        return Err(SdkError::CustodySetupInvalid);
    };
    if custody::valid_id(&id).is_err() || !entry.path().join("authority.json").is_file() {
        return Ok(None);
    }
    let now = crate::custody::network_now()?;
    let Some(account) = custody::store::load_human_data_account(root, &id, now)? else {
        return Ok(None);
    };
    Ok(Some(HumanRow { id, anchor: account.record().body.account_anchor.clone() }))
}

fn move_files(root: &Path, human: &str) -> Result<Vec<String>, SdkError> {
    let base = root.join("custody_accounts").join(human);
    let mut files = Vec::new();
    push_json(&mut files, &base.join("agent_creation"), "agent_creation")?;
    push_json(&mut files, &base.join("agent_creation").join("rebind"), "agent_creation/rebind")?;
    push_json(&mut files, &base.join("agent_record"), "agent_record")?;
    files.sort();
    files.dedup();
    if files.len() > MAX_FILES {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(files)
}

fn push_json(files: &mut Vec<String>, dir: &Path, prefix: &str) -> Result<(), SdkError> {
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(()),
        Err(_) => return Err(SdkError::CustodyVaultUnavailable),
    };
    for entry in entries {
        let entry = entry.map_err(|_| SdkError::CustodyVaultUnavailable)?;
        if !entry.file_type().map_err(|_| SdkError::CustodyVaultUnavailable)?.is_file() {
            continue;
        }
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            return Err(SdkError::CustodySetupInvalid);
        };
        let Some(stem) = name.strip_suffix(".json") else {
            continue;
        };
        if Path::new(stem).extension().is_some_and(|ext| ext.eq_ignore_ascii_case("tmp")) {
            continue;
        }
        custody::valid_id(stem)?;
        files.push(format!("{prefix}/{name}"));
    }
    Ok(())
}

fn agent_ids(store: &AgentCreationStore) -> Result<Vec<String>, SdkError> {
    let mut ids = BTreeSet::new();
    for record in store.records()? {
        let keep = matches!(
            record.state,
            AgentCreationState::PublicationPending
                | AgentCreationState::PublicationUnknown
                | AgentCreationState::Complete
        ) || is_rebind(&record);
        if keep && let Some(account_id) = record.account_id.clone() {
            ids.insert(account_id);
        }
    }
    for entry in store.rebind_entries()? {
        ids.insert(entry.agent_account_id);
    }
    if ids.len() > MAX_AGENTS {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(ids.into_iter().collect())
}

fn copy_files(root: &Path, journal: &Journal) -> Result<(), SdkError> {
    for relative in &journal.files {
        copy_one(root, journal, relative)?;
    }
    Ok(())
}

fn copy_one(root: &Path, journal: &Journal, relative: &str) -> Result<(), SdkError> {
    let from = account_file(root, &journal.source_account_id, relative)?;
    let to = account_file(root, &journal.destination_account_id, relative)?;
    match (read_file(&from)?, read_file(&to)?) {
        (None, None) => Err(SdkError::CustodySetupInvalid),
        (None, Some(_)) => Ok(()),
        (Some(bytes), Some(existing)) if bytes == existing => Ok(()),
        (Some(_), Some(_)) => Err(SdkError::AgentCreationRefused("reassociation_conflict")),
        (Some(bytes), None) => {
            let parent = to.parent().ok_or(SdkError::CustodySetupInvalid)?;
            fs::create_dir_all(parent).map_err(|_| SdkError::CustodyVaultUnavailable)?;
            let name = to
                .file_name()
                .and_then(|name| name.to_str())
                .ok_or(SdkError::CustodySetupInvalid)?;
            write_json_atomic(parent, name, &bytes)
        }
    }
}

fn remove_source_files(root: &Path, journal: &Journal) -> Result<(), SdkError> {
    for relative in &journal.files {
        let from = account_file(root, &journal.source_account_id, relative)?;
        let to = account_file(root, &journal.destination_account_id, relative)?;
        let source = read_file(&from)?;
        let destination = read_file(&to)?;
        match (&source, &destination) {
            (Some(left), Some(right)) if left == right => {
                fs::remove_file(&from).map_err(|_| SdkError::CustodyVaultUnavailable)?;
            }
            // Source already gone, or `freeze_plans` rewrote the destination after the copy.
            // That rewrite is the repair request. Failing here returns before `SendRebind`.
            (None | Some(_), Some(_)) => {}
            _ => return Err(SdkError::AgentCreationRefused("reassociation_conflict")),
        }
    }
    Ok(())
}

fn retarget_all(root: &Path, journal: &Journal) -> Result<(), SdkError> {
    for agent in &journal.agents {
        retarget_agent_custodian(
            root,
            agent,
            &journal.source_account_id,
            &journal.destination_account_id,
        )?;
    }
    Ok(())
}

fn suspend_destination(store: &AgentCreationStore, journal: &mut Journal) -> Result<(), SdkError> {
    adopt_saved_receipts(store)?;
    invalidate_pending(store)?;
    journal.unresolved = unresolved_ids(store)?;
    for agent in &journal.agents {
        suspend_one(store, agent)?;
    }
    Ok(())
}

fn adopt_saved_receipts(store: &AgentCreationStore) -> Result<(), SdkError> {
    for record in store.records()? {
        if !matches!(
            record.state,
            AgentCreationState::PublicationPending | AgentCreationState::PublicationUnknown
        ) || record.receipt_b64.is_none()
        {
            continue;
        }
        let mut record = record;
        record.state = AgentCreationState::Complete;
        store.save(&record)?;
        if !is_rebind(&record) {
            match crate::agent_record::record_completed(store.agent_record_dir(), &record) {
                Ok(()) | Err(SdkError::AgentCreationRefused("agent_retired")) => {}
                Err(error) => return Err(error),
            }
        }
    }
    Ok(())
}

fn invalidate_pending(store: &AgentCreationStore) -> Result<(), SdkError> {
    for record in store.records()? {
        if publishing(&record) || record.state.is_terminal() {
            continue;
        }
        let mut record = record;
        record.state = AgentCreationState::Cancelled;
        record.decision_b64 = None;
        record.intended = None;
        store.save(&record)?;
    }
    Ok(())
}

fn suspend_one(store: &AgentCreationStore, agent_id: &str) -> Result<(), SdkError> {
    let (bound_primary, master_range) = match store.load_rebind(agent_id)? {
        Some(entry) => (entry.bound_primary, entry.master_range),
        None => match newest_publishing(store, agent_id)? {
            Some(record) => publishing_anchor(&record)?,
            None => return Ok(()),
        },
    };
    if master_range == 0 || bound_primary.device_id.is_empty() {
        return Ok(());
    }
    store.save_rebind(&RebindEntry {
        agent_account_id: agent_id.to_owned(),
        binding: RebindBinding::RebindPending,
        bound_primary,
        master_range,
        request_id: None,
        failure: None,
    })
}

fn publishing_anchor(record: &AgentCreationRecord) -> Result<(DeviceRef, u64), SdkError> {
    let plan =
        decode_register_plan(&record.plan_bytes()?).map_err(|_| SdkError::CustodySetupInvalid)?;
    Ok((plan.human_primary, record.master_range))
}

fn newest_publishing(
    store: &AgentCreationStore,
    agent_account_id: &str,
) -> Result<Option<AgentCreationRecord>, SdkError> {
    newest_matching(store, agent_account_id, |record| {
        matches!(
            record.state,
            AgentCreationState::Complete
                | AgentCreationState::PublicationPending
                | AgentCreationState::PublicationUnknown
        )
    })
}

fn freeze_plans(root: &Path, journal: &Journal, now: u64) -> Result<(), SdkError> {
    // A fresh enroll fences admission while a pending refresh exists. The signed record is
    // already the authority the new plan must name, so the fence must not block the freeze.
    let account = match load_account(root, &journal.destination_account_id, now) {
        Ok(account) => account,
        Err(SdkError::PairingCode("PublicationPending")) => {
            load_data_account(root, &journal.destination_account_id, now)?
        }
        Err(error) => return Err(error),
    };
    let desktop = plan_desktop(&account, &journal.desktop)?;
    let human = account.record().clone();
    let store = AgentCreationStore::open(root, &journal.destination_account_id)?;
    for agent in &journal.agents {
        if journal.unresolved.iter().any(|id| id == agent)
            || !fresh_plan_ready(root, &store, agent)?
        {
            continue;
        }
        let entry = store.load_rebind(agent)?;
        if entry.as_ref().is_some_and(|entry| entry.request_id.is_some()) {
            continue;
        }
        if let Err(error) = prepare_rebind_request(&store, &human, &desktop, agent, now)
            && !matches!(
                error,
                SdkError::AgentCreationRefused(
                    "creation_pairing_required" | "creation_not_primary"
                ) | SdkError::CustodyExpired
            )
        {
            return Err(error);
        }
    }
    Ok(())
}

/// This installation's device when it is the desktop the journal was opened for.
/// The epoch may move when the directory is refreshed; the plan names the record's current ref.
fn plan_desktop(
    account: &crate::custody::BornAccount,
    journal_desktop: &DeviceRef,
) -> Result<DeviceRef, SdkError> {
    let current = local_desktop(account)?;
    if current.device_id == journal_desktop.device_id
        && current.account_anchor == journal_desktop.account_anchor
    {
        Ok(current)
    } else {
        Err(SdkError::AgentCreationRefused("reassociation_conflict"))
    }
}

/// Primary named by the admitted record, or by the verified record when a finished repair
/// still has an unsent plan and admission is fenced. Other accounts keep the fence.
pub(crate) fn advance_primary(root: &Path, human: &str, now: u64) -> Result<DeviceRef, SdkError> {
    match load_account(root, human, now) {
        Ok(account) => Ok(account.record().body.master_certificate.body.primary_device_ref.clone()),
        Err(SdkError::PairingCode("PublicationPending")) => {
            if repair_plans_unsent(root, human)? {
                let account = load_data_account(root, human, now)?;
                Ok(account.record().body.master_certificate.body.primary_device_ref.clone())
            } else {
                Err(SdkError::PairingCode("PublicationPending"))
            }
        }
        Err(error) => Err(error),
    }
}

fn repair_plans_unsent(root: &Path, human: &str) -> Result<bool, SdkError> {
    let Some(journal) = load_journal(root, human)? else {
        return Ok(false);
    };
    if journal.phase != Phase::Complete || journal.destination_account_id != human {
        return Ok(false);
    }
    let store = AgentCreationStore::open(root, human)?;
    for agent in &journal.agents {
        let Some(entry) = store.load_rebind(agent)? else {
            continue;
        };
        if rebind_awaits_owner(&store, &entry)? {
            return Ok(true);
        }
    }
    Ok(false)
}

fn newest_complete(
    store: &AgentCreationStore,
    agent_account_id: &str,
) -> Result<Option<AgentCreationRecord>, SdkError> {
    newest_matching(store, agent_account_id, |record| record.state == AgentCreationState::Complete)
}

fn newest_matching(
    store: &AgentCreationStore,
    agent_account_id: &str,
    keep: impl Fn(&AgentCreationRecord) -> bool,
) -> Result<Option<AgentCreationRecord>, SdkError> {
    let mut found = None;
    for record in store.records()? {
        if record.account_id.as_deref() != Some(agent_account_id) || !keep(&record) {
            continue;
        }
        if found
            .as_ref()
            .is_none_or(|known: &AgentCreationRecord| record.master_range > known.master_range)
        {
            found = Some(record);
        }
    }
    Ok(found)
}

fn unresolved_ids(store: &AgentCreationStore) -> Result<Vec<String>, SdkError> {
    let mut ids = BTreeSet::new();
    for record in store.records()? {
        if matches!(
            record.state,
            AgentCreationState::PublicationPending | AgentCreationState::PublicationUnknown
        ) && let Some(account_id) = record.account_id.clone()
        {
            ids.insert(account_id);
        }
    }
    Ok(ids.into_iter().collect())
}

fn publishing(record: &AgentCreationRecord) -> bool {
    matches!(
        record.state,
        AgentCreationState::PublicationPending
            | AgentCreationState::PublicationUnknown
            | AgentCreationState::Complete
    )
}

fn authority_matches(
    root: &Path,
    agent_account_id: &str,
    record: &AgentCreationRecord,
) -> Result<bool, SdkError> {
    let stored = crate::custody::store::stored_record_unverified(root, agent_account_id)?;
    let copied = decoded_agent(record)?;
    Ok(object_hash(&stored).map_err(|_| SdkError::CustodySetupInvalid)?
        == object_hash(&copied).map_err(|_| SdkError::CustodySetupInvalid)?)
}

fn decoded_agent(record: &AgentCreationRecord) -> Result<Envelope<DeviceSet>, SdkError> {
    let encoded = record.agent_record_b64.as_deref().ok_or(SdkError::CustodySetupInvalid)?;
    let bytes = decode_base64url(encoded).map_err(|_| SdkError::CustodySetupInvalid)?;
    serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)
}

fn local_desktop(account: &crate::custody::BornAccount) -> Result<DeviceRef, SdkError> {
    let device_id = account.local_device_id()?.to_owned();
    let device = account
        .record()
        .body
        .devices
        .iter()
        .find(|device| device.device_id == device_id)
        .ok_or(SdkError::CustodySetupInvalid)?;
    Ok(DeviceRef {
        account_anchor: account.record().body.account_anchor.clone(),
        device_id,
        device_epoch: device.device_epoch,
    })
}

fn account_file(root: &Path, account_id: &str, relative: &str) -> Result<PathBuf, SdkError> {
    let (dir, name) = split_rel(relative)?;
    Ok(root.join("custody_accounts").join(account_id).join(dir).join(name))
}

fn split_rel(relative: &str) -> Result<(&str, &str), SdkError> {
    let (dir, name) = relative.rsplit_once('/').ok_or(SdkError::CustodySetupInvalid)?;
    if !matches!(dir, "agent_creation" | "agent_creation/rebind" | "agent_record") {
        return Err(SdkError::CustodySetupInvalid);
    }
    let stem = name.strip_suffix(".json").ok_or(SdkError::CustodySetupInvalid)?;
    custody::valid_id(stem)?;
    Ok((dir, name))
}

fn read_file(path: &Path) -> Result<Option<Vec<u8>>, SdkError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SdkError::CustodyVaultUnavailable),
    };
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SdkError::CustodyVaultUnavailable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_FILE_BYTES {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(Some(bytes))
}

fn journal_dir(root: &Path) -> PathBuf {
    root.join(DIR_NAME)
}

fn journal_path(root: &Path, destination: &str) -> Result<PathBuf, SdkError> {
    custody::valid_id(destination)?;
    Ok(journal_dir(root).join(format!("{destination}.json")))
}

fn save_journal(root: &Path, journal: &Journal) -> Result<(), SdkError> {
    check_journal(journal)?;
    let bytes = serde_json::to_vec(journal).map_err(|_| SdkError::CustodySetupInvalid)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_JOURNAL_BYTES {
        return Err(SdkError::CustodySetupInvalid);
    }
    let dir = journal_dir(root);
    fs::create_dir_all(&dir).map_err(|_| SdkError::CustodyVaultUnavailable)?;
    write_json_atomic(&dir, &format!("{}.json", journal.destination_account_id), &bytes)
}

fn load_journal(root: &Path, destination: &str) -> Result<Option<Journal>, SdkError> {
    let Some(bytes) = read_journal_bytes(&journal_path(root, destination)?)? else {
        return Ok(None);
    };
    let journal: Journal =
        serde_json::from_slice(&bytes).map_err(|_| SdkError::CustodySetupInvalid)?;
    check_journal(&journal)?;
    if journal.destination_account_id != destination {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(Some(journal))
}

fn read_journal_bytes(path: &Path) -> Result<Option<Vec<u8>>, SdkError> {
    let file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(None),
        Err(_) => return Err(SdkError::CustodyVaultUnavailable),
    };
    let mut bytes = Vec::new();
    file.take(MAX_JOURNAL_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| SdkError::CustodyVaultUnavailable)?;
    if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > MAX_JOURNAL_BYTES {
        return Err(SdkError::CustodySetupInvalid);
    }
    Ok(Some(bytes))
}

fn open_journals(root: &Path) -> Result<Vec<Journal>, SdkError> {
    let entries = match fs::read_dir(journal_dir(root)) {
        Ok(entries) => entries,
        Err(error) if error.kind() == ErrorKind::NotFound => return Ok(Vec::new()),
        Err(_) => return Err(SdkError::CustodyVaultUnavailable),
    };
    let mut journals = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|_| SdkError::CustodyVaultUnavailable)?;
        let name = entry.file_name();
        let Some(destination) = name.to_str().and_then(|name| name.strip_suffix(".json")) else {
            continue;
        };
        if let Some(journal) = load_journal(root, destination)?
            && journal.phase != Phase::Complete
        {
            journals.push(journal);
        }
        if journals.len() > 32 {
            return Err(SdkError::CustodySetupInvalid);
        }
    }
    Ok(journals)
}

fn open_journal_for(root: &Path, human: &str) -> Result<Option<Journal>, SdkError> {
    let mut found = None;
    for journal in open_journals(root)? {
        if journal.source_account_id == human || journal.destination_account_id == human {
            if found.is_some() {
                return Err(SdkError::AgentCreationRefused("reassociation_ambiguous"));
            }
            found = Some(journal);
        }
    }
    Ok(found)
}

fn journal_destination_exists(root: &Path, destination: &str) -> Result<bool, SdkError> {
    Ok(load_journal(root, destination)?.is_some())
}

fn check_journal(journal: &Journal) -> Result<(), SdkError> {
    if journal.schema != SCHEMA
        || journal.source_account_id == journal.destination_account_id
        || journal.source_anchor != journal.destination_anchor
        || journal.agents.len() > MAX_AGENTS
        || journal.files.len() > MAX_FILES
        || journal.unresolved.len() > MAX_AGENTS
    {
        return Err(SdkError::CustodySetupInvalid);
    }
    custody::valid_id(&journal.source_account_id)?;
    custody::valid_id(&journal.destination_account_id)?;
    custody::valid_id(&journal.operation_id)?;
    if journal.source_anchor.is_empty() || journal.source_anchor.len() > 128 {
        return Err(SdkError::CustodySetupInvalid);
    }
    for agent in journal.agents.iter().chain(journal.unresolved.iter()) {
        custody::valid_id(agent)?;
    }
    for relative in &journal.files {
        split_rel(relative)?;
    }
    Ok(())
}
