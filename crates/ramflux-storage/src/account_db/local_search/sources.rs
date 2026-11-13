// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Point hydration and ID keysets; no history, receipt or ciphertext scans.
use super::*;
use crate::AccountDb;
use rusqlite::{OptionalExtension as _, params};

pub struct SearchMessageInput {
    pub message_id: String,
    pub conversation_id: String,
    pub sender_id: String,
    pub created_at: i64,
    pub expires_at: Option<i64>,
    pub body: zeroize::Zeroizing<Vec<u8>>,
    pub identity: zeroize::Zeroizing<Vec<u8>>,
    pub group_projection: Option<zeroize::Zeroizing<Vec<u8>>>,
    pub revision: u64,
}

impl AccountDb {
    /// Clock used to recheck time-based visibility at the final publication boundary.
    #[must_use]
    pub fn search_clock(&self, _activation: &SearchActivation) -> crate::AccountClock {
        self.clock.clone()
    }
    /// Returns IDs only, with an indexed keyset and no held cross-batch snapshot.
    /// # Errors
    /// Refuses cancellation, unsupported source kinds or invalid identifiers.
    pub fn search_source_keys(
        &self,
        _activation: &SearchActivation,
        kind: SearchKind,
        after: &str,
        control: &SearchControl,
    ) -> SearchResult<Vec<String>> {
        if after.len() > 1024 {
            return Err(SearchError::InvalidQuery);
        }
        let after = after.to_owned();
        self.search_call(control,move |db| {
            if kind==SearchKind::Conversation {
                let mut ids=std::collections::BTreeSet::<String>::new();
                for table in ["conversation_projection","conversation_list_state"] {
                    let mut statement=db.prepare(&format!("SELECT CASE WHEN length(CAST(conversation_id AS BLOB))<=256 THEN conversation_id END FROM {table} WHERE conversation_id>?1 ORDER BY conversation_id LIMIT 128"))?;
                    for id in statement.query_map([&after],|r|r.get::<_,String>(0))? {ids.insert(id?);}
                }
                let mut statement=db.prepare("SELECT CASE WHEN length(CAST(state_kind AS BLOB))<=279 THEN substr(state_kind,24) END FROM runtime_actor_state WHERE state_kind>?1 AND state_kind<'directory/conversation0' ORDER BY state_kind LIMIT 128")?;
                for id in statement.query_map([format!("directory/conversation/{after}")],|r|r.get::<_,String>(0))? {ids.insert(id?);}
                return Ok(ids.into_iter().take(MAX_REBUILD_SOURCES).collect());
            }
            let sql=match kind {
                SearchKind::Conversation=>"SELECT CASE WHEN length(CAST(conversation_id AS BLOB))<=256 THEN conversation_id END FROM conversation_projection WHERE conversation_id>?1 ORDER BY conversation_id LIMIT 128",
                SearchKind::Message=>"SELECT CASE WHEN length(CAST(message_id AS BLOB))<=256 THEN message_id END FROM direct_message_projection WHERE message_id>?1 ORDER BY message_id LIMIT 128",
                SearchKind::Attachment=>return Err(SearchError::InvalidQuery),
            };
            let mut statement=db.prepare(sql)?;
            Ok(statement.query_map([after],|r|r.get(0))?.collect::<rusqlite::Result<Vec<String>>>()?)
        })
    }

    /// Bounded actor record loading. A present oversized value fails closed.
    /// # Errors
    /// Returns capacity instead of allocating a hostile actor record.
    pub fn search_actor_bytes(
        &self,
        _activation: &SearchActivation,
        key: &str,
        control: &SearchControl,
    ) -> SearchResult<Option<zeroize::Zeroizing<Vec<u8>>>> {
        if key.len() > 1024 {
            return Err(SearchError::InvalidQuery);
        }
        let key = key.to_owned();
        self.search_call(control,move |db| {
            let value:Option<Option<Vec<u8>>>=db.query_row("SELECT CASE WHEN length(CAST(state_json AS BLOB))<=131072 THEN CAST(state_json AS BLOB) END FROM runtime_actor_state WHERE state_kind=?1",[key],|r|r.get(0)).optional()?;
            match value {None=>Ok(None),Some(Some(bytes))=>Ok(Some(zeroize::Zeroizing::new(bytes))),Some(None)=>Err(SearchError::Capacity)}
        })
    }

    /// Visibility is checked by indexed point probes before any source text allocation.
    /// # Errors
    /// Returns typed storage/work failures, never a stale visible fallback.
    pub fn search_message_input(
        &self,
        _activation: &SearchActivation,
        message: &str,
        control: &SearchControl,
    ) -> SearchResult<Option<SearchMessageInput>> {
        if message.is_empty() || message.len() > 256 {
            return Err(SearchError::InvalidQuery);
        }
        let message = message.to_owned();
        let now = self.now_unix();
        self.search_call(control,move |db| {
            let header:Option<(String,String,i64,Option<i64>)>=db.query_row("SELECT CASE WHEN length(CAST(d.conversation_id AS BLOB))<=256 THEN d.conversation_id END,CASE WHEN length(CAST(d.sender_id AS BLOB))<=256 THEN d.sender_id END,d.created_at,(SELECT d.created_at+p.timer_seconds FROM conversation_disappearing_policy p WHERE p.conversation_id=d.conversation_id AND p.timer_seconds>0 AND p.countdown_mode='on_send') FROM direct_message_projection d WHERE d.message_id=?1 AND d.deleted=0 AND NOT EXISTS(SELECT 1 FROM conversation_list_state c WHERE c.conversation_id=d.conversation_id AND (c.hidden_at IS NOT NULL OR d.created_at<=c.cleared_at)) AND NOT EXISTS(SELECT 1 FROM conversation_projection c WHERE c.conversation_id=d.conversation_id AND (c.hidden_at IS NOT NULL OR d.created_at<=c.cleared_at)) AND NOT EXISTS(SELECT 1 FROM conversation_disappearing_policy p WHERE p.conversation_id=d.conversation_id AND p.timer_seconds>0 AND p.countdown_mode='on_send' AND d.created_at+p.timer_seconds<=?2)",params![message,now],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
            let Some((conversation_id,sender_id,created_at,expires_at))=header else {return Ok(None)};
            let actor=|key:String|->SearchResult<Option<Vec<u8>>> {
                let value:Option<Option<Vec<u8>>>=db.query_row("SELECT CASE WHEN length(CAST(state_json AS BLOB))<=131072 THEN CAST(state_json AS BLOB) END FROM runtime_actor_state WHERE state_kind=?1",[key],|r|r.get(0)).optional()?;
                match value {None=>Ok(None),Some(Some(value))=>Ok(Some(value)),Some(None)=>Err(SearchError::Capacity)}
            };
            let Some(identity)=actor(format!("routed/generated-identity/{message}"))? else {return Ok(None)};
            let unsupported:bool=db.query_row("SELECT EXISTS(SELECT 1 FROM runtime_actor_state WHERE state_kind=?1)",[format!("routed/unsupported/{message}")],|r|r.get(0))?;
            if unsupported {return Ok(None);}
            let body:Option<Option<Vec<u8>>>=db.query_row("SELECT CASE WHEN length(body)<=131072 THEN body END FROM runtime_message_content WHERE message_id=?1",[&message],|r|r.get(0)).optional()?;
            let body=match body {None=>return Ok(None),Some(Some(body))=>body,Some(None)=>return Err(SearchError::Capacity)};
            let revision=actor(format!("routed/edit-revision/{message}"))?.map(|bytes|serde_json::from_slice::<serde_json::Value>(&bytes).map_err(|_|SearchError::IndexUnavailable)).transpose()?.and_then(|value|value.get("revision").and_then(serde_json::Value::as_u64)).unwrap_or(0);
            let group_projection=actor(format!("routed/group-projection/{message}"))?.map(zeroize::Zeroizing::new);
            Ok(Some(SearchMessageInput {message_id:message,conversation_id,sender_id,created_at,expires_at,body:zeroize::Zeroizing::new(body),identity:zeroize::Zeroizing::new(identity),group_projection,revision}))
        })
    }
}

impl AccountDb {
    /// # Errors
    /// Requires visible local metadata and current, non-deleted group authority.
    pub fn search_conversation_visible(
        &self,
        _activation: &SearchActivation,
        conversation: &str,
        control: &SearchControl,
    ) -> SearchResult<bool> {
        if conversation.is_empty() || conversation.len() > 256 {
            return Err(SearchError::InvalidQuery);
        }
        let conversation = conversation.to_owned();
        self.search_call(control,move |db| Ok(db.query_row("SELECT NOT EXISTS(SELECT 1 FROM conversation_list_state WHERE conversation_id=?1 AND hidden_at IS NOT NULL) AND NOT EXISTS(SELECT 1 FROM conversation_projection WHERE conversation_id=?1 AND hidden_at IS NOT NULL)",[conversation],|r|r.get(0))?))
    }
    /// # Errors
    /// Membership probes use the complete indexed viewer key, never a group-wide scan.
    pub fn search_group_member(
        &self,
        _activation: &SearchActivation,
        group: &str,
        viewer: &ramflux_crypto::RootQualifiedDeviceRef,
        control: &SearchControl,
    ) -> SearchResult<bool> {
        if group.len() > 256 {
            return Err(SearchError::InvalidQuery);
        }
        let group = group.to_owned();
        let root = viewer.root_commitment().to_owned();
        let device = viewer.device_id().to_owned();
        self.search_call(control,move |db| Ok(db.query_row("SELECT EXISTS(SELECT 1 FROM shared_group_member_projection m WHERE group_id=?1 AND root_commitment=?2 AND device_id=?3 AND active=1) AND NOT EXISTS(SELECT 1 FROM group_projection WHERE group_id=?1 AND deleted_at IS NOT NULL)",params![group,root,device],|r|r.get(0))?))
    }
    /// # Errors
    /// Resolves only bounded, admitted local references for the exact wire/manifest identity.
    pub fn search_attachment_dependencies(
        &self,
        _activation: &SearchActivation,
        message: &str,
        object: &str,
        manifest: &str,
        control: &SearchControl,
    ) -> SearchResult<Option<Vec<SearchDependency>>> {
        if message.len() > 256 || object.len() > 256 || manifest.len() > 256 {
            return Err(SearchError::InvalidQuery);
        }
        let message = message.to_owned();
        let object = object.to_owned();
        let manifest = manifest.to_owned();
        self.search_call(control,move |db| {
            let mut statement=db.prepare("SELECT CASE WHEN length(CAST(p.commitment AS BLOB))<=256 THEN p.commitment END,CASE WHEN length(CAST(r.reference_hash AS BLOB))<=256 THEN r.reference_hash END FROM object_retention_payload p INDEXED BY object_retention_wire CROSS JOIN object_retention_reference r INDEXED BY object_reference_payload ON r.commitment=p.commitment CROSS JOIN object_message_reference m ON m.reference_hash=r.reference_hash AND m.message_id=?1 WHERE p.wire_id=?2 AND p.manifest_hash=?3 AND NOT EXISTS(SELECT 1 FROM object_erasure_fence f WHERE f.commitment=p.commitment) LIMIT 129")?;
            let mut rows=statement.query(params![message,object,manifest])?;
            let mut dependencies=Vec::new();let mut references=0;
            while let Some(row)=rows.next()? {
                references+=1;if references>128 {return Err(SearchError::Capacity);}
                let commitment:String=row.get(0)?;let reference:String=row.get(1)?;
                dependencies.push(SearchDependency{table:"object_retention_payload".into(),key:commitment.clone()});
                dependencies.push(SearchDependency{table:"object_erasure_fence".into(),key:commitment});
                dependencies.push(SearchDependency{table:"object_retention_reference".into(),key:reference});
            }
            Ok((references>0).then_some(dependencies))
        })
    }
}
