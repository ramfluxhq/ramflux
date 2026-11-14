// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Immutable signed base state, final text commitments and fenced resync/bootstrap.
use super::wire::{canonical, decode_canonical, validate_identifier, validate_metadata};
use super::{
    AppendText, CATALOG_ID, CreateSurface, EVENT_SCHEMA, EventFrame, FinalRecord, JsonPointer,
    MAX_COMPONENTS, MAX_DELTA_BYTES, MAX_FINAL_RECORDS, MAX_MODEL_BYTES, MAX_STATE_BYTES, Metadata,
    Mutation, MutationMessage, Reject, Resync, SurfaceEvent,
};
use serde::{Deserialize, Serialize};
use serde_json::Value;

/// The exact P6 hash input. Conversation, author and sequence belong to the carrier/frame.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SurfaceSnapshot {
    pub surface_id: String,
    pub catalog_id: String,
    pub fallback_text: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<Metadata>,
    pub components: Vec<Value>,
    pub data_model: Value,
    #[serde(rename = "final")]
    pub final_: Vec<FinalRecord>,
    pub closed: bool,
}
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SurfaceState {
    snapshot: Option<SurfaceSnapshot>,
    hash: Option<String>,
    conversation_id: Option<String>,
    version: u64,
}
#[derive(Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct Checkpoint {
    conversation_id: String,
    surface_version: u64,
    #[serde(flatten)]
    snapshot: SurfaceSnapshot,
}
impl SurfaceState {
    #[must_use]
    pub const fn version(&self) -> u64 {
        self.version
    }
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.snapshot.as_ref().is_some_and(|s| s.closed)
    }
    #[must_use]
    pub const fn content(&self) -> Option<&SurfaceSnapshot> {
        self.snapshot.as_ref()
    }
    #[must_use]
    pub fn hash(&self) -> Option<&str> {
        self.hash.as_deref()
    }
    #[must_use]
    pub fn conversation_id(&self) -> Option<&str> {
        self.conversation_id.as_deref()
    }

    /// Apply an original-byte validated frame atomically. The caller authenticates the scope.
    /// # Errors
    /// Refuses any broken sequence, hash, terminal-close or finality invariant.
    pub fn apply(&self, event: &SurfaceEvent) -> Result<Self, Reject> {
        self.apply_inner(event, true)
    }
    fn apply_inner(&self, event: &SurfaceEvent, verify_hash: bool) -> Result<Self, Reject> {
        let frame = event.frame();
        if frame.resync.is_some() {
            return self.replace(frame);
        }
        if self.is_closed() {
            return Err(Reject::Closed);
        }
        if self.version.checked_add(1) != Some(frame.surface_version)
            || frame.surface_version > crate::MAX_SAFE_JSON_INTEGER
        {
            return Err(Reject::Version {
                expected: self.version.saturating_add(1),
                actual: frame.surface_version,
            });
        }
        if self.conversation_id.as_deref().is_some_and(|c| c != frame.conversation_id)
            || self.snapshot.as_ref().is_some_and(|s| s.surface_id != frame.surface_id())
        {
            return Err(Reject::Integrity);
        }
        let mut next = match (self.snapshot.as_ref(), frame.a2ui.as_ref().map(|m| &m.mutation)) {
            (None, Some(Mutation::CreateSurface(create))) => SurfaceSnapshot::from_create(
                create,
                frame.fallback_text.as_deref().ok_or(Reject::Encoding)?,
            ),
            (None, _) => return Err(Reject::NotCreated),
            (Some(_), Some(Mutation::CreateSurface(_))) => return Err(Reject::AlreadyCreated),
            (Some(previous), _) => {
                if frame.base_surface_hash.as_deref() != self.hash() {
                    return Err(Reject::Conflict);
                }
                let mut next = previous.clone();
                if let Some(append) = &frame.append_text {
                    next.append(append)?;
                } else {
                    match &frame.a2ui.as_ref().ok_or(Reject::Encoding)?.mutation {
                        Mutation::CreateSurface(_) => return Err(Reject::AlreadyCreated),
                        Mutation::UpdateComponents(update) => {
                            if update.components.len() > MAX_COMPONENTS {
                                return Err(Reject::Limit);
                            }
                            let mut seen = std::collections::BTreeSet::new();
                            for component in &update.components {
                                let id = component
                                    .get("id")
                                    .and_then(Value::as_str)
                                    .ok_or(Reject::Encoding)?;
                                if !seen.insert(id) {
                                    return Err(Reject::Integrity);
                                }
                                if let Some(old) = next
                                    .components
                                    .iter_mut()
                                    .find(|v| v.get("id").and_then(Value::as_str) == Some(id))
                                {
                                    *old = component.clone();
                                } else {
                                    next.components.push(component.clone());
                                }
                            }
                        }
                        Mutation::UpdateDataModel(update) => {
                            let path = update.path.as_deref().unwrap_or("/");
                            if path == "/" {
                                next.data_model = if update.value.is_null() {
                                    serde_json::json!({})
                                } else {
                                    update.value.clone()
                                };
                            } else {
                                JsonPointer::parse(path)?
                                    .update(&mut next.data_model, update.value.clone())?;
                            }
                        }
                        Mutation::DeleteSurface(_) => next.closed = true,
                    }
                }
                next.ensure_continuity(previous)?;
                next
            }
        };
        next.validate()?;
        let hash = next.hash()?;
        if verify_hash && hash != frame.new_surface_hash {
            return Err(Reject::Integrity);
        }
        Ok(Self {
            snapshot: Some(next),
            hash: Some(hash),
            conversation_id: Some(frame.conversation_id.clone()),
            version: frame.surface_version,
        })
    }

    /// Compute the resulting hash for local author intent, then perform normal admission.
    /// # Errors
    /// Refuses any invalid transition or state; never normalizes received wire bytes.
    pub fn prepare_event(&self, mut frame: EventFrame) -> Result<EventFrame, Reject> {
        if let Some(resync) = &frame.resync {
            let Mutation::CreateSurface(create) = &resync.a2ui.mutation else {
                return Err(Reject::Encoding);
            };
            let mut snapshot = SurfaceSnapshot::from_create(
                create,
                frame.fallback_text.as_deref().ok_or(Reject::Encoding)?,
            );
            snapshot.closed = frame.closed.ok_or(Reject::Encoding)?;
            snapshot.final_ = frame.final_.clone().ok_or(Reject::Encoding)?;
            if create.metadata != frame.metadata {
                return Err(Reject::Integrity);
            }
            snapshot.validate()?;
            frame.new_surface_hash = snapshot.hash()?;
        } else {
            frame.new_surface_hash = "pending".into();
            let event = SurfaceEvent::from_wire_bytes(&frame.wire_bytes()?)?;
            let next = self.apply_inner(&event, false)?;
            frame.new_surface_hash = next.hash.ok_or(Reject::NotCreated)?;
        }
        self.apply(&SurfaceEvent::from_wire_bytes(&frame.wire_bytes()?)?)?;
        Ok(frame)
    }
    #[must_use]
    pub fn stream_states(&self) -> std::collections::BTreeMap<String, SurfaceStreamState> {
        let mut out = std::collections::BTreeMap::new();
        if let Some(snapshot) = &self.snapshot {
            text_paths(&snapshot.data_model, "", snapshot, &mut out);
        }
        out
    }
    /// Validate a complete proof without consulting or replacing any stored state.
    /// # Errors
    /// Refuses invalid finality, component/model limits or a signed hash mismatch.
    pub fn validate_proof(event: &SurfaceEvent) -> Result<Self, Reject> {
        let frame = event.frame();
        if let Some(resync) = &frame.resync {
            let Mutation::CreateSurface(create) = &resync.a2ui.mutation else {
                return Err(Reject::Encoding);
            };
            let mut snapshot = SurfaceSnapshot::from_create(
                create,
                frame.fallback_text.as_deref().ok_or(Reject::Encoding)?,
            );
            snapshot.closed = frame.closed.ok_or(Reject::Encoding)?;
            snapshot.final_ = frame.final_.clone().ok_or(Reject::Encoding)?;
            // Metadata has one signed representation, never conflicting duplicate values.
            if create.metadata != frame.metadata {
                return Err(Reject::Integrity);
            }
            snapshot.validate()?;
            let hash = snapshot.hash()?;
            if hash != frame.new_surface_hash {
                return Err(Reject::Integrity);
            }
            Ok(Self {
                snapshot: Some(snapshot),
                hash: Some(hash),
                conversation_id: Some(frame.conversation_id.clone()),
                version: frame.surface_version,
            })
        } else {
            Self::default().apply(event)
        }
    }
    fn replace(&self, frame: &EventFrame) -> Result<Self, Reject> {
        // Stateless checks do not erase the stored context used for continuity fences.
        if let Some(known) = &self.snapshot {
            if self.conversation_id.as_deref() != Some(frame.conversation_id.as_str())
                || known.surface_id != frame.surface_id()
            {
                return Err(Reject::Integrity);
            }
            if frame.surface_version < self.version {
                return Err(Reject::Conflict);
            }
            if frame.surface_version == self.version
                && (Some(frame.new_surface_hash.as_str()) != self.hash()
                    || frame.closed != Some(known.closed))
            {
                return Err(Reject::Conflict);
            }
            if known.closed
                && (frame.surface_version != self.version
                    || Some(frame.new_surface_hash.as_str()) != self.hash())
            {
                return Err(Reject::Closed);
            }
            let records = frame.final_.as_ref().ok_or(Reject::Encoding)?;
            for record in &known.final_ {
                if !records.contains(record) {
                    return Err(Reject::Integrity);
                }
            }
        }
        let bytes = frame.wire_bytes()?;
        Self::validate_proof(&SurfaceEvent::from_wire_bytes(&bytes)?)
    }
    /// Build a v3 resync containing exactly the current signed base and finality.
    /// # Errors
    /// Refuses absent state or invalid serialization.
    pub fn resync_frame(&self) -> Result<EventFrame, Reject> {
        let s = self.snapshot.as_ref().ok_or(Reject::NotCreated)?;
        Ok(EventFrame {
            schema: EVENT_SCHEMA.into(),
            conversation_id: self.conversation_id.clone().ok_or(Reject::NotCreated)?,
            surface_version: self.version,
            base_surface_hash: None,
            new_surface_hash: self.hash.clone().ok_or(Reject::NotCreated)?,
            fallback_text: Some(s.fallback_text.clone()),
            close_reason: None,
            a2ui: None,
            append_text: None,
            resync: Some(Resync {
                a2ui: MutationMessage::new(Mutation::CreateSurface(s.create())),
            }),
            final_: Some(s.final_.clone()),
            closed: Some(s.closed),
            metadata: s.metadata.clone(),
        })
    }
    /// The checkpoint contains P6 fields plus conversation and sequence, with no unhashed state.
    /// # Errors
    /// Refuses absent or inconsistent state.
    pub fn checkpoint_bytes(&self) -> Result<Vec<u8>, Reject> {
        canonical(&Checkpoint {
            conversation_id: self.conversation_id.clone().ok_or(Reject::NotCreated)?,
            surface_version: self.version,
            snapshot: self.snapshot.clone().ok_or(Reject::NotCreated)?,
        })
    }
    /// Restore local canonical state, validating every final text commitment.
    /// # Errors
    /// Refuses tampering, unknown fields, invalid versions, finality and incomplete state.
    pub fn from_checkpoint_bytes(bytes: &[u8]) -> Result<Self, Reject> {
        let raw: Value = decode_canonical(bytes, MAX_STATE_BYTES + MAX_MODEL_BYTES)?;
        let object = raw.as_object().ok_or(Reject::Encoding)?;
        if object.keys().any(|k| {
            ![
                "conversationId",
                "surfaceVersion",
                "surfaceId",
                "catalogId",
                "fallbackText",
                "metadata",
                "components",
                "dataModel",
                "final",
                "closed",
            ]
            .contains(&k.as_str())
        }) {
            return Err(Reject::Encoding);
        }
        let mut checkpoint: Checkpoint =
            serde_json::from_value(raw).map_err(|_| Reject::Encoding)?;
        if checkpoint.conversation_id.is_empty()
            || !(1..=crate::MAX_SAFE_JSON_INTEGER).contains(&checkpoint.surface_version)
        {
            return Err(Reject::Encoding);
        }
        let before = checkpoint.snapshot.clone();
        checkpoint.snapshot.validate()?;
        if before != checkpoint.snapshot {
            return Err(Reject::Integrity);
        }
        let hash = checkpoint.snapshot.hash()?;
        Ok(Self {
            snapshot: Some(checkpoint.snapshot),
            hash: Some(hash),
            conversation_id: Some(checkpoint.conversation_id),
            version: checkpoint.surface_version,
        })
    }
}
impl SurfaceSnapshot {
    fn from_create(create: &CreateSurface, fallback: &str) -> Self {
        Self {
            surface_id: create.surface_id.clone(),
            catalog_id: create.catalog_id.clone(),
            fallback_text: fallback.into(),
            metadata: create.metadata.clone(),
            components: create.components.clone().unwrap_or_default(),
            data_model: create.data_model.clone().unwrap_or_else(|| serde_json::json!({})),
            final_: Vec::new(),
            closed: false,
        }
    }
    #[must_use]
    pub fn create(&self) -> CreateSurface {
        CreateSurface {
            surface_id: self.surface_id.clone(),
            catalog_id: self.catalog_id.clone(),
            send_data_model: None,
            components: Some(self.components.clone()),
            data_model: Some(self.data_model.clone()),
            metadata: self.metadata.clone(),
        }
    }
    /// Compute the P6 signed-base commitment. Callers must validate/prune state before signing.
    /// # Errors
    /// Refuses noncanonical I-JSON and state outside the whole-state cap.
    pub fn hash(&self) -> Result<String, Reject> {
        let bytes = canonical(self)?;
        if bytes.len() > MAX_STATE_BYTES {
            return Err(Reject::Limit);
        }
        Ok(crate::hash_base64url("ramflux.a2ui.surface_hash.v2", &bytes))
    }
    fn validate(&mut self) -> Result<(), Reject> {
        validate_identifier(&self.surface_id)?;
        if self.catalog_id != CATALOG_ID
            || self.fallback_text.trim().is_empty()
            || !crate::text_safety::free_text_is_safe(&self.fallback_text)
        {
            return Err(Reject::Validation("catalog/fallback".into()));
        }
        validate_metadata(self.metadata.as_ref())?;
        if self.components.len() > MAX_COMPONENTS * 2
            || canonical(&self.data_model)?.len() > MAX_MODEL_BYTES
            || !self.data_model.is_object()
        {
            return Err(Reject::Limit);
        }
        safe_model(&self.data_model, 0)?;
        super::action::validate_components(self)?;
        if self.components.len() > MAX_COMPONENTS {
            return Err(Reject::Limit);
        }
        self.components.sort_by(|a, b| {
            a.get("id").and_then(Value::as_str).cmp(&b.get("id").and_then(Value::as_str))
        });
        self.validate_finality()?;
        validate_depth(&serde_json::to_value(&*self).map_err(|_| Reject::Encoding)?, 0)?;
        self.hash()?;
        Ok(())
    }
    fn validate_finality(&self) -> Result<(), Reject> {
        if self.final_.len() > MAX_FINAL_RECORDS {
            return Err(Reject::Limit);
        }
        let mut previous: Option<&str> = None;
        for record in &self.final_ {
            if previous.is_some_and(|p| p.as_bytes() >= record.pointer.as_bytes()) {
                return Err(Reject::Integrity);
            }
            let pointer = JsonPointer::parse(&record.pointer)?;
            let text = pointer.text(&self.data_model)?;
            if text_hash(text) != record.text_hash {
                return Err(Reject::Integrity);
            }
            previous = Some(&record.pointer);
        }
        Ok(())
    }
    fn ensure_continuity(&self, previous: &Self) -> Result<(), Reject> {
        for record in &previous.final_ {
            if !self.final_.contains(record)
                || text_hash(JsonPointer::parse(&record.pointer)?.text(&self.data_model)?)
                    != record.text_hash
            {
                return Err(Reject::Integrity);
            }
        }
        Ok(())
    }
    fn append(&mut self, append: &AppendText) -> Result<(), Reject> {
        let pointer = JsonPointer::parse(&append.path)?;
        if self.final_.iter().any(|r| r.pointer == append.path) {
            return Err(Reject::Integrity);
        }
        if append.delta.len() > MAX_DELTA_BYTES {
            return Err(Reject::Limit);
        }
        let text = pointer.text(&self.data_model)?;
        if text.len().saturating_add(append.delta.len()) > MAX_MODEL_BYTES {
            return Err(Reject::Limit);
        }
        let mut text = text.to_owned();
        text.push_str(&append.delta);
        if append.final_ {
            self.final_
                .push(FinalRecord { pointer: append.path.clone(), text_hash: text_hash(&text) });
            self.final_.sort_by(|a, b| a.pointer.as_bytes().cmp(b.pointer.as_bytes()));
        }
        pointer.update(&mut self.data_model, Value::String(text))
    }
}
fn text_hash(text: &str) -> String {
    crate::hash_base64url("ramflux.a2ui.final_text.v2", text.as_bytes())
}
fn validate_depth(value: &Value, depth: usize) -> Result<(), Reject> {
    if depth > 16 {
        return Err(Reject::Limit);
    }
    match value {
        Value::Object(map) => {
            for value in map.values() {
                validate_depth(value, depth + 1)?;
            }
        }
        Value::Array(array) => {
            for value in array {
                validate_depth(value, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}
fn safe_model(value: &Value, depth: usize) -> Result<(), Reject> {
    if depth > 16 {
        return Err(Reject::Limit);
    }
    match value {
        Value::Number(n) if n.as_i64().is_none() && n.as_u64().is_none() => {
            return Err(Reject::Encoding);
        }
        Value::Array(a) => {
            for v in a {
                safe_model(v, depth + 1)?;
            }
        }
        Value::Object(m) => {
            for (key, v) in m {
                if matches!(key.as_str(), "__proto__" | "prototype" | "constructor") {
                    return Err(Reject::Expression);
                }
                safe_model(v, depth + 1)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Finality is keyed by canonical model pointer, not a component identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SurfaceStreamState {
    Open,
    Final,
}
fn text_paths(
    model: &Value,
    prefix: &str,
    snapshot: &SurfaceSnapshot,
    out: &mut std::collections::BTreeMap<String, SurfaceStreamState>,
) {
    if let Some(map) = model.as_object() {
        for (key, value) in map {
            let path = format!("{prefix}/{}", key.replace('~', "~0").replace('/', "~1"));
            if value.is_string() {
                out.insert(
                    path.clone(),
                    if snapshot.closed || snapshot.final_.iter().any(|r| r.pointer == path) {
                        SurfaceStreamState::Final
                    } else {
                        SurfaceStreamState::Open
                    },
                );
            } else {
                text_paths(value, &path, snapshot, out);
            }
        }
    }
}
