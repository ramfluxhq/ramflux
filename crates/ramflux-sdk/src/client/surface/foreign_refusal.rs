// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! A foreign card is stored as a typed refusal. It never becomes renderer state.
use super::Carrier;
use crate::{RamfluxClient, SdkError};
use serde_json::{Value, json};

/// Stable reason on `surface.get` and `card.session.open` for a card this owner did not create.
pub(crate) const FOREIGN_CARD_REASON: &str = "card_session_foreign";

const DIRECTORY: &str = "foreign_card";
const ID_DIRECTORY: &str = "foreign_card_id";

impl RamfluxClient {
    pub(crate) fn record_foreign_card(
        &self,
        carrier: &Carrier,
        text: &str,
        version: u64,
    ) -> Result<(), SdkError> {
        let reference = carrier.surface_reference()?;
        let db = self.account_db()?;
        let prior = db.client_record(DIRECTORY, &reference)?;
        let (kept_text, kept_version) = kept_fallback(prior.as_ref(), text, version);
        db.persist_client_record(
            DIRECTORY,
            &reference,
            &json!({
                "surface_ref": &reference,
                "surface_id": &carrier.surface_id,
                "conversation_id": &carrier.conversation_id,
                "author_principal_id": &carrier.author_principal_id,
                "text": kept_text,
                "version": kept_version,
                "reason": FOREIGN_CARD_REASON,
            }),
        )?;
        remember_surface_id(db, &carrier.surface_id, &reference)
    }

    pub(crate) fn foreign_card_fallback(
        &self,
        reference: &str,
    ) -> Result<Option<String>, SdkError> {
        Ok(self.foreign_row(reference)?.as_ref().map(rendered))
    }

    pub(crate) fn foreign_refusal_view(&self, reference: &str) -> Result<Value, SdkError> {
        let Some(row) = self.foreign_row(reference)? else {
            return Ok(Value::Null);
        };
        Ok(refusal_view(&row))
    }

    pub(crate) fn foreign_refusal_view_by_id(&self, surface_id: &str) -> Result<Value, SdkError> {
        let Some(reference) = self.one_foreign_ref(surface_id)? else {
            return Ok(Value::Null);
        };
        self.foreign_refusal_view(&reference)
    }

    pub(crate) fn foreign_refusal_read(
        &self,
        surface_id: &str,
        conversation: Option<&str>,
        author: Option<&str>,
    ) -> Result<Value, SdkError> {
        if let (Some(conversation), Some(author)) = (conversation, author) {
            let reference = super::scope::surface_reference(conversation, author, surface_id)?;
            return self.foreign_refusal_view(&reference);
        }
        self.foreign_refusal_view_by_id(surface_id)
    }

    fn foreign_row(&self, reference: &str) -> Result<Option<Value>, SdkError> {
        let Some(row) = self.account_db()?.client_record(DIRECTORY, reference)? else {
            return Ok(None);
        };
        let author = row.get("author_principal_id").and_then(Value::as_str).unwrap_or("");
        if self.surface_authored_locally(author) || self.surface_author_is_own_agent(author)? {
            return Ok(None);
        }
        Ok(Some(row))
    }

    fn one_foreign_ref(&self, surface_id: &str) -> Result<Option<String>, SdkError> {
        let Some(row) = self.account_db()?.client_record(ID_DIRECTORY, surface_id)? else {
            return Ok(None);
        };
        let refs: Vec<String> = row
            .get("refs")
            .and_then(Value::as_array)
            .map(|list| list.iter().filter_map(Value::as_str).map(str::to_owned).collect())
            .unwrap_or_default();
        match refs.as_slice() {
            [reference] => Ok(Some(reference.clone())),
            [] => Ok(None),
            _ => Err(super::invalid(
                "ambiguous surface id; provide conversation_id and author_principal_id or surface_ref",
            )),
        }
    }
}

fn kept_fallback(prior: Option<&Value>, text: &str, version: u64) -> (String, u64) {
    let prior_version =
        prior.and_then(|row| row.get("version")).and_then(Value::as_u64).unwrap_or(0);
    if prior_version > version {
        let kept =
            prior.and_then(|row| row.get("text")).and_then(Value::as_str).unwrap_or("").to_owned();
        return (kept, prior_version);
    }
    (text.to_owned(), version)
}

fn rendered(row: &Value) -> String {
    let author = row.get("author_principal_id").and_then(Value::as_str).unwrap_or("");
    let text = row.get("text").and_then(Value::as_str).unwrap_or("");
    super::fallback::render(author, text)
}

fn refusal_view(row: &Value) -> Value {
    json!({
        "surface_ref": row.get("surface_ref").and_then(Value::as_str).unwrap_or(""),
        "surface_id": row.get("surface_id").and_then(Value::as_str).unwrap_or(""),
        "conversation_id": row.get("conversation_id").and_then(Value::as_str).unwrap_or(""),
        "author_principal_id": row.get("author_principal_id").and_then(Value::as_str).unwrap_or(""),
        "render_allowed": false,
        "snapshot": Value::Null,
        "fallback_text": rendered(row),
        "reason": FOREIGN_CARD_REASON,
        "version": row.get("version").and_then(Value::as_u64).unwrap_or(0),
        "closed": false,
    })
}

fn remember_surface_id(
    db: &ramflux_storage::AccountDb,
    surface_id: &str,
    reference: &str,
) -> Result<(), SdkError> {
    if surface_id.is_empty() {
        return Ok(());
    }
    let prior = db.client_record(ID_DIRECTORY, surface_id)?;
    let mut refs: Vec<String> = prior
        .as_ref()
        .and_then(|row| row.get("refs"))
        .and_then(Value::as_array)
        .map(|list| list.iter().filter_map(Value::as_str).map(str::to_owned).take(2).collect())
        .unwrap_or_default();
    if !refs.iter().any(|item| item == reference) && refs.len() < 2 {
        refs.push(reference.to_owned());
    }
    db.persist_client_record(ID_DIRECTORY, surface_id, &json!({ "refs": refs }))?;
    Ok(())
}
