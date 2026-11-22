// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Agent routes (`agent_crud_v1`) and Main readback (`agent_main_readback_v1`).
//! Every call checks its token first. `PUT` and `DELETE` send `If-Match` with the config
//! revision. `limits` is sent only when a bound is set and `agent_limits_v1` is advertised.

use crate::autonomy::Autonomy;
use crate::capabilities::{
    AGENT_CRUD_V1, AGENT_LIMITS_V1, AGENT_MAIN_READBACK_V1, Capabilities, require,
};
use crate::client::PrxClient;
use crate::error::{ApiCode, PrxError, decode_ok, local_refusal, present, protocol};
use crate::name::AgentName;
use crate::revision::ConfigRevision;
use reqwest::Method;
use serde::Deserialize;
use serde_json::{Map, Value, json};
use std::collections::BTreeSet;

/// Largest `prompt` PRX stores, in bytes. Over it PRX returns `field_invalid`.
pub const PROMPT_MAX_BYTES: usize = 32_768;
const MAIN_NAME: &str = "main";
const WILDCARD: &str = "*";

/// An agent's tools: all of Main's (`["*"]` on the wire) or named ones (`[]` is no tools).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Tools {
    All,
    List(Vec<String>),
}

impl Tools {
    fn to_wire(&self) -> Vec<String> {
        match self {
            Self::All => vec![WILDCARD.to_owned()],
            Self::List(names) => names.clone(),
        }
    }

    fn from_wire(names: Vec<String>) -> Result<Self, PrxError> {
        if names.len() == 1 && names.first().is_some_and(|n| n == WILDCARD) {
            Ok(Self::All)
        } else if names.iter().any(|n| n == WILDCARD) {
            Err(protocol("tools mix * with names"))
        } else {
            Ok(Self::List(names))
        }
    }

    /// Refuses what PRX refuses with `agent_tools_invalid`: `*` beside names, or duplicates.
    fn check_local(&self) -> Result<(), PrxError> {
        if let Self::List(names) = self {
            let distinct: BTreeSet<&String> = names.iter().collect();
            if distinct.len() != names.len() || names.iter().any(|n| n == WILDCARD) {
                return Err(local_refusal(ApiCode::AgentToolsInvalid));
            }
        }
        Ok(())
    }
}

/// Admission limits for a named agent's rf turns (`agent_limits_v1`).
///
/// Each field unset means that limit is off. A set `max_concurrent_turns` is `1..=1024`.
/// A set `max_cost_per_day_cents` is `1..=1_000_000_000`. Both unset is the same as omitting
/// `AgentConfig::limits`: nothing is sent.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct AgentLimits {
    pub max_concurrent_turns: Option<u32>,
    pub max_cost_per_day_cents: Option<u64>,
}

impl AgentLimits {
    fn is_unset(&self) -> bool {
        self.max_concurrent_turns.is_none() && self.max_cost_per_day_cents.is_none()
    }

    fn bounds_ok(&self) -> bool {
        self.max_concurrent_turns.is_none_or(|value| (1..=1024).contains(&value))
            && self.max_cost_per_day_cents.is_none_or(|value| (1..=1_000_000_000).contains(&value))
    }
}

/// The config an agent is written with (`PUT`) and read back with (`GET`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentConfig {
    pub provider: String,
    pub model: String,
    /// `None` means PRX composes the prompt; `Some("")` is stored and returned as empty.
    pub prompt: Option<String>,
    pub autonomy: Autonomy,
    pub tools: Tools,
    pub enabled: bool,
    /// `None`, or both inner fields unset, means PRX's default (no admission limits).
    pub limits: Option<AgentLimits>,
}

impl AgentConfig {
    fn check_local(&self) -> Result<(), PrxError> {
        if self.prompt.as_ref().is_some_and(|p| p.len() > PROMPT_MAX_BYTES) {
            return Err(local_refusal(ApiCode::FieldInvalid));
        }
        if self.limits.as_ref().is_some_and(|limits| !limits.bounds_ok()) {
            return Err(local_refusal(ApiCode::FieldInvalid));
        }
        self.tools.check_local()
    }

    /// A bound that must be sent. Both-unset limits are omitted.
    fn limits_to_send(&self) -> Option<&AgentLimits> {
        self.limits.as_ref().filter(|limits| !limits.is_unset())
    }

    /// The `PUT` body: a full replacement, `prompt` only when present, `limits` only when a bound
    /// is set. An unset inner field is JSON null, which is what PRX stores.
    fn to_body(&self) -> Value {
        let mut body = Map::new();
        body.insert("provider".to_owned(), json!(self.provider));
        body.insert("model".to_owned(), json!(self.model));
        body.insert("autonomy".to_owned(), json!(autonomy_wire(self.autonomy)));
        body.insert("tools".to_owned(), json!(self.tools.to_wire()));
        body.insert("enabled".to_owned(), json!(self.enabled));
        if let Some(prompt) = &self.prompt {
            body.insert("prompt".to_owned(), json!(prompt));
        }
        if let Some(limits) = self.limits_to_send() {
            body.insert(
                "limits".to_owned(),
                json!({
                    "max_concurrent_turns": limits.max_concurrent_turns,
                    "max_cost_per_day_cents": limits.max_cost_per_day_cents,
                }),
            );
        }
        Value::Object(body)
    }
}

fn autonomy_wire(level: Autonomy) -> &'static str {
    match level {
        Autonomy::Readonly => "readonly",
        Autonomy::Supervised => "supervised",
        Autonomy::Full => "full",
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireConfig {
    provider: String,
    model: String,
    #[serde(default, deserialize_with = "present")]
    prompt: Option<String>,
    autonomy: Autonomy,
    tools: Vec<String>,
    enabled: bool,
    /// Absent on older readbacks. An explicit JSON null fails closed. Inner nulls are unset.
    #[serde(default, deserialize_with = "present")]
    limits: Option<WireLimits>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLimits {
    #[serde(default)]
    max_concurrent_turns: Option<u32>,
    #[serde(default)]
    max_cost_per_day_cents: Option<u64>,
}

fn limits_from_wire(wire: Option<WireLimits>) -> Result<Option<AgentLimits>, PrxError> {
    let Some(wire) = wire else {
        return Ok(None);
    };
    let limits = AgentLimits {
        max_concurrent_turns: wire.max_concurrent_turns,
        max_cost_per_day_cents: wire.max_cost_per_day_cents,
    };
    if limits.is_unset() {
        return Ok(None);
    }
    if limits.bounds_ok() {
        Ok(Some(limits))
    } else {
        Err(protocol("limits are outside the documented range"))
    }
}

impl WireConfig {
    fn into_config(self) -> Result<AgentConfig, PrxError> {
        Ok(AgentConfig {
            provider: self.provider,
            model: self.model,
            prompt: self.prompt,
            autonomy: self.autonomy,
            tools: Tools::from_wire(self.tools)?,
            enabled: self.enabled,
            limits: limits_from_wire(self.limits)?,
        })
    }
}

/// An agent's state: `active` (enabled), `disabled` (configured off) or `retired` (purge pending).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum AgentStatus {
    Active,
    Disabled,
    Retired,
}

/// One named agent as PRX reports it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentReadback {
    pub name: AgentName,
    pub config: AgentConfig,
    pub revision: ConfigRevision,
    /// UUID that never changes across `PUT`s.
    pub incarnation: String,
    pub status: AgentStatus,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireReadback {
    name: AgentName,
    config: WireConfig,
    revision: ConfigRevision,
    incarnation: String,
    status: AgentStatus,
}

impl WireReadback {
    fn into_readback(self) -> Result<AgentReadback, PrxError> {
        check_uuid(&self.incarnation)?;
        Ok(AgentReadback {
            name: self.name,
            config: self.config.into_config()?,
            revision: self.revision,
            incarnation: self.incarnation,
            status: self.status,
        })
    }
}

pub(crate) fn check_uuid(raw: &str) -> Result<(), PrxError> {
    let shaped = raw.len() == 36
        && raw.bytes().enumerate().all(|(i, b)| match i {
            8 | 13 | 18 | 23 => b == b'-',
            _ => b.is_ascii_hexdigit(),
        });
    if shaped { Ok(()) } else { Err(protocol("incarnation is not a UUID")) }
}

/// `GET /api/agents`: the config revision and every configured named agent, retired included.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AgentList {
    pub revision: ConfigRevision,
    pub agents: Vec<AgentReadback>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireList {
    revision: ConfigRevision,
    agents: Vec<WireReadback>,
}

/// `GET /api/agents/main`: Main's configuration (no `enabled`, `prompt` or `status`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MainReadback {
    pub provider: String,
    pub model: String,
    pub autonomy: Autonomy,
    pub tools: Tools,
    pub revision: ConfigRevision,
    pub incarnation: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMainConfig {
    provider: String,
    model: String,
    autonomy: Autonomy,
    tools: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireMain {
    name: String,
    config: WireMainConfig,
    revision: ConfigRevision,
    incarnation: String,
}

/// Whether `PUT` created the agent (201) or replaced it (200).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PutKind {
    Created,
    Replaced,
}

/// The result of a `PUT`: the kind and the readback that came with it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PutOutcome {
    pub kind: PutKind,
    pub readback: AgentReadback,
}

/// The result of a `DELETE`: the agent is retired, its purge is pending.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Retired {
    pub name: AgentName,
    pub revision: ConfigRevision,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRetired {
    name: AgentName,
    status: String,
    revision: ConfigRevision,
}

impl AgentList {
    pub(crate) fn from_body(body: &[u8]) -> Result<Self, PrxError> {
        let wire: WireList = decode_ok(body)?;
        let agents = wire
            .agents
            .into_iter()
            .map(WireReadback::into_readback)
            .collect::<Result<Vec<_>, _>>()?;
        Ok(Self { revision: wire.revision, agents })
    }
}

impl AgentReadback {
    pub(crate) fn from_body(body: &[u8], expected: &AgentName) -> Result<Self, PrxError> {
        let wire: WireReadback = decode_ok(body)?;
        if wire.name != *expected {
            return Err(protocol("readback names a different agent"));
        }
        wire.into_readback()
    }
}

impl MainReadback {
    pub(crate) fn from_body(body: &[u8]) -> Result<Self, PrxError> {
        let wire: WireMain = decode_ok(body)?;
        if wire.name != MAIN_NAME {
            return Err(protocol("Main readback names another agent"));
        }
        check_uuid(&wire.incarnation)?;
        Ok(Self {
            provider: wire.config.provider,
            model: wire.config.model,
            autonomy: wire.config.autonomy,
            tools: Tools::from_wire(wire.config.tools)?,
            revision: wire.revision,
            incarnation: wire.incarnation,
        })
    }
}

impl Retired {
    pub(crate) fn from_body(body: &[u8], expected: &AgentName) -> Result<Self, PrxError> {
        let wire: WireRetired = decode_ok(body)?;
        if wire.name != *expected || wire.status != "retired" {
            return Err(protocol("delete answer is not a retirement of the named agent"));
        }
        Ok(Self { name: wire.name, revision: wire.revision })
    }
}

impl PrxClient {
    /// Lists every configured named agent. Needs `agent_crud_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported` without the token, otherwise the transport, API or contract error.
    pub async fn list(&self, caps: &Capabilities) -> Result<AgentList, PrxError> {
        require(caps, AGENT_CRUD_V1)?;
        let raw = self.transport.call(Method::GET, "/api/agents", None, None).await?;
        AgentList::from_body(&raw.body)
    }

    /// Reads one agent. Needs `agent_crud_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (for example `agent_unknown`), or a transport or contract error.
    pub async fn get(
        &self,
        caps: &Capabilities,
        name: &AgentName,
    ) -> Result<AgentReadback, PrxError> {
        require(caps, AGENT_CRUD_V1)?;
        let path = format!("/api/agents/{}", name.as_str());
        let raw = self.transport.call(Method::GET, &path, None, None).await?;
        AgentReadback::from_body(&raw.body, name)
    }

    /// Creates or replaces an agent with a full body. `revision` is the config revision read
    /// from `list` or from the last readback. `confirm_high_risk` is sent only when true.
    /// Needs `agent_crud_v1`. Local refusals (prompt size, tool list) send nothing.
    ///
    /// # Errors
    /// Returns `Unsupported`, the refusal of PRX (for example `revision_conflict`,
    /// `confirmation_required`), or a transport or contract error.
    pub async fn put(
        &self,
        caps: &Capabilities,
        name: &AgentName,
        config: &AgentConfig,
        revision: &ConfigRevision,
        confirm_high_risk: bool,
    ) -> Result<PutOutcome, PrxError> {
        require(caps, AGENT_CRUD_V1)?;
        config.check_local()?;
        if config.limits_to_send().is_some() {
            require(caps, AGENT_LIMITS_V1)?;
        }
        let mut path = format!("/api/agents/{}", name.as_str());
        if confirm_high_risk {
            path.push_str("?confirm_high_risk=true");
        }
        let body = config.to_body();
        let raw =
            self.transport.call(Method::PUT, &path, Some(revision.as_str()), Some(&body)).await?;
        let kind = match raw.status {
            201 => PutKind::Created,
            200 => PutKind::Replaced,
            _ => return Err(protocol("PUT answered an unexpected 2xx status")),
        };
        let readback = AgentReadback::from_body(&raw.body, name)?;
        Ok(PutOutcome { kind, readback })
    }

    /// Retires an agent (idempotent on PRX's side). Needs `agent_crud_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, `Api` (for example `revision_conflict`, `agent_unknown`), or a
    /// transport or contract error.
    pub async fn retire(
        &self,
        caps: &Capabilities,
        name: &AgentName,
        revision: &ConfigRevision,
    ) -> Result<Retired, PrxError> {
        require(caps, AGENT_CRUD_V1)?;
        let path = format!("/api/agents/{}", name.as_str());
        let raw = self.transport.call(Method::DELETE, &path, Some(revision.as_str()), None).await?;
        Retired::from_body(&raw.body, name)
    }

    /// Reads Main's configuration. Needs `agent_main_readback_v1`.
    ///
    /// # Errors
    /// Returns `Unsupported`, the API error, or a transport or contract error.
    pub async fn main(&self, caps: &Capabilities) -> Result<MainReadback, PrxError> {
        require(caps, AGENT_MAIN_READBACK_V1)?;
        let raw = self.transport.call(Method::GET, "/api/agents/main", None, None).await?;
        MainReadback::from_body(&raw.body)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_support::{caps_with, offline_client};

    const HEX: &str = "d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4d4";
    const UUID: &str = "5f1c2a3e-8b4d-4c6a-9e7f-0a1b2c3d4e5f";
    const NAME: &str = "a_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    fn name() -> AgentName {
        AgentName::parse(NAME).expect("test: literal rf-derived name parses")
    }

    fn readback(config: &str, status: &str) -> String {
        format!(
            r#"{{"name":"{NAME}","config":{config},"revision":"{HEX}","incarnation":"{UUID}","status":"{status}"}}"#
        )
    }

    #[test]
    fn decodes_documented_readback() {
        let body = readback(
            r#"{"provider":"ollama","model":"codellama","autonomy":"full","tools":["*"],"enabled":true}"#,
            "active",
        );
        let read = AgentReadback::from_body(body.as_bytes(), &name())
            .expect("test: documented readback decodes");
        assert_eq!(read.config.tools, Tools::All);
        assert_eq!(read.config.prompt, None, "absent prompt means PRX composition");
        assert!(read.config.enabled);
        assert_eq!(read.status, AgentStatus::Active);
    }

    #[test]
    fn empty_prompt_round_trips_distinct_from_absent() {
        let body = readback(
            r#"{"provider":"ollama","model":"m","prompt":"","autonomy":"readonly","tools":[],"enabled":false}"#,
            "disabled",
        );
        let read = AgentReadback::from_body(body.as_bytes(), &name()).expect("test: decodes");
        assert_eq!(read.config.prompt, Some(String::new()), "empty prompt is kept, not dropped");
        assert_eq!(read.config.tools, Tools::List(Vec::new()), "[] means no tools");
    }

    #[test]
    fn retired_status_and_strict_fields() {
        let retired = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":false}"#,
            "retired",
        );
        assert_eq!(
            AgentReadback::from_body(retired.as_bytes(), &name()).map(|r| r.status).ok(),
            Some(AgentStatus::Retired)
        );
        let bad_status = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true}"#,
            "gone",
        );
        let bad_autonomy = readback(
            r#"{"provider":"p","model":"m","autonomy":"read_only","tools":["*"],"enabled":true}"#,
            "active",
        );
        let string_bool = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":"true"}"#,
            "active",
        );
        let top_enabled = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true}"#,
            "active",
        )
        .replace(r#""status""#, r#""enabled":true,"status""#);
        for bad in [bad_status, bad_autonomy, string_bool, top_enabled] {
            assert!(
                matches!(
                    AgentReadback::from_body(bad.as_bytes(), &name()),
                    Err(PrxError::Protocol { .. })
                ),
                "readback must fail closed: {bad}"
            );
        }
    }

    #[test]
    fn tools_mixing_wildcard_with_names_fail_closed() {
        let body = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*","read_file"],"enabled":true}"#,
            "active",
        );
        assert!(matches!(
            AgentReadback::from_body(body.as_bytes(), &name()),
            Err(PrxError::Protocol { .. })
        ));
    }

    #[test]
    fn readback_must_name_the_requested_agent() {
        let other = AgentName::parse("worker1").expect("test: valid name");
        let body = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true}"#,
            "active",
        );
        assert!(matches!(
            AgentReadback::from_body(body.as_bytes(), &other),
            Err(PrxError::Protocol { .. })
        ));
    }

    #[test]
    fn main_readback_has_no_enabled_or_prompt() {
        let body = format!(
            r#"{{"name":"main","config":{{"provider":"kimi-code","model":"k3","autonomy":"full","tools":["*"]}},"revision":"{HEX}","incarnation":"{UUID}"}}"#
        );
        let main =
            MainReadback::from_body(body.as_bytes()).expect("test: documented Main shape decodes");
        assert_eq!(main.autonomy, Autonomy::Full);
        assert_eq!(main.tools, Tools::All);
        let with_enabled = body.replace(r#""tools":["*"]}"#, r#""tools":["*"],"enabled":true}"#);
        assert!(matches!(
            MainReadback::from_body(with_enabled.as_bytes()),
            Err(PrxError::Protocol { .. })
        ));
    }

    #[test]
    fn list_and_retire_decode_their_documented_shapes() {
        let list = format!(r#"{{"revision":"{HEX}","agents":[]}}"#);
        let parsed = AgentList::from_body(list.as_bytes())
            .expect("test: empty list still carries the revision");
        assert_eq!(parsed.agents, Vec::new(), "an empty list has no agents");
        let retire = format!(r#"{{"name":"{NAME}","status":"retired","revision":"{HEX}"}}"#);
        let retired = Retired::from_body(retire.as_bytes(), &name())
            .expect("test: documented retire decodes");
        assert_eq!(retired.revision.as_str(), HEX);
        let not_retired = retire.replace("retired", "active");
        assert!(matches!(
            Retired::from_body(not_retired.as_bytes(), &name()),
            Err(PrxError::Protocol { .. })
        ));
    }

    #[test]
    fn put_body_sends_documented_fields_only() {
        let config = AgentConfig {
            provider: "ollama".to_owned(),
            model: "codellama".to_owned(),
            prompt: None,
            autonomy: Autonomy::Full,
            tools: Tools::All,
            enabled: true,
            limits: None,
        };
        let body = config.to_body();
        assert!(body.get("prompt").is_none(), "absent prompt is not sent");
        assert_eq!(body.get("tools"), Some(&json!(["*"])));
        assert!(body.get("limits").is_none(), "unset limits are not sent");
        let bounded = AgentConfig {
            limits: Some(AgentLimits {
                max_concurrent_turns: Some(1),
                max_cost_per_day_cents: None,
            }),
            ..config.clone()
        };
        let sent = bounded.to_body();
        assert_eq!(
            sent.get("limits"),
            Some(&json!({"max_concurrent_turns": 1, "max_cost_per_day_cents": null})),
            "a set bound sends both fields"
        );
        let both_unset = AgentConfig { limits: Some(AgentLimits::default()), ..config.clone() };
        assert!(both_unset.to_body().get("limits").is_none(), "both-unset limits are omitted");
        let empty =
            AgentConfig { prompt: Some(String::new()), tools: Tools::List(Vec::new()), ..config };
        assert_eq!(
            empty.to_body().get("prompt"),
            Some(&json!("")),
            "empty prompt is sent as empty"
        );
        assert_eq!(empty.to_body().get("tools"), Some(&json!([])));
    }

    #[test]
    fn limits_nulls_decode_as_unset_and_a_bound_round_trips() {
        let unset = readback(
            r#"{"provider":"ollama","model":"m","autonomy":"full","tools":["*"],"enabled":true,"limits":{"max_concurrent_turns":null,"max_cost_per_day_cents":null}}"#,
            "active",
        );
        let parsed = AgentReadback::from_body(unset.as_bytes(), &name())
            .expect("test: both-null limits decode");
        assert_eq!(parsed.config.limits, None, "both nulls are unset");
        let set = readback(
            r#"{"provider":"ollama","model":"m","autonomy":"full","tools":["*"],"enabled":true,"limits":{"max_concurrent_turns":1,"max_cost_per_day_cents":null}}"#,
            "active",
        );
        let parsed =
            AgentReadback::from_body(set.as_bytes(), &name()).expect("test: a set bound decodes");
        assert_eq!(
            parsed.config.limits,
            Some(AgentLimits { max_concurrent_turns: Some(1), max_cost_per_day_cents: None })
        );
        let null_object = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true,"limits":null}"#,
            "active",
        );
        assert!(matches!(
            AgentReadback::from_body(null_object.as_bytes(), &name()),
            Err(PrxError::Protocol { .. })
        ));
        let out_of_range = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true,"limits":{"max_concurrent_turns":0,"max_cost_per_day_cents":null}}"#,
            "active",
        );
        assert!(matches!(
            AgentReadback::from_body(out_of_range.as_bytes(), &name()),
            Err(PrxError::Protocol { .. })
        ));
    }

    #[tokio::test]
    async fn local_refusals_send_nothing() {
        let (_dir, client) = offline_client();
        let caps = caps_with(&[AGENT_CRUD_V1]);
        let revision = ConfigRevision::parse(HEX).expect("test: literal revision");
        let base = AgentConfig {
            provider: "p".to_owned(),
            model: "m".to_owned(),
            prompt: None,
            autonomy: Autonomy::Full,
            tools: Tools::All,
            enabled: true,
            limits: None,
        };
        let oversized =
            AgentConfig { prompt: Some("x".repeat(PROMPT_MAX_BYTES + 1)), ..base.clone() };
        let duplicate = AgentConfig {
            tools: Tools::List(vec!["read_file".to_owned(), "read_file".to_owned()]),
            ..base.clone()
        };
        let wildcard_beside_name = AgentConfig {
            tools: Tools::List(vec!["*".to_owned(), "read_file".to_owned()]),
            ..base.clone()
        };
        let turns_zero = AgentConfig {
            limits: Some(AgentLimits { max_concurrent_turns: Some(0), ..AgentLimits::default() }),
            ..base.clone()
        };
        let turns_high = AgentConfig {
            limits: Some(AgentLimits {
                max_concurrent_turns: Some(1025),
                ..AgentLimits::default()
            }),
            ..base.clone()
        };
        let cost_zero = AgentConfig {
            limits: Some(AgentLimits { max_cost_per_day_cents: Some(0), ..AgentLimits::default() }),
            ..base.clone()
        };
        let cost_high = AgentConfig {
            limits: Some(AgentLimits {
                max_cost_per_day_cents: Some(1_000_000_001),
                ..AgentLimits::default()
            }),
            ..base.clone()
        };
        let cases = [
            (oversized, ApiCode::FieldInvalid),
            (duplicate, ApiCode::AgentToolsInvalid),
            (wildcard_beside_name, ApiCode::AgentToolsInvalid),
            (turns_zero, ApiCode::FieldInvalid),
            (turns_high, ApiCode::FieldInvalid),
            (cost_zero, ApiCode::FieldInvalid),
            (cost_high, ApiCode::FieldInvalid),
        ];
        for (config, expected) in cases {
            let result = client.put(&caps, &name(), &config, &revision, false).await;
            assert!(
                matches!(&result, Err(PrxError::Api { status: 400, code, .. }) if *code == expected),
                "local refusal must return {expected:?} without a request, got {result:?}"
            );
        }
        let limited = AgentConfig {
            limits: Some(AgentLimits { max_concurrent_turns: Some(1), ..AgentLimits::default() }),
            ..base
        };
        let refused = client.put(&caps, &name(), &limited, &revision, false).await;
        assert!(
            matches!(&refused, Err(PrxError::Unsupported { token, .. }) if token == AGENT_LIMITS_V1),
            "a bound without agent_limits_v1 sends nothing, got {refused:?}"
        );
    }

    #[tokio::test]
    async fn absent_capability_is_refused_before_any_request() {
        let (_dir, client) = offline_client();
        let caps = caps_with(&[]);
        let revision = ConfigRevision::parse(HEX).expect("test: literal revision");
        let result = client.list(&caps).await;
        assert!(matches!(result, Err(PrxError::Unsupported { .. })), "list needs agent_crud_v1");
        let main = client.main(&caps).await;
        assert!(
            matches!(main, Err(PrxError::Unsupported { .. })),
            "main needs agent_main_readback_v1"
        );
        let deleted = client.retire(&caps, &name(), &revision).await;
        assert!(matches!(deleted, Err(PrxError::Unsupported { .. })));
    }

    #[test]
    fn null_prompt_is_refused() {
        let literal = readback(
            r#"{"provider":"ollama","model":"m","prompt":"x","autonomy":"readonly","tools":[],"enabled":false}"#,
            "disabled",
        );
        crate::test_support::assert_null_refused(&literal, "/config/prompt", |b| {
            AgentReadback::from_body(b, &name())
        });
    }

    #[test]
    fn null_enabled_is_refused() {
        let literal = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true}"#,
            "active",
        );
        crate::test_support::assert_null_refused(&literal, "/config/enabled", |b| {
            AgentReadback::from_body(b, &name())
        });
    }

    #[test]
    fn null_tools_is_refused() {
        let literal = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true}"#,
            "active",
        );
        crate::test_support::assert_null_refused(&literal, "/config/tools", |b| {
            AgentReadback::from_body(b, &name())
        });
    }

    #[test]
    fn null_status_is_refused() {
        let literal = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true}"#,
            "active",
        );
        crate::test_support::assert_null_refused(&literal, "/status", |b| {
            AgentReadback::from_body(b, &name())
        });
    }

    #[test]
    fn null_incarnation_is_refused() {
        let literal = readback(
            r#"{"provider":"p","model":"m","autonomy":"full","tools":["*"],"enabled":true}"#,
            "active",
        );
        crate::test_support::assert_null_refused(&literal, "/incarnation", |b| {
            AgentReadback::from_body(b, &name())
        });
    }

    #[test]
    fn null_list_revision_is_refused() {
        let literal = r#"{"revision":"HEX","agents":[]}"#.replace("HEX", HEX);
        crate::test_support::assert_null_refused(&literal, "/revision", AgentList::from_body);
    }

    #[test]
    fn null_retire_revision_is_refused() {
        let literal = r#"{"name":"NAME","status":"retired","revision":"HEX"}"#.replace("NAME", NAME).replace("HEX", HEX);
        crate::test_support::assert_null_refused(&literal, "/revision", |b| {
            Retired::from_body(b, &name())
        });
    }
}
