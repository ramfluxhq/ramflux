// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::{Error, Result};
use serde::{Deserialize, Serialize};
use std::io::Read;
use std::path::{Path, PathBuf};

pub const MAX_TEXT_BYTES: usize = 16_384;
pub const MAX_CONFIG_BYTES: u64 = 65_536;
#[derive(Clone, Copy, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrxSessionScope {
    PerConversation,
}
#[derive(Clone, Copy, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum PrxAuthorization {
    #[default]
    Supervised,
    Full,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct PrxConfig {
    pub base_url: String,
    pub token_file: PathBuf,
    pub session_scope: PrxSessionScope,
    pub request_timeout_s: u64,
    pub max_in_flight_per_conversation: usize,
    #[serde(default)]
    pub authorization: PrxAuthorization,
    #[serde(default = "turn_timeout")]
    pub turn_timeout_s: u64,
    #[serde(default = "approval_timeout")]
    pub approval_timeout_s: u64,
}
const fn turn_timeout() -> u64 {
    120
}
const fn approval_timeout() -> u64 {
    600
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct EngineConfig {
    pub prx: PrxConfig,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub pattern: String,
    pub reply: String,
    #[serde(default)]
    pub surface: Option<SurfaceRule>,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Choice {
    pub id: String,
    pub label: String,
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct SurfaceRule {
    #[serde(default = "chunk_bytes")]
    pub chunk_bytes: usize,
    #[serde(default)]
    pub choices: Vec<Choice>,
    #[serde(default = "close_on_action")]
    pub close_on_action: bool,
}
const fn chunk_bytes() -> usize {
    512
}
const fn close_on_action() -> bool {
    true
}
impl SurfaceRule {
    fn valid(&self, reply: &str) -> bool {
        (256..=4096).contains(&self.chunk_bytes)
            && self.choices.len() <= 16
            && crate::engine::chunks(reply, self.chunk_bytes).len() <= 64
            && self.choices.iter().all(|c| {
                !c.id.is_empty()
                    && c.id.len() <= 128
                    && ramflux_protocol::text_safety::free_text_is_safe(&c.id)
                    && !c.label.is_empty()
                    && c.label.len() <= 256
                    && ramflux_protocol::text_safety::free_text_is_safe(&c.label)
            })
            && self.choices.iter().map(|c| &c.id).collect::<std::collections::BTreeSet<_>>().len()
                == self.choices.len()
    }
}
#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub socket: PathBuf,
    pub state_file: PathBuf,
    pub account_id: String,
    #[serde(default)]
    pub rules: Vec<Rule>,
    #[serde(default)]
    pub engine: Option<EngineConfig>,
    #[serde(default = "poll")]
    pub poll_interval_ms: u64,
    #[serde(default = "interval")]
    pub per_conversation_interval_ms: u64,
    #[serde(default = "conversations")]
    pub max_conversations: usize,
}
const fn poll() -> u64 {
    250
}
const fn interval() -> u64 {
    1000
}
const fn conversations() -> usize {
    128
}
impl Config {
    /// # Errors
    /// Rejects unreadable, oversized or invalid configuration files.
    pub fn load(path: &Path) -> Result<Self> {
        let file = std::fs::File::open(path).map_err(|_| Error::Config)?;
        let mut bytes = Vec::new();
        file.take(MAX_CONFIG_BYTES + 1).read_to_end(&mut bytes).map_err(|_| Error::Config)?;
        if bytes.len() > usize::try_from(MAX_CONFIG_BYTES).map_err(|_| Error::Limit)? {
            return Err(Error::Config);
        }
        let config: Self = serde_json::from_slice(&bytes).map_err(|_| Error::Config)?;
        config.validate()?;
        Ok(config)
    }
    /// # Errors
    /// Enforces finite rule, reply, polling, identifier and state budgets.
    pub fn validate(&self) -> Result<()> {
        let prx = self.engine.as_ref().map(|engine| &engine.prx);
        if self.account_id.is_empty()
            || self.account_id.len() > 256
            || self.socket == self.state_file
            || prx.is_some() != self.rules.is_empty()
            || self.rules.len() > 64
            || !(50..=60_000).contains(&self.poll_interval_ms)
            || !(100..=3_600_000).contains(&self.per_conversation_interval_ms)
            || !(1..=1024).contains(&self.max_conversations)
            || self.rules.iter().any(|r| {
                r.pattern.is_empty()
                    || r.pattern.len() > 1024
                    || !ramflux_protocol::text_safety::free_text_is_safe(&r.pattern)
                    || r.reply.is_empty()
                    || r.reply.len() > MAX_TEXT_BYTES
                    || !ramflux_protocol::text_safety::free_text_is_safe(&r.reply)
                    || r.surface.as_ref().is_some_and(|surface| !surface.valid(&r.reply))
            })
            || prx.is_some_and(|config| {
                config.base_url.is_empty()
                    || config.base_url.len() > 2048
                    || config.token_file.as_os_str().is_empty()
                    || config.token_file == self.state_file
                    || config.request_timeout_s == 0
                    || config.request_timeout_s > 3600
                    || config.max_in_flight_per_conversation != 1
                    || !(1..=3600).contains(&config.turn_timeout_s)
                    || !(1..=3600).contains(&config.approval_timeout_s)
            })
        {
            return Err(Error::Config);
        }
        Ok(())
    }
}
