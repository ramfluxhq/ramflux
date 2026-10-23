// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain
use crate::{Config, Result, Rule};

/// Approved conversation text; later inputs can extend this API with merged protocol types.
pub struct ConversationInput<'a> {
    pub conversation_id: &'a str,
    pub message_id: &'a str,
    pub text: &'a str,
}
/// Only normal text replies are currently executable; no approval or tool intent exists.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Intent {
    ReplyText(String),
}
pub trait EngineProvider {
    /// # Errors
    /// Reports provider failures without exposing input text.
    fn intents(&mut self, input: &ConversationInput<'_>) -> Result<Vec<Intent>>;
}
pub struct RuleEngine {
    rules: Vec<Rule>,
}
impl RuleEngine {
    /// # Errors
    /// Rejects configurations exceeding the host's finite rule/reply bounds.
    pub fn new(config: &Config) -> Result<Self> {
        config.validate()?;
        Ok(Self { rules: config.rules.clone() })
    }
}
impl EngineProvider for RuleEngine {
    fn intents(&mut self, input: &ConversationInput<'_>) -> Result<Vec<Intent>> {
        // Exact, case-sensitive whole-message matching prevents incidental or recursive triggers.
        Ok(self
            .rules
            .iter()
            .find(|rule| input.text.trim() == rule.pattern)
            .map(|rule| vec![Intent::ReplyText(rule.reply.clone())])
            .unwrap_or_default())
    }
}
