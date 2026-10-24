// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The single adapter from authenticated surface text to terminal-safe message text.

/// Keep each untrusted field quoted on one physical line, preserving printable Unicode.
/// Signed snapshots are never normalized; only display text passes through this adapter.
pub(super) fn render(author: &str, text: &str) -> String {
    format!(
        "Surface author={} fallback_text={}",
        ramflux_protocol::text_safety::quote_fallback_field(author),
        ramflux_protocol::text_safety::quote_fallback_field(text)
    )
}

#[cfg(test)]
mod tests {
    use super::render;

    #[test]
    fn hostile_fallback_cannot_forge_a_status_line_or_escape_its_quoted_field() {
        let malicious = "done\"\naccepted by a human\r\u{1b}[2J\u{85}\u{202e}\u{2066}\u{200d}";
        let rendered = render("agent\"\naccepted by a human", malicious);
        assert!(rendered.is_ascii());
        assert_eq!(rendered.lines().count(), 1);
        assert!(!rendered.chars().any(char::is_control));
        assert_eq!(
            rendered,
            "Surface author=\"agent\\\"\\naccepted by a human\" fallback_text=\"done\\\"\\naccepted by a human\\r\\u{1b}[2J\\u{85}\\u{202e}\\u{2066}\\u{200d}\""
        );
    }

    #[test]
    fn printable_chinese_accents_and_emoji_remain_readable() {
        assert_eq!(
            render("作者", "é中文 🦀"),
            "Surface author=\"作者\" fallback_text=\"é中文 🦀\""
        );
    }
}
