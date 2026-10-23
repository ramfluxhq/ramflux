// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! The single adapter from authenticated surface text to terminal-safe message text.

/// Keep untrusted fields quoted on one physical ASCII line. Replace this conservative
/// escaping with the shared protocol text rule when it is available. Do not normalize
/// or sanitize signed snapshots: only their text presentation passes through here.
pub(super) fn render(author: &str, text: &str) -> String {
    format!(
        "Surface author=\"{}\" fallback_text=\"{}\"",
        author.escape_default(),
        text.escape_default()
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
    fn non_ascii_text_is_preserved_as_visible_escapes() {
        assert_eq!(
            render("author", "é中"),
            "Surface author=\"author\" fallback_text=\"\\u{e9}\\u{4e2d}\""
        );
    }
}
