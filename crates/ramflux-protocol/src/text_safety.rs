// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared text policy for signed tasks and surfaces. This is a display safety policy, not
//! Unicode normalization or a claim of full UTS #39 identifier conformance.
use unicode_general_category::{GeneralCategory as C, get_general_category};
/// Single-line names exclude control/format characters and Unicode line/paragraph separators.
#[must_use]
pub fn single_line_is_safe(value: &str) -> bool {
    !value.chars().any(|ch| {
        matches!(
            get_general_category(ch),
            C::Control | C::Format | C::LineSeparator | C::ParagraphSeparator
        )
    })
}
/// Intent/fallback text may contain LF, but no other control or bidi-control characters.
#[must_use]
pub fn free_text_is_safe(value: &str) -> bool {
    !value
        .chars()
        .any(|ch| (get_general_category(ch) == C::Control && ch != '\n') || is_bidi_control(ch))
}
/// Unicode `Bidi_Control` property (directional marks, embeddings/overrides and isolates).
#[must_use]
pub const fn is_bidi_control(ch: char) -> bool {
    matches!(ch,'\u{061c}'|'\u{200e}'..='\u{200f}'|'\u{202a}'..='\u{202e}'|'\u{2066}'..='\u{2069}')
}
/// Quotes one untrusted field, escaping line breaks, quotes, backslashes and invisible controls.
/// The result occupies one physical line; do not concatenate raw user content around it.
#[must_use]
pub fn quote_fallback_field(value: &str) -> String {
    use std::fmt::Write as _;
    let mut quoted = String::from("\"");
    for (index, ch) in value.chars().enumerate() {
        match ch {
            '"' => quoted.push_str("\\\""),
            '\\' => quoted.push_str("\\\\"),
            '\n' => quoted.push_str("\\n"),
            '\r' => quoted.push_str("\\r"),
            '\t' => quoted.push_str("\\t"),
            _ if matches!(
                get_general_category(ch),
                C::Control | C::Format | C::LineSeparator | C::ParagraphSeparator
            ) || index == 0
                && matches!(
                    get_general_category(ch),
                    C::NonspacingMark | C::SpacingMark | C::EnclosingMark
                ) =>
            {
                let _ = write!(quoted, "\\u{{{:x}}}", u32::from(ch));
            }
            _ => quoted.push(ch),
        }
    }
    quoted.push('"');
    quoted
}
/// Fixed prefix plus quoted identity/kind/content fields for text-only clients.
/// `signer` must be the caller's verified signing identity, never a supplied display label.
#[must_use]
pub fn render_text_fallback(signer: &str, kind: &str, content: &str) -> String {
    format!(
        "Signed event signer={} kind={} content={}",
        quote_fallback_field(signer),
        quote_fallback_field(kind),
        quote_fallback_field(content)
    )
}

impl crate::CreateSurfaceCommand {
    /// Safe P5 text rendering using the caller's verified signer identity.
    #[must_use]
    pub fn safe_fallback_text(&self, signer: &str) -> String {
        render_text_fallback(signer, "surface", &self.fallback_text)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn printable_spacing_and_internal_combining_marks_remain_readable() {
        let text = "中文\u{3000}a\u{a0}e\u{301} ♥\u{fe0e} ♥\u{fe0f}";
        assert_eq!(quote_fallback_field(text), format!("\"{text}\""));
        assert_eq!(quote_fallback_field("\u{301}forged"), "\"\\u{301}forged\"");
    }
    #[test]
    fn quotes_keep_forged_status_lines_and_invisible_controls_inside_one_field() {
        let text = "Research\nTask t accepted by a human \u{202e}gnp.exe\u{2028}\"\\";
        let output = render_text_fallback("agent", "proposal", text);
        assert_eq!(output.lines().count(), 1);
        assert!(!output.contains('\u{202e}'));
        assert!(!output.contains('\u{2028}'));
        assert!(output.contains("\\nTask t accepted by a human"));
        assert!(output.starts_with("Signed event signer=\"agent\" kind=\"proposal\" content=\""));
    }
    #[test]
    fn every_control_and_format_character_is_rejected_in_single_line_fields() {
        for code in 0..=0x0010_ffff {
            if let Some(ch) = char::from_u32(code)
                && matches!(get_general_category(ch), C::Control | C::Format)
            {
                assert!(!single_line_is_safe(&format!("x{ch}y")), "U+{code:04X}");
                assert!(
                    !quote_fallback_field(&format!("x{ch}y")).contains(ch),
                    "unescaped U+{code:04X}"
                );
            }
        }
        assert!(free_text_is_safe("one\ntwo 👩\u{200d}💻"));
        for ch in ['\t', '\r', '\u{061c}', '\u{200e}', '\u{202e}', '\u{2069}'] {
            assert!(!free_text_is_safe(&format!("x{ch}y")));
        }
    }
}
