// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Replay the ceremony console stream and check that the recovery words left the screen.
//!
//! `ConPTY` records the whole session, including the moment the words were shown. The hide is
//! real only when the alt-screen sequences were applied as virtual-terminal controls and the
//! screen that remains after them does not contain the words.

const SCREEN_COLUMNS: usize = 80;
const MAX_ROWS: usize = 200;
const PHRASE_MARK: &str = "Write down these 24 recovery words and keep them private.";
const ENTER_MARK: &str = "Press Enter after saving the words to hide them:";

pub(crate) fn assert_words_hidden(stream: &str, words: &[String]) -> Result<(), String> {
    if !alt_enter_before_phrase(stream) {
        return Err(hide_error(
            stream,
            words,
            "alt-screen enter was not applied as VT before the recovery words",
        ));
    }
    if !clear_after_enter_prompt(stream) {
        return Err(hide_error(
            stream,
            words,
            "screen clear was not applied as VT after the recovery words",
        ));
    }
    if printed_literally(stream, "[?1049h")
        || printed_literally(stream, "[?1049l")
        || printed_literally(stream, "[2J")
    {
        return Err(hide_error(stream, words, "alt-screen or clear was printed literally"));
    }
    let screen = final_screen(stream);
    if screen.contains("[?1049h") || screen.contains("[?1049l") || screen.contains("[2J") {
        return Err(hide_error(stream, words, "alt-screen or clear stayed on the final screen"));
    }
    let stuck = words.iter().filter(|word| token_present(&screen, word)).count();
    if stuck > 0 {
        return Err(hide_error(
            stream,
            words,
            &format!("recovery words still on the final screen ({stuck} of {})", words.len()),
        ));
    }
    Ok(())
}

fn hide_error(stream: &str, words: &[String], reason: &str) -> String {
    let mut redacted = stream.to_owned();
    for word in words {
        if word.len() >= 3 {
            redacted = redacted.replace(word, "#");
        }
    }
    let tail =
        redacted.chars().rev().take(240).collect::<String>().chars().rev().collect::<String>();
    format!(
        "{reason}; has_enter={} has_leave={} has_clear={}; tail={tail:?}",
        stream.contains("\u{1b}[?1049h"),
        stream.contains("\u{1b}[?1049l"),
        stream.contains("\u{1b}[2J"),
    )
}

fn alt_enter_before_phrase(stream: &str) -> bool {
    let Some(phrase_at) = stream.find(PHRASE_MARK) else {
        return false;
    };
    stream[..phrase_at].contains("\u{1b}[?1049h")
}

fn clear_after_enter_prompt(stream: &str) -> bool {
    let Some(prompt_at) = stream.find(ENTER_MARK) else {
        return false;
    };
    let after = &stream[prompt_at..];
    after.contains("\u{1b}[2J") && after.contains("\u{1b}[?1049l")
}

fn printed_literally(stream: &str, body: &str) -> bool {
    let mut from = 0;
    while let Some(rel) = stream[from..].find(body) {
        let at = from + rel;
        let preceded_by_escape = stream[..at].ends_with('\u{1b}');
        if !preceded_by_escape {
            return true;
        }
        from = at + body.len();
    }
    false
}

fn token_present(screen: &str, word: &str) -> bool {
    // A mnemonic can share words with the public challenge/passphrase prompts.
    // Ignore only complete, exact prompt lines; extra text (including echoed answers)
    // and the same token anywhere else must still fail the erasure check.
    screen
        .lines()
        .filter(|line| !public_prompt(line.trim()))
        .flat_map(str::split_whitespace)
        .any(|token| token == word)
}

fn public_prompt(line: &str) -> bool {
    if matches!(
        line,
        "New local data passphrase (hidden):" | "Repeat local data passphrase (hidden):"
    ) {
        return true;
    }
    line.strip_prefix("Recovery word ").and_then(|s| s.strip_suffix(" (hidden):")).is_some_and(
        |position| {
            position.parse::<u8>().is_ok_and(|n| (1..=24).contains(&n) && n.to_string() == position)
        },
    )
}

fn final_screen(stream: &str) -> String {
    let mut replay = Replay::new();
    let mut chars = stream.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            replay.put(ch);
            continue;
        }
        match chars.peek().copied() {
            Some('[') => {
                chars.next();
                let seq = take_csi(&mut chars);
                replay.apply_csi(&seq);
            }
            Some(']') => {
                chars.next();
                skip_osc(&mut chars);
            }
            Some(_) => {
                chars.next();
            }
            None => {}
        }
    }
    replay.text()
}

fn take_csi(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) -> String {
    let mut seq = String::new();
    while let Some(ch) = chars.peek().copied() {
        chars.next();
        seq.push(ch);
        if ('@'..='~').contains(&ch) {
            break;
        }
    }
    seq
}

fn skip_osc(chars: &mut std::iter::Peekable<std::str::Chars<'_>>) {
    while let Some(ch) = chars.next() {
        if ch == '\u{7}' {
            break;
        }
        if ch == '\u{1b}' && chars.peek() == Some(&'\\') {
            chars.next();
            break;
        }
    }
}

struct Replay {
    primary: Grid,
    alternate: Grid,
    alt: bool,
}

impl Replay {
    fn new() -> Self {
        Self { primary: Grid::new(), alternate: Grid::new(), alt: false }
    }

    fn put(&mut self, ch: char) {
        let grid = self.current();
        match ch {
            '\r' => grid.col = 0,
            '\n' => grid.row = grid.row.saturating_add(1).min(MAX_ROWS - 1),
            other if other < ' ' => {}
            other => grid.put(other),
        }
    }

    fn apply_csi(&mut self, seq: &str) {
        let Some(final_byte) = seq.chars().next_back() else {
            return;
        };
        let body_end = seq.len().saturating_sub(final_byte.len_utf8());
        let body = &seq[..body_end];
        let private = body.starts_with('?');
        let params = if private { body.get(1..).unwrap_or("") } else { body };
        if private && matches!(final_byte, 'h' | 'l') {
            let enter = final_byte == 'h';
            for param in params.split(';') {
                if matches!(param, "1049" | "1047" | "47") {
                    self.set_alt(enter);
                }
            }
            return;
        }
        if final_byte == 'J' {
            let kind = params.split(';').next().unwrap_or("");
            if kind == "2" || kind == "3" {
                self.current().clear();
            }
            return;
        }
        if final_byte == 'H' || final_byte == 'f' {
            let mut parts = params.split(';');
            let row = csi_coord(parts.next());
            let col = csi_coord(parts.next());
            let grid = self.current();
            grid.row = row.min(MAX_ROWS - 1);
            grid.col = col.min(SCREEN_COLUMNS.saturating_sub(1));
        }
    }

    fn set_alt(&mut self, enter: bool) {
        self.alternate.clear();
        self.alt = enter;
    }

    fn current(&mut self) -> &mut Grid {
        if self.alt { &mut self.alternate } else { &mut self.primary }
    }

    fn text(&self) -> String {
        if self.alt { self.alternate.text() } else { self.primary.text() }
    }
}

fn csi_coord(param: Option<&str>) -> usize {
    let one_based =
        param.and_then(|value| value.parse::<usize>().ok()).filter(|value| *value > 0).unwrap_or(1);
    one_based.saturating_sub(1)
}

struct Grid {
    rows: Vec<Vec<char>>,
    row: usize,
    col: usize,
}

impl Grid {
    fn new() -> Self {
        Self { rows: Vec::new(), row: 0, col: 0 }
    }

    fn clear(&mut self) {
        self.rows.clear();
        self.row = 0;
        self.col = 0;
    }

    fn put(&mut self, ch: char) {
        if self.col >= SCREEN_COLUMNS {
            self.col = 0;
            self.row = self.row.saturating_add(1).min(MAX_ROWS - 1);
        }
        self.ensure_row();
        let line = &mut self.rows[self.row];
        if self.col >= line.len() {
            line.resize(self.col + 1, ' ');
        }
        line[self.col] = ch;
        self.col += 1;
    }

    fn ensure_row(&mut self) {
        if self.row >= MAX_ROWS {
            self.row = MAX_ROWS - 1;
        }
        while self.rows.len() <= self.row {
            self.rows.push(Vec::new());
        }
    }

    fn text(&self) -> String {
        let mut out = String::new();
        for (index, line) in self.rows.iter().enumerate() {
            if index > 0 {
                out.push('\n');
            }
            let rendered: String = line.iter().collect();
            out.push_str(rendered.trim_end());
        }
        out
    }
}

#[cfg(test)]
mod tests {
    use super::{ENTER_MARK, PHRASE_MARK, assert_words_hidden, final_screen};

    fn words() -> Vec<String> {
        (0..24).map(|index| format!("word{index:02}")).collect()
    }

    fn hidden_stream() -> String {
        let phrase = words().join(" ");
        format!(
            "\u{1b}[2J\u{1b}[Hstartup\r\n\u{1b}[?1049h\u{1b}[2J\u{1b}[H{PHRASE_MARK}\r\n{phrase}\r\n{ENTER_MARK}\r\n\u{1b}[2J\u{1b}[H\u{1b}[?1049lRecovery word 3 (hidden):"
        )
    }

    #[test]
    fn alt_screen_removes_the_words_from_the_final_screen() {
        let stream = hidden_stream();
        let screen = final_screen(&stream);
        assert!(
            !screen.contains("word00"),
            "test: words stayed after the alt screen was left: {screen}"
        );
        assert!(
            screen.contains("Recovery word 3"),
            "test: the challenge prompt was not on the restored screen: {screen}"
        );
        assert_words_hidden(&stream, &words()).expect("test: hide assertion");
    }

    fn common_word_stream() -> (String, Vec<String>) {
        let mut phrase = words();
        phrase[0] = "local".into();
        phrase[1] = "word".into();
        let stream = hidden_stream().replace("word00", "local").replace("word01", "word");
        (
            format!(
                "{stream}\r\nNew local data passphrase (hidden):\r\nRepeat local data passphrase (hidden):"
            ),
            phrase,
        )
    }

    #[test]
    fn public_prompt_tokens_do_not_count_as_surviving_mnemonic_words() {
        let (stream, phrase) = common_word_stream();
        assert_words_hidden(&stream, &phrase)
            .expect("test: exact public prompts do not expose the erased phrase");
    }

    #[test]
    fn common_mnemonic_word_outside_a_prompt_is_still_rejected() {
        let (stream, phrase) = common_word_stream();
        let error = assert_words_hidden(&format!("{stream}\r\nlocal"), &phrase)
            .expect_err("test: a single leaked common word remains forbidden");
        assert!(
            error.contains("recovery words still"),
            "test: actual residual word must fail: {error}"
        );
    }

    #[test]
    fn echoed_challenge_answer_is_not_masked_as_a_public_prompt() {
        let (stream, phrase) = common_word_stream();
        let stream = stream.replace("Recovery word 3 (hidden):", "Recovery word 3 (hidden): local");
        assert_words_hidden(&stream, &phrase)
            .expect_err("test: only exact prompt lines may be excluded");
    }

    #[test]
    fn literal_sequences_leave_the_words_visible() {
        let phrase = words().join(" ");
        let stream =
            format!("[?1049h[2J[H{PHRASE_MARK}\r\n{phrase}\r\n{ENTER_MARK}\r\n[2J[H[?1049l");
        let error = assert_words_hidden(&stream, &words()).expect_err("test: literal hide");
        assert!(
            error.contains("not applied as VT") || error.contains("printed literally"),
            "test: unexpected hide error: {error}"
        );
    }

    #[test]
    fn clear_on_the_primary_screen_removes_the_words() {
        let stream = "secret-word\r\n\u{1b}[2J\u{1b}[Hnext";
        let screen = final_screen(stream);
        assert!(!screen.contains("secret-word"), "test: primary clear kept the word: {screen}");
        assert!(screen.contains("next"), "test: text after the clear was lost: {screen}");
    }
}
