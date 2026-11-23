// SPDX-License-Identifier: BSD-3-Clause
//! Display-locale fallback. Formatting lives in `locale_format`.
use super::Reject;
use super::state::SurfaceSnapshot;
use serde_json::Value;

const TAG_CAP: usize = 35;
const MAX_HANT_KEYS: usize = 8;
const MAX_SCAN_STEPS: usize = 4096;
const MAX_SCAN_DEPTH: usize = 16;
const FORMAT_TAGS: [&str; 15] = [
    "ar", "de", "en", "es", "fr", "hi", "id", "it", "ja", "ko", "pt-BR", "ru", "tr", "zh-CN",
    "zh-TW",
];

/// Resolved display locale.
///
/// Unknown tags never fail. String catalogs fall back exact, then language
/// (Traditional Chinese is not treated as Simplified), then `zh-TW` / `zh-HK` /
/// `zh-Hant` to `zh-CN` when the card has no Traditional strings, then `en`.
/// Formatting uses a launch locale. Arabic is right-to-left.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct DisplayLocale {
    requested: [u8; TAG_CAP],
    requested_len: u8,
    catalog: [u8; TAG_CAP],
    catalog_len: u8,
    format_idx: u8,
    rtl: bool,
    hant_request: bool,
}
impl DisplayLocale {
    /// English catalog, English formatting, left to right.
    #[must_use]
    pub fn en() -> Self {
        Self::parse("en")
    }
    /// Resolve `locale`. Malformed and unknown tags become English.
    #[must_use]
    pub fn parse(locale: &str) -> Self {
        resolve_tag(locale, &[])
    }
    /// The tag the caller asked for, or `en` when that tag is not usable.
    #[must_use]
    pub fn requested_tag(&self) -> &str {
        tag_text(&self.requested, self.requested_len)
    }
    /// String-catalog tag after fallback.
    #[must_use]
    pub fn catalog_tag(&self) -> &str {
        tag_text(&self.catalog, self.catalog_len)
    }
    /// CLDR locale used for numbers, dates and plurals.
    #[must_use]
    pub fn format_tag(&self) -> &'static str {
        FORMAT_TAGS.get(usize::from(self.format_idx)).copied().unwrap_or("en")
    }
    /// `true` when the requested language is Arabic.
    #[must_use]
    pub const fn is_rtl(&self) -> bool {
        self.rtl
    }
    /// `true` when check-message defaults should use the Simplified Chinese catalog.
    #[must_use]
    pub fn uses_zh_cn_copy(self) -> bool {
        eq_ci(self.catalog_tag(), "zh-CN")
    }
    /// Prefer Traditional strings shipped on this card over the `zh-CN` fallback.
    #[must_use]
    pub(super) fn with_card_catalog(self, snapshot: &SurfaceSnapshot) -> Self {
        if !self.hant_request {
            return self;
        }
        let found = hant_keys(snapshot);
        if found.count == 0 {
            return self;
        }
        resolve_tag(self.requested_tag(), &found.keys())
    }
}
pub(super) fn format(
    name: &str,
    args: &serde_json::Map<String, Value>,
    locale: DisplayLocale,
) -> Result<String, Reject> {
    super::locale_format::format(name, args, locale)
}

struct Parts {
    language: [u8; 8],
    language_len: u8,
    script: [u8; 8],
    script_len: u8,
    region: [u8; 8],
    region_len: u8,
    exact: [u8; TAG_CAP],
    exact_len: u8,
    ok: bool,
}
impl Parts {
    fn language(&self) -> &str {
        tag_text(&self.language, self.language_len)
    }
    fn script(&self) -> &str {
        tag_text(&self.script, self.script_len)
    }
    fn region(&self) -> &str {
        tag_text(&self.region, self.region_len)
    }
    fn exact(&self) -> &str {
        tag_text(&self.exact, self.exact_len)
    }
    fn hant(&self) -> bool {
        match self.script() {
            "hant" => true,
            "hans" => false,
            _ => matches!(self.region(), "tw" | "hk" | "mo"),
        }
    }
}
struct Found {
    keys: [[u8; TAG_CAP]; MAX_HANT_KEYS],
    lens: [u8; MAX_HANT_KEYS],
    count: usize,
    steps: usize,
}
impl Found {
    fn keys(&self) -> Vec<&str> {
        let mut out = Vec::new();
        for index in 0..self.count {
            let (Some(len), Some(key)) = (self.lens.get(index), self.keys.get(index)) else {
                break;
            };
            out.push(tag_text(key, *len));
        }
        out
    }
    fn note(&mut self, key: &str) {
        if self.count >= MAX_HANT_KEYS || !hant_label(key) || key.len() > TAG_CAP || !key.is_ascii()
        {
            return;
        }
        if self.keys().iter().any(|have| eq_ci(have, key)) {
            return;
        }
        let Some(slot) = self.keys.get_mut(self.count) else {
            return;
        };
        let Some(len) = self.lens.get_mut(self.count) else {
            return;
        };
        for (index, byte) in key.bytes().enumerate() {
            if let Some(cell) = slot.get_mut(index) {
                *cell = byte;
            }
        }
        *len = u8::try_from(key.len()).unwrap_or(0);
        self.count = self.count.saturating_add(1);
    }
    fn step(&mut self) -> bool {
        self.steps = self.steps.saturating_add(1);
        self.steps <= MAX_SCAN_STEPS
    }
}

fn resolve_tag(locale: &str, hant: &[&str]) -> DisplayLocale {
    let parts = parts_of(locale);
    let format = format_of(&parts);
    let catalog = catalog_of(&parts, hant);
    let mut out = DisplayLocale {
        requested: [0; TAG_CAP],
        requested_len: 0,
        catalog: [0; TAG_CAP],
        catalog_len: 0,
        format_idx: tag_index(format),
        rtl: parts.ok && parts.language() == "ar",
        hant_request: parts.ok && parts.language() == "zh" && parts.hant(),
    };
    let requested = if parts.ok { locale } else { "en" };
    write_tag(&mut out.requested, &mut out.requested_len, requested);
    write_tag(&mut out.catalog, &mut out.catalog_len, catalog);
    out
}
fn format_of(parts: &Parts) -> &'static str {
    if !parts.ok {
        return "en";
    }
    if let Some(tag) = FORMAT_TAGS.iter().find(|tag| eq_ci(parts.exact(), tag)) {
        return tag;
    }
    match (parts.language(), parts.region(), parts.hant()) {
        ("ar", _, _) => "ar",
        ("de", _, _) => "de",
        ("es", _, _) => "es",
        ("fr", _, _) => "fr",
        ("hi", _, _) => "hi",
        ("id", _, _) => "id",
        ("it", _, _) => "it",
        ("ja", _, _) => "ja",
        ("ko", _, _) => "ko",
        ("pt", "br", _) => "pt-BR",
        ("ru", _, _) => "ru",
        ("tr", _, _) => "tr",
        ("zh", _, true) => "zh-TW",
        ("zh", _, false) => "zh-CN",
        _ => "en",
    }
}
fn catalog_of<'a>(parts: &Parts, hant: &'a [&'a str]) -> &'a str {
    if !parts.ok {
        return "en";
    }
    if eq_ci(parts.exact(), "en") || eq_ci(parts.exact(), "zh-CN") {
        return if eq_ci(parts.exact(), "zh-CN") { "zh-CN" } else { "en" };
    }
    if let Some(tag) = hant.iter().find(|tag| eq_ci(parts.exact(), tag)) {
        return tag;
    }
    if parts.language() == "en" {
        return "en";
    }
    if parts.language() == "zh" && !parts.hant() {
        return "zh-CN";
    }
    if parts.language() == "zh" && parts.hant() {
        return hant
            .iter()
            .find(|tag| !parts.region().is_empty() && same_region(tag, parts.region()))
            .copied()
            .or_else(|| hant.first().copied())
            .unwrap_or("zh-CN");
    }
    "en"
}
fn parts_of(tag: &str) -> Parts {
    let mut parts = Parts {
        language: [0; 8],
        language_len: 0,
        script: [0; 8],
        script_len: 0,
        region: [0; 8],
        region_len: 0,
        exact: [0; TAG_CAP],
        exact_len: 0,
        ok: false,
    };
    if !usable(tag) {
        return parts;
    }
    write_lower(&mut parts.exact, &mut parts.exact_len, tag);
    let Some((language, mut cursor)) = subtag(tag, 0) else {
        return parts;
    };
    if !language.bytes().all(|b| b.is_ascii_alphabetic()) || !matches!(language.len(), 2 | 3) {
        return parts;
    }
    write_lower(&mut parts.language, &mut parts.language_len, language);
    if let Some((next, advanced)) = subtag(tag, cursor) {
        cursor = advanced;
        if next.len() == 4 && next.bytes().all(|b| b.is_ascii_alphabetic()) {
            write_lower(&mut parts.script, &mut parts.script_len, next);
        } else if region_shape(next) {
            write_lower(&mut parts.region, &mut parts.region_len, next);
        } else {
            return parts;
        }
    }
    if let Some((next, _)) = subtag(tag, cursor)
        && parts.region_len == 0
        && region_shape(next)
    {
        write_lower(&mut parts.region, &mut parts.region_len, next);
    }
    parts.ok = true;
    parts
}
fn usable(tag: &str) -> bool {
    !tag.is_empty()
        && tag.len() <= TAG_CAP
        && !tag.starts_with('-')
        && !tag.ends_with('-')
        && !tag.contains("--")
        && tag.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}
fn subtag(tag: &str, start: usize) -> Option<(&str, usize)> {
    let rest = tag.get(start..)?;
    if rest.is_empty() {
        return None;
    }
    let end = rest.find('-').unwrap_or(rest.len());
    let text = rest.get(..end).filter(|text| (1..=8).contains(&text.len()))?;
    if !text.bytes().all(|b| b.is_ascii_alphanumeric()) {
        return None;
    }
    let next = start.saturating_add(end).saturating_add(usize::from(end < rest.len()));
    Some((text, next))
}
fn region_shape(text: &str) -> bool {
    (text.len() == 2 && text.bytes().all(|b| b.is_ascii_alphabetic()))
        || (text.len() == 3 && text.bytes().all(|b| b.is_ascii_digit()))
}
fn same_region(tag: &str, region: &str) -> bool {
    let parts = parts_of(tag);
    parts.ok && parts.region() == region
}
fn hant_label(key: &str) -> bool {
    eq_ci(key, "zh-TW")
        || eq_ci(key, "zh-HK")
        || eq_ci(key, "zh-MO")
        || eq_ci(key, "zh-Hant")
        || starts_ci(key, "zh-Hant-")
}
fn hant_keys(snapshot: &SurfaceSnapshot) -> Found {
    let mut found =
        Found { keys: [[0; TAG_CAP]; MAX_HANT_KEYS], lens: [0; MAX_HANT_KEYS], count: 0, steps: 0 };
    if let Some(metadata) = &snapshot.metadata {
        walk_map(&metadata.extensions, &mut found, 0);
    }
    for component in &snapshot.components {
        walk_value(component, &mut found, 0);
    }
    found
}
fn walk_map(map: &serde_json::Map<String, Value>, found: &mut Found, depth: usize) {
    if depth > MAX_SCAN_DEPTH || !found.step() {
        return;
    }
    for (key, value) in map {
        found.note(key);
        walk_value(value, found, depth.saturating_add(1));
    }
}
fn walk_value(value: &Value, found: &mut Found, depth: usize) {
    if !found.step() {
        return;
    }
    match value {
        Value::Object(map) => walk_map(map, found, depth),
        Value::Array(items) => {
            for item in items {
                walk_value(item, found, depth.saturating_add(1));
            }
        }
        _ => {}
    }
}
fn tag_index(tag: &str) -> u8 {
    FORMAT_TAGS
        .iter()
        .position(|item| *item == tag)
        .and_then(|index| u8::try_from(index).ok())
        .unwrap_or(2)
}
fn tag_text(buf: &[u8], len: u8) -> &str {
    buf.get(..usize::from(len)).and_then(|bytes| core::str::from_utf8(bytes).ok()).unwrap_or("en")
}
fn write_tag(buf: &mut [u8], len: &mut u8, text: &str) {
    let mut count = 0usize;
    for (slot, byte) in buf.iter_mut().zip(text.bytes()) {
        *slot = byte;
        count = count.saturating_add(1);
    }
    *len = u8::try_from(count).unwrap_or(0);
}
fn write_lower(buf: &mut [u8], len: &mut u8, text: &str) {
    let mut count = 0usize;
    for (slot, byte) in buf.iter_mut().zip(text.bytes()) {
        *slot = byte.to_ascii_lowercase();
        count = count.saturating_add(1);
    }
    *len = u8::try_from(count).unwrap_or(0);
}
fn eq_ci(left: &str, right: &str) -> bool {
    left.len() == right.len()
        && left.bytes().zip(right.bytes()).all(|(a, b)| a.eq_ignore_ascii_case(&b))
}
fn starts_ci(value: &str, prefix: &str) -> bool {
    value.get(..prefix.len()).is_some_and(|head| eq_ci(head, prefix))
}
