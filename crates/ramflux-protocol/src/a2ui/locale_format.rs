// SPDX-License-Identifier: BSD-3-Clause
//! CLDR number, date and plural formatting for the launch locales.
use super::Reject;
use super::locale::DisplayLocale;
use icu_calendar::cal::Gregorian;
use icu_datetime::input::{Date, DateTime, Time};
use icu_datetime::pattern::{
    DateTimePattern, DayPeriodNameLength, FixedCalendarDateTimeNames, MonthNameLength,
    WeekdayNameLength,
};
use icu_decimal::DecimalFormatter;
use icu_decimal::input::Decimal;
use icu_decimal::options::{DecimalFormatterOptions, GroupingStrategy};
use icu_locale_core::{Locale, locale};
use icu_plurals::{PluralCategory, PluralRules};
use serde_json::{Map, Value};
use std::str::FromStr;
use time::format_description::well_known::Rfc3339;
use time::{Date as CalendarDate, OffsetDateTime, PrimitiveDateTime, Time as Clock};
use writeable::TryWriteable;

const MAX_NUMBER: f64 = 9_007_199_254_740_991.0;
const MAX_OUT: usize = 1024;

pub(super) fn format(
    name: &str,
    args: &Map<String, Value>,
    locale: DisplayLocale,
) -> Result<String, Reject> {
    match name {
        "formatNumber" => render_number(args, locale, 0),
        "formatCurrency" => render_currency(args, locale),
        "pluralize" => render_plural(args, locale),
        "formatDate" => render_date(args, locale),
        _ => Err(Reject::Expression),
    }
}
fn render_number(
    args: &Map<String, Value>,
    locale: DisplayLocale,
    default_decimals: usize,
) -> Result<String, Reject> {
    let (value, decimals, grouping) = number_args(args, default_decimals)?;
    render_decimal(locale.format_tag(), value, decimals, grouping)
}
fn render_currency(args: &Map<String, Value>, locale: DisplayLocale) -> Result<String, Reject> {
    let currency = args.get("currency").and_then(Value::as_str).ok_or(Reject::Expression)?;
    if currency.len() != 3 || !currency.bytes().all(|byte| byte.is_ascii_uppercase()) {
        return Err(Reject::Expression);
    }
    let digits = usize::from(u8::from(!matches!(currency, "JPY" | "KRW"))) * 2;
    let (value, decimals, grouping) = number_args(args, digits)?;
    let magnitude = render_decimal(locale.format_tag(), value.abs(), decimals, grouping)?;
    let symbol = currency_symbol(currency, locale.format_tag());
    let sign = if value.is_sign_negative() { "-" } else { "" };
    let gap = if symbol == currency { "\u{a0}" } else { "" };
    bounded(&format!("{sign}{symbol}{gap}{magnitude}"))
}
fn render_plural(args: &Map<String, Value>, locale: DisplayLocale) -> Result<String, Reject> {
    let value = args.get("value").and_then(Value::as_f64).ok_or(Reject::Expression)?;
    let literal = plural_literal(value)?;
    let decimal = Decimal::from_str(&literal).map_err(|_| Reject::Expression)?;
    let rules = PluralRules::try_new_cardinal(icu_locale(locale.format_tag()).into())
        .map_err(|_| Reject::Expression)?;
    let category = category_name(rules.category_for(&decimal));
    args.get(category)
        .or_else(|| args.get("other"))
        .and_then(Value::as_str)
        .map(str::to_owned)
        .ok_or(Reject::Expression)
}
fn render_date(args: &Map<String, Value>, locale: DisplayLocale) -> Result<String, Reject> {
    let when = timestamp(args.get("value").ok_or(Reject::Expression)?)?;
    let pattern = args.get("format").and_then(Value::as_str).ok_or(Reject::Expression)?;
    if pattern.len() > 256 {
        return Err(Reject::Limit);
    }
    let mut chars = pattern.chars().peekable();
    let mut out = String::new();
    while let Some(ch) = chars.next() {
        if ch == '\'' {
            push_literal(&mut chars, &mut out)?;
        } else if ch.is_ascii_alphabetic() {
            let mut count = 1usize;
            while chars.peek() == Some(&ch) {
                chars.next();
                count = count.saturating_add(1);
            }
            let (shape, kind) = token_shape(ch, count)?;
            let rendered = format_token(locale.format_tag(), shape, kind, when)?;
            push_limited(&mut out, &rendered)?;
        } else {
            push_limited(&mut out, &ch.to_string())?;
        }
    }
    Ok(out)
}
fn number_args(
    args: &Map<String, Value>,
    default_decimals: usize,
) -> Result<(f64, usize, bool), Reject> {
    let value = args.get("value").and_then(Value::as_f64).ok_or(Reject::Expression)?;
    if !value.is_finite() || value.abs() > MAX_NUMBER {
        return Err(Reject::Expression);
    }
    let decimals = args
        .get("decimals")
        .map(|item| {
            item.as_u64()
                .and_then(|item| usize::try_from(item).ok())
                .filter(|item| *item <= 20)
                .ok_or(Reject::Expression)
        })
        .transpose()?
        .unwrap_or(default_decimals);
    let grouping = args
        .get("grouping")
        .map(|item| item.as_bool().ok_or(Reject::Expression))
        .transpose()?
        .unwrap_or(true);
    Ok((value, decimals, grouping))
}
fn render_decimal(
    tag: &str,
    value: f64,
    decimals: usize,
    grouping: bool,
) -> Result<String, Reject> {
    let literal = format!("{value:.decimals$}");
    let decimal = Decimal::from_str(&literal).map_err(|_| Reject::Expression)?;
    let mut options = DecimalFormatterOptions::default();
    options.grouping_strategy =
        Some(if grouping { GroupingStrategy::Always } else { GroupingStrategy::Never });
    let formatter = DecimalFormatter::try_new(icu_locale(tag).into(), options)
        .map_err(|_| Reject::Expression)?;
    bounded(&formatter.format_to_string(&decimal))
}
fn plural_literal(value: f64) -> Result<String, Reject> {
    if !value.is_finite() || value.abs() > MAX_NUMBER {
        return Err(Reject::Expression);
    }
    let literal = format!("{value}");
    if literal.contains(['e', 'E']) {
        return Err(Reject::Expression);
    }
    Ok(literal)
}
const fn category_name(category: PluralCategory) -> &'static str {
    match category {
        PluralCategory::Zero => "zero",
        PluralCategory::One => "one",
        PluralCategory::Two => "two",
        PluralCategory::Few => "few",
        PluralCategory::Many => "many",
        PluralCategory::Other => "other",
    }
}
fn currency_symbol<'a>(code: &'a str, format_tag: &str) -> &'a str {
    let zh = matches!(format_tag, "zh-CN" | "zh-TW");
    match (code, zh) {
        ("USD", false) => "$",
        ("USD", true) => "US$",
        ("CNY", false) => "CN¥",
        ("CNY", true) | ("JPY", false) => "¥",
        ("JPY", true) => "JP¥",
        ("EUR", _) => "€",
        ("GBP", _) => "£",
        _ => code,
    }
}
fn timestamp(value: &Value) -> Result<OffsetDateTime, Reject> {
    if let Some(text) = value.as_str() {
        if let Ok(date) = OffsetDateTime::parse(text, &Rfc3339) {
            return Ok(date);
        }
        let mut parts = text.split('-');
        if let (Some(year), Some(month), Some(day), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        {
            let year = year.parse::<i32>().map_err(|_| Reject::Expression)?;
            let month = month.parse::<u8>().map_err(|_| Reject::Expression)?;
            let day = day.parse::<u8>().map_err(|_| Reject::Expression)?;
            let date = CalendarDate::from_calendar_date(
                year,
                month.try_into().map_err(|_| Reject::Expression)?,
                day,
            )
            .map_err(|_| Reject::Expression)?;
            return Ok(PrimitiveDateTime::new(date, Clock::MIDNIGHT).assume_utc());
        }
    }
    let millis = value.as_i64().ok_or(Reject::Expression)?;
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .map_err(|_| Reject::Expression)
}
fn push_literal(
    chars: &mut std::iter::Peekable<std::str::Chars<'_>>,
    out: &mut String,
) -> Result<(), Reject> {
    if chars.peek() == Some(&'\'') {
        chars.next();
        return push_limited(out, "'");
    }
    let mut closed = false;
    while let Some(literal) = chars.next() {
        if literal == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
                push_limited(out, "'")?;
            } else {
                closed = true;
                break;
            }
        } else {
            push_limited(out, &literal.to_string())?;
        }
    }
    if closed { Ok(()) } else { Err(Reject::Expression) }
}
fn token_shape(token: char, count: usize) -> Result<(&'static str, NameKind), Reject> {
    Ok(match (token, count) {
        ('y', 2) => ("yy", NameKind::Numeric),
        ('y', 4) => ("yyyy", NameKind::Numeric),
        ('M', 1) => ("M", NameKind::Numeric),
        ('M', 2) => ("MM", NameKind::Numeric),
        ('M', 3) => ("MMM", NameKind::MonthAbbr),
        ('M', 4) => ("MMMM", NameKind::MonthWide),
        ('d', 1) => ("d", NameKind::Numeric),
        ('d', 2) => ("dd", NameKind::Numeric),
        ('H', 1) => ("H", NameKind::Numeric),
        ('H', 2) => ("HH", NameKind::Numeric),
        ('h', 1) => ("h", NameKind::Numeric),
        ('h', 2) => ("hh", NameKind::Numeric),
        ('m', 2) => ("mm", NameKind::Numeric),
        ('s', 2) => ("ss", NameKind::Numeric),
        ('E', 1) => ("E", NameKind::WeekAbbr),
        ('E', 3) => ("EEE", NameKind::WeekAbbr),
        ('E', 4) => ("EEEE", NameKind::WeekWide),
        ('a', 1) => ("a", NameKind::Period),
        _ => return Err(Reject::Expression),
    })
}
#[derive(Clone, Copy)]
enum NameKind {
    Numeric,
    MonthAbbr,
    MonthWide,
    WeekAbbr,
    WeekWide,
    Period,
}
fn format_token(
    tag: &str,
    shape: &str,
    kind: NameKind,
    when: OffsetDateTime,
) -> Result<String, Reject> {
    let mut names = FixedCalendarDateTimeNames::<Gregorian>::try_new(icu_locale(tag).into())
        .map_err(|_| Reject::Expression)?;
    load_names(&mut names, kind)?;
    let pattern = DateTimePattern::try_from_pattern_str(shape).map_err(|_| Reject::Expression)?;
    let datetime = gregorian_datetime(when)?;
    let formatted = names.with_pattern_unchecked(&pattern).format(&datetime);
    let mut out = String::new();
    match formatted.try_write_to(&mut out) {
        Ok(Ok(())) => bounded(&out),
        _ => Err(Reject::Expression),
    }
}
fn load_names(
    names: &mut FixedCalendarDateTimeNames<Gregorian>,
    kind: NameKind,
) -> Result<(), Reject> {
    match kind {
        NameKind::Numeric => Ok(()),
        NameKind::MonthAbbr => names
            .include_month_names(MonthNameLength::Abbreviated)
            .map(|_| ())
            .map_err(|_| Reject::Expression),
        NameKind::MonthWide => names
            .include_month_names(MonthNameLength::Wide)
            .map(|_| ())
            .map_err(|_| Reject::Expression),
        NameKind::WeekAbbr => names
            .include_weekday_names(WeekdayNameLength::Abbreviated)
            .map(|_| ())
            .map_err(|_| Reject::Expression),
        NameKind::WeekWide => names
            .include_weekday_names(WeekdayNameLength::Wide)
            .map(|_| ())
            .map_err(|_| Reject::Expression),
        NameKind::Period => names
            .include_day_period_names(DayPeriodNameLength::Abbreviated)
            .map(|_| ())
            .map_err(|_| Reject::Expression),
    }
}
fn gregorian_datetime(when: OffsetDateTime) -> Result<DateTime<Gregorian>, Reject> {
    let date = Date::try_new_gregorian(when.year(), u8::from(when.month()), when.day())
        .map_err(|_| Reject::Expression)?;
    let time = Time::try_new(when.hour(), when.minute(), when.second(), 0)
        .map_err(|_| Reject::Expression)?;
    Ok(DateTime { date, time })
}
fn icu_locale(tag: &str) -> Locale {
    Locale::from_str(tag).unwrap_or(locale!("en"))
}
fn bounded(text: &str) -> Result<String, Reject> {
    if text.len() > MAX_OUT { Err(Reject::Limit) } else { Ok(text.to_owned()) }
}
fn push_limited(out: &mut String, text: &str) -> Result<(), Reject> {
    if out.len().saturating_add(text.len()) > MAX_OUT {
        return Err(Reject::Limit);
    }
    out.push_str(text);
    Ok(())
}
