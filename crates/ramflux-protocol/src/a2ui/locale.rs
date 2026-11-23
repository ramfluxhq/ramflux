// SPDX-License-Identifier: BSD-3-Clause
//! Bounded display formatting shared by native card hosts and terminal clients.
use super::Reject;
use serde_json::{Map, Value};
use time::{
    Date, OffsetDateTime, PrimitiveDateTime, Time, format_description::well_known::Rfc3339,
};

/// Launch locales. Unsupported locale identifiers fail closed at the host boundary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DisplayLocale {
    En,
    ZhCn,
}
impl DisplayLocale {
    /// Select one supported locale.
    /// # Errors
    /// Rejects locales outside the launch catalog.
    pub fn parse(locale: &str) -> Result<Self, Reject> {
        match locale {
            "en" => Ok(Self::En),
            "zh-CN" => Ok(Self::ZhCn),
            _ => Err(Reject::Validation("unsupported display locale".into())),
        }
    }
}
pub(super) fn format(
    name: &str,
    args: &Map<String, Value>,
    locale: DisplayLocale,
) -> Result<String, Reject> {
    match name {
        "formatNumber" => number(args, 0),
        "formatCurrency" => {
            let currency =
                args.get("currency").and_then(Value::as_str).ok_or(Reject::Expression)?;
            if currency.len() != 3 || !currency.bytes().all(|c| c.is_ascii_uppercase()) {
                return Err(Reject::Expression);
            }
            let digits = if matches!(currency, "JPY" | "KRW") { 0 } else { 2 };
            let value = number(args, digits)?;
            let symbol = match (currency, locale) {
                ("USD", DisplayLocale::En) => "$",
                ("USD", DisplayLocale::ZhCn) => "US$",
                ("CNY", DisplayLocale::En) => "CN¥",
                ("CNY", DisplayLocale::ZhCn) | ("JPY", DisplayLocale::En) => "¥",
                ("EUR", _) => "€",
                ("GBP", _) => "£",
                ("JPY", DisplayLocale::ZhCn) => "JP¥",
                _ => currency,
            };
            let (sign, magnitude) =
                value.strip_prefix('-').map_or(("", value.as_str()), |v| ("-", v));
            Ok(format!(
                "{sign}{symbol}{}{magnitude}",
                if symbol == currency { "\u{a0}" } else { "" }
            ))
        }
        "pluralize" => {
            let value = args.get("value").and_then(Value::as_f64).ok_or(Reject::Expression)?;
            let category =
                if locale == DisplayLocale::En && value.abs().to_bits() == 1.0_f64.to_bits() {
                    "one"
                } else {
                    "other"
                };
            args.get(category)
                .or_else(|| args.get("other"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .ok_or(Reject::Expression)
        }
        "formatDate" => date(args, locale),
        _ => Err(Reject::Expression),
    }
}
fn number(args: &Map<String, Value>, default_decimals: usize) -> Result<String, Reject> {
    let value = args.get("value").and_then(Value::as_f64).ok_or(Reject::Expression)?;
    if !value.is_finite() || value.abs() > 9_007_199_254_740_991.0 {
        return Err(Reject::Expression);
    }
    let decimals = args
        .get("decimals")
        .map(|n| {
            n.as_u64()
                .and_then(|n| usize::try_from(n).ok())
                .filter(|n| *n <= 20)
                .ok_or(Reject::Expression)
        })
        .transpose()?
        .unwrap_or(default_decimals);
    let grouping = args
        .get("grouping")
        .map(|v| v.as_bool().ok_or(Reject::Expression))
        .transpose()?
        .unwrap_or(true);
    let fixed = format!("{value:.decimals$}");
    let (whole, fraction) =
        fixed.split_once('.').map_or((fixed.as_str(), None), |(a, b)| (a, Some(b)));
    let (sign, digits) = whole.strip_prefix('-').map_or(("", whole), |v| ("-", v));
    let mut out = sign.to_owned();
    for (i, c) in digits.chars().enumerate() {
        if grouping && i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    if let Some(fraction) = fraction {
        out.push('.');
        out.push_str(fraction);
    }
    Ok(out)
}
fn timestamp(value: &Value) -> Result<OffsetDateTime, Reject> {
    if let Some(text) = value.as_str() {
        if let Ok(date) = OffsetDateTime::parse(text, &Rfc3339) {
            return Ok(date);
        }
        let parts: Vec<_> = text.split('-').collect();
        if let [year, month, day] = parts.as_slice() {
            let year = year.parse::<i32>().map_err(|_| Reject::Expression)?;
            let month = month.parse::<u8>().map_err(|_| Reject::Expression)?;
            let day = day.parse::<u8>().map_err(|_| Reject::Expression)?;
            let date = Date::from_calendar_date(
                year,
                month.try_into().map_err(|_| Reject::Expression)?,
                day,
            )
            .map_err(|_| Reject::Expression)?;
            return Ok(PrimitiveDateTime::new(date, Time::MIDNIGHT).assume_utc());
        }
    }
    let millis = value.as_i64().ok_or(Reject::Expression)?;
    OffsetDateTime::from_unix_timestamp_nanos(i128::from(millis) * 1_000_000)
        .map_err(|_| Reject::Expression)
}
fn date(args: &Map<String, Value>, locale: DisplayLocale) -> Result<String, Reject> {
    let date = timestamp(args.get("value").ok_or(Reject::Expression)?)?;
    let pattern = args.get("format").and_then(Value::as_str).ok_or(Reject::Expression)?;
    if pattern.len() > 256 {
        return Err(Reject::Limit);
    }
    let mut chars = pattern.chars().peekable();
    let mut out = String::new();
    while let Some(c) = chars.next() {
        if c == '\'' {
            if chars.peek() == Some(&'\'') {
                chars.next();
                out.push('\'');
                continue;
            }
            let mut closed = false;
            while let Some(literal) = chars.next() {
                if literal == '\'' {
                    if chars.peek() == Some(&'\'') {
                        chars.next();
                        out.push('\'');
                    } else {
                        closed = true;
                        break;
                    }
                } else {
                    out.push(literal);
                }
            }
            if !closed {
                return Err(Reject::Expression);
            }
        } else if c.is_ascii_alphabetic() {
            let mut count = 1;
            while chars.peek() == Some(&c) {
                chars.next();
                count += 1;
            }
            out.push_str(&date_token(date, c, count, locale)?);
        } else {
            out.push(c);
        }
    }
    Ok(out)
}
fn date_token(
    date: OffsetDateTime,
    token: char,
    count: usize,
    locale: DisplayLocale,
) -> Result<String, Reject> {
    let zh = locale == DisplayLocale::ZhCn;
    let month = usize::from(u8::from(date.month())).checked_sub(1).ok_or(Reject::Expression)?;
    let weekday = usize::from(date.weekday().number_days_from_monday());
    let months = [
        "January",
        "February",
        "March",
        "April",
        "May",
        "June",
        "July",
        "August",
        "September",
        "October",
        "November",
        "December",
    ];
    let days = ["Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday"];
    let zh_days = ["一", "二", "三", "四", "五", "六", "日"];
    let numeric = match token {
        'y' if count == 2 => i32::rem_euclid(date.year(), 100),
        'y' if count == 4 => date.year(),
        'M' if count <= 2 => i32::from(u8::from(date.month())),
        'd' if count <= 2 => i32::from(date.day()),
        'H' if count <= 2 => i32::from(date.hour()),
        'h' if count <= 2 => {
            i32::from(if date.hour().is_multiple_of(12) { 12 } else { date.hour() % 12 })
        }
        'm' if count == 2 => i32::from(date.minute()),
        's' if count == 2 => i32::from(date.second()),
        'M' if matches!(count, 3 | 4) => {
            return if zh {
                Ok(format!("{}月", month + 1))
            } else {
                let name = months.get(month).ok_or(Reject::Expression)?;
                Ok(if count == 3 { name.get(..3).ok_or(Reject::Expression)? } else { name }
                    .to_string())
            };
        }
        'E' if matches!(count, 1 | 3 | 4) => {
            return if zh {
                Ok(format!(
                    "{}{}",
                    if count == 4 { "星期" } else { "周" },
                    zh_days.get(weekday).ok_or(Reject::Expression)?
                ))
            } else {
                let name = days.get(weekday).ok_or(Reject::Expression)?;
                Ok(if count == 4 { name } else { name.get(..3).ok_or(Reject::Expression)? }
                    .to_string())
            };
        }
        'a' if count == 1 => {
            return Ok(match (zh, date.hour() < 12) {
                (true, true) => "上午",
                (true, false) => "下午",
                (false, true) => "AM",
                (false, false) => "PM",
            }
            .into());
        }
        _ => return Err(Reject::Expression),
    };
    Ok(format!("{numeric:0count$}"))
}
