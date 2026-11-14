// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deterministic author-side validation expressions and the bounded A2UI regex dialect.
use super::{JsonPointer, Reject};
use regex_syntax::ast::{Ast, RepetitionKind as R, RepetitionRange as Range};
use serde_json::{Value, json};

pub(super) fn checks(checks: Option<&Value>, model: &Value, prefix: &str) -> Result<(), Reject> {
    if let Some(checks) = checks {
        let checks = checks.as_array().ok_or(Reject::Expression)?;
        if checks.len() > 8 {
            return Err(Reject::Limit);
        }
        for check in checks {
            let result =
                evaluate(check.get("condition").ok_or(Reject::Expression)?, model, prefix, 0)?;
            if result.as_bool().or_else(|| result.get("valid").and_then(Value::as_bool))
                != Some(true)
            {
                return Err(Reject::Validation("button check failed".into()));
            }
        }
    }
    Ok(())
}
pub(super) fn evaluate(
    expression: &Value,
    model: &Value,
    prefix: &str,
    depth: usize,
) -> Result<Value, Reject> {
    if depth > 16 {
        return Err(Reject::Limit);
    }
    let Some(object) = expression.as_object() else {
        return Ok(expression.clone());
    };
    if let Some(path) = object.get("@path") {
        let path = path.as_str().ok_or(Reject::Expression)?;
        return JsonPointer::parse(&if path.starts_with('/') {
            path.into()
        } else {
            format!("{prefix}/{path}")
        })?
        .get(model)
        .cloned()
        .ok_or(Reject::Expression);
    }
    let Some(call) = object.get("@call") else {
        return Ok(expression.clone());
    };
    let name = call.as_str().ok_or(Reject::Expression)?;
    let args = object.get("args").and_then(Value::as_object).ok_or(Reject::Expression)?;
    let get =
        |key: &str| evaluate(args.get(key).ok_or(Reject::Expression)?, model, prefix, depth + 1);
    match name {
        "@index" => {
            if prefix.is_empty() {
                return Err(Reject::Expression);
            }
            let index = prefix
                .rsplit('/')
                .next()
                .ok_or(Reject::Expression)?
                .parse::<i64>()
                .map_err(|_| Reject::Expression)?;
            let offset = args
                .get("offset")
                .map(|v| evaluate(v, model, prefix, depth + 1))
                .transpose()?
                .map(|v| v.as_i64().ok_or(Reject::Expression))
                .transpose()?
                .unwrap_or(0);
            Ok(serde_json::json!(index.checked_add(offset).ok_or(Reject::Expression)?))
        }
        "formatString" => {
            let value = get("value")?;
            Ok(serde_json::json!(super::format_string::render(
                value.as_str().ok_or(Reject::Expression)?,
                model,
                prefix,
                depth + 1
            )?))
        }
        "required" => {
            let value = get("value")?;
            let valid = match &value {
                Value::Null => false,
                Value::String(s) => !s.is_empty(),
                Value::Array(a) => !a.is_empty(),
                Value::Object(o) => !o.is_empty(),
                _ => true,
            };
            Ok(json!({"valid":valid}))
        }
        "length" => {
            let value = get("value")?;
            let n = value.as_str().ok_or(Reject::Expression)?.chars().count();
            let n = u64::try_from(n).map_err(|_| Reject::Limit)?;
            let min = args.get("min").and_then(Value::as_u64).unwrap_or(0);
            let max =
                args.get("max").and_then(Value::as_u64).unwrap_or(crate::MAX_SAFE_JSON_INTEGER);
            Ok(json!({"valid":n >= min && n <= max}))
        }
        "numeric" => {
            let value = get("value")?;
            let n = value.as_i64().ok_or(Reject::Expression)?;
            let min = args
                .get("min")
                .and_then(Value::as_i64)
                .unwrap_or(-(crate::MAX_SAFE_JSON_INTEGER as i64));
            let max = args
                .get("max")
                .and_then(Value::as_i64)
                .unwrap_or(crate::MAX_SAFE_JSON_INTEGER as i64);
            Ok(json!({"valid":n >= min && n <= max}))
        }
        "regex" => {
            let value = get("value")?;
            let text = value.as_str().ok_or(Reject::Expression)?;
            let pattern = args.get("pattern").and_then(Value::as_str).ok_or(Reject::Expression)?;
            let translated = translated_regex(pattern)?;
            let matched = text.chars().take(4097).count() <= 4096
                && regex::Regex::new(&translated).map_err(|_| Reject::Expression)?.is_match(text);
            Ok(json!({"valid":matched}))
        }
        "email" => {
            let value = get("value")?;
            let text = value.as_str().ok_or(Reject::Expression)?;
            let validator = jsonschema::options()
                .should_validate_formats(true)
                .build(&json!({"format":"email","type":"string"}))
                .map_err(|_| Reject::Expression)?;
            Ok(json!({"valid":validator.is_valid(&json!(text))}))
        }
        "and" | "or" => {
            let values = args.get("values").and_then(Value::as_array).ok_or(Reject::Expression)?;
            let mut result = name == "and";
            for value in values {
                let v = evaluate(value, model, prefix, depth + 1)?;
                let v = v.as_bool().ok_or(Reject::Expression)?;
                if name == "and" {
                    result &= v;
                } else {
                    result |= v;
                }
            }
            Ok(json!(result))
        }
        "not" => Ok(json!(!get("value")?.as_bool().ok_or(Reject::Expression)?)),
        // Locale-dependent functions are forbidden in button checks at admission. Display
        // formatting belongs to the card runtime; it never becomes an action witness.
        _ => Err(Reject::Expression),
    }
}
pub(super) fn validate_regex(pattern: &str) -> Result<(), Reject> {
    translated_regex(pattern).map(|_| ())
}
fn translated_regex(pattern: &str) -> Result<String, Reject> {
    if pattern.chars().take(257).count() > 256 {
        return Err(Reject::Expression);
    }
    let mut out = String::new();
    let mut chars = pattern.chars().peekable();
    let mut in_class = false;
    while let Some(c) = chars.next() {
        match c {
            '[' => {
                in_class = true;
                out.push(c);
            }
            ']' => {
                in_class = false;
                out.push(c);
            }
            '(' => {
                if chars.peek() == Some(&'?') {
                    chars.next();
                    if chars.next() != Some(':') {
                        return Err(Reject::Expression);
                    }
                    out.push_str("(?:");
                } else {
                    out.push(c);
                }
            }
            '.' if !in_class => out.push_str("[^\\n\\r\\u{2028}\\u{2029}]"),
            '^' if !in_class => out.push_str("\\A"),
            '$' if !in_class => out.push_str("\\z"),
            '\\' => {
                let escaped = chars.next().ok_or(Reject::Expression)?;
                match escaped {
                    'd' => out.push_str(if in_class { "0-9" } else { "[0-9]" }),
                    'w' => out.push_str(if in_class { "A-Za-z0-9_" } else { "[A-Za-z0-9_]" }),
                    's' => out.push_str(if in_class { "\\t-\\r \\u{00a0}\\u{1680}\\u{2000}-\\u{200a}\\u{2028}\\u{2029}\\u{202f}\\u{205f}\\u{3000}\\u{feff}" } else { "[\\t-\\r \\u{00a0}\\u{1680}\\u{2000}-\\u{200a}\\u{2028}\\u{2029}\\u{202f}\\u{205f}\\u{3000}\\u{feff}]" }),
                    'D' => out.push_str("[^0-9]"),
                    'W' => out.push_str("[^A-Za-z0-9_]"),
                    'S' => out.push_str("[^\\t-\\r \\u{00a0}\\u{1680}\\u{2000}-\\u{200a}\\u{2028}\\u{2029}\\u{202f}\\u{205f}\\u{3000}\\u{feff}]"),
                    'b' if !in_class => out.push_str("(?-u:\\b)"),
                    'B' if !in_class => out.push_str("(?-u:\\B)"),
                    'b' => out.push_str("\\x08"),
                    'v' => out.push_str("\\x0b"),
                    '0' => { if chars.peek().is_some_and(char::is_ascii_digit) { return Err(Reject::Expression); } out.push_str("\\x00"); },
                    't' | 'n' | 'f' | 'r' | 'x' | 'u' => { out.push('\\'); out.push(escaped); },
                    c if "^$\\.*+?()[]{}|/".contains(c) => { if c != '/' { out.push('\\'); } out.push(c); },
                    _ => return Err(Reject::Expression),
                }
            }
            _ => out.push(c),
        }
    }
    let ast =
        regex_syntax::ast::parse::Parser::new().parse(&out).map_err(|_| Reject::Expression)?;
    safety(&ast)?;
    regex::Regex::new(&out).map_err(|_| Reject::Expression)?;
    Ok(out)
}
#[derive(Default)]
struct Info {
    first: Vec<(u32, u32)>,
    empty: bool,
    unbounded: bool,
    atom_unbounded: bool,
}
fn overlaps(a: &[(u32, u32)], b: &[(u32, u32)]) -> bool {
    a.iter().any(|(a, z)| b.iter().any(|(b, y)| a <= y && b <= z))
}
fn ungroup(ast: &Ast) -> &Ast {
    if let Ast::Group(g) = ast { ungroup(&g.ast) } else { ast }
}
fn safety(ast: &Ast) -> Result<Info, Reject> {
    match ast {
        Ast::Group(g) => safety(&g.ast),
        Ast::Repetition(r) => {
            let child = safety(&r.ast)?;
            let (min, max) = match r.op.kind {
                R::ZeroOrOne => (0, Some(1)),
                R::ZeroOrMore => (0, None),
                R::OneOrMore => (1, None),
                R::Range(Range::Exactly(n)) => (n, Some(n)),
                R::Range(Range::AtLeast(n)) => (n, None),
                R::Range(Range::Bounded(a, b)) => (a, Some(b)),
            };
            if child.unbounded && max.is_none_or(|v| v > 1) {
                return Err(Reject::Expression);
            }
            if max.is_none()
                && let Ast::Alternation(a) = ungroup(&r.ast)
            {
                let mut previous: Vec<Info> = Vec::new();
                for branch in &a.asts {
                    let info = safety(branch)?;
                    if previous.iter().any(|p| overlaps(&p.first, &info.first)) {
                        return Err(Reject::Expression);
                    }
                    previous.push(info);
                }
            }
            Ok(Info {
                first: child.first,
                empty: min == 0 || child.empty,
                unbounded: max.is_none() || child.unbounded,
                atom_unbounded: max.is_none(),
            })
        }
        Ast::Concat(c) => {
            let mut info = Info { empty: true, ..Info::default() };
            let mut previous: Vec<Vec<(u32, u32)>> = Vec::new();
            for atom in &c.asts {
                let child = safety(atom)?;
                if child.atom_unbounded && previous.iter().any(|p| overlaps(p, &child.first)) {
                    return Err(Reject::Expression);
                }
                if !child.empty {
                    previous.clear();
                }
                if child.atom_unbounded {
                    previous.push(child.first.clone());
                }
                if info.empty {
                    info.first.extend(child.first);
                }
                info.empty &= child.empty;
                info.unbounded |= child.unbounded;
            }
            Ok(info)
        }
        Ast::Alternation(a) => {
            let mut info = Info::default();
            for atom in &a.asts {
                let child = safety(atom)?;
                info.first.extend(child.first);
                info.empty |= child.empty;
                info.unbounded |= child.unbounded;
            }
            Ok(info)
        }
        Ast::Empty(_) | Ast::Assertion(_) => Ok(Info { empty: true, ..Info::default() }),
        Ast::Flags(_) => Ok(Info { empty: true, ..Info::default() }), // only trusted ASCII-boundary flags are introduced by translation
        _ => {
            let hir = regex_syntax::Parser::new()
                .parse(&ast.to_string())
                .map_err(|_| Reject::Expression)?;
            let first = match hir.kind() {
                regex_syntax::hir::HirKind::Literal(l) => {
                    let c = std::str::from_utf8(&l.0)
                        .map_err(|_| Reject::Expression)?
                        .chars()
                        .next()
                        .ok_or(Reject::Expression)?;
                    vec![(u32::from(c), u32::from(c))]
                }
                regex_syntax::hir::HirKind::Class(regex_syntax::hir::Class::Unicode(class)) => {
                    class.iter().map(|r| (u32::from(r.start()), u32::from(r.end()))).collect()
                }
                _ => return Err(Reject::Expression),
            };
            Ok(Info { first, ..Info::default() })
        }
    }
}

pub(super) fn locale_sensitive(name: &str) -> bool {
    matches!(name, "formatDate" | "formatNumber" | "formatCurrency" | "pluralize")
}
