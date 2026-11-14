// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Parse formatString programs so indirect reads and nested functions obey the check closure.
use super::{MAX_DELTA_BYTES, Reject};
use serde_json::{Map, Value};
use std::{iter::Peekable, str::CharIndices};
struct Parser<'a> {
    source: &'a str,
    chars: Peekable<CharIndices<'a>>,
}
impl<'a> Parser<'a> {
    fn new(source: &'a str) -> Self {
        Self { source, chars: source.char_indices().peekable() }
    }
    fn peek(&mut self) -> Option<char> {
        self.chars.peek().map(|(_, c)| *c)
    }
    fn take(&mut self, c: char) -> bool {
        if self.peek() == Some(c) {
            self.chars.next();
            true
        } else {
            false
        }
    }
    fn space(&mut self) {
        while self.peek().is_some_and(char::is_whitespace) {
            self.chars.next();
        }
    }
    fn word(&mut self) -> Result<String, Reject> {
        let start = self.chars.peek().map(|(i, _)| *i).ok_or(Reject::Expression)?;
        while self.peek().is_some_and(|c| !c.is_whitespace() && !"(){}:,".contains(c)) {
            self.chars.next();
        }
        let end = self.chars.peek().map_or(self.source.len(), |(i, _)| *i);
        if start == end {
            return Err(Reject::Expression);
        }
        Ok(self.source.get(start..end).ok_or(Reject::Expression)?.to_owned())
    }
    fn string(&mut self, quote: char) -> Result<Value, Reject> {
        let mut out = String::new();
        while let Some((_, c)) = self.chars.next() {
            if c == quote {
                return Ok(Value::String(out));
            }
            if c == '\\' {
                let (_, escaped) = self.chars.next().ok_or(Reject::Expression)?;
                match escaped {
                    'n' => out.push('\n'),
                    'r' => out.push('\r'),
                    't' => out.push('\t'),
                    'u' => {
                        let braced = self.take('{');
                        let mut code = String::new();
                        if braced {
                            while self.peek().is_some_and(|c| c != '}') {
                                let (_, c) = self.chars.next().ok_or(Reject::Expression)?;
                                if code.len() >= 6 || !c.is_ascii_hexdigit() {
                                    return Err(Reject::Expression);
                                }
                                code.push(c);
                            }
                            if !self.take('}') {
                                return Err(Reject::Expression);
                            }
                        } else {
                            for _ in 0..4 {
                                code.push(self.chars.next().ok_or(Reject::Expression)?.1);
                            }
                        }
                        let c = char::from_u32(
                            u32::from_str_radix(&code, 16).map_err(|_| Reject::Expression)?,
                        )
                        .ok_or(Reject::Expression)?;
                        out.push(c);
                    }
                    c => out.push(c),
                }
            } else {
                out.push(c);
            }
        }
        Err(Reject::Expression)
    }
    fn expression(&mut self, depth: usize) -> Result<Value, Reject> {
        if depth > 16 {
            return Err(Reject::Limit);
        }
        self.space();
        if self.take('$') {
            if !self.take('{') {
                return Err(Reject::Expression);
            }
            let expression = self.expression(depth + 1)?;
            self.space();
            if !self.take('}') {
                return Err(Reject::Expression);
            }
            return Ok(expression);
        }
        if let Some(quote @ ('\'' | '"')) = self.peek() {
            self.chars.next();
            return self.string(quote);
        }
        let token = self.word()?;
        self.space();
        if self.take('(') {
            let mut args = Map::new();
            self.space();
            if !self.take(')') {
                loop {
                    self.space();
                    let name = self.word()?;
                    self.space();
                    if !self.take(':') || args.contains_key(&name) {
                        return Err(Reject::Expression);
                    }
                    let value = self.expression(depth + 1)?;
                    args.insert(name, value);
                    self.space();
                    if self.take(')') {
                        break;
                    }
                    if !self.take(',') {
                        return Err(Reject::Expression);
                    }
                }
            }
            let value = serde_json::json!({"@call":token,"args":args});
            super::schema::function(&value)?;
            return Ok(value);
        }
        match token.as_str() {
            "true" => Ok(Value::Bool(true)),
            "false" => Ok(Value::Bool(false)),
            "null" => Ok(Value::Null),
            _ => {
                if let Ok(number) = token.parse::<serde_json::Number>() {
                    Ok(Value::Number(number))
                } else {
                    Ok(serde_json::json!({"@path":token}))
                }
            }
        }
    }
}
enum Part {
    Text(String),
    Expression(Value),
}
fn parse(program: &str) -> Result<Vec<Part>, Reject> {
    if program.len() > super::MAX_MODEL_BYTES {
        return Err(Reject::Limit);
    }
    let mut parser = Parser::new(program);
    let mut text = String::new();
    let mut out = Vec::new();
    while let Some((_, c)) = parser.chars.next() {
        if c == '\\' && parser.peek() == Some('$') {
            parser.chars.next();
            if parser.take('{') {
                text.push_str("${");
            } else {
                text.push_str("\\$");
            }
        } else if c == '$' && parser.take('{') {
            out.push(Part::Text(std::mem::take(&mut text)));
            let expression = parser.expression(0)?;
            parser.space();
            if !parser.take('}') {
                return Err(Reject::Expression);
            }
            out.push(Part::Expression(expression));
        } else {
            text.push(c);
        }
    }
    out.push(Part::Text(text));
    Ok(out)
}
pub(super) fn expressions(program: &str) -> Result<Vec<Value>, Reject> {
    Ok(parse(program)?
        .into_iter()
        .filter_map(|part| if let Part::Expression(value) = part { Some(value) } else { None })
        .collect())
}
pub(super) fn render(
    program: &str,
    model: &Value,
    prefix: &str,
    depth: usize,
) -> Result<String, Reject> {
    let mut out = String::new();
    for part in parse(program)? {
        let text = match part {
            Part::Text(text) => text,
            Part::Expression(expression) => {
                let value = super::expression::evaluate(&expression, model, prefix, depth + 1)?;
                match value {
                    Value::Null => String::new(),
                    Value::String(text) => text,
                    _ => String::from_utf8(super::wire::canonical(&value)?)
                        .map_err(|_| Reject::Encoding)?,
                }
            }
        };
        if out.len().saturating_add(text.len()) > MAX_DELTA_BYTES {
            return Err(Reject::Limit);
        }
        out.push_str(&text);
    }
    Ok(out)
}
