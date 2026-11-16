// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Parse each production item, including items following an inline test module.
use syn::visit::{self, Visit};

fn test_only(attributes: &[syn::Attribute]) -> bool {
    attributes.iter().any(|attribute| {
        attribute.path().is_ident("cfg")
            && matches!(&attribute.meta, syn::Meta::List(list) if list.tokens.to_string() == "test")
    })
}
fn attributes(item: &syn::Item) -> &[syn::Attribute] {
    match item {
        syn::Item::Const(value) => &value.attrs,
        syn::Item::Enum(value) => &value.attrs,
        syn::Item::ExternCrate(value) => &value.attrs,
        syn::Item::Fn(value) => &value.attrs,
        syn::Item::ForeignMod(value) => &value.attrs,
        syn::Item::Impl(value) => &value.attrs,
        syn::Item::Macro(value) => &value.attrs,
        syn::Item::Mod(value) => &value.attrs,
        syn::Item::Static(value) => &value.attrs,
        syn::Item::Struct(value) => &value.attrs,
        syn::Item::Trait(value) => &value.attrs,
        syn::Item::TraitAlias(value) => &value.attrs,
        syn::Item::Type(value) => &value.attrs,
        syn::Item::Union(value) => &value.attrs,
        syn::Item::Use(value) => &value.attrs,
        _ => &[],
    }
}
struct Scanner<'a> {
    markers: &'a [&'a str],
    found: bool,
}
impl<'ast> Visit<'ast> for Scanner<'_> {
    fn visit_item(&mut self, item: &'ast syn::Item) {
        if !test_only(attributes(item)) {
            visit::visit_item(self, item);
        }
    }
    fn visit_expr_call(&mut self, call: &'ast syn::ExprCall) {
        if let syn::Expr::Path(path) = call.func.as_ref()
            && let Some(segment) = path.path.segments.last()
            && self
                .markers
                .iter()
                .any(|marker| marker.strip_suffix("()").is_some_and(|name| segment.ident == name))
        {
            self.found = true;
        }
        visit::visit_expr_call(self, call);
    }
    fn visit_lit_str(&mut self, literal: &'ast syn::LitStr) {
        self.found |= self.markers.iter().any(|marker| literal.value().contains(marker));
    }
}
pub(super) fn contains(source: &str, markers: &[&str]) -> syn::Result<bool> {
    let file = syn::parse_file(source)?;
    if test_only(&file.attrs) {
        return Ok(false);
    }
    let mut scanner = Scanner { markers, found: false };
    scanner.visit_file(&file);
    Ok(scanner.found)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn scans_production_after_an_inline_test_without_counting_test_calls() -> syn::Result<()> {
        let marker = ["active_generation()"];
        assert!(
            !contains("#[cfg(test)] mod tests { fn f() { active_generation(); } }", &marker)?,
            "test-only profile assertions are not production selectors"
        );
        assert!(
            contains("#[cfg(test)] mod tests {} fn validate() { active_generation(); }", &marker)?,
            "production after a test module must remain visible"
        );
        Ok(())
    }
}
