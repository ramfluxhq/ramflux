// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Stable directory ordering, bounded local search and unread/attention totals.

/// Local query byte budget. This does not change any protocol limit.
pub const QUERY_LIMIT: usize = 1024;
/// Maximum number of rows returned in one page.
pub const PAGE_LIMIT: usize = 100;

/// Borrowed source facts, valid for one account snapshot only.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct Row<'a> {
    /// Stable conversation identifier.
    pub id: &'a str,
    /// Display title supplied by the adapter.
    pub title: &'a str,
    /// Body preview already cleared for display by the adapter.
    pub preview: Option<&'a str>,
    /// Pin state.
    pub pinned: bool,
    /// Latest activity in Unix milliseconds, if known.
    pub latest_ms: Option<i64>,
    /// Unread count from the source.
    pub unread: u32,
    /// Pending decisions counted by the adapter.
    pub attention: u32,
}

impl<'a> Row<'a> {
    /// Creates an unpinned row with no content, unread count or attention.
    #[must_use]
    pub const fn new(id: &'a str, title: &'a str) -> Self {
        Self { id, title, preview: None, pinned: false, latest_ms: None, unread: 0, attention: 0 }
    }
}

/// Query rejected before normalization/allocation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct QueryTooLong;

/// A page borrowing the input snapshot; offsets reset whenever that snapshot changes.
#[derive(Debug)]
#[non_exhaustive]
pub struct Page<'a, 's> {
    /// At most [`PAGE_LIMIT`] visible rows.
    pub rows: Vec<&'s Row<'a>>,
    /// Offset into the same filtered and sorted snapshot, if more rows remain.
    pub next_offset: Option<usize>,
}

/// Filters IDs, titles and displayable previews, then orders pin/recent/id.
/// `visible` must be false for a locked or otherwise inaccessible account.
/// This function never retrieves content, changes unread state or schedules a send.
///
/// # Errors
/// Returns [`QueryTooLong`] if the query exceeds [`QUERY_LIMIT`] bytes.
pub fn page<'a, 's>(
    rows: &'s [Row<'a>],
    visible: bool,
    query: &str,
    offset: usize,
    limit: usize,
) -> Result<Page<'a, 's>, QueryTooLong> {
    if query.len() > QUERY_LIMIT {
        return Err(QueryTooLong);
    }
    if !visible {
        return Ok(Page { rows: Vec::new(), next_offset: None });
    }
    let query = query.trim().to_lowercase();
    let mut matches: Vec<_> = rows
        .iter()
        .filter(|row| {
            query.is_empty()
                || row.id.to_lowercase().contains(&query)
                || row.title.to_lowercase().contains(&query)
                || row.preview.is_some_and(|text| text.to_lowercase().contains(&query))
        })
        .collect();
    matches.sort_by(|a, b| {
        b.pinned
            .cmp(&a.pinned)
            .then_with(|| b.latest_ms.cmp(&a.latest_ms))
            .then_with(|| a.id.cmp(b.id))
    });
    let limit = limit.clamp(1, PAGE_LIMIT);
    let next_offset = offset.checked_add(limit).filter(|next| *next < matches.len());
    Ok(Page { rows: matches.into_iter().skip(offset).take(limit).collect(), next_offset })
}

/// Unread and decision totals for a snapshot. Saturates instead of wrapping.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Totals {
    /// Sum of source unread counts.
    pub unread: u64,
    /// Sum of pending decision counts.
    pub attention: u64,
}

/// Computes navigation totals without treating unread messages as pending decisions.
#[must_use]
pub fn totals(rows: &[Row<'_>], visible: bool) -> Totals {
    if !visible {
        return Totals::default();
    }
    rows.iter().fold(Totals::default(), |total, row| Totals {
        unread: total.unread.saturating_add(u64::from(row.unread)),
        attention: total.attention.saturating_add(u64::from(row.attention)),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn list_search_and_badges_preserve_snapshot_and_privacy() {
        let mut old = Row::new("old", "Pinned");
        old.pinned = true;
        old.unread = 3;
        let mut recent = Row::new("recent", "Peer");
        recent.latest_ms = Some(10);
        recent.attention = 2;
        recent.preview = Some("Cached message");
        let rows = [recent, old];
        let first = page(&rows, true, "", 0, 1).expect("test: valid query");
        assert_eq!(
            first.rows.first().map(|r| r.id),
            Some("old"),
            "pins precede activity without changing source order"
        );
        assert_eq!(first.next_offset, Some(1), "the second row must remain reachable");
        assert_eq!(
            page(&rows, true, "MESSAGE", 0, 100).expect("test: body search").rows.len(),
            1,
            "cached previews participate in case-folded search"
        );
        assert!(
            page(&rows, false, "", 0, 100).expect("test: locked snapshot").rows.is_empty(),
            "locked snapshots expose no rows"
        );
        assert_eq!(
            totals(&rows, true),
            Totals { unread: 3, attention: 2 },
            "unread and decisions are independent totals"
        );
        assert_eq!(
            totals(&rows, false),
            Totals::default(),
            "locked snapshots expose no badge metadata"
        );
        assert_eq!(
            page(&rows, true, &"x".repeat(QUERY_LIMIT + 1), 0, 100).err(),
            Some(QueryTooLong),
            "oversized input is refused"
        );
    }
}
