// SPDX-License-Identifier: MIT OR Apache-2.0
mod array_range_set;
mod btree_range_set;
#[cfg(test)]
mod tests;

pub(crate) use array_range_set::ArrayRangeSet;
pub(crate) use btree_range_set::{RangeSet, Replace};
