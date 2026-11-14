// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Drive the existing conversation bus methods and the typing sender.

mod drive;
mod output;
mod typing;

pub(crate) use drive::handle;
