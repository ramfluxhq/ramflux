// SPDX-License-Identifier: BSD-3-Clause
//! Bounded, signed card interpretation. Hosts retain all SDK and approval authority.
mod budget;
#[cfg(any(test, feature = "compiler"))]
pub mod compiler;
mod components;
#[cfg(any(test, feature = "compiler"))]
mod engine_compiler;
mod error;
#[cfg(all(feature = "c-abi", not(target_arch = "wasm32")))]
mod ffi;
#[cfg(test)]
mod library_tests;
mod package;
mod presentation;
mod projection;
mod runtime;
mod session;
mod spec;
mod tree;
#[cfg(all(feature = "web", target_arch = "wasm32"))]
mod web;

pub use components::{
    Approval, Chart, ChartKind, Choice, Component, Field, FieldKind, Form, HostSecuritySlot, Point,
    Scalar, Series, Task, TaskStatus, TaskStep,
};
pub use error::CardError;
pub use package::{
    AcceptancePolicy, ENGINE_ID, HOST_ABI, PackageDescriptor, SignedPackage, catalog_digest,
};
pub use presentation::{Direction, Presentation};
pub use runtime::CardRuntime;
pub use session::{CardSession, Event, EventKind, EventResult, EventToken};
pub use spec::{CardSpec, Theme};
pub use tree::{Attrs, Mutation, MutationBatch, Node, NodeKind, Plot, Style, Tree};
