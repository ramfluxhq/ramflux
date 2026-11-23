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
mod slots;
mod spec;
mod tree;
#[cfg(all(feature = "web", target_arch = "wasm32"))]
mod web;

pub use components::NodeKind;
pub use error::CardError;
pub use package::{
    AcceptancePolicy, ENGINE_ID, HOST_ABI, PackageDescriptor, SignedPackage, catalog_digest,
};
pub use presentation::{Direction, Presentation};
pub use runtime::CardRuntime;
pub use session::{CardSession, EventResult, EventToken, HostEvent, HostEventKind};
pub use slots::{HostSlot, HostSlotReply, ImageResult, SlotOutcome, SlotRequest};
pub use spec::CardSpec;
pub use tree::{Mutation, MutationBatch, Node, Tree};
