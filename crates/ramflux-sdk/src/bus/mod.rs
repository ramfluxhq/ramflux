// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod account_runtime;
mod ack_cache;
mod actor;
mod attachment_scheduler;
mod backup_jobs;
pub mod client;
mod connection;
mod control_state;
mod courier_cycle;
mod creation_client;
mod creation_confirm;
mod recovery;
pub use creation_client::{
    LocalBusCreationClient, LocalBusPendingCreation, LocalBusPendingRecovery,
    LocalBusRecoveryClient,
};
mod custody_response;
mod custody_setup;
pub mod daemon;
pub(crate) mod data_root_lock;
mod delivery_receipts;
pub mod dispatch;
mod events;
mod gateway_resume;
pub(crate) mod group_conversation;
mod group_delivery;
pub mod io;
mod journal;
mod lifecycle;
mod message_projection;
mod metadata;
mod mutations;
mod native_account;
mod networking_events;
pub(crate) mod own_device_copy;
pub mod protocol;
pub(crate) mod read_model;
mod readers;
mod requests;
mod secrets;
mod shared_group_sync;
pub(crate) use shared_group_sync::enqueue as enqueue_shared_group;
mod socket;
pub mod state;
mod subscription;
mod supervisor;
pub(crate) mod sync_driver;
mod sync_status;

pub use client::*;
pub use daemon::*;
pub use protocol::*;

#[cfg(test)]
mod runtime_tests;

mod task_courier;
mod task_courier_apply;
mod task_courier_queue;
mod task_delivery;

#[cfg(test)]
mod transport_security_tests;

mod own_contact_backfill;

mod contact_backpressure;

#[cfg(test)]
pub(crate) use readers::test_account_reader_request;

#[cfg(test)]
mod custody_setup_tests;

#[cfg(test)]
mod native_account_tests;

#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod account_error_tests;

#[cfg(test)]
mod custody_daemon_tests;
