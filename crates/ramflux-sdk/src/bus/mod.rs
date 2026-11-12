// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub(crate) mod account_runtime;
#[cfg(test)]
pub(crate) use account_runtime::apply_ack_flush;
mod ack_cache;
mod actor;
mod attachment_scheduler;
mod backup_jobs;
pub mod client;
mod command_admission;
mod connection;
pub(crate) mod connection_manager;
mod control_state;
pub(crate) mod couriers;
mod creation_client;
mod creation_confirm;
#[cfg(test)]
#[path = "tests/native_actor.rs"]
pub(crate) mod native_actor;
mod recovery;
pub(crate) mod runtime_limits;
mod transfer_slots;
pub use creation_client::{
    LocalBusCreationClient, LocalBusPendingCreation, LocalBusPendingRecovery,
    LocalBusRecoveryClient,
};
mod custody_response;
mod custody_setup;
pub mod daemon;
pub(crate) mod data_root_lock;
pub(crate) mod delivery_receipts;
pub mod dispatch;
mod events;
#[expect(dead_code, reason = "resume fence port follows in the next integration round")]
mod gateway_resume;
mod generated_typing;
pub(crate) mod group_conversation;
mod group_delivery;
pub mod io;
mod journal;
mod lifecycle;
mod lifecycle_registry;
mod message_projection;
mod metadata;
mod method_table;
mod mutation_intent;
mod mutations;
pub(crate) mod native_account;
mod networking_events;
pub(crate) mod own_device_copy;
pub mod protocol;
pub(crate) mod read_model;
mod readers;
mod requests;
mod secrets;
mod shared_group_sync;
pub(crate) use shared_group_sync::enqueue as enqueue_shared_group;
pub(crate) mod push_receiver;
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
pub(crate) mod runtime_tests;

mod task_courier;
mod task_courier_apply;
mod task_courier_queue;
mod task_delivery;

#[cfg(test)]
mod transport_security_tests;

mod own_contact_backfill;

pub(crate) mod contact_backpressure;

#[cfg(test)]
pub(crate) use readers::test_account_reader_request;

#[cfg(test)]
mod custody_setup_tests;
#[cfg(test)]
pub(crate) mod vault_reason_tests;

#[cfg(test)]
mod native_account_tests;

#[cfg(test)]
mod recovery_tests;

#[cfg(test)]
mod account_error_tests;

#[cfg(all(test, unix))]
mod custody_daemon_tests;

#[cfg(test)]
mod generated_typing_tests;
