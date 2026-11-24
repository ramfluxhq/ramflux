// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

mod account_local;
pub(crate) mod account_runtime;
mod background;
#[cfg(test)]
pub(crate) use account_runtime::apply_ack_flush;
mod ack_cache;
mod actor;
mod agent_advance;
mod agent_directory;
mod agent_methods;
mod agent_retire;
pub(crate) mod attachment_plane;
mod attachment_scheduler;
pub(crate) mod backup_jobs;
pub mod client;
mod command_admission;
mod connection;
pub(crate) mod connection_manager;
mod control_state;
pub(crate) mod couriers;
mod creation_client;
mod creation_confirm;
pub(crate) mod credentials;
#[cfg(test)]
#[path = "tests/native_actor.rs"]
pub(crate) mod native_actor;
mod recovery;
pub(crate) mod runtime_limits;
#[cfg(unix)]
mod socket_dir;
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
mod host_branch;
mod host_manage;
pub mod io;
mod journal;
mod lifecycle;
mod lifecycle_registry;
mod metadata;
mod method_table;
pub(crate) mod mutation_intent;
mod mutations;
pub(crate) mod native_account;
mod networking_events;
pub(crate) mod own_device_copy;
pub mod protocol;
mod publication_wait;
pub(crate) mod read_model;
mod readers;
mod requests;
pub(crate) mod secrets;
mod session_lease;
mod shared_group_sync;
pub use session_lease::SessionLeasePriority;
pub mod shared_snapshot;
mod username_directory;
#[cfg(feature = "c-abi")]
pub(crate) mod wake_fetch;
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
#[cfg(test)]
pub(crate) mod test_gateway;

mod task_courier;
mod task_courier_apply;
mod task_courier_queue;
mod task_delivery;

#[cfg(test)]
mod transport_security_tests;

pub(crate) mod outbound;

mod own_contact_backfill;
mod pairing;
#[cfg(test)]
pub(crate) use pairing::unlock_for_test;

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

#[cfg(test)]
mod search_tests;

#[cfg(feature = "c-abi")]
pub(crate) mod inprocess;
mod search_dispatch;
