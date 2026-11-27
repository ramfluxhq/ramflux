// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Generic native account fixtures: one person, a sibling device, and the directory exchange.
use super::{Fixture, bus};
use crate::bus::state::LocalBusAccountState;
use crate::prekey::SdkDeviceManifestResponse;
use crate::{RamfluxClient, SdkError};

/// Runs one native fixture future to completion on a fresh current-thread runtime.
fn native_block_on<T>(
    future: impl std::future::Future<Output = Result<T, Box<dyn std::error::Error>>>,
) -> Result<T, SdkError> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(future)
        .map_err(|error| SdkError::LocalBus(error.to_string()))
}

/// One native account whose only device is `device`, held as a public-bus fixture.
pub(crate) fn native_person(id: &str, device: &str) -> Result<LocalBusAccountState, SdkError> {
    native_block_on(async move {
        let fixture = Fixture::with_device(id, device).await?;
        Ok(fixture.into_bus())
    })
}

/// `native_person`, also returning the recovery words the fixture was created with.
pub(crate) fn native_person_keeping_phrase(
    id: &str,
    device: &str,
) -> Result<(LocalBusAccountState, zeroize::Zeroizing<String>), SdkError> {
    native_block_on(async move {
        let (fixture, phrase) = Fixture::with_device_keeping_phrase(id, device).await?;
        Ok((fixture.into_bus(), phrase))
    })
}

/// A laptop sibling of `phone`. It carries the account primary, as the phone holds it.
pub(crate) fn native_sibling(
    phone: &mut LocalBusAccountState,
    id: &str,
    device: &str,
) -> Result<LocalBusAccountState, SdkError> {
    native_block_on(Box::pin(bus::sibling(phone, id, device)))
}

/// Manifest that the account's own native fixture published.
pub(crate) fn manifest_of(
    account: &LocalBusAccountState,
) -> Result<SdkDeviceManifestResponse, SdkError> {
    account
        .client
        .native_bus_fixture
        .as_ref()
        .map(|material| material.manifest.clone())
        .ok_or(SdkError::CustodySetupInvalid)
}

/// Device storage key that the raw group entry points expect as their target.
pub(crate) fn native_target(client: &RamfluxClient) -> Result<String, SdkError> {
    Ok(client.owned_device_identity()?.storage_key().into())
}

/// Publishes each listed account's native manifest into every listed account's directory.
pub(crate) fn install_native_directories(
    accounts: &[&LocalBusAccountState],
) -> Result<(), SdkError> {
    for holder in accounts {
        for source in accounts {
            holder.client.persist_observed_identity_directory_now(&manifest_of(source)?)?;
        }
    }
    Ok(())
}
