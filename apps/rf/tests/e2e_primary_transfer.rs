// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Full transfer through real services, daemons and product CLI commands.
#![cfg(all(unix, feature = "itest-memory-vault"))]

#[path = "e2e/mod.rs"]
mod e2e;

#[test]
#[ignore = "real process seed; requires the branch's rf and node service binaries"]
fn primary_transfer_native_populated_seed() -> e2e::Result<()> {
    let stack = e2e::boot_pairing_stack(&[])?;
    let seed = e2e::primary_transfer::Seed::create(&stack)?;
    e2e::primary_transfer::read(
        &seed.source,
        &seed.account,
        &seed.conversation,
        &seed.authored,
        "transfer own native body",
    )?;
    e2e::primary_transfer::read(
        &seed.source,
        &seed.account,
        &seed.conversation,
        &seed.received,
        "transfer peer native body",
    )?;
    Ok(())
}

#[test]
#[ignore = "real CLI pairing; requires the branch's rf and node service binaries"]
fn primary_transfer_native_existing_recipient() -> e2e::Result<()> {
    let network = e2e::primary_transfer_pairing::Network::open()?;
    let seed = e2e::primary_transfer::Seed::create(&network.stack)?;
    let (_target, account) =
        e2e::primary_transfer_pairing::enroll(&network.stack, &seed.source, &seed.account)?;
    if account.principal_commitment != seed.account.principal_commitment
        || account.device_id == seed.account.device_id
    {
        return Err(
            "CLI enrollment did not produce an independent branch of the same account".into()
        );
    }
    Ok(())
}

#[test]
#[ignore = "independent native recipient seed; requires the branch's rf and node service binaries"]
fn primary_transfer_native_independent_recipient() -> e2e::Result<()> {
    let network = e2e::primary_transfer_pairing::Network::open()?;
    let seed = e2e::primary_transfer::Seed::create(&network.stack)?;
    let (target, account) =
        e2e::primary_transfer_pairing::enroll(&network.stack, &seed.source, &seed.account)?;
    let independent = e2e::primary_transfer_vertical::Independent::populate(
        &network.stack,
        &seed,
        &target,
        &account,
    )?;
    if independent.consumer.cursor == 0 {
        return Err("vertical slice has no independently running B consumer".into());
    }
    Ok(())
}
