// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded protected replay/rate ledger and retained reporting-home observations.
use super::{
    CheckpointError, DirectoryAuthority, DirectoryRequest, HomeFloor, META, ReportingChannel,
    ReportingRequest, Result, VerifiedReporter, canonical, storage,
    transitions::{after, ensure},
};
use ramflux_protocol::username_directory::DirectoryCode as Code;
use redb::{ReadableDatabase, ReadableTable};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Bucket {
    window: u64,
    used: u64,
    expires: u64,
}

fn read<T: serde::de::DeserializeOwned>(
    table: &impl ReadableTable<&'static str, &'static [u8]>,
    key: &str,
) -> Result<Option<T>> {
    table
        .get(key)
        .map_err(storage)?
        .map(|v| serde_json::from_slice(v.value()).map_err(CheckpointError::from))
        .transpose()
}

fn add(table: &mut redb::Table<&str, &[u8]>, key: &str, delta: i64, cap: u64) -> Result<()> {
    let current: u64 = read(table, key)?.unwrap_or(0);
    let next = current
        .checked_add_signed(delta)
        .ok_or(CheckpointError::Directory(Code::DirectoryUnavailable))?;
    ensure(next <= cap, Code::Capacity)?;
    table.insert(key, canonical(&next)?.as_slice()).map_err(storage)?;
    Ok(())
}

fn prune(
    table: &mut redb::Table<&str, &[u8]>,
    prefix: &str,
    count_key: &str,
    now: u64,
) -> Result<()> {
    let mut expired = Vec::new();
    for item in table.range(prefix..).map_err(storage)?.take(128) {
        let (key, value) = item.map_err(storage)?;
        if !key.value().starts_with(prefix) {
            break;
        }
        let (at, target): (u64, String) = serde_json::from_slice(value.value())?;
        if at > now {
            break;
        }
        expired.push((key.value().to_owned(), target));
    }
    for (index, target) in expired {
        table.remove(index.as_str()).map_err(storage)?;
        ensure(
            table.remove(target.as_str()).map_err(storage)?.is_some(),
            Code::DirectoryUnavailable,
        )?;
        add(table, count_key, -1, u64::MAX)?;
    }
    Ok(())
}

fn charge_node(
    table: &mut redb::Table<&str, &[u8]>,
    channel: &ReportingChannel<'_>,
    now: u64,
) -> Result<()> {
    let key = format!("auth_node:{}", channel.node_key);
    rate(table, &key, channel.node_rate_per_min, 60, now, false)
}

fn rate(
    table: &mut redb::Table<&str, &[u8]>,
    key: &str,
    limit: u64,
    period: u64,
    now: u64,
    source: bool,
) -> Result<()> {
    let count_key = if source { "auth_source_count" } else { "auth_bucket_count" };
    let prefix = if source { "auth_source_expiry:" } else { "auth_bucket_expiry:" };
    let old: Option<Bucket> = read(table, key)?;
    let window = now / period;
    let used = old.as_ref().filter(|b| b.window == window).map_or(0, |b| b.used);
    ensure(used < limit, Code::RateLimited)?;
    if let Some(old) = &old {
        table.remove(format!("{prefix}{:020}:{key}", old.expires).as_str()).map_err(storage)?;
    } else {
        add(table, count_key, 1, if source { 4096 } else { 8192 })?;
    }
    let expires = after(now, 300)?;
    table
        .insert(key, canonical(&Bucket { window, used: used + 1, expires })?.as_slice())
        .map_err(storage)?;
    table
        .insert(
            format!("{prefix}{expires:020}:{key}").as_str(),
            canonical(&(expires, key))?.as_slice(),
        )
        .map_err(storage)?;
    Ok(())
}

impl DirectoryAuthority {
    /// Latest authenticated locator for a home, shared by its independently verified root floors.
    /// # Errors
    /// Refuses malformed homes or unavailable/corrupt protected metadata.
    pub fn reporting_service(&self, home: &str) -> Result<Option<super::SignedHomeServiceAddress>> {
        super::config::validate_node(home)?;
        let tx = self.witness.db.begin_read().map_err(storage)?;
        read(&tx.open_table(META).map_err(storage)?, &format!("auth_home_service:{home}"))
    }
    /// Retained transport hint and immutable master identity; neither grants lookup permission.
    /// # Errors
    /// Refuses malformed roots or unavailable/corrupt protected state.
    pub fn reporting_floor(&self, root: &str) -> Result<Option<HomeFloor>> {
        super::fixed(root)?;
        let tx = self.witness.db.begin_read().map_err(storage)?;
        read(&tx.open_table(META).map_err(storage)?, &format!("auth_home_floor:{root}"))
    }
    /// TLS facts and source address come from the witness-owned transport adapter.
    /// Node proofs consume nonces durably before account signatures/mutations are dispatched.
    /// # Errors
    /// Refuses noncanonical input, wrong reporters/channels, replay, rollback and quota exhaustion.
    pub fn admit_reporting(
        &mut self,
        bytes: &[u8],
        channel: &ReportingChannel<'_>,
        pin: &super::CenterPin,
        source: std::net::IpAddr,
    ) -> Result<(ReportingRequest, VerifiedReporter)> {
        let request = super::decode_reporting_request(bytes)?;
        let time = self.witness.sample_time()?;
        let floor_key = format!("auth_home_floor:{}", request.proof.body.root);
        let retained: Option<HomeFloor> = {
            let tx = self.witness.db.begin_read().map_err(storage)?;
            read(&tx.open_table(META).map_err(storage)?, &floor_key)?
        };
        let reporter =
            super::verify_reporting_request(&request, channel, pin, retained.as_ref(), time.wall)?;
        let nonce_key = format!("auth_nonce:{}:{}", reporter.home, reporter.nonce);
        let lookup = !matches!(request.request, DirectoryRequest::Mutate { .. });
        let prefix = match source {
            std::net::IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                format!("{a}.{b}.{c}.0/24")
            }
            std::net::IpAddr::V6(ip) => format!("{:032x}/56", u128::from(ip) & (u128::MAX << 72)),
        };
        let admitted = self.witness.update_aux(time, |tx| {
            let mut meta = tx.open_table(META).map_err(storage)?;
            prune(&mut meta, "auth_nonce_expiry:", "auth_nonce_count", time.wall)?;
            prune(&mut meta, "auth_bucket_expiry:", "auth_bucket_count", time.wall)?;
            prune(&mut meta, "auth_source_expiry:", "auth_source_count", time.wall)?;
            ensure(read::<u64>(&meta, &nonce_key)?.is_none(), Code::Replay)?;
            add(&mut meta, "auth_nonce_count", 1, 16384)?;
            meta.insert(nonce_key.as_str(), canonical(&reporter.expires_at)?.as_slice())
                .map_err(storage)?;
            meta.insert(
                format!("auth_nonce_expiry:{:020}:{nonce_key}", reporter.expires_at).as_str(),
                canonical(&(reporter.expires_at, &nonce_key))?.as_slice(),
            )
            .map_err(storage)?;
            let result = (|| {
                rate(&mut meta, "auth_global_rate", 1000, 1, time.wall, false)?;
                charge_node(&mut meta, channel, time.wall)?;
                rate(
                    &mut meta,
                    &format!(
                        "auth_{}_home:{}",
                        if lookup { "lookup" } else { "mutate" },
                        reporter.home
                    ),
                    if lookup { 600 } else { 60 },
                    60,
                    time.wall,
                    false,
                )?;
                rate(
                    &mut meta,
                    &format!(
                        "auth_{}_root:{}",
                        if lookup { "lookup" } else { "mutate" },
                        reporter.root
                    ),
                    if lookup { 30 } else { 10 },
                    60,
                    time.wall,
                    false,
                )?;
                if lookup {
                    rate(&mut meta, &format!("auth_prefix:{prefix}"), 120, 60, time.wall, true)?;
                }
                if retained.is_none() {
                    add(&mut meta, "auth_lifetime_roots", 1, 1_000_000)?;
                    add(&mut meta, &format!("auth_lifetime_home:{}", reporter.home), 1, 100_000)?;
                } else if let Some(old) = &retained
                    && old.home != reporter.home
                {
                    add(&mut meta, &format!("auth_lifetime_home:{}", reporter.home), 1, 100_000)?;
                    add(&mut meta, &format!("auth_lifetime_home:{}", old.home), -1, 100_000)?;
                }
                let floor = HomeFloor {
                    reach: reporter.reach.clone(),
                    epoch: reporter.history.epoch(),
                    hash: reporter.history.hash().into(),
                    home: reporter.home.clone(),
                    master_public_key: ramflux_protocol::encode_base64url(
                        reporter.master.to_bytes(),
                    ),
                    service: reporter.service.clone(),
                };
                retain_service(&mut meta, &reporter)?;
                meta.insert(floor_key.as_str(), canonical(&floor)?.as_slice()).map_err(storage)?;
                Ok(())
            })();
            // Commit request-attempt charges on a rate refusal. Capacity/storage errors roll
            // back atomically so lifetime attribution cannot be partially moved.
            match result {
                Ok(()) => Ok(Ok(())),
                Err(CheckpointError::Directory(Code::RateLimited)) => {
                    Ok(Err(CheckpointError::Directory(Code::RateLimited)))
                }
                Err(error) => Err(error),
            }
        })?;
        admitted?;
        Ok((request, reporter))
    }
}

fn retain_service(meta: &mut redb::Table<&str, &[u8]>, reporter: &VerifiedReporter) -> Result<()> {
    let service_key = format!("auth_home_service:{}", reporter.home);
    let old_service: Option<super::SignedHomeServiceAddress> = read(meta, &service_key)?;
    if let Some(old) = old_service {
        ensure(old.body.public_key == reporter.service.body.public_key, Code::KeyChanged)?;
        ensure(old.body.issued_at <= reporter.service.body.issued_at, Code::Replay)?;
        if old.body.issued_at == reporter.service.body.issued_at {
            ensure(old == reporter.service, Code::Replay)?;
        }
    } else {
        add(meta, "auth_lifetime_services", 1, 1_000_000)?;
    }
    meta.insert(service_key.as_str(), canonical(&reporter.service)?.as_slice()).map_err(storage)?;
    Ok(())
}
