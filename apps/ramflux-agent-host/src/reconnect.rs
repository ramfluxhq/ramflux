// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bound retry traffic across socket reconnects, including validated authentication races.
//! An owner decision is posted during the backoff, before the agent socket is up again.
use ramflux_agent_host::{
    AgentBus, AgentHost, Config, EngineProvider, Error, Result, RfdBus, subscribe_owner,
};
use ramflux_sdk::LocalBusFrameKind;
use std::time::Duration;

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Wait {
    Slept,
    Stop,
}

type OwnerFrame = std::result::Result<ramflux_sdk::LocalBusFrame, Error>;

enum Wake {
    Slept,
    Flush,
    Event(Box<OwnerFrame>),
}

pub(super) async fn one_attempt<E: EngineProvider>(
    config: &Config,
    host: &mut AgentHost<E>,
    owner: &mut Option<RfdBus>,
) -> Result<()> {
    let mut bus = RfdBus::connect(&config.socket, &config.account_id).await?;
    host.start(&mut bus).await?;
    if owner.is_none() {
        *owner = connect_owner(config, host.owner_account()).await?;
    }
    host.run_paired(&mut bus, owner).await
}

pub(super) async fn wait_and_forward<E: EngineProvider>(
    config: &Config,
    host: &mut AgentHost<E>,
    owner: &mut Option<RfdBus>,
    delay: Duration,
) -> Result<Wait> {
    if owner.is_none() {
        *owner = connect_owner(config, host.owner_account()).await.ok().flatten();
    }
    let sleep = tokio::time::sleep(delay);
    tokio::pin!(sleep);
    let mut flush = tokio::time::interval(Duration::from_millis(250));
    flush.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    flush.tick().await;
    let mut replaced = false;
    loop {
        // `owner_frame` borrows `owner`. Drop that future before `forward_one` borrows it again.
        let wake = tokio::select! {
            () = &mut sleep => Wake::Slept,
            _ = flush.tick() => Wake::Flush,
            result = tokio::signal::ctrl_c() => {
                result.map_err(|_| Error::State)?;
                return Ok(Wait::Stop);
            }
            event = owner_frame(owner) => Wake::Event(Box::new(event)),
        };
        match wake {
            Wake::Slept => return Ok(Wait::Slept),
            Wake::Flush => host.flush_held_posts().await?,
            Wake::Event(event) => {
                if let Err(error) = forward_one(config, host, owner, &mut replaced, *event).await {
                    eprintln!("prx approval forward deferred: {error}");
                }
            }
        }
    }
}

async fn connect_owner(config: &Config, account: Option<&str>) -> Result<Option<RfdBus>> {
    let Some(account) = account else { return Ok(None) };
    let mut bus = RfdBus::connect_owner(&config.socket, account).await?;
    subscribe_owner(&mut bus).await?;
    Ok(Some(bus))
}

async fn forward_one<E: EngineProvider>(
    config: &Config,
    host: &mut AgentHost<E>,
    owner: &mut Option<RfdBus>,
    replaced: &mut bool,
    event: OwnerFrame,
) -> Result<()> {
    let frame = match event {
        Ok(frame) if frame.kind == LocalBusFrameKind::Event && frame.method == "stream.lagged" => {
            return replace_owner(config, host, owner, replaced).await;
        }
        Ok(frame) => frame,
        Err(error) => {
            replace_owner(config, host, owner, replaced).await?;
            return Err(error);
        }
    };
    match host.post_owner_decision(&frame).await {
        Ok(()) => Ok(()),
        Err(error) if error.stops_host() => Err(error),
        Err(ramflux_agent_host::Error::RateLimited { retry_after_ms }) => {
            host.hold_owner(frame, retry_after_ms);
            Ok(())
        }
        Err(error) => {
            eprintln!("prx approval forward deferred: {error}");
            host.hold_owner(frame, 3_000);
            Ok(())
        }
    }
}

async fn replace_owner<E: EngineProvider>(
    config: &Config,
    host: &AgentHost<E>,
    owner: &mut Option<RfdBus>,
    replaced: &mut bool,
) -> Result<()> {
    *owner = None;
    if *replaced {
        return Ok(());
    }
    *replaced = true;
    *owner = connect_owner(config, host.owner_account()).await.ok().flatten();
    Ok(())
}

async fn owner_frame(owner: &mut Option<RfdBus>) -> OwnerFrame {
    if let Some(bus) = owner.as_mut() {
        return bus.next_event().await;
    }
    std::future::pending().await
}
#[derive(Default)]
pub(super) struct ReconnectBackoff {
    failures: u32,
}
impl ReconnectBackoff {
    pub(super) fn failed(&mut self, attempt_duration: Duration) -> Duration {
        // A long-lived attempt already spaces traffic by at least the maximum retry interval.
        if attempt_duration >= Duration::from_secs(60) {
            self.failures = 0;
        }
        self.failures = self.failures.saturating_add(1);
        Duration::from_secs((1_u64 << self.failures.saturating_sub(1).min(6)).min(60))
    }
    pub(super) const fn failures(&self) -> u32 {
        self.failures
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn repeated_reconnect_failures_back_off_from_one_to_sixty_seconds() {
        let mut backoff = ReconnectBackoff::default();
        for (failures, seconds) in (1..).zip([1, 2, 4, 8, 16, 32, 60, 60, 60]) {
            assert_eq!(backoff.failed(Duration::ZERO), Duration::from_secs(seconds));
            assert_eq!(backoff.failures(), failures);
        }
    }
    #[test]
    fn a_sustained_connection_restores_the_initial_reconnect_delay() {
        let mut backoff = ReconnectBackoff::default();
        for _ in 0..10 {
            backoff.failed(Duration::from_secs(1));
        }
        assert_eq!(backoff.failed(Duration::from_secs(60)), Duration::from_secs(1));
        assert_eq!(backoff.failures(), 1);
    }
}
