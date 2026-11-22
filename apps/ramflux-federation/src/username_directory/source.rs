// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Shared preauthentication source-prefix bounds for TCP and QUIC, independent of durable quotas.
use std::{collections::BTreeMap, net::IpAddr, sync::Mutex, time::Instant};

pub struct Sources {
    started: Instant,
    rows: Mutex<BTreeMap<IpAddr, (u64, u32)>>,
}

impl Sources {
    pub fn new() -> Self {
        Self { started: Instant::now(), rows: Mutex::new(BTreeMap::new()) }
    }

    pub fn admit(&self, ip: IpAddr) -> bool {
        let prefix = match ip {
            IpAddr::V4(ip) => {
                let [a, b, c, _] = ip.octets();
                IpAddr::V4([a, b, c, 0].into())
            }
            IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & (u128::MAX << 72)).into()),
        };
        let Ok(mut rows) = self.rows.lock() else {
            return false;
        };
        let window = self.started.elapsed().as_secs() / 60;
        rows.retain(|_, (old, _)| *old == window);
        if !rows.contains_key(&prefix) && rows.len() >= 4096 {
            return false;
        }
        let entry = rows.entry(prefix).or_insert((window, 0));
        entry.1 = entry.1.saturating_add(1);
        if entry.1 == 61 {
            tracing::warn!(limit = 60, window, "username source-prefix admission exhausted");
        }
        entry.1 <= 60
    }
}
