// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

pub(crate) fn run_smoke_from_env() -> anyhow::Result<()> {
    let core = std::env::var("RAMFLUX_GLOMMIO_CORE")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .unwrap_or(0);
    run_smoke(core)
}

fn run_smoke(core: usize) -> anyhow::Result<()> {
    use std::sync::mpsc;

    use glommio::{LocalExecutorBuilder, Placement};

    let (sender, receiver) = mpsc::sync_channel(1);
    let handle = LocalExecutorBuilder::new(Placement::Fixed(core))
        .name("ramflux-router-glommio-smoke")
        .spawn(move || async move {
            let result = match current_linux_cpu() {
                Some(observed_core) if observed_core == core => {
                    println!("ramflux-router:glommio-smoke core={core} observed_core={observed_core}");
                    Ok(())
                }
                Some(observed_core) => Err(format!(
                    "glommio smoke executor was not pinned to requested core {core}; observed {observed_core}"
                )),
                None => Err("could not read /proc/thread-self/stat CPU".to_owned()),
            };
            let _ = sender.send(result);
        })
        .map_err(|error| anyhow::anyhow!("glommio smoke executor failed to spawn: {error:?}"))?;
    if handle.join().is_err() {
        anyhow::bail!("glommio smoke executor panicked");
    }
    receiver
        .recv()
        .map_err(|error| anyhow::anyhow!("glommio smoke result missing: {error}"))?
        .map_err(anyhow::Error::msg)
}

fn current_linux_cpu() -> Option<usize> {
    let stat = std::fs::read_to_string("/proc/thread-self/stat").ok()?;
    stat.split_whitespace().nth(38)?.parse().ok()
}
