// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Bounded network offloads waits for disk; network workers never wait on the writer gate.
use crate::GatewayQuicContext;

pub(crate) async fn run<T, F>(
    context: &GatewayQuicContext,
    root: Option<&ramflux_crypto::RootQualifiedDeviceRef>,
    work: F,
) -> anyhow::Result<T>
where
    T: Send + 'static,
    F: FnOnce(&GatewayQuicContext) -> anyhow::Result<T> + Send + 'static,
{
    let permit = match root {
        Some(root) => context.store.try_admit_root_write(root)?,
        None => context.store.try_admit_async_write()?,
    };
    let context = context.clone();
    tokio::task::spawn_blocking(move || {
        let _permit = permit;
        work(&context)
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{sync::Arc, time::Duration};

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn noisy_root_and_unverified_saturation_leave_another_root_able_to_commit()
    -> anyhow::Result<()> {
        tokio::time::timeout(Duration::from_secs(15), async {
            let directory = tempfile::TempDir::new()?;
            let mut context = crate::session::tests::test_gateway_context()?;
            context.store = Arc::new(ramflux_node_core::GatewayRedbStore::open(
                directory.path().join("gateway.redb"),
            )?);
            let source = |seed| {
                let root = ramflux_crypto::create_identity_root("peer", [seed; 32]);
                ramflux_crypto::RootQualifiedDeviceRef::for_owned_account_device(&root, "device")
            };
            let noisy = source(1)?;
            let other = source(2)?;
            let unverified =
                [context.store.try_admit_async_write()?, context.store.try_admit_async_write()?];
            let (started, observed) = tokio::sync::oneshot::channel();
            let (release, waiting) = std::sync::mpsc::sync_channel(1);
            let worker_context = context.clone();
            let worker_root = noisy.clone();
            let worker = tokio::spawn(async move {
                run(&worker_context, Some(&worker_root), move |context| {
                    started.send(()).map_err(|_| anyhow::anyhow!("observer gone"))?;
                    waiting.recv_timeout(Duration::from_secs(5))?;
                    let writer = context.store.write_guard()?;
                    let snapshot = { crate::gateway_state(&context.state)?.clone() };
                    writer.save_state(&snapshot)?;
                    Ok(())
                })
                .await
            });
            observed.await?;
            let busy = run(&context, Some(&noisy), |_| -> anyhow::Result<()> {
                anyhow::bail!("refused root executed work")
            })
            .await;
            assert!(
                matches!(
                    busy.as_ref()
                        .err()
                        .and_then(|error| error.downcast_ref::<ramflux_node_core::NodeCoreError>()),
                    Some(ramflux_node_core::NodeCoreError::GatewayWriterBusy)
                ),
                "noisy root must get typed busy before offload"
            );
            run(&context, Some(&other), |context| {
                let writer = context.store.write_guard()?;
                let snapshot = { crate::gateway_state(&context.state)?.clone() };
                writer.save_state(&snapshot)?;
                Ok(())
            })
            .await?;
            assert_eq!(
                context.store.full_snapshot_commit_count(),
                1,
                "another root must commit while noisy and unverified slots remain occupied"
            );
            release.send(())?;
            worker.await??;
            drop(unverified);
            assert_eq!(
                context.store.pending_network_writes(),
                0,
                "completed work must release all admission slots"
            );
            Ok(())
        })
        .await?
    }
}
