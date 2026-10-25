// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Delivery is a receiving-daemon responsibility; no recipient socket is opened in these tests.
use super::*;
use crate::bus::runtime_tests;
use fixture::{Shared, Spec, TestResult};
use std::sync::{Arc, Mutex};
use tokio::task::LocalSet;
mod fixture;
#[tokio::test(flavor = "current_thread")]
async fn peer_dm_is_delivered_without_a_recipient_ui_and_restart_does_not_send_another_receipt()
-> TestResult {
    LocalSet::new()
        .run_until(async {
            let root = runtime_tests::root("receipt-two-daemons");
            let a = Spec::new(&root, "alice", 51);
            let b = Spec::new(&root, "bob", 61);
            let mail: Shared = Arc::new(Mutex::default());
            fixture::seed_pair(&a, &b)?;
            let source = a.account(None, mail.clone())?;
            let mut engine = source.gateway_config.clone();
            let _ = &mut engine;
            let mut source = source;
            let mut gateway = source.take_live_engine().await?;
            source
                .client
                .send_plaintext_direct_message_without_franking(
                    &mut gateway,
                    a.message(&b, "dm-one"),
                    b"hello",
                    crate::client::routed::Route::direct(),
                )
                .await?;
            source.put_engine(gateway);
            drop(source);
            let sender = a.daemon(mail.clone())?;
            let recipient = b.daemon(mail.clone())?;
            let (bus, server) = fixture::socket(&a, Rc::clone(&sender)).await?;
            let result = fixture::delivered(&bus, "alice", "dm-one", 1).await?;
            assert_eq!(result["messages"][0]["receipts"][0]["device_id"], b.device);
            recipient.shutdown().await?;
            drop(recipient);
            let resumed = b.daemon(mail.clone())?;
            tokio::time::sleep(Duration::from_millis(700)).await;
            let envelopes = mail.lock().map_err(|_| "mailbox")?.submissions.clone();
            assert_eq!(envelopes.iter().filter(|e| e.source_device_id == b.device).count(), 1);
            assert!(
                envelopes
                    .iter()
                    .filter(|e| e.source_device_id == b.device)
                    .all(|e| e.target_delivery_id == a.device)
            );
            resumed.shutdown().await?;
            sender.shutdown().await?;
            drop(bus);
            server.abort();
            let _ = server.await;
            drop(sender);
            drop(resumed);
            let observer = b.client(None)?;
            let origin = observer.message_origin("thread", "dm-one")?.ok_or("origin")?;
            assert_eq!(origin["sender_device_id"], a.device);
            assert_eq!(
                origin["sender_root_commitment"],
                a.client(None)?.surface_local_root_commitment()?
            );
            assert!(
                origin["sender_device_display"].as_str().is_some_and(|s| s.starts_with("Laptop@"))
            );
            drop(observer);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn group_delivery_receipts_go_only_to_the_sender_device_without_recipient_uis() -> TestResult
{
    LocalSet::new()
        .run_until(async {
            let root = runtime_tests::root("receipt-group-daemons");
            let a = Spec::new(&root, "alice", 51);
            let b = Spec::new(&root, "bob", 61);
            let c = Spec::new(&root, "charlie", 71);
            let mail: Shared = Arc::new(Mutex::default());
            fixture::seed_pair(&a, &b)?;
            fixture::seed_pair(&a, &c)?;
            let source = a.client(None)?;
            let bob = b.client(None)?;
            let charlie = c.client(None)?;
            for (spec, client) in [(&a, &source), (&b, &bob), (&c, &charlie)] {
                for member in [&a, &b, &c] {
                    spec.trust(client, member)?;
                }
                client.create_group("group", &a.device)?;
                client.add_group_member("group", &b.device, "member")?;
                client.add_group_member("group", &c.device, "member")?;
                client.account_db()?.persist_client_record(
                    "conversation",
                    "thread",
                    &serde_json::json!({"kind":"group","group_id":"group"}),
                )?;
            }
            let distribution = source.export_group_sender_key_distribution("group", &a.device)?;
            bob.import_group_sender_key_distribution(&distribution)?;
            charlie.import_group_sender_key_distribution(&distribution)?;
            let encrypted = source.encrypt_group_message("group", &a.device, b"group hello")?;
            source.send_direct_message("thread", "group-one", &a.device, &encrypted)?;
            let mut account = a.account(None, mail.clone())?;
            let mut gateway = account.take_live_engine().await?;
            for member in [&b, &c] {
                let mut message = a.message(member, "group-one");
                let sealed = source
                    .seal_routed_as(
                        &mut gateway,
                        &message,
                        &encrypted,
                        crate::client::routed::Route::group_message("group"),
                    )
                    .await?;
                message.encrypted_body = serde_json::to_vec(&sealed)?;
                gateway
                    .submit_envelope(gateway_direct_message_envelope(
                        &gateway.config,
                        &message,
                        None,
                    )?)
                    .await?;
            }
            drop(gateway);
            drop(account);
            drop(source);
            drop(bob);
            drop(charlie);
            let sender = a.daemon(mail.clone())?;
            let recipient = b.daemon(mail.clone())?;
            let third = c.daemon(mail.clone())?;
            let (bus, server) = fixture::socket(&a, Rc::clone(&sender)).await?;
            let result = fixture::delivered(&bus, "alice", "group-one", 2).await?;
            let devices = result["messages"][0]["receipts"]
                .as_array()
                .ok_or("receipts")?
                .iter()
                .filter_map(|r| r["device_id"].as_str())
                .collect::<BTreeSet<_>>();
            assert_eq!(devices, BTreeSet::from([b.device.as_str(), c.device.as_str()]));
            let packets = mail.lock().map_err(|_| "mailbox")?.submissions.clone();
            assert_eq!(packets.iter().filter(|p| p.source_device_id != a.device).count(), 2);
            assert!(
                packets
                    .iter()
                    .filter(|p| p.source_device_id != a.device)
                    .all(|p| p.target_delivery_id == a.device)
            );
            for daemon in [&sender, &recipient, &third] {
                daemon.shutdown().await?;
            }
            drop(bus);
            server.abort();
            let _ = server.await;
            drop(sender);
            drop(recipient);
            drop(third);
            std::fs::remove_dir_all(root)?;
            Ok(())
        })
        .await
}

#[tokio::test(flavor = "current_thread")]
async fn an_uncertain_receipt_ack_reuses_its_ciphertext_after_restart_and_client_calls_are_noops()
-> TestResult {
    LocalSet::new().run_until(async {
        let root=runtime_tests::root("receipt-lost-ack");let a=Spec::new(&root,"alice",51);let b=Spec::new(&root,"bob",61);let mail:Shared=Arc::new(Mutex::default());fixture::seed_pair(&a,&b)?;
        let mut source=a.account(None,mail.clone())?;let mut gateway=source.take_live_engine().await?;
        source.client.send_plaintext_direct_message_without_franking(&mut gateway,a.message(&b,"dm-one"),b"hello",crate::client::routed::Route::direct()).await?;source.put_engine(gateway);drop(source);
        mail.lock().map_err(|_|"mailbox")?.lose_ack=true;
        let mut receiver=b.account(None,mail.clone())?;
        crate::bus::sync_driver::run(&mut receiver).await?;
        let prefix=crate::client::delivery_receipts::PREFIX;
        let key=receiver.client.account_db()?.actor_state_key_page(prefix,256)?.into_iter().next().ok_or("retry")?;
        let work=receiver.client.account_db()?.load_actor_state::<crate::client::delivery_receipts::Work>(&key)?.ok_or("work")?;
        assert_eq!(work.attempts,1);assert!(work.next_at>now_unix_timestamp());assert!(work.packet.is_some());drop(receiver);
        let mut receiver=b.account(None,mail.clone())?;
        let mut recovered=receiver.client.account_db()?.load_actor_state::<crate::client::delivery_receipts::Work>(&key)?.ok_or("recovered")?;
        assert_eq!(recovered.packet,work.packet);recovered.next_at=0;receiver.client.account_db()?.persist_actor_state(&key,&recovered)?;
        assert_eq!(super::flush(&mut receiver).await?,1);assert_eq!(super::flush(&mut receiver).await?,0);
        let packets=mail.lock().map_err(|_|"mailbox")?.submissions.iter().filter(|e|e.source_device_id==b.device).cloned().collect::<Vec<_>>();assert_eq!(packets.len(),2);assert_eq!(packets[0],packets[1]);drop(receiver);
        let recipient=b.daemon(mail.clone())?;let (bus,server)=fixture::socket(&b,Rc::clone(&recipient)).await?;
        let response=bus.request_frame(LocalBusFrame::request("explicit",Some("bob".into()),"test","message.receipt.delivered",serde_json::json!({"conversation_id":"thread","message_id":"dm-one","receiver_device_id":b.device,"recipient_device_id":a.device,"target_delivery_id":a.device}))).await?;
        assert_eq!(response["already_sent"],true);
        let read=bus.request_frame(LocalBusFrame::request("read",Some("bob".into()),"test","message.read",serde_json::json!({"conversation_id":"thread"}))).await?;
        assert_eq!(read["messages"][0]["sender_device_id"],a.device);assert!(read["messages"][0]["sender_device_display"].as_str().is_some_and(|s|s.starts_with("Laptop@")));
        assert_eq!(mail.lock().map_err(|_|"mailbox")?.submissions.iter().filter(|e|e.source_device_id==b.device).count(),2);
        recipient.shutdown().await?;drop(bus);server.abort();let _=server.await;drop(recipient);
        let mut sender=a.account(None,mail.clone())?;crate::bus::sync_driver::run(&mut sender).await?;
        let message=sender.client.direct_message_by_id("dm-one")?.ok_or("sender row")?;assert_eq!(message.receipts.len(),1);assert_eq!(message.receipts[0].state,"delivered");
        assert_eq!(sender.client.account_db()?.actor_state_usage(prefix)?.0,0);drop(sender);std::fs::remove_dir_all(root)?;Ok(())
    }).await
}
