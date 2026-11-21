// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Ordinary preference writers, independent B settings and original-branch DV.
use crate::account_db::full_transfer::receiver_copy::owner_tests::{Case, TestResult, run};

#[test]
fn full_conversation_preferences_keep_b_settings_and_union_hidden_clear_boundaries() -> TestResult {
    run(Case {
        name: "conversation-preferences",
        seed: |a, b| {
            a.set_conversation_archived("thread", true)?;
            a.pin_conversation("thread", 99)?;
            a.mute_conversation("thread", 300)?;
            a.hide_conversation_at("thread", 1000)?;
            a.pin_conversation("source-only", -1)?;
            b.set_conversation_archived("thread", false)?;
            b.pin_conversation("thread", 7)?;
            b.mute_conversation("thread", 200)?;
            b.clear_conversation_at("thread", 500, "local")?;
            Ok(())
        },
        before: None,
        inspect: |private, b| {
            let value=private.db.query_row("SELECT archived,pin_order,mute_until,hidden_at,cleared_at FROM conversation_list_state WHERE conversation_id='thread'",[],|row|Ok((row.get::<_,bool>(0)?,row.get::<_,Option<i64>>(1)?,row.get::<_,Option<i64>>(2)?,row.get::<_,Option<i64>>(3)?,row.get::<_,Option<i64>>(4)?)))?;
            assert_eq!(
                value,
                (false, Some(7), Some(200), Some(1000), Some(500)),
                "test: transfer overwrote independent B preferences or weakened a history visibility boundary"
            );
            assert_eq!(private.db.query_row("SELECT pin_order FROM conversation_list_state WHERE conversation_id='source-only'",[],|row|row.get::<_,i64>(0))?,-1,"test: source-only pin order was dropped or coerced");
            assert_eq!(
                b.connection.query_row(
                    "SELECT hidden_at FROM conversation_list_state WHERE conversation_id='thread'",
                    [],
                    |row| row.get::<_, Option<i64>>(0)
                )?,
                None,
                "test: private union mutated actual B visibility"
            );
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn full_disappearing_policy_owners_never_disable_or_lengthen_an_independent_timer() -> TestResult {
    run(Case {
        name: "conversation-expiry",
        seed: |a, b| {
            for (id, left, right) in
                [("shorter", 60, 600), ("disabled-a", 0, 600), ("disabled-b", 60, 0)]
            {
                a.set_disappearing_policy(id, left, "on_send", "own_devices", 100)?;
                b.set_disappearing_policy(id, right, "on_send", "own_devices", 200)?;
            }
            a.set_disappearing_policy("source-only", 240, "on_send", "own_devices", 100)?;
            Ok(())
        },
        before: None,
        inspect: |private, b| {
            for (id, expected) in
                [("shorter", 60), ("disabled-a", 600), ("disabled-b", 60), ("source-only", 240)]
            {
                let value=private.db.query_row("SELECT timer_seconds,countdown_mode,scope FROM conversation_disappearing_policy WHERE conversation_id=?1",[id],|row|Ok((row.get::<_,i64>(0)?,row.get::<_,String>(1)?,row.get::<_,String>(2)?)))?;
                assert_eq!(
                    value,
                    (expected, "on_send".to_owned(), "own_devices".to_owned()),
                    "test: {id} lost its shortest operative timer or changed expiry context"
                );
            }
            assert_eq!(
                b.disappearing_policy("shorter")?
                    .ok_or("test: original B policy missing")?
                    .timer_seconds,
                600,
                "test: unselected private policy changed live B"
            );
            Ok(())
        },
        conflict: false,
    })
}
#[test]
fn full_disappearing_policy_conflicting_scopes_refuse_before_dv() -> TestResult {
    run(Case {
        name: "conversation-expiry-context-fork",
        seed: |a, b| {
            a.set_disappearing_policy("thread", 60, "on_send", "all_devices", 100)?;
            b.set_disappearing_policy("thread", 600, "on_send", "own_devices", 200)?;
            Ok(())
        },
        before: None,
        inspect: |_, _| Ok(()),
        conflict: true,
    })
}
