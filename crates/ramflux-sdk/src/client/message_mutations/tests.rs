// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

use super::*;
use crate::RamfluxClient;
use crate::client::generated_content::GeneratedEventStream;
use crate::client::target_selection::{Encoding, FanoutScope};
use ramflux_protocol::message::registry::{COMPILED_LAYER, PROFILE_FLOOR};
use ramflux_protocol::message::{
    Delete, DeleteScope, Edit, KindId, Message, MessageRef, QualifiedDevice, Reaction, content,
};

type TestResult = Result<(), Box<dyn std::error::Error>>;

fn author() -> QualifiedDevice {
    QualifiedDevice { account_anchor: "root-a".into(), device_id: "dev-a".into(), device_epoch: 1 }
}

fn named() -> MessageRef {
    MessageRef { id: vec![8; 32], conversation_id: "c".into(), author_anchor: "root-a".into() }
}

fn stored(conversation: ConversationKind, tombstoned: bool) -> StoredTarget {
    StoredTarget { author_root: "root-a".into(), revision: 2, tombstoned, conversation }
}

fn encode_edit_delete(scope: FanoutScope) -> TestResult {
    let mut stream = match scope {
        FanoutScope::Group => GeneratedEventStream::new("c", author()).with_group("g1", 1),
        FanoutScope::Dm | FanoutScope::OwnCopy => GeneratedEventStream::new("c", author()),
    };
    let edit = RamfluxClient::encode_generated_edit(
        &mut stream,
        b"edit-1".to_vec(),
        Edit {
            target: Some(named()),
            revision: 3,
            previous_content_digest: vec![1; 32],
            replacement: Some(Message { text: "n".into(), ..Default::default() }),
        },
    )?;
    let delete = RamfluxClient::encode_generated_delete(
        &mut stream,
        b"del-1".to_vec(),
        Delete {
            targets: vec![named()],
            scope: DeleteScope::Everyone as i32,
            tombstone_id: b"tomb".to_vec(),
            native_group_authorization: Vec::new(),
        },
    )?;
    let (edit_id, edit_content) = RamfluxClient::decode_generated_inner(&edit)?;
    let (delete_id, delete_content) = RamfluxClient::decode_generated_inner(&delete)?;
    assert_eq!(edit_id.device_sequence + 1, delete_id.device_sequence);
    assert!(matches!(edit_content.value, Some(content::Value::Edit(_))));
    let Some(content::Value::Delete(delete)) = delete_content.value else {
        return Err("Delete content missing".into());
    };
    assert_eq!(
        delete.tombstone_id,
        ramflux_protocol::message::identity::delete_tombstone(&delete_id.id)?
    );
    assert_eq!(
        mutation_encoding(KindId::KindEdit, PROFILE_FLOOR)?,
        Encoding::Typed { kind: KindId::KindEdit, layer: PROFILE_FLOOR }
    );
    assert_eq!(
        mutation_encoding(KindId::KindDelete, PROFILE_FLOOR)?,
        Encoding::Typed { kind: KindId::KindDelete, layer: PROFILE_FLOOR }
    );
    Ok(())
}

#[test]
fn edit_reaction_delete_authorization() -> TestResult {
    let dm = stored(ConversationKind::Direct, false);
    authorize_edit("root-a", &dm)?;
    assert!(authorize_edit("root-b", &dm).is_err());
    apply_edit_revision(2, 3)?;
    assert!(apply_edit_revision(2, 2).is_err());
    assert!(apply_edit_revision(2, 1).is_err());
    authorize_delete("root-a", MutationActor::Author, &dm, DeleteScope::Everyone)?;
    assert!(
        authorize_delete("root-b", MutationActor::Recipient, &dm, DeleteScope::Everyone).is_err(),
        "recipient EVERYONE delete of a peer DM must fail"
    );
    authorize_delete("root-b", MutationActor::Recipient, &dm, DeleteScope::Local)?;
    let own = stored(ConversationKind::OwnCopy, false);
    authorize_delete("root-a", MutationActor::Author, &own, DeleteScope::Everyone)?;
    assert!(
        authorize_delete("root-b", MutationActor::Recipient, &own, DeleteScope::Everyone).is_err()
    );
    let group = stored(ConversationKind::Group, false);
    authorize_delete("root-b", MutationActor::GroupModerator, &group, DeleteScope::Everyone)?;
    assert!(
        authorize_delete("root-b", MutationActor::Recipient, &group, DeleteScope::Everyone)
            .is_err()
    );
    let live = stored(ConversationKind::Direct, false);
    authorize_reaction(&live)?;
    let dead = stored(ConversationKind::Direct, true);
    assert!(authorize_edit("root-a", &dead).is_err());
    assert!(authorize_reaction(&dead).is_err(), "recreate reaction after tombstone must fail");
    let mut stream = GeneratedEventStream::new("c", author());
    let reaction = RamfluxClient::encode_generated_reaction(
        &mut stream,
        b"rxn-1".to_vec(),
        Reaction { target: Some(named()), token: "👍".into(), ..Default::default() },
    )?;
    let (identity, content) = RamfluxClient::decode_generated_inner(&reaction)?;
    let Some(content::Value::Reaction(reaction)) = content.value else {
        return Err("Reaction content missing".into());
    };
    assert_eq!(reaction.operation_id, identity.id);
    Ok(())
}

#[test]
fn stale_declaration_target_receives_and_executes_delete_and_edit() -> TestResult {
    assert_eq!(PROFILE_FLOOR, 2, "S10a floor is 2; F=1 would refuse Delete or send Edit as text");
    assert_eq!(mutation_first_layer(KindId::KindEdit), Some(2));
    assert_eq!(mutation_first_layer(KindId::KindDelete), Some(2));
    for expired in [false, true] {
        assert_eq!(
            receive_compiled_layer(expired),
            COMPILED_LAYER,
            "receive maximum must not follow own declaration expiry"
        );
    }
    for scope in [FanoutScope::Dm, FanoutScope::Group, FanoutScope::OwnCopy] {
        encode_edit_delete(scope)?;
    }
    assert_eq!(
        mutation_encoding(KindId::KindEdit, 1)?,
        Encoding::PeerUpgradeRequired,
        "layer 1 is below the floor; Edit stays typed, never text"
    );
    Ok(())
}

#[test]
fn erasure_fields_require_floor_raise_and_profile_reset() -> TestResult {
    for (name, tag, layer) in ERASURE_FIELDS {
        assert_eq!(*layer, PROFILE_FLOOR, "{name} field {tag} is a floor-2 erasure field");
        admit_erasure_field(*layer, PROFILE_FLOOR)?;
    }
    assert!(
        admit_erasure_field(PROFILE_FLOOR + 1, PROFILE_FLOOR).is_err(),
        "new erasure field above F without a floor raise must fail"
    );
    admit_erasure_field(PROFILE_FLOOR + 1, PROFILE_FLOOR + 1)?;
    Ok(())
}

#[test]
fn edit_digest_uses_framed_domain_and_exact_plain_content() -> Result<(), Box<dyn std::error::Error>>
{
    let target = ramflux_protocol::message::MessageRef {
        id: (0..32).collect(),
        conversation_id: "c".into(),
        author_anchor: "author".into(),
    };
    let digest = super::digest_exact_content(&target, b"\x0a\x05hello")?;
    let expected = [
        0xc7, 0x12, 0x3b, 0xa3, 0x1a, 0xda, 0x58, 0xbf, 0xe8, 0xfb, 0x6a, 0x0b, 0x02, 0xfd, 0x0a,
        0x29, 0x2e, 0x89, 0x95, 0x4d, 0x73, 0xc1, 0x7e, 0xc0, 0x40, 0x7b, 0xd8, 0xf9, 0xa7, 0x63,
        0x22, 0xb5,
    ];
    assert_eq!(digest, expected, "independent Python BLAKE3 transcript vector");
    Ok(())
}
