// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

#![allow(clippy::wildcard_imports)]
use crate::*;
use rusqlite::{Connection, OptionalExtension, params};

struct AccountMigration {
    schema_version: i64,
    app_version: &'static str,
    checksum: &'static str,
    notes: &'static str,
    sql: &'static str,
}

const ACCOUNT_MIGRATIONS: &[AccountMigration] = &[
    AccountMigration {
        schema_version: 1,
        app_version: "mvp-1",
        checksum: "2026-06-14-account-core-v1",
        notes: "identity event projection and legacy mvp tables",
        sql: r"
            CREATE TABLE IF NOT EXISTS account_key_check (
                singleton_id INTEGER PRIMARY KEY CHECK (singleton_id = 1),
                key_fingerprint TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_identity (
                device_id TEXT PRIMARY KEY,
                principal_id TEXT NOT NULL,
                principal_commitment TEXT NOT NULL,
                device_epoch INTEGER NOT NULL,
                branch_proof_hash BLOB NOT NULL,
                capability_scope_json TEXT NOT NULL,
                client_mode TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS lineage_checkpoint (
                checkpoint_id TEXT PRIMARY KEY,
                lineage_head TEXT NOT NULL,
                device_id TEXT NOT NULL,
                device_epoch INTEGER NOT NULL,
                checkpoint_hash BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                FOREIGN KEY(device_id) REFERENCES device_identity(device_id)
            );
            CREATE TABLE IF NOT EXISTS home_node_binding (
                binding_id TEXT PRIMARY KEY,
                home_node_id TEXT NOT NULL,
                target_delivery_id TEXT NOT NULL,
                routing_set_id TEXT,
                binding_state TEXT NOT NULL,
                migration_proof_hash BLOB,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS session_capability_cache (
                capability_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                capability_scope TEXT NOT NULL,
                expires_at INTEGER NOT NULL,
                revoked_at INTEGER,
                proof_hash BLOB NOT NULL,
                FOREIGN KEY(device_id) REFERENCES device_identity(device_id)
            );
            CREATE TABLE IF NOT EXISTS raw_envelope_log (
                envelope_id TEXT PRIMARY KEY,
                source_device_id TEXT,
                target_delivery_id TEXT NOT NULL,
                routing_set_id TEXT,
                delivery_class TEXT NOT NULL,
                received_at INTEGER NOT NULL,
                payload_hash BLOB NOT NULL,
                encrypted_payload BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS local_event_log (
                event_id TEXT PRIMARY KEY,
                event_type TEXT NOT NULL,
                actor_principal_id TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                device_counter INTEGER NOT NULL,
                lamport_time INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                causal_prev_json TEXT,
                event_body BLOB NOT NULL,
                signature BLOB NOT NULL,
                signature_status TEXT NOT NULL,
                projection_status TEXT NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_local_event_actor_counter
                ON local_event_log(actor_device_id, device_counter);
            CREATE INDEX IF NOT EXISTS idx_local_event_order
                ON local_event_log(lamport_time, actor_device_id, event_id);
            CREATE TABLE IF NOT EXISTS event_causal_dependency (
                event_id TEXT NOT NULL,
                depends_on_event_id TEXT NOT NULL,
                dependency_state TEXT NOT NULL,
                PRIMARY KEY(event_id, depends_on_event_id),
                FOREIGN KEY(event_id) REFERENCES local_event_log(event_id)
            );
            CREATE TABLE IF NOT EXISTS event_tombstone (
                tombstone_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                causal_event_id TEXT,
                signature BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS projection_checkpoint (
                projection_name TEXT PRIMARY KEY,
                projection_version INTEGER NOT NULL,
                last_event_id TEXT,
                checkpoint_hash BLOB,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS cursor_checkpoint (
                cursor_id TEXT PRIMARY KEY,
                device_id TEXT NOT NULL,
                inbox_seq INTEGER NOT NULL,
                last_envelope_id TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS device_inbox_cursor (
                device_id TEXT PRIMARY KEY,
                cursor_id TEXT NOT NULL,
                inbox_seq INTEGER NOT NULL,
                last_envelope_id TEXT,
                lamport_time INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS identity_lifecycle_projection (
                identity_commitment TEXT PRIMARY KEY,
                lifecycle_state TEXT NOT NULL CHECK (lifecycle_state IN ('active','deactivated','deleted')),
                lifecycle_epoch INTEGER NOT NULL,
                causal_event_id TEXT NOT NULL,
                reason_code TEXT,
                timelock_until INTEGER,
                grace_window_until INTEGER,
                finalization_time INTEGER,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS contact_verification_projection (
                contact_identity_commitment TEXT PRIMARY KEY,
                verification_state TEXT NOT NULL CHECK (verification_state IN ('verified','unverified','changed','blocked_by_policy')),
                safety_number_hash TEXT NOT NULL,
                verified_device_set_hash TEXT NOT NULL,
                verified_lineage_head TEXT NOT NULL,
                verified_at INTEGER NOT NULL,
                verified_by_device_id TEXT NOT NULL,
                last_change_event_id TEXT,
                last_change_seen_at INTEGER,
                kt_tree_size INTEGER,
                kt_tree_root_hash TEXT,
                kt_leaf_index INTEGER,
                last_gossip_lineage_head TEXT
            );
            CREATE TABLE IF NOT EXISTS friend_link_projection (
                link_id TEXT PRIMARY KEY,
                requester_id TEXT NOT NULL,
                target_id TEXT NOT NULL,
                state TEXT NOT NULL,
                remove_scope TEXT,
                blocked INTEGER NOT NULL DEFAULT 0,
                capability_revoked_at INTEGER,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS rejected_inbox_projection (
                conversation_id TEXT NOT NULL,
                message_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                rejected_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_rejected_inbox_conversation
                ON rejected_inbox_projection(conversation_id, rejected_at);
            CREATE TABLE IF NOT EXISTS direct_message_projection (
                conversation_id TEXT NOT NULL,
                message_id TEXT PRIMARY KEY,
                sender_id TEXT NOT NULL,
                encrypted_body BLOB NOT NULL,
                metadata_json BLOB NOT NULL,
                deleted INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_direct_message_conversation
                ON direct_message_projection(conversation_id, created_at);
            CREATE TABLE IF NOT EXISTS group_pending_undecrypted (
                message_id TEXT PRIMARY KEY,
                group_id TEXT NOT NULL,
                conversation_id TEXT NOT NULL,
                group_key_epoch INTEGER NOT NULL,
                sender_id TEXT NOT NULL,
                inbox_seq INTEGER NOT NULL,
                envelope_json BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_group_pending_undecrypted_epoch
                ON group_pending_undecrypted(group_id, group_key_epoch, inbox_seq);
            CREATE TABLE IF NOT EXISTS group_sender_key_counter_seen (
                group_id TEXT NOT NULL,
                group_key_epoch INTEGER NOT NULL,
                sender_id TEXT NOT NULL,
                counter INTEGER NOT NULL,
                message_id TEXT NOT NULL,
                seen_at INTEGER NOT NULL,
                PRIMARY KEY(group_id, group_key_epoch, sender_id, counter)
            );
            CREATE INDEX IF NOT EXISTS idx_group_sender_key_counter_seen_sender
                ON group_sender_key_counter_seen(group_id, group_key_epoch, sender_id, counter);
            CREATE TABLE IF NOT EXISTS group_member_device_key (
                group_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                device_signing_public_key TEXT NOT NULL,
                verified_at INTEGER NOT NULL,
                PRIMARY KEY(group_id, member_id)
            );
            CREATE TABLE IF NOT EXISTS group_control_event_seen (
                group_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                event_kind TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                target_member_id TEXT NOT NULL,
                previous_epoch INTEGER NOT NULL,
                new_group_epoch INTEGER NOT NULL,
                applied_at INTEGER NOT NULL,
                PRIMARY KEY(group_id, event_id)
            );
            CREATE TABLE IF NOT EXISTS group_message_tombstone_projection (
                group_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                tombstone_id TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                delete_scope TEXT NOT NULL,
                deleted_epoch INTEGER NOT NULL,
                reason TEXT NOT NULL,
                deleted_at INTEGER NOT NULL,
                PRIMARY KEY(group_id, message_id)
            );
            CREATE TABLE IF NOT EXISTS group_ban_projection (
                group_id TEXT NOT NULL,
                member_id TEXT NOT NULL,
                ban_id TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                banned_epoch INTEGER NOT NULL,
                reason TEXT NOT NULL,
                active INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                PRIMARY KEY(group_id, member_id)
            );
            CREATE TABLE IF NOT EXISTS group_invite_projection (
                group_id TEXT NOT NULL,
                invite_id TEXT NOT NULL,
                invitee_identity TEXT NOT NULL,
                invitee_signing_public_key TEXT NOT NULL,
                invited_role TEXT NOT NULL,
                inviter_device_id TEXT NOT NULL,
                invite_epoch INTEGER NOT NULL,
                expires_at INTEGER NOT NULL,
                state TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(group_id, invite_id)
            );
            CREATE TABLE IF NOT EXISTS conversation_disappearing_policy (
                conversation_id TEXT PRIMARY KEY,
                timer_seconds INTEGER NOT NULL,
                countdown_mode TEXT NOT NULL,
                scope TEXT NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversation_list_state (
                conversation_id TEXT PRIMARY KEY,
                archived INTEGER NOT NULL,
                pin_order INTEGER,
                mute_until INTEGER,
                hidden_at INTEGER,
                cleared_at INTEGER,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversation_projection (
                conversation_id TEXT PRIMARY KEY,
                conversation_kind TEXT NOT NULL,
                root_ref TEXT,
                hidden_at INTEGER,
                archived_at INTEGER,
                pinned_order INTEGER,
                muted_until INTEGER,
                cleared_at INTEGER,
                projection_version INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS message_projection (
                message_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                sender_device_id TEXT NOT NULL,
                event_id TEXT NOT NULL,
                body_cipher BLOB NOT NULL,
                edit_counter INTEGER NOT NULL DEFAULT 0,
                deleted_at INTEGER,
                event_tombstone_id TEXT,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(conversation_id) REFERENCES conversation_projection(conversation_id)
            );
            CREATE INDEX IF NOT EXISTS idx_message_projection_conversation
                ON message_projection(conversation_id, created_at, message_id);
            CREATE TABLE IF NOT EXISTS friend_projection (
                link_id TEXT PRIMARY KEY,
                peer_principal_id TEXT NOT NULL,
                link_state TEXT NOT NULL,
                capability_id TEXT,
                blocked_at INTEGER,
                removed_at INTEGER,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_projection (
                group_id TEXT PRIMARY KEY,
                group_epoch INTEGER NOT NULL,
                role TEXT,
                notification_state TEXT,
                max_members INTEGER NOT NULL DEFAULT 1000,
                new_member_history TEXT NOT NULL DEFAULT 'no_history',
                deleted_at INTEGER,
                created_at INTEGER NOT NULL DEFAULT 1760000000,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS group_member_projection (
                group_id TEXT NOT NULL,
                member_principal_id TEXT NOT NULL,
                member_id TEXT,
                role TEXT NOT NULL,
                joined_epoch INTEGER NOT NULL,
                removed_epoch INTEGER,
                active INTEGER NOT NULL DEFAULT 1,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(group_id, member_principal_id),
                FOREIGN KEY(group_id) REFERENCES group_projection(group_id)
            );
            CREATE TABLE IF NOT EXISTS receipt_projection (
                receipt_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                message_id TEXT,
                receipt_type TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS conversation_tombstone (
                tombstone_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                causal_event_id TEXT,
                signature BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS message_tombstone_projection (
                tombstone_id TEXT PRIMARY KEY,
                conversation_id TEXT NOT NULL,
                message_id TEXT NOT NULL,
                delete_scope TEXT NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_message_tombstone_message
                ON message_tombstone_projection(conversation_id, message_id);
            CREATE TABLE IF NOT EXISTS conversation_read_state (
                conversation_id TEXT NOT NULL,
                reader_id TEXT NOT NULL,
                read_through_message_id TEXT NOT NULL,
                read_at INTEGER NOT NULL,
                PRIMARY KEY(conversation_id, reader_id)
            );
            CREATE TABLE IF NOT EXISTS conversation_delivery_state (
                conversation_id TEXT NOT NULL,
                receiver_device_id TEXT NOT NULL,
                delivered_through_message_id TEXT NOT NULL,
                delivered_at INTEGER NOT NULL,
                ttl_seconds INTEGER NOT NULL,
                PRIMARY KEY(conversation_id, receiver_device_id)
            );
            CREATE TABLE IF NOT EXISTS conversation_unread_marker (
                conversation_id TEXT NOT NULL,
                marker_owner TEXT NOT NULL,
                message_id TEXT NOT NULL,
                marker_epoch INTEGER NOT NULL,
                active INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                PRIMARY KEY(conversation_id, marker_owner)
            );
            CREATE TABLE IF NOT EXISTS outbox_queue (
                outbox_id TEXT PRIMARY KEY,
                envelope_id TEXT NOT NULL,
                target_delivery_id TEXT NOT NULL,
                delivery_class TEXT NOT NULL,
                encrypted_envelope BLOB NOT NULL,
                state TEXT NOT NULL,
                retry_count INTEGER NOT NULL DEFAULT 0,
                next_retry_at INTEGER,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_outbox_state_retry
                ON outbox_queue(state, next_retry_at);
            CREATE TABLE IF NOT EXISTS ack_state (
                ack_id TEXT PRIMARY KEY,
                envelope_id TEXT NOT NULL,
                receiver_device_id TEXT NOT NULL,
                cursor_after TEXT,
                received_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS nack_state (
                nack_id TEXT PRIMARY KEY,
                envelope_id TEXT NOT NULL,
                receiver_device_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                retry_after INTEGER,
                received_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sync_checkpoint (
                checkpoint_id TEXT PRIMARY KEY,
                sync_scope TEXT NOT NULL,
                cursor_id TEXT,
                checkpoint_body BLOB NOT NULL,
                checkpoint_hash BLOB NOT NULL,
                updated_at INTEGER NOT NULL
            );
        ",
    },
    AccountMigration {
        schema_version: 2,
        app_version: "m2.1",
        checksum: "2026-06-14-object-control-sync-v2",
        notes: "object store mcp a2ui bot audit and sync ddl",
        sql: r"
            CREATE TABLE IF NOT EXISTS object_index (
                object_id TEXT PRIMARY KEY,
                chunk_manifest_hash BLOB NOT NULL,
                object_created_group_key_epoch INTEGER,
                object_state TEXT NOT NULL,
                total_cipher_size INTEGER NOT NULL,
                chunk_count INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                updated_at INTEGER NOT NULL,
                manifest_hash BLOB,
                nonce TEXT,
                ciphertext BLOB,
                plaintext_hash TEXT,
                tombstoned INTEGER NOT NULL DEFAULT 0,
                backup_excluded INTEGER NOT NULL DEFAULT 0,
                object_content_key BLOB,
                object_body BLOB
            );
            CREATE TABLE IF NOT EXISTS object_manifest (
                object_id TEXT PRIMARY KEY,
                manifest_hash BLOB NOT NULL,
                encrypted_owner_ref BLOB NOT NULL,
                encrypted_relation_ref BLOB,
                encrypted_metadata BLOB NOT NULL,
                object_key_slots BLOB NOT NULL,
                object_created_group_key_epoch INTEGER,
                chunk_manifest_hash BLOB NOT NULL,
                chunk_count INTEGER NOT NULL,
                total_cipher_size INTEGER NOT NULL,
                signature BLOB,
                updated_at INTEGER NOT NULL
            );
            CREATE UNIQUE INDEX IF NOT EXISTS idx_object_manifest_hash
                ON object_manifest(manifest_hash);
            CREATE TABLE IF NOT EXISTS object_key_slot (
                slot_id TEXT PRIMARY KEY,
                object_id TEXT NOT NULL,
                recipient_kind TEXT NOT NULL,
                recipient_id_hash BLOB NOT NULL,
                group_key_epoch INTEGER,
                wrapped_key BLOB NOT NULL,
                key_wrap_alg TEXT NOT NULL,
                FOREIGN KEY(object_id) REFERENCES object_manifest(object_id)
            );
            CREATE TABLE IF NOT EXISTS object_chunk (
                chunk_id TEXT PRIMARY KEY,
                object_id TEXT NOT NULL,
                chunk_index INTEGER NOT NULL,
                chunk_cipher_hash BLOB NOT NULL,
                chunk_plain_hash BLOB,
                cipher_size INTEGER NOT NULL,
                local_path TEXT,
                chunk_state TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                UNIQUE(object_id, chunk_index),
                FOREIGN KEY(object_id) REFERENCES object_manifest(object_id)
            );
            CREATE INDEX IF NOT EXISTS idx_object_chunk_state
                ON object_chunk(object_id, chunk_state);
            CREATE TABLE IF NOT EXISTS object_transfer_state (
                transfer_id TEXT PRIMARY KEY,
                object_id TEXT NOT NULL,
                peer_device_id TEXT NOT NULL,
                manifest_hash BLOB NOT NULL,
                resume_token TEXT,
                missing_chunk_bitmap BLOB NOT NULL,
                completed_chunk_bitmap BLOB NOT NULL,
                state TEXT NOT NULL,
                last_error TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS object_tombstone (
                tombstone_id TEXT PRIMARY KEY,
                target_id TEXT NOT NULL,
                target_kind TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                reason TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                causal_event_id TEXT,
                signature BLOB NOT NULL
            );
            CREATE TABLE IF NOT EXISTS self_device_control_log (
                control_event_id TEXT PRIMARY KEY,
                control_domain TEXT NOT NULL,
                action TEXT NOT NULL,
                source_device_id TEXT NOT NULL,
                target_device_id TEXT NOT NULL,
                correlation_id TEXT NOT NULL,
                encrypted_subject BLOB NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS a2ui_surface_cache (
                surface_id TEXT PRIMARY KEY,
                surface_hash BLOB NOT NULL,
                control_session_id TEXT,
                correlation_id TEXT NOT NULL,
                encrypted_surface_payload BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mcp_server_registry (
                server_id TEXT PRIMARY KEY,
                registry_hash BLOB NOT NULL,
                tool_manifest_set_hash BLOB NOT NULL,
                server_label TEXT,
                transport TEXT NOT NULL,
                endpoint_or_command_hash BLOB NOT NULL,
                server_public_key BLOB,
                trust_state TEXT NOT NULL,
                server_state TEXT NOT NULL DEFAULT 'active',
                revocation_cursor TEXT,
                updated_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS mcp_tool_manifest (
                tool_manifest_hash BLOB PRIMARY KEY,
                server_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                manifest_body BLOB NOT NULL,
                required_capability TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                updated_at INTEGER NOT NULL,
                FOREIGN KEY(server_id) REFERENCES mcp_server_registry(server_id)
            );
            CREATE INDEX IF NOT EXISTS idx_mcp_tool_manifest_server
                ON mcp_tool_manifest(server_id);
            CREATE INDEX IF NOT EXISTS idx_mcp_tool_manifest_capability_risk
                ON mcp_tool_manifest(required_capability, risk_level);
            CREATE TABLE IF NOT EXISTS mcp_grant (
                grant_id TEXT PRIMARY KEY,
                target_ai_device_id TEXT NOT NULL,
                source_app_device_id TEXT NOT NULL,
                capability TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                mcp_registry_hash BLOB,
                tool_manifest_set_hash BLOB,
                expires_at INTEGER NOT NULL,
                signature BLOB NOT NULL,
                created_at INTEGER NOT NULL,
                grant_body BLOB NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS mcp_standing_approval (
                standing_approval_id TEXT PRIMARY KEY,
                server_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                capability TEXT NOT NULL,
                risk_level TEXT NOT NULL,
                mcp_registry_hash BLOB NOT NULL,
                tool_manifest_set_hash BLOB NOT NULL,
                expires_at INTEGER NOT NULL,
                created_at INTEGER NOT NULL,
                created_by_device_id TEXT NOT NULL,
                approval_body BLOB NOT NULL,
                revoked INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_mcp_standing_approval_tool
                ON mcp_standing_approval(server_id, tool_name, revoked, expires_at);
            CREATE TABLE IF NOT EXISTS bot_manifest_cache (
                bot_identity_commitment TEXT NOT NULL,
                bot_manifest_hash BLOB PRIMARY KEY,
                actor_type TEXT NOT NULL CHECK(actor_type = 'bot'),
                display_name TEXT NOT NULL,
                home_node TEXT NOT NULL,
                owner_identity_commitment TEXT NOT NULL,
                hosting_model TEXT NOT NULL,
                capabilities_json BLOB NOT NULL,
                permissions_json BLOB NOT NULL,
                safety_disclosure_json BLOB NOT NULL,
                manifest_body BLOB NOT NULL,
                signature_by_bot_identity BLOB NOT NULL,
                expires_at INTEGER,
                cached_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_bot_manifest_identity
                ON bot_manifest_cache(bot_identity_commitment);
            CREATE TABLE IF NOT EXISTS bot_trust_pin (
                bot_identity_commitment TEXT PRIMARY KEY,
                bot_public_key TEXT NOT NULL,
                signing_key_id TEXT NOT NULL,
                trust_source TEXT NOT NULL,
                pinned_at INTEGER NOT NULL
            );
            CREATE TABLE IF NOT EXISTS bot_install_grant (
                grant_id TEXT PRIMARY KEY,
                bot_identity_commitment TEXT NOT NULL,
                bot_manifest_hash BLOB NOT NULL,
                installer_identity TEXT NOT NULL,
                installer_device_id TEXT NOT NULL,
                scope_json BLOB NOT NULL,
                conversation_id TEXT,
                group_id TEXT,
                expires_at INTEGER NOT NULL,
                signature BLOB NOT NULL,
                revoked_at INTEGER,
                revocation_event_id TEXT,
                grant_hash TEXT,
                grant_body BLOB,
                consent_member_ids_json BLOB,
                state TEXT NOT NULL DEFAULT 'installed',
                created_at INTEGER NOT NULL,
                FOREIGN KEY(bot_manifest_hash) REFERENCES bot_manifest_cache(bot_manifest_hash)
            );
            CREATE INDEX IF NOT EXISTS idx_bot_install_grant_bot
                ON bot_install_grant(bot_identity_commitment, expires_at);
            CREATE INDEX IF NOT EXISTS idx_bot_install_grant_scope_group
                ON bot_install_grant(group_id, revoked_at);
            CREATE TABLE IF NOT EXISTS audit_log (
                audit_id TEXT PRIMARY KEY,
                audit_type TEXT NOT NULL,
                actor_device_id TEXT NOT NULL,
                subject_hash BLOB,
                redacted_summary TEXT NOT NULL,
                created_at INTEGER NOT NULL,
                audit_body BLOB
            );
        ",
    },
    AccountMigration {
        schema_version: 3,
        app_version: "mvp-s4x",
        checksum: "2026-06-26-device-directory-v1",
        notes: "trusted local device directory for manifest fanout resolution",
        sql: r"
            CREATE TABLE IF NOT EXISTS device_directory (
                device_id TEXT PRIMARY KEY,
                principal_commitment TEXT NOT NULL,
                source TEXT NOT NULL,
                verified_at INTEGER NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_device_directory_principal
                ON device_directory(principal_commitment);
        ",
    },
];

pub(crate) fn migrate_account_db(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "PRAGMA foreign_keys = ON;
         CREATE TABLE IF NOT EXISTS schema_migration (
            schema_version INTEGER PRIMARY KEY,
            applied_at INTEGER NOT NULL,
            app_version TEXT NOT NULL,
            checksum TEXT NOT NULL,
            notes TEXT
        );",
    )?;
    for migration in ACCOUNT_MIGRATIONS {
        apply_account_migration(connection, migration)?;
    }
    ensure_legacy_columns(connection)?;
    Ok(())
}

fn apply_account_migration(
    connection: &Connection,
    migration: &AccountMigration,
) -> Result<(), StorageError> {
    let existing: Option<String> = connection
        .query_row(
            "SELECT checksum FROM schema_migration WHERE schema_version = ?1",
            params![migration.schema_version],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(checksum) = existing {
        if checksum == migration.checksum {
            return Ok(());
        }
        return Err(StorageError::MigrationChecksumMismatch {
            schema_version: migration.schema_version,
            expected: migration.checksum.to_owned(),
            actual: checksum,
        });
    }
    connection.execute_batch("BEGIN IMMEDIATE;")?;
    let result = (|| -> Result<(), StorageError> {
        connection.execute_batch(migration.sql)?;
        connection.execute(
            "INSERT INTO schema_migration
                (schema_version, applied_at, app_version, checksum, notes)
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![
                migration.schema_version,
                unix_now(),
                migration.app_version,
                migration.checksum,
                migration.notes
            ],
        )?;
        Ok(())
    })();
    match result {
        Ok(()) => {
            connection.execute_batch("COMMIT;")?;
            Ok(())
        }
        Err(error) => {
            let _rollback_ignored = connection.execute_batch("ROLLBACK;");
            Err(error)
        }
    }
}

fn ensure_legacy_columns(connection: &Connection) -> Result<(), StorageError> {
    ensure_column(
        connection,
        "contact_verification_projection",
        "kt_tree_size",
        "kt_tree_size INTEGER",
    )?;
    ensure_column(
        connection,
        "contact_verification_projection",
        "kt_tree_root_hash",
        "kt_tree_root_hash TEXT",
    )?;
    ensure_column(
        connection,
        "contact_verification_projection",
        "kt_leaf_index",
        "kt_leaf_index INTEGER",
    )?;
    ensure_column(
        connection,
        "contact_verification_projection",
        "last_gossip_lineage_head",
        "last_gossip_lineage_head TEXT",
    )?;
    ensure_column(connection, "friend_link_projection", "remove_scope", "remove_scope TEXT")?;
    ensure_column(
        connection,
        "friend_link_projection",
        "blocked",
        "blocked INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        connection,
        "friend_link_projection",
        "capability_revoked_at",
        "capability_revoked_at INTEGER",
    )?;
    ensure_column(connection, "group_projection", "role", "role TEXT")?;
    ensure_column(connection, "group_projection", "notification_state", "notification_state TEXT")?;
    ensure_column(connection, "group_projection", "deleted_at", "deleted_at INTEGER")?;
    ensure_column(
        connection,
        "group_projection",
        "created_at",
        "created_at INTEGER NOT NULL DEFAULT 1760000000",
    )?;
    ensure_column(
        connection,
        "group_projection",
        "updated_at",
        "updated_at INTEGER NOT NULL DEFAULT 1760000000",
    )?;
    ensure_column(connection, "group_member_projection", "member_id", "member_id TEXT")?;
    ensure_column(connection, "group_member_projection", "removed_epoch", "removed_epoch INTEGER")?;
    ensure_column(
        connection,
        "group_member_projection",
        "active",
        "active INTEGER NOT NULL DEFAULT 1",
    )?;
    ensure_column(
        connection,
        "group_member_projection",
        "updated_at",
        "updated_at INTEGER NOT NULL DEFAULT 1760000000",
    )?;
    ensure_group_control_tables(connection)?;
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS bot_trust_pin (
            bot_identity_commitment TEXT PRIMARY KEY,
            bot_public_key TEXT NOT NULL,
            signing_key_id TEXT NOT NULL,
            trust_source TEXT NOT NULL,
            pinned_at INTEGER NOT NULL
        );",
    )?;
    ensure_column(connection, "bot_install_grant", "grant_hash", "grant_hash TEXT")?;
    ensure_column(connection, "bot_install_grant", "grant_body", "grant_body BLOB")?;
    ensure_column(
        connection,
        "bot_install_grant",
        "consent_member_ids_json",
        "consent_member_ids_json BLOB",
    )?;
    ensure_column(
        connection,
        "bot_install_grant",
        "state",
        "state TEXT NOT NULL DEFAULT 'installed'",
    )?;
    ensure_mcp_legacy_columns(connection)?;
    ensure_column(connection, "audit_log", "audit_body", "audit_body BLOB")?;
    ensure_object_index_legacy_columns(connection)?;
    ensure_object_transfer_state_columns(connection)?;
    ensure_device_directory_table(connection)?;
    Ok(())
}

fn ensure_device_directory_table(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS device_directory (
            device_id TEXT PRIMARY KEY,
            principal_commitment TEXT NOT NULL,
            source TEXT NOT NULL,
            verified_at INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_device_directory_principal
            ON device_directory(principal_commitment);",
    )?;
    Ok(())
}

fn ensure_group_control_tables(connection: &Connection) -> Result<(), StorageError> {
    connection.execute_batch(
        "CREATE TABLE IF NOT EXISTS group_member_device_key (
            group_id TEXT NOT NULL,
            member_id TEXT NOT NULL,
            device_signing_public_key TEXT NOT NULL,
            verified_at INTEGER NOT NULL,
            PRIMARY KEY(group_id, member_id)
        );
        CREATE TABLE IF NOT EXISTS group_control_event_seen (
            group_id TEXT NOT NULL,
            event_id TEXT NOT NULL,
            event_kind TEXT NOT NULL,
            actor_device_id TEXT NOT NULL,
            target_member_id TEXT NOT NULL,
            previous_epoch INTEGER NOT NULL,
            new_group_epoch INTEGER NOT NULL,
            applied_at INTEGER NOT NULL,
            PRIMARY KEY(group_id, event_id)
        );
        CREATE TABLE IF NOT EXISTS group_message_tombstone_projection (
            group_id TEXT NOT NULL,
            message_id TEXT NOT NULL,
            tombstone_id TEXT NOT NULL,
            actor_device_id TEXT NOT NULL,
            delete_scope TEXT NOT NULL,
            deleted_epoch INTEGER NOT NULL,
            reason TEXT NOT NULL,
            deleted_at INTEGER NOT NULL,
            PRIMARY KEY(group_id, message_id)
        );
        CREATE TABLE IF NOT EXISTS group_ban_projection (
            group_id TEXT NOT NULL,
            member_id TEXT NOT NULL,
            ban_id TEXT NOT NULL,
            actor_device_id TEXT NOT NULL,
            banned_epoch INTEGER NOT NULL,
            reason TEXT NOT NULL,
            active INTEGER NOT NULL,
            created_at INTEGER NOT NULL,
            PRIMARY KEY(group_id, member_id)
        );
        CREATE TABLE IF NOT EXISTS group_invite_projection (
            group_id TEXT NOT NULL,
            invite_id TEXT NOT NULL,
            invitee_identity TEXT NOT NULL,
            invitee_signing_public_key TEXT NOT NULL,
            invited_role TEXT NOT NULL,
            inviter_device_id TEXT NOT NULL,
            invite_epoch INTEGER NOT NULL,
            expires_at INTEGER NOT NULL,
            state TEXT NOT NULL,
            reason TEXT NOT NULL,
            created_at INTEGER NOT NULL,
            updated_at INTEGER NOT NULL,
            PRIMARY KEY(group_id, invite_id)
        );",
    )?;
    Ok(())
}

fn ensure_mcp_legacy_columns(connection: &Connection) -> Result<(), StorageError> {
    ensure_column(connection, "mcp_grant", "grant_body", "grant_body BLOB")?;
    ensure_column(connection, "mcp_grant", "revoked", "revoked INTEGER NOT NULL DEFAULT 0")?;
    ensure_column(connection, "mcp_standing_approval", "approval_body", "approval_body BLOB")?;
    ensure_column(
        connection,
        "mcp_standing_approval",
        "revoked",
        "revoked INTEGER NOT NULL DEFAULT 0",
    )?;
    Ok(())
}

fn ensure_object_index_legacy_columns(connection: &Connection) -> Result<(), StorageError> {
    ensure_column(connection, "object_index", "manifest_hash", "manifest_hash BLOB")?;
    ensure_column(connection, "object_index", "nonce", "nonce TEXT")?;
    ensure_column(connection, "object_index", "ciphertext", "ciphertext BLOB")?;
    ensure_column(connection, "object_index", "plaintext_hash", "plaintext_hash TEXT")?;
    ensure_column(
        connection,
        "object_index",
        "tombstoned",
        "tombstoned INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        connection,
        "object_index",
        "backup_excluded",
        "backup_excluded INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(connection, "object_index", "object_content_key", "object_content_key BLOB")?;
    ensure_column(connection, "object_index", "object_body", "object_body BLOB")?;
    Ok(())
}

fn ensure_object_transfer_state_columns(connection: &Connection) -> Result<(), StorageError> {
    ensure_column(
        connection,
        "object_transfer_state",
        "direction",
        "direction TEXT NOT NULL DEFAULT 'upload'",
    )?;
    ensure_column(connection, "object_transfer_state", "relay_endpoint", "relay_endpoint TEXT")?;
    ensure_column(
        connection,
        "object_transfer_state",
        "chunk_size",
        "chunk_size INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        connection,
        "object_transfer_state",
        "total_bytes",
        "total_bytes INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        connection,
        "object_transfer_state",
        "done_bytes",
        "done_bytes INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        connection,
        "object_transfer_state",
        "total_chunks",
        "total_chunks INTEGER NOT NULL DEFAULT 0",
    )?;
    ensure_column(
        connection,
        "object_transfer_state",
        "next_chunk_index",
        "next_chunk_index INTEGER",
    )?;
    ensure_column(connection, "object_transfer_state", "expires_at", "expires_at INTEGER")?;
    Ok(())
}

fn ensure_column(
    connection: &Connection,
    table_name: &str,
    column_name: &str,
    column_definition: &str,
) -> Result<(), StorageError> {
    let mut statement = connection.prepare(&format!("PRAGMA table_info({table_name})"))?;
    let mut rows = statement.query([])?;
    while let Some(row) = rows.next()? {
        let existing: String = row.get(1)?;
        if existing == column_name {
            return Ok(());
        }
    }
    connection.execute(&format!("ALTER TABLE {table_name} ADD COLUMN {column_definition}"), [])?;
    Ok(())
}
