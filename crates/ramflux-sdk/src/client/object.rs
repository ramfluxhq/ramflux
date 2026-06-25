#![allow(clippy::missing_errors_doc)]
#![allow(clippy::wildcard_imports)]
use crate::prelude::*;

impl RamfluxClient {
    fn persist_object_if_unlocked(
        &self,
        object: &EncryptedObject,
        content_key: Option<&[u8; 32]>,
    ) -> Result<(), SdkError> {
        let Some(db) = self.active_account_db.as_ref() else {
            return Ok(());
        };
        db.upsert_object(&ObjectWrite {
            object_id: &object.object_id,
            manifest_hash: &object.manifest_hash,
            nonce: &object.nonce,
            ciphertext: &object.ciphertext,
            plaintext_hash: &object.plaintext_hash,
            tombstoned: object.tombstoned,
            backup_excluded: object.backup_excluded,
            content_key,
            object,
            updated_at: now_unix_timestamp(),
        })?;
        Ok(())
    }

    pub(crate) fn hydrate_object_store_from_account_db(&mut self) -> Result<(), SdkError> {
        let (objects, object_keys) = self.account_db()?.load_objects::<EncryptedObject>()?;
        self.object_store.replace_persisted(objects, object_keys);
        Ok(())
    }

    pub async fn share_object_key_with_dm_recipient(
        &self,
        engine: &mut GatewaySessionEngine,
        request: LocalBusObjectShareRequest,
    ) -> Result<SdkObjectSharePackage, SdkError> {
        let object = self
            .object_store
            .objects()
            .into_iter()
            .find(|object| object.object_id == request.object_id)
            .ok_or(SyncError::ObjectNotFound)?;
        let object_key = self.object_store.object_key(&object.object_id)?;
        let recipient_device_id = request.recipient_device_id.clone().ok_or_else(|| {
            SdkError::LocalBus("object.share requires recipient_device_id".to_owned())
        })?;
        let sender_id = request.sender_id.clone().unwrap_or_else(|| {
            self.device_branch
                .as_ref()
                .map_or_else(|| "rf_object_sender".to_owned(), |branch| branch.device_id.clone())
        });
        let target_delivery_id = request.target_delivery_id.clone().ok_or_else(|| {
            SdkError::LocalBus("object.share requires target_delivery_id".to_owned())
        })?;
        let message = GatewayDirectMessage {
            conversation_id: request.conversation_id.clone(),
            message_id: format!("object.slot:{}:{recipient_device_id}", object.object_id),
            envelope_id: format!("object.slot:{}:{recipient_device_id}", object.object_id),
            source_principal_id: sender_id.clone(),
            sender_id,
            recipient_device_id: Some(recipient_device_id.clone()),
            target_delivery_id,
            encrypted_body: Vec::new(),
            created_at: now_unix_timestamp(),
            ttl: 3_600,
        };
        let (mut session, x3dh) = self.load_or_create_send_dm_session(engine, &message).await?;
        let associated_data = object_key_slot_associated_data(
            &object.object_id,
            &request.conversation_id,
            &recipient_device_id,
        );
        let ciphertext = session.encrypt(&object_key, &associated_data)?;
        self.persist_dm_session(
            &request.conversation_id,
            &format!("object-slot:{}", object.object_id),
            "send",
            &session,
        )?;
        Ok(SdkObjectSharePackage {
            schema: "ramflux.sdk.object_share_package.v1".to_owned(),
            version: 1,
            ciphertext_base64: ramflux_protocol::encode_base64url(&object.ciphertext),
            key_slot: SdkObjectKeySlot {
                schema: "ramflux.sdk.object_key_slot.dm.v1".to_owned(),
                version: 1,
                object_id: object.object_id.clone(),
                conversation_id: request.conversation_id,
                recipient_device_id,
                x3dh,
                ciphertext,
            },
            object,
        })
    }

    /// # Errors
    /// Returns an error when the key slot cannot be decrypted or the object cannot be imported.
    pub fn import_shared_object(
        &mut self,
        package: &SdkObjectSharePackage,
    ) -> Result<EncryptedObject, SdkError> {
        if package.schema != "ramflux.sdk.object_share_package.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported object share package schema: {}",
                package.schema
            )));
        }
        if package.key_slot.schema != "ramflux.sdk.object_key_slot.dm.v1" {
            return Err(SdkError::LocalBus(format!(
                "unsupported object key slot schema: {}",
                package.key_slot.schema
            )));
        }
        let mut session = self.load_or_create_recv_dm_session(
            &package.key_slot.conversation_id,
            package.key_slot.x3dh.as_ref(),
        )?;
        let associated_data = object_key_slot_associated_data(
            &package.key_slot.object_id,
            &package.key_slot.conversation_id,
            &package.key_slot.recipient_device_id,
        );
        let plaintext_key = session.decrypt(&package.key_slot.ciphertext, &associated_data)?;
        let object_key: [u8; 32] = plaintext_key
            .try_into()
            .map_err(|_err| SdkError::LocalBus("invalid object key length".to_owned()))?;
        self.persist_dm_session(
            &package.key_slot.conversation_id,
            &format!("object-slot:{}", package.object.object_id),
            "recv",
            &session,
        )?;
        let ciphertext = ramflux_protocol::decode_base64url(&package.ciphertext_base64)
            .map_err(|error| SdkError::LocalBus(format!("invalid object ciphertext: {error}")))?;
        let object = self.object_store.put_received_encrypted_object_with_key(
            &package.object.object_id,
            &package.object.manifest_hash,
            &ciphertext,
            &package.object.plaintext_hash,
            object_key,
        );
        self.persist_object_if_unlocked(&object, Some(&object_key))?;
        Ok(object)
    }

    /// # Errors
    /// Returns an error when the OS CSPRNG cannot generate an object key.
    pub fn put_encrypted_object(
        &mut self,
        object_id: &str,
        plaintext: &[u8],
    ) -> Result<EncryptedObject, SdkError> {
        let object = self.object_store.put_encrypted_object(object_id, plaintext)?;
        let object_key = self.object_store.object_key(&object.object_id)?;
        self.persist_object_if_unlocked(&object, Some(&object_key))?;
        Ok(object)
    }

    /// # Errors
    /// Returns an error when validation, serialization, storage, or state checks fail.
    pub fn decrypt_object(&self, object_id: &str) -> Result<Vec<u8>, SdkError> {
        Ok(self.object_store.decrypt_object(object_id)?)
    }

    /// # Errors
    /// Returns an error when the object does not exist or cannot be tombstoned.
    pub fn tombstone_object(&mut self, object_id: &str) -> Result<(), SdkError> {
        self.object_store.tombstone(object_id)?;
        if let Some(db) = self.active_account_db.as_ref() {
            db.set_object_tombstoned(object_id)?;
        }
        Ok(())
    }
}
