use serde::Serialize;

pub struct ObjectWrite<'a, T>
where
    T: Serialize,
{
    pub object_id: &'a str,
    pub manifest_hash: &'a str,
    pub nonce: &'a str,
    pub ciphertext: &'a [u8],
    pub plaintext_hash: &'a str,
    pub tombstoned: bool,
    pub backup_excluded: bool,
    pub content_key: Option<&'a [u8; 32]>,
    pub object: &'a T,
    pub updated_at: i64,
}
