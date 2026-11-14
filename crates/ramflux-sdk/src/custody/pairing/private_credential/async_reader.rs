// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Async private reads retain the small discriminator/length gate before secret allocation.
use super::{MAX_BODY, PrivateCredentialReply, TAG, action, finish_reply, invalid};
use crate::SdkError;
use tokio::io::{AsyncRead, AsyncReadExt};
use zeroize::Zeroizing;
/// Finish a designated private reply after the connection reader consumed length and tag.
/// The expected generation/action come only from that connection's pending prompt.
/// # Errors
/// Refuses another discriminator/generation or any malformed/bounded secret field.
pub async fn read_reply_after_discriminator<R: AsyncRead + Unpin>(
    reader: &mut R,
    prefix: [u8; 4],
    discriminator: u8,
    requested: &str,
    expected_generation: u64,
) -> Result<PrivateCredentialReply, SdkError> {
    action(requested)?;
    let total = usize::try_from(u32::from_be_bytes(prefix)).map_err(|_| invalid())?;
    if discriminator != TAG || !(14..=MAX_BODY).contains(&total) {
        return Err(invalid());
    }
    let mut header = [0; 11];
    reader.read_exact(&mut header).await?;
    let generation = u64::from_be_bytes(header[..8].try_into().map_err(|_| invalid())?);
    if generation == 0 || generation != expected_generation {
        return Err(invalid());
    }
    let arm = header[8];
    let pass_len = usize::from(u16::from_be_bytes([header[9], header[10]]));
    if arm > 1 || pass_len > 1024 || total < 14 + pass_len || (arm == 0 && pass_len != 0) {
        return Err(invalid());
    }
    let mut pass = Zeroizing::new(vec![0; pass_len]);
    reader.read_exact(&mut pass).await?;
    let mut length = [0; 2];
    reader.read_exact(&mut length).await?;
    let confirm_len = usize::from(u16::from_be_bytes(length));
    if confirm_len > 1024
        || total != 14 + pass_len + confirm_len
        || (arm == 0 && confirm_len != 0)
        || (requested != "setup" && confirm_len != 0)
    {
        return Err(invalid());
    }
    let mut confirm = Zeroizing::new(vec![0; confirm_len]);
    reader.read_exact(&mut confirm).await?;
    finish_reply(generation, requested, arm, pass, confirm)
}
