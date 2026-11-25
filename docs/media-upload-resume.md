<!-- SPDX-License-Identifier: BSD-3-Clause -->
# Resuming prepared attachment uploads

Retry `conversation.send` with the same operation and prepare IDs after reconnecting
or reopening the account. A sealed prepare retains its upload ID, object ID,
manifest, generation and ciphertext. The SDK durably records each successful
512 KiB slice acknowledgement before issuing the next slice.

On retry, each segment is checked against its manifest digest and the relay's
existing authenticated `upload_status` checkpoint. Confirmed slices are skipped.
A slice whose reply was lost is replayed from stored ciphertext with the same
identity and bytes and a fresh requester proof. Relay reconciliation never
extends the reservation deadline. A recovered committed upload does not issue
another Commit.

If the sender dies during sealing, recovery discards the partial ciphertext and
sealed key, records the abandoned reservation for retirement, and advances the
prepare generation. The retry draws a fresh key, object ID and upload ID before
sealing again. It never encrypts new plaintext under the abandoned key.

This behavior adds no bus method, C ABI symbol or progress API.
