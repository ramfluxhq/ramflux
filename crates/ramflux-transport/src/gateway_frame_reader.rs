// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Cancellation-safe client-session framing; partial input belongs to the stream owner.

use crate::TransportError;
use tokio::io::{AsyncRead, AsyncReadExt};

#[derive(Default)]
pub(crate) struct GatewayFrameReader {
    prefix: [u8; 4],
    prefix_read: usize,
    body: Vec<u8>,
    body_read: usize,
    deadline: Option<tokio::time::Instant>,
    #[cfg(feature = "itest-fingerprint")]
    progress: Option<std::sync::Arc<std::sync::atomic::AtomicUsize>>,
}

impl GatewayFrameReader {
    #[cfg(feature = "itest-fingerprint")]
    pub(crate) fn progress_probe(&mut self) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        std::sync::Arc::clone(self.progress.get_or_insert_with(Default::default))
    }
    #[cfg(feature = "itest-fingerprint")]
    fn publish_progress(&self) {
        if let Some(progress) = &self.progress {
            progress.store(self.prefix_read + self.body_read, std::sync::atomic::Ordering::Release);
        }
    }
    pub(crate) async fn timed<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        input: &mut R,
        limit: usize,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, TransportError> {
        let deadline = *self.deadline.get_or_insert_with(|| tokio::time::Instant::now() + timeout);
        tokio::time::timeout_at(deadline, self.read(input, limit)).await.map_err(|error| {
            TransportError::Io(std::io::Error::new(std::io::ErrorKind::TimedOut, error))
        })?
    }

    pub(crate) async fn idle<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        input: &mut R,
        limit: usize,
        timeout: std::time::Duration,
    ) -> Result<Vec<u8>, TransportError> {
        // No deadline while a healthy idle peer sends nothing. Once a byte arrives,
        // the same frame deadline survives interruptions and later active reads.
        if self.prefix_read == 0 && self.deadline.is_none() {
            if input.read(&mut self.prefix[..1]).await? == 0 {
                return Err(eof());
            }
            self.prefix_read = 1;
            #[cfg(feature = "itest-fingerprint")]
            self.publish_progress();
        }
        self.timed(input, limit, timeout).await
    }

    pub(crate) async fn read<R: AsyncRead + Unpin + ?Sized>(
        &mut self,
        input: &mut R,
        limit: usize,
    ) -> Result<Vec<u8>, TransportError> {
        while self.prefix_read < self.prefix.len() {
            let count = input.read(&mut self.prefix[self.prefix_read..]).await?;
            if count == 0 {
                return Err(eof());
            }
            self.prefix_read += count;
            #[cfg(feature = "itest-fingerprint")]
            self.publish_progress();
        }
        let length = u32::from_be_bytes(self.prefix) as usize;
        if length > limit {
            return Err(TransportError::FrameTooLarge { len: length });
        }
        if self.body.is_empty() {
            self.body.resize(length, 0);
        }
        while self.body_read < length {
            let count = input.read(&mut self.body[self.body_read..]).await?;
            if count == 0 {
                return Err(eof());
            }
            self.body_read += count;
            #[cfg(feature = "itest-fingerprint")]
            self.publish_progress();
        }
        self.prefix_read = 0;
        self.body_read = 0;
        self.deadline = None;
        #[cfg(feature = "itest-fingerprint")]
        self.publish_progress();
        Ok(std::mem::take(&mut self.body))
    }
}

fn eof() -> TransportError {
    std::io::Error::new(std::io::ErrorKind::UnexpectedEof, "gateway frame ended early").into()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{future::Future, task::Poll};
    use tokio::io::AsyncWriteExt;

    #[tokio::test]
    async fn cancelled_partial_frame_resumes_at_the_exact_byte()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut writer, mut input) = tokio::io::duplex(64);
        let mut reader = GatewayFrameReader::default();
        let length = 6_u32.to_be_bytes();
        writer.write_all(&length[..2]).await?;
        {
            let read = reader.read(&mut input, 64);
            tokio::pin!(read);
            std::future::poll_fn(|cx| {
                assert!(read.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(reader.prefix_read, 2);
        writer.write_all(&length[2..]).await?;
        writer.write_all(b"abc").await?;
        {
            let read = reader.read(&mut input, 64);
            tokio::pin!(read);
            std::future::poll_fn(|cx| {
                assert!(read.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(reader.body_read, 3);
        writer.write_all(b"def").await?;
        assert_eq!(reader.read(&mut input, 64).await?, b"abcdef");
        writer.write_all(&1_u32.to_be_bytes()).await?;
        writer.write_all(b"z").await?;
        assert_eq!(reader.read(&mut input, 64).await?, b"z");
        Ok(())
    }

    #[tokio::test(start_paused = true)]
    async fn idle_silence_is_unbounded_but_partial_frame_deadline_cannot_be_renewed()
    -> Result<(), Box<dyn std::error::Error>> {
        use std::time::Duration;
        let (mut writer, mut input) = tokio::io::duplex(64);
        let mut reader = GatewayFrameReader::default();
        {
            let read = reader.idle(&mut input, 64, Duration::from_secs(15));
            tokio::pin!(read);
            std::future::poll_fn(|cx| {
                assert!(read.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
            tokio::time::advance(Duration::from_secs(600)).await;
            std::future::poll_fn(|cx| {
                assert!(read.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert!(reader.deadline.is_none());
        let started = tokio::time::Instant::now();
        writer.write_all(&[0]).await?;
        {
            let read = reader.idle(&mut input, 64, Duration::from_secs(15));
            tokio::pin!(read);
            std::future::poll_fn(|cx| {
                assert!(read.as_mut().poll(cx).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(reader.prefix_read, 1);
        assert_eq!(reader.deadline, Some(started + Duration::from_secs(15)));
        tokio::time::advance(Duration::from_secs(14)).await;
        let result = reader.timed(&mut input, 64, Duration::from_secs(600)).await;
        assert!(
            matches!(result, Err(TransportError::Io(error)) if error.kind() == std::io::ErrorKind::TimedOut)
        );
        assert_eq!(tokio::time::Instant::now() - started, Duration::from_secs(15));
        Ok(())
    }

    #[tokio::test]
    async fn oversized_frame_is_refused_before_body_allocation()
    -> Result<(), Box<dyn std::error::Error>> {
        let (mut writer, mut input) = tokio::io::duplex(64);
        let mut reader = GatewayFrameReader::default();
        writer.write_all(&65_u32.to_be_bytes()).await?;
        assert!(matches!(
            reader.read(&mut input, 64).await,
            Err(TransportError::FrameTooLarge { len: 65 })
        ));
        assert_eq!(reader.body.capacity(), 0);
        Ok(())
    }
}
