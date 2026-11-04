// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Deadline-first polling prevents a late nested result from masking item expiry.
use std::{
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};
use tokio::time::{Instant, Sleep};

#[must_use]
pub(super) struct ItemDeadline<F> {
    inner: Pin<Box<F>>,
    timer: Pin<Box<Sleep>>,
    deadline: Instant,
}
impl<F: Future> ItemDeadline<F> {
    pub(super) fn new(inner: F, deadline: Instant) -> Self {
        Self {
            inner: Box::pin(inner),
            timer: Box::pin(tokio::time::sleep_until(deadline)),
            deadline,
        }
    }
}
impl<F: Future> Future for ItemDeadline<F> {
    type Output = Result<F::Output, ()>;
    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        if Instant::now() >= self.deadline {
            return Poll::Ready(Err(()));
        }
        if let Poll::Ready(value) = self.inner.as_mut().poll(cx) {
            return Poll::Ready(Ok(value));
        }
        if Instant::now() >= self.deadline || self.timer.as_mut().poll(cx).is_ready() {
            Poll::Ready(Err(()))
        } else {
            Poll::Pending
        }
    }
}
