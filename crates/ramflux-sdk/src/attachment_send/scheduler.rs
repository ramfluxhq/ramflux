// SPDX-License-Identifier: BSD-3-Clause
// Copyright (c) 2026 Span Brain

//! Process-wide worker scheduler for import bodies. Four workers, a queue of 64 for the
//! process and 16 per account, and at most two large bodies at a time so small ones still
//! make progress. A full queue is `disk_full` (the scheduler's backpressure code) and starts
//! nothing, so a caller can never spawn unbounded threads or handles.

use std::collections::{BTreeMap, VecDeque};
use std::sync::{Condvar, Mutex, OnceLock};
use std::thread;

use super::codes::{CODE_DISK_FULL, CODE_SEAL_FAILED, Refusal};

pub(crate) const WORKERS: usize = 4;
pub(crate) const LARGE_WORKERS: usize = 2;
pub(crate) const QUEUE_PROCESS: usize = 64;
pub(crate) const QUEUE_ACCOUNT: usize = 16;
/// Plaintext at or above this many bytes is a large body.
pub(crate) const LARGE_BYTES: u64 = 64 * 1024 * 1024;

type Work = Box<dyn FnOnce() + Send + 'static>;

struct Task {
    account: String,
    large: bool,
    work: Work,
}

#[derive(Default)]
struct State {
    queue: VecDeque<Task>,
    per_account: BTreeMap<String, usize>,
    large_running: usize,
}

struct Scheduler {
    state: Mutex<State>,
    wake: Condvar,
}

fn scheduler() -> Result<&'static Scheduler, Refusal> {
    static SCHEDULER: OnceLock<Result<&'static Scheduler, ()>> = OnceLock::new();
    SCHEDULER
        .get_or_init(|| {
            let scheduler: &'static Scheduler = Box::leak(Box::new(Scheduler {
                state: Mutex::new(State::default()),
                wake: Condvar::new(),
            }));
            for index in 0..WORKERS {
                let spawned = thread::Builder::new()
                    .name(format!("rf-attach-import-{index}"))
                    .spawn(move || scheduler.run());
                if spawned.is_err() {
                    return Err(());
                }
            }
            Ok(scheduler)
        })
        .as_ref()
        .map(|scheduler| *scheduler)
        .map_err(|()| Refusal::new(CODE_SEAL_FAILED))
}

/// Queues `work` for `account`. `large` bodies share two of the four workers.
/// # Errors
/// Returns `disk_full` when the process or account queue is full.
pub(crate) fn submit(
    account: &str,
    large: bool,
    work: impl FnOnce() + Send + 'static,
) -> Result<(), Refusal> {
    let scheduler = scheduler()?;
    let mut state = scheduler.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
    let mine = state.per_account.get(account).copied().unwrap_or(0);
    if state.queue.len() >= QUEUE_PROCESS || mine >= QUEUE_ACCOUNT {
        return Err(Refusal::new(CODE_DISK_FULL));
    }
    *state.per_account.entry(account.to_owned()).or_insert(0) += 1;
    state.queue.push_back(Task { account: account.to_owned(), large, work: Box::new(work) });
    drop(state);
    scheduler.wake.notify_one();
    Ok(())
}

impl Scheduler {
    fn run(&self) {
        loop {
            let task = self.next();
            let large = task.large;
            let account = task.account.clone();
            (task.work)();
            let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
            if large {
                state.large_running = state.large_running.saturating_sub(1);
            }
            if let Some(count) = state.per_account.get_mut(&account) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    state.per_account.remove(&account);
                }
            }
            drop(state);
            self.wake.notify_all();
        }
    }

    fn next(&self) -> Task {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        loop {
            let runnable = state
                .queue
                .iter()
                .position(|task| !task.large || state.large_running < LARGE_WORKERS);
            if let Some(index) = runnable
                && let Some(task) = state.queue.remove(index)
            {
                if task.large {
                    state.large_running += 1;
                }
                return task;
            }
            state = self.wake.wait(state).unwrap_or_else(std::sync::PoisonError::into_inner);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant};

    #[test]
    fn a_full_account_queue_is_backpressure_not_a_new_thread() {
        let gate = Arc::new((Mutex::new(false), Condvar::new()));
        let account = "rf-scheduler-backpressure";
        let mut accepted = 0_usize;
        for _ in 0..(QUEUE_ACCOUNT + 4) {
            let hold = Arc::clone(&gate);
            let result = submit(account, false, move || {
                let (lock, cv) = &*hold;
                let mut open = lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
                let deadline = Instant::now() + Duration::from_secs(20);
                while !*open && Instant::now() < deadline {
                    let (next, _) = cv
                        .wait_timeout(open, Duration::from_millis(50))
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    open = next;
                }
            });
            match result {
                Ok(()) => accepted += 1,
                Err(error) => assert_eq!(error, Refusal::new(CODE_DISK_FULL)),
            }
        }
        assert_eq!(accepted, QUEUE_ACCOUNT, "no more than the per-account queue is admitted");
        let (lock, cv) = &*gate;
        *lock.lock().unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        cv.notify_all();
    }

    #[test]
    fn queued_work_runs_on_the_bounded_pool() -> Result<(), Refusal> {
        let done = Arc::new(AtomicUsize::new(0));
        for _ in 0..3 {
            let done = Arc::clone(&done);
            submit("rf-scheduler-runs", false, move || {
                done.fetch_add(1, Ordering::SeqCst);
            })?;
        }
        let deadline = Instant::now() + Duration::from_secs(20);
        while done.load(Ordering::SeqCst) < 3 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(10));
        }
        assert_eq!(done.load(Ordering::SeqCst), 3, "every queued task ran within the deadline");
        Ok(())
    }
}
