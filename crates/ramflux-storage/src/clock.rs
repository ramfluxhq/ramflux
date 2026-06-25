use std::sync::Arc;
use std::sync::atomic::{AtomicI64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Clone, Debug, Default)]
pub enum AccountClock {
    #[default]
    Real,
    Fixed(i64),
    Sequence(Arc<AtomicI64>),
}

impl AccountClock {
    #[must_use]
    pub const fn real() -> Self {
        Self::Real
    }

    #[must_use]
    pub const fn fixed(unix_seconds: i64) -> Self {
        Self::Fixed(unix_seconds)
    }

    #[must_use]
    pub fn sequence(start_unix_seconds: i64) -> Self {
        Self::Sequence(Arc::new(AtomicI64::new(start_unix_seconds)))
    }

    #[must_use]
    pub fn now_unix(&self) -> i64 {
        match self {
            Self::Real => unix_now(),
            Self::Fixed(value) => *value,
            Self::Sequence(next) => next.fetch_add(1, Ordering::Relaxed),
        }
    }
}

#[must_use]
pub fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |duration| i64::try_from(duration.as_secs()).unwrap_or(i64::MAX))
}
