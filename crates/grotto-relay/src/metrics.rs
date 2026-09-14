use std::sync::atomic::{AtomicU64, Ordering};
pub static QUEUE_PRESSURE: AtomicU64 = AtomicU64::new(0);
pub static TIMEOUTS: AtomicU64 = AtomicU64::new(0);
pub static QUOTA_REJECTIONS: AtomicU64 = AtomicU64::new(0);
pub static COMMIT_CONFLICTS: AtomicU64 = AtomicU64::new(0);
pub static RECOVERY_FAILURES: AtomicU64 = AtomicU64::new(0);
pub fn increment(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}
pub fn report() {
    eprintln!(
        "grotto_metrics queue_pressure={} timeouts={} quota_rejections={} commit_conflicts={} recovery_failures={}",
        QUEUE_PRESSURE.load(Ordering::Relaxed),
        TIMEOUTS.load(Ordering::Relaxed),
        QUOTA_REJECTIONS.load(Ordering::Relaxed),
        COMMIT_CONFLICTS.load(Ordering::Relaxed),
        RECOVERY_FAILURES.load(Ordering::Relaxed)
    );
}
