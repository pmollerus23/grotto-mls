use std::sync::atomic::{AtomicU64, Ordering};
pub static BLOCKED_ROOMS: AtomicU64 = AtomicU64::new(0);
pub static COMMIT_CONFLICTS: AtomicU64 = AtomicU64::new(0);
pub static RECOVERY_FAILURES: AtomicU64 = AtomicU64::new(0);
pub fn increment(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}
pub fn report() {
    eprintln!(
        "grotto_client_metrics blocked_rooms={} commit_conflicts={} recovery_failures={}",
        BLOCKED_ROOMS.load(Ordering::Relaxed),
        COMMIT_CONFLICTS.load(Ordering::Relaxed),
        RECOVERY_FAILURES.load(Ordering::Relaxed)
    );
}
