//! Signal handlers only set a lock-free flag; async code performs orderly teardown.
use std::sync::atomic::{AtomicBool, Ordering};
static STOP: AtomicBool = AtomicBool::new(false);
extern "C" fn request_stop(_signal: libc::c_int) {
    STOP.store(true, Ordering::Relaxed);
}
pub struct Signals {
    old_int: libc::sigaction,
    old_term: libc::sigaction,
}
impl Signals {
    pub fn install() -> std::io::Result<Self> {
        STOP.store(false, Ordering::Relaxed);
        // SAFETY: sigaction is a C POD; masks and handlers are initialized before use.
        let mut action: libc::sigaction = unsafe { std::mem::zeroed() };
        action.sa_sigaction = request_stop as *const () as usize;
        // SAFETY: all pointers refer to live sigaction records of the correct type.
        unsafe {
            libc::sigemptyset(&mut action.sa_mask);
            let mut old_int = std::mem::zeroed();
            let mut old_term = std::mem::zeroed();
            if libc::sigaction(libc::SIGINT, &action, &mut old_int) != 0 {
                return Err(std::io::Error::last_os_error());
            }
            if libc::sigaction(libc::SIGTERM, &action, &mut old_term) != 0 {
                libc::sigaction(libc::SIGINT, &old_int, std::ptr::null_mut());
                return Err(std::io::Error::last_os_error());
            }
            Ok(Self { old_int, old_term })
        }
    }
    pub fn requested(&self) -> bool {
        STOP.load(Ordering::Relaxed)
    }
}
impl Drop for Signals {
    fn drop(&mut self) {
        // SAFETY: restore the live signal-handler records returned by sigaction.
        unsafe {
            libc::sigaction(libc::SIGINT, &self.old_int, std::ptr::null_mut());
            libc::sigaction(libc::SIGTERM, &self.old_term, std::ptr::null_mut());
        }
    }
}
