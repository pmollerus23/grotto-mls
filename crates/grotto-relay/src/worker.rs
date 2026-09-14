//! One database thread with bounded, nonblocking admission.
//!
//! Once admitted, a command runs even if its caller disconnects. Mutations
//! therefore retain their durable retry result after uncertain delivery.
//! Dropping the last worker handle closes the queue; admitted work is drained.

use std::io;

use tokio::sync::{mpsc, oneshot};

use crate::storage::RelayState;

type Command = Box<dyn FnOnce(&RelayState) + Send>;

pub struct DatabaseWorker {
    sender: mpsc::Sender<Command>,
}

impl DatabaseWorker {
    pub fn start(state: RelayState, capacity: usize) -> io::Result<Self> {
        if capacity == 0 {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "empty database queue",
            ));
        }
        let (sender, mut receiver) = mpsc::channel::<Command>(capacity);
        std::thread::Builder::new()
            .name("grotto-database".into())
            .spawn(move || {
                while let Some(command) = receiver.blocking_recv() {
                    command(&state);
                }
            })?;
        Ok(Self { sender })
    }

    /// Reject overload before allocating another waiting task or OS thread.
    /// A closed result channel is an uncertain outcome, never a failed mutation.
    pub async fn execute<T: Send + 'static>(
        &self,
        operation: impl FnOnce(&RelayState) -> T + Send + 'static,
    ) -> io::Result<T> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .try_send(Box::new(move |state| {
                let result = operation(state);
                let _ = sender.send(result);
            }))
            .map_err(|error| match error {
                mpsc::error::TrySendError::Full(_) => {
                    crate::metrics::increment(&crate::metrics::QUEUE_PRESSURE);
                    io::Error::new(io::ErrorKind::WouldBlock, "database queue full")
                }
                mpsc::error::TrySendError::Closed(_) => {
                    io::Error::new(io::ErrorKind::BrokenPipe, "database worker stopped")
                }
            })?;
        receiver
            .await
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "database result unavailable"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, mpsc as blocking};

    #[tokio::test]
    async fn saturation_is_bounded_and_admitted_work_survives_cancellation() {
        let dir = crate::private_test_directory().unwrap();
        let worker = Arc::new(
            DatabaseWorker::start(RelayState::open(&dir.path().join("relay.db")).unwrap(), 1)
                .unwrap(),
        );
        let (started_tx, started_rx) = oneshot::channel();
        let (release_tx, release_rx) = blocking::channel();
        let first_worker = worker.clone();
        let first = tokio::spawn(async move {
            first_worker
                .execute(move |_| {
                    started_tx.send(std::thread::current().id()).unwrap();
                    release_rx.recv().unwrap();
                })
                .await
        });
        let worker_thread = started_rx.await.unwrap();
        let (done_tx, done_rx) = oneshot::channel();
        let mut queued = Box::pin(worker.execute(move |_| {
            done_tx.send(std::thread::current().id()).unwrap();
        }));
        // Poll once to admit the command, then cancel its waiting caller.
        assert!(
            std::future::poll_fn(|cx| {
                std::task::Poll::Ready(queued.as_mut().poll(cx).is_pending())
            })
            .await
        );
        let error = worker
            .execute(|_| panic!("overload must not execute"))
            .await
            .unwrap_err();
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
        drop(queued);
        drop(worker);
        release_tx.send(()).unwrap();
        first.await.unwrap().unwrap();
        assert_eq!(done_rx.await.unwrap(), worker_thread);
    }

    #[tokio::test]
    async fn panic_stops_worker_and_fails_closed() {
        let dir = crate::private_test_directory().unwrap();
        let worker =
            DatabaseWorker::start(RelayState::open(&dir.path().join("relay.db")).unwrap(), 1)
                .unwrap();
        assert_eq!(
            worker
                .execute(|_| panic!("injected failure"))
                .await
                .unwrap_err()
                .kind(),
            io::ErrorKind::BrokenPipe
        );
        assert_eq!(
            worker.execute(|_| ()).await.unwrap_err().kind(),
            io::ErrorKind::BrokenPipe
        );
    }
}
