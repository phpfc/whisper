//! Ctrl-C handling shared by every command.
//!
//! The handler is installed once, before anything is opened on the router.
//! Until `tokio::signal::ctrl_c()` is first polled the default SIGINT action
//! (kill the process) applies, and a kill skips `PortMap::close`, which would
//! leave the mapping on the router until its lease expires. From the moment
//! the handler exists the press is only recorded here, and each step that can
//! take long races its work against [`Cancel::run`] so it can release what it
//! opened before the process exits.

use std::fmt;
use std::future::{poll_fn, Future};
use std::task::Poll;
use tokio::sync::{oneshot, watch};

/// The user pressed Ctrl-C. Travels as an `anyhow` error to `main`, which
/// prints `Cancelled.` and exits with 130 once everything is released.
#[derive(Debug)]
pub struct Cancelled;

impl fmt::Display for Cancelled {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Cancelled.")
    }
}

impl std::error::Error for Cancelled {}

/// A Ctrl-C press, remembered: it is seen even by a step that starts after it
/// happened. Cheap to clone.
#[derive(Clone)]
pub struct Cancel(watch::Receiver<bool>);

impl Cancel {
    /// A handle and the sender that triggers it.
    pub fn channel() -> (watch::Sender<bool>, Cancel) {
        let (tx, rx) = watch::channel(false);
        (tx, Cancel(rx))
    }

    /// Installs the Ctrl-C handler and returns once it is in place. If the
    /// system refuses a handler, Ctrl-C keeps its default action and the
    /// returned handle never fires.
    pub async fn install() -> Cancel {
        let (tx, cancel) = Cancel::channel();
        let (installed_tx, installed_rx) = oneshot::channel();
        tokio::spawn(async move {
            let mut ctrl_c = Box::pin(tokio::signal::ctrl_c());
            // The first poll is what installs the handler.
            let first = poll_fn(|cx| Poll::Ready(ctrl_c.as_mut().poll(cx))).await;
            let _ = installed_tx.send(());
            let pressed = match first {
                Poll::Ready(result) => result,
                Poll::Pending => ctrl_c.await,
            };
            if pressed.is_ok() {
                let _ = tx.send(true);
            }
        });
        let _ = installed_rx.await;
        cancel
    }

    /// Whether Ctrl-C was pressed already.
    pub fn is_cancelled(&self) -> bool {
        *self.0.borrow()
    }

    /// Resolves when Ctrl-C is pressed (at once if it already was).
    pub async fn cancelled(&self) {
        let mut rx = self.0.clone();
        if rx.wait_for(|pressed| *pressed).await.is_err() {
            // No handler behind this handle: it never fires.
            std::future::pending::<()>().await;
        }
    }

    /// Runs `work`, giving up (and dropping it) if Ctrl-C comes first. A
    /// press that already happened wins.
    pub async fn run<T>(&self, work: impl Future<Output = T>) -> Result<T, Cancelled> {
        tokio::select! {
            biased;
            _ = self.cancelled() => Err(Cancelled),
            result = work => Ok(result),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[tokio::test]
    async fn a_press_before_the_wait_is_still_seen() {
        let (tx, cancel) = Cancel::channel();
        assert!(!cancel.is_cancelled());
        tx.send(true).unwrap();
        assert!(cancel.is_cancelled());
        cancel.cancelled().await;
        // Every clone sees it.
        cancel.clone().cancelled().await;
    }

    #[tokio::test]
    async fn run_gives_up_on_a_press_and_not_before() {
        let (tx, cancel) = Cancel::channel();
        assert_eq!(cancel.run(async { 7 }).await.unwrap(), 7);

        let pressed = async {
            tokio::time::sleep(Duration::from_millis(20)).await;
            tx.send(true).unwrap();
        };
        let (result, ()) = tokio::join!(cancel.run(std::future::pending::<()>()), pressed);
        assert!(result.is_err());

        // Already pressed: the work does not even get to finish.
        assert!(cancel.run(async { 7 }).await.is_err());
    }

    #[tokio::test]
    async fn a_handle_without_a_handler_never_fires() {
        let (tx, cancel) = Cancel::channel();
        drop(tx);
        assert!(!cancel.is_cancelled());
        let waited = tokio::time::timeout(Duration::from_millis(50), cancel.cancelled()).await;
        assert!(waited.is_err());
        assert_eq!(cancel.run(async { 1 }).await.unwrap(), 1);
    }
}
