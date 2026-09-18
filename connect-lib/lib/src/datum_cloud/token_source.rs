//! Bearer-token abstraction shared by every client that talks to Datum.
//!
//! Production uses [`ExternalTokenSource`](super::external_token_source::ExternalTokenSource),
//! which execs the credentials helper and refreshes in the background.
//! Embedders that already hold a token, and tests, use [`StaticTokenSource`].

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use arc_swap::ArcSwap;
use secrecy::{ExposeSecret, SecretString};
use tokio::sync::watch;

/// Source of the bearer token used against the Datum API and project
/// control planes.
///
/// Implementations must be cheap to call from hot paths: [`token`](Self::token)
/// is read on every control-plane client refresh.
pub trait TokenSource: Send + Sync + 'static {
    /// The current token.
    fn token(&self) -> SecretString;

    /// Subscribe to token rotations. The receiver's initial value is the
    /// token at subscription time; it changes whenever the source rotates.
    fn watch(&self) -> watch::Receiver<SecretString>;

    /// Ask the source to obtain a fresh token now, ahead of any schedule.
    /// Called after a 401 is observed. Sources that cannot refresh treat
    /// this as a no-op.
    fn force_refresh(&self);
}

/// A [`TokenSource`] holding a token that only changes when the owner calls
/// [`set`](Self::set). It never refreshes on its own; [`force_refresh`]
/// (TokenSource::force_refresh) only increments a counter so callers can
/// assert that a refresh was requested.
#[derive(Clone)]
pub struct StaticTokenSource {
    token: Arc<ArcSwap<SecretString>>,
    token_tx: Arc<watch::Sender<SecretString>>,
    refresh_requests: Arc<AtomicU64>,
}

impl std::fmt::Debug for StaticTokenSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("StaticTokenSource")
            .field(
                "refresh_requests",
                &self.refresh_requests.load(Ordering::Relaxed),
            )
            .finish_non_exhaustive()
    }
}

impl StaticTokenSource {
    pub fn new(token: impl Into<String>) -> Self {
        let token = SecretString::from(token.into());
        let (token_tx, _) = watch::channel(token.clone());
        Self {
            token: Arc::new(ArcSwap::from_pointee(token)),
            token_tx: Arc::new(token_tx),
            refresh_requests: Arc::new(AtomicU64::new(0)),
        }
    }

    /// Replace the token and notify watchers.
    pub fn set(&self, token: impl Into<String>) {
        let token = SecretString::from(token.into());
        self.token.store(Arc::new(token.clone()));
        let _ = self.token_tx.send(token);
    }

    /// Number of times [`force_refresh`](TokenSource::force_refresh) was called.
    pub fn refresh_requests(&self) -> u64 {
        self.refresh_requests.load(Ordering::Relaxed)
    }
}

impl TokenSource for StaticTokenSource {
    fn token(&self) -> SecretString {
        SecretString::from(self.token.load_full().expose_secret().to_owned())
    }

    fn watch(&self) -> watch::Receiver<SecretString> {
        self.token_tx.subscribe()
    }

    fn force_refresh(&self) {
        self.refresh_requests.fetch_add(1, Ordering::Relaxed);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn static_source_returns_and_rotates_token() {
        let source = StaticTokenSource::new("first");
        let rx = source.watch();
        assert_eq!(source.token().expose_secret(), "first");
        assert_eq!(rx.borrow().expose_secret(), "first");

        source.set("second");
        assert_eq!(source.token().expose_secret(), "second");
        assert_eq!(rx.borrow().expose_secret(), "second");
    }

    #[test]
    fn static_source_counts_refresh_requests() {
        let source = StaticTokenSource::new("t");
        assert_eq!(source.refresh_requests(), 0);
        source.force_refresh();
        source.force_refresh();
        assert_eq!(source.refresh_requests(), 2);
        assert_eq!(
            source.token().expose_secret(),
            "t",
            "no rotation on refresh"
        );
    }

    #[test]
    fn static_source_clone_shares_state() {
        let source = StaticTokenSource::new("a");
        let cloned = source.clone();
        source.set("b");
        assert_eq!(cloned.token().expose_secret(), "b");
    }

    #[test]
    fn debug_does_not_print_the_token() {
        let source = StaticTokenSource::new("super-secret");
        assert!(!format!("{source:?}").contains("super-secret"));
    }
}
