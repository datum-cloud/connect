//! Byte counts for a dial, readable while it runs.
use std::{
    io,
    pin::Pin,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};

/// Counters a dial adds to as it forwards. Clones share the same counters, so
/// a caller keeps one and reads [`Self::snapshot`] while the dial runs, for
/// example once a second to work out bandwidth.
#[derive(Clone, Debug, Default)]
pub struct Traffic(Arc<Counters>);

#[derive(Debug, Default)]
struct Counters {
    sent: AtomicU64,
    received: AtomicU64,
    opened: AtomicU64,
    closed: AtomicU64,
}

/// Totals since the dial started.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TrafficSnapshot {
    /// Bytes read from local connections and sent to the sharer.
    pub bytes_sent: u64,
    /// Bytes received from the sharer and written to local connections.
    pub bytes_received: u64,
    /// Local connections forwarded so far, including open ones.
    pub connections: u64,
    /// Local connections being forwarded now.
    pub open_connections: u64,
}

impl Traffic {
    pub fn snapshot(&self) -> TrafficSnapshot {
        // Read closed before opened so a connection closing between the two
        // loads cannot make the open count negative.
        let closed = self.0.closed.load(Ordering::Relaxed);
        let opened = self.0.opened.load(Ordering::Relaxed);
        TrafficSnapshot {
            bytes_sent: self.0.sent.load(Ordering::Relaxed),
            bytes_received: self.0.received.load(Ordering::Relaxed),
            connections: opened,
            open_connections: opened.saturating_sub(closed),
        }
    }

    /// Wraps a local connection so its bytes are counted as they move, not
    /// only when it closes. The connection counts as open until the wrapper
    /// drops.
    pub(crate) fn count<S>(&self, stream: S) -> Counted<S> {
        self.0.opened.fetch_add(1, Ordering::Relaxed);
        Counted {
            stream,
            traffic: self.clone(),
        }
    }
}

/// A local connection whose reads count as sent and writes as received.
pub(crate) struct Counted<S> {
    stream: S,
    traffic: Traffic,
}

impl<S> Drop for Counted<S> {
    fn drop(&mut self) {
        self.traffic.0.closed.fetch_add(1, Ordering::Relaxed);
    }
}

impl<S: AsyncRead + Unpin> AsyncRead for Counted<S> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buf.filled().len();
        let result = Pin::new(&mut self.stream).poll_read(cx, buf);
        let read = (buf.filled().len() - before) as u64;
        if read > 0 {
            self.traffic.0.sent.fetch_add(read, Ordering::Relaxed);
        }
        result
    }
}

impl<S: AsyncWrite + Unpin> AsyncWrite for Counted<S> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, buf);
        if let Poll::Ready(Ok(written)) = result {
            self.traffic
                .0
                .received
                .fetch_add(written as u64, Ordering::Relaxed);
        }
        result
    }

    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }

    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

#[cfg(test)]
mod tests {
    use tokio::io::{AsyncReadExt, AsyncWriteExt, duplex};

    use super::*;

    #[tokio::test]
    async fn counts_both_directions_and_open_connections() {
        let traffic = Traffic::default();
        let (local, mut app) = duplex(64);
        let mut counted = traffic.count(local);
        assert_eq!(traffic.snapshot().open_connections, 1);

        app.write_all(b"hello").await.unwrap();
        let mut buf = [0u8; 5];
        counted.read_exact(&mut buf).await.unwrap();
        counted.write_all(b"hi").await.unwrap();

        let snapshot = traffic.clone().snapshot();
        assert_eq!(snapshot.bytes_sent, 5);
        assert_eq!(snapshot.bytes_received, 2);
        drop(counted);
        assert_eq!(
            traffic.snapshot(),
            TrafficSnapshot {
                bytes_sent: 5,
                bytes_received: 2,
                connections: 1,
                open_connections: 0,
            }
        );
    }
}
