//! Adapter between iroh's QUIC connection and hyperium's HTTP/3 traits.
//!
//! This follows the adapter structure used by the MIT-licensed `h3-quinn`
//! crate, but targets the `noq` stream types returned by iroh 1.0 rather than
//! upstream Quinn. Using `h3-quinn` directly would create an unrelated nested
//! QUIC endpoint and cannot wrap an authenticated iroh connection.

use std::{
    future::Future,
    pin::Pin,
    sync::Arc,
    task::{self, Poll},
};

use bytes::{Buf, Bytes};
use h3::{
    error::Code,
    quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf},
};
use h3_datagram::{
    ConnectionErrorIncoming as DatagramConnectionError,
    datagram::EncodedDatagram,
    quic_traits::{DatagramConnectionExt, RecvDatagram, SendDatagram, SendDatagramErrorIncoming},
};
use iroh::endpoint::{
    Connection as IrohConnection, ConnectionError, ReadError, RecvStream as IrohRecvStream,
    SendDatagramError, SendStream as IrohSendStream, VarInt, WriteError,
};

type BoxFuture<T> = Pin<Box<dyn Future<Output = T> + Send + 'static>>;
type BidiResult = Result<(IrohSendStream, IrohRecvStream), ConnectionError>;
type UniSendResult = Result<IrohSendStream, ConnectionError>;
type UniRecvResult = Result<IrohRecvStream, ConnectionError>;
type ReadResult = (IrohRecvStream, Result<Option<Bytes>, ReadError>);

/// An HTTP/3 QUIC adapter backed by an authenticated iroh connection.
pub(crate) struct Connection {
    conn: IrohConnection,
    incoming_bi: Option<BoxFuture<BidiResult>>,
    opening_bi: Option<BoxFuture<BidiResult>>,
    incoming_uni: Option<BoxFuture<UniRecvResult>>,
    opening_uni: Option<BoxFuture<UniSendResult>>,
}

impl Connection {
    pub(crate) fn new(conn: IrohConnection) -> Self {
        Self {
            conn,
            incoming_bi: None,
            opening_bi: None,
            incoming_uni: None,
            opening_uni: None,
        }
    }

    fn poll_accept_bi_inner(&mut self, cx: &mut task::Context<'_>) -> Poll<BidiResult> {
        let fut = self.incoming_bi.get_or_insert_with(|| {
            let conn = self.conn.clone();
            Box::pin(async move { conn.accept_bi().await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.incoming_bi = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_accept_uni_inner(&mut self, cx: &mut task::Context<'_>) -> Poll<UniRecvResult> {
        let fut = self.incoming_uni.get_or_insert_with(|| {
            let conn = self.conn.clone();
            Box::pin(async move { conn.accept_uni().await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.incoming_uni = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_bi_inner(&mut self, cx: &mut task::Context<'_>) -> Poll<BidiResult> {
        let fut = self.opening_bi.get_or_insert_with(|| {
            let conn = self.conn.clone();
            Box::pin(async move { conn.open_bi().await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.opening_bi = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_uni_inner(&mut self, cx: &mut task::Context<'_>) -> Poll<UniSendResult> {
        let fut = self.opening_uni.get_or_insert_with(|| {
            let conn = self.conn.clone();
            Box::pin(async move { conn.open_uni().await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.opening_uni = None;
                Poll::Ready(result)
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<B: Buf> quic::Connection<B> for Connection {
    type RecvStream = RecvStream;
    type OpenStreams = OpenStreams;

    fn poll_accept_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, ConnectionErrorIncoming>> {
        match self.poll_accept_bi_inner(cx) {
            Poll::Ready(Ok((send, recv))) => Poll::Ready(Ok(BidiStream::new(send, recv))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(convert_connection_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_accept_recv(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        match self.poll_accept_uni_inner(cx) {
            Poll::Ready(Ok(recv)) => Poll::Ready(Ok(RecvStream::new(recv))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(convert_connection_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn opener(&self) -> Self::OpenStreams {
        OpenStreams::new(self.conn.clone())
    }
}

impl<B: Buf> quic::OpenStreams<B> for Connection {
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        match self.poll_open_bi_inner(cx) {
            Poll::Ready(Ok((send, recv))) => Poll::Ready(Ok(BidiStream::new(send, recv))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(connection_stream_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        match self.poll_open_uni_inner(cx) {
            Poll::Ready(Ok(send)) => Poll::Ready(Ok(SendStream::new(send))),
            Poll::Ready(Err(err)) => Poll::Ready(Err(connection_stream_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        self.conn.close(
            VarInt::from_u64(code.value()).unwrap_or(VarInt::MAX),
            reason,
        );
    }
}

/// A clonable HTTP/3 stream opener for one iroh connection.
pub(crate) struct OpenStreams {
    inner: Connection,
}

impl OpenStreams {
    fn new(conn: IrohConnection) -> Self {
        Self {
            inner: Connection::new(conn),
        }
    }
}

impl Clone for OpenStreams {
    fn clone(&self) -> Self {
        Self::new(self.inner.conn.clone())
    }
}

impl<B: Buf> quic::OpenStreams<B> for OpenStreams {
    type SendStream = SendStream<B>;
    type BidiStream = BidiStream<B>;

    fn poll_open_bidi(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::BidiStream, StreamErrorIncoming>> {
        quic::OpenStreams::poll_open_bidi(&mut self.inner, cx)
    }

    fn poll_open_send(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Self::SendStream, StreamErrorIncoming>> {
        quic::OpenStreams::poll_open_send(&mut self.inner, cx)
    }

    fn close(&mut self, code: Code, reason: &[u8]) {
        <Connection as quic::OpenStreams<B>>::close(&mut self.inner, code, reason);
    }
}

pub(crate) struct BidiStream<B: Buf> {
    send: SendStream<B>,
    recv: RecvStream,
}
impl<B: Buf> BidiStream<B> {
    fn new(send: IrohSendStream, recv: IrohRecvStream) -> Self {
        Self {
            send: SendStream::new(send),
            recv: RecvStream::new(recv),
        }
    }
}

impl<B: Buf> quic::BidiStream<B> for BidiStream<B> {
    type SendStream = SendStream<B>;
    type RecvStream = RecvStream;
    fn split(self) -> (Self::SendStream, Self::RecvStream) {
        (self.send, self.recv)
    }
}

impl<B: Buf> quic::RecvStream for BidiStream<B> {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        self.recv.poll_data(cx)
    }
    fn stop_sending(&mut self, error_code: u64) {
        self.recv.stop_sending(error_code);
    }
    fn recv_id(&self) -> StreamId {
        self.recv.recv_id()
    }
}

impl<B: Buf> quic::SendStream<B> for BidiStream<B> {
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }
    fn poll_finish(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }
    fn reset(&mut self, error_code: u64) {
        self.send.reset(error_code);
    }
    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }
    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}

impl<B: Buf> quic::SendStreamUnframed<B> for BidiStream<B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        self.send.poll_send(cx, buf)
    }
}

pub(crate) struct RecvStream {
    stream: Option<IrohRecvStream>,
    reading: Option<BoxFuture<ReadResult>>,
}

impl RecvStream {
    fn new(stream: IrohRecvStream) -> Self {
        Self {
            stream: Some(stream),
            reading: None,
        }
    }
}

impl quic::RecvStream for RecvStream {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        if self.reading.is_none() {
            let mut stream = self.stream.take().expect("receive stream must be present");
            self.reading = Some(Box::pin(async move {
                let result = stream.read_chunk(usize::MAX).await;
                (stream, result)
            }));
        }
        let Poll::Ready((stream, result)) =
            self.reading.as_mut().expect("set above").as_mut().poll(cx)
        else {
            return Poll::Pending;
        };
        self.reading = None;
        self.stream = Some(stream);
        Poll::Ready(result.map_err(convert_read_error))
    }
    fn stop_sending(&mut self, error_code: u64) {
        if let Some(stream) = self.stream.as_mut() {
            let _ = stream.stop(VarInt::from_u64(error_code).unwrap_or(VarInt::MAX));
        }
    }
    fn recv_id(&self) -> StreamId {
        let id: u64 = self
            .stream
            .as_ref()
            .expect("receive stream present")
            .id()
            .into();
        id.try_into().expect("valid HTTP/3 stream id")
    }
}

pub(crate) struct SendStream<B: Buf> {
    stream: IrohSendStream,
    writing: Option<WriteBuf<B>>,
}
impl<B: Buf> SendStream<B> {
    fn new(stream: IrohSendStream) -> Self {
        Self {
            stream,
            writing: None,
        }
    }
}

impl<B: Buf> quic::SendStream<B> for SendStream<B> {
    fn poll_ready(&mut self, cx: &mut task::Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        if let Some(data) = self.writing.as_mut() {
            while data.has_remaining() {
                match Pin::new(&mut self.stream).poll_write(cx, data.chunk()) {
                    Poll::Ready(Ok(written)) => data.advance(written),
                    Poll::Ready(Err(err)) => return Poll::Ready(Err(convert_write_error(err))),
                    Poll::Pending => return Poll::Pending,
                }
            }
        }
        self.writing = None;
        Poll::Ready(Ok(()))
    }
    fn poll_finish(
        &mut self,
        _cx: &mut task::Context<'_>,
    ) -> Poll<Result<(), StreamErrorIncoming>> {
        Poll::Ready(
            self.stream
                .finish()
                .map_err(|err| StreamErrorIncoming::Unknown(Box::new(err))),
        )
    }
    fn reset(&mut self, error_code: u64) {
        let _ = self
            .stream
            .reset(VarInt::from_u64(error_code).unwrap_or(VarInt::MAX));
    }
    fn send_data<D: Into<WriteBuf<B>>>(&mut self, data: D) -> Result<(), StreamErrorIncoming> {
        if self.writing.is_some() {
            return Err(StreamErrorIncoming::ConnectionErrorIncoming {
                connection_error: ConnectionErrorIncoming::InternalError(
                    "send_data called before poll_ready completed".into(),
                ),
            });
        }
        self.writing = Some(data.into());
        Ok(())
    }
    fn send_id(&self) -> StreamId {
        let id: u64 = self.stream.id().into();
        id.try_into().expect("valid HTTP/3 stream id")
    }
}

impl<B: Buf> quic::SendStreamUnframed<B> for SendStream<B> {
    fn poll_send<D: Buf>(
        &mut self,
        cx: &mut task::Context<'_>,
        buf: &mut D,
    ) -> Poll<Result<usize, StreamErrorIncoming>> {
        match Pin::new(&mut self.stream).poll_write(cx, buf.chunk()) {
            Poll::Ready(Ok(written)) => {
                buf.advance(written);
                Poll::Ready(Ok(written))
            }
            Poll::Ready(Err(err)) => Poll::Ready(Err(convert_write_error(err))),
            Poll::Pending => Poll::Pending,
        }
    }
}

pub(crate) struct SendDatagramHandler {
    conn: IrohConnection,
}
impl<B: Buf> SendDatagram<B> for SendDatagramHandler {
    fn send_datagram<T: Into<EncodedDatagram<B>>>(
        &mut self,
        data: T,
    ) -> Result<(), SendDatagramErrorIncoming> {
        let mut data = data.into();
        self.conn
            .send_datagram(data.copy_to_bytes(data.remaining()))
            .map_err(convert_send_datagram_error)
    }
}

pub(crate) struct RecvDatagramHandler {
    conn: IrohConnection,
    reading: Option<BoxFuture<Result<Bytes, ConnectionError>>>,
}
impl RecvDatagram for RecvDatagramHandler {
    type Buffer = Bytes;
    fn poll_incoming_datagram(
        &mut self,
        cx: &mut task::Context<'_>,
    ) -> Poll<Result<Bytes, DatagramConnectionError>> {
        let fut = self.reading.get_or_insert_with(|| {
            let conn = self.conn.clone();
            Box::pin(async move { conn.read_datagram().await })
        });
        match fut.as_mut().poll(cx) {
            Poll::Ready(result) => {
                self.reading = None;
                Poll::Ready(result.map_err(convert_datagram_connection_error))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

impl<B: Buf> DatagramConnectionExt<B> for Connection {
    type SendDatagramHandler = SendDatagramHandler;
    type RecvDatagramHandler = RecvDatagramHandler;
    fn send_datagram_handler(&self) -> Self::SendDatagramHandler {
        SendDatagramHandler {
            conn: self.conn.clone(),
        }
    }
    fn recv_datagram_handler(&self) -> Self::RecvDatagramHandler {
        RecvDatagramHandler {
            conn: self.conn.clone(),
            reading: None,
        }
    }
}

fn connection_stream_error(error: ConnectionError) -> StreamErrorIncoming {
    StreamErrorIncoming::ConnectionErrorIncoming {
        connection_error: convert_connection_error(error),
    }
}

fn convert_connection_error(error: ConnectionError) -> ConnectionErrorIncoming {
    match error {
        ConnectionError::ApplicationClosed(close) => ConnectionErrorIncoming::ApplicationClose {
            error_code: close.error_code.into_inner(),
        },
        ConnectionError::TimedOut => ConnectionErrorIncoming::Timeout,
        other => ConnectionErrorIncoming::Undefined(Arc::new(other)),
    }
}

fn convert_datagram_connection_error(error: ConnectionError) -> DatagramConnectionError {
    match convert_connection_error(error) {
        ConnectionErrorIncoming::ApplicationClose { error_code } => {
            DatagramConnectionError::ApplicationClose { error_code }
        }
        ConnectionErrorIncoming::Timeout => DatagramConnectionError::Timeout,
        ConnectionErrorIncoming::InternalError(error) => {
            DatagramConnectionError::InternalError(error)
        }
        ConnectionErrorIncoming::Undefined(error) => DatagramConnectionError::Undefined(error),
    }
}

fn convert_read_error(error: ReadError) -> StreamErrorIncoming {
    match error {
        ReadError::Reset(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        ReadError::ConnectionLost(error) => connection_stream_error(error),
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}

fn convert_write_error(error: WriteError) -> StreamErrorIncoming {
    match error {
        WriteError::Stopped(code) => StreamErrorIncoming::StreamTerminated {
            error_code: code.into_inner(),
        },
        WriteError::ConnectionLost(error) => connection_stream_error(error),
        other => StreamErrorIncoming::Unknown(Box::new(other)),
    }
}

fn convert_send_datagram_error(error: SendDatagramError) -> SendDatagramErrorIncoming {
    match error {
        SendDatagramError::UnsupportedByPeer | SendDatagramError::Disabled => {
            SendDatagramErrorIncoming::NotAvailable
        }
        SendDatagramError::TooLarge => SendDatagramErrorIncoming::TooLarge,
        SendDatagramError::ConnectionLost(error) => {
            SendDatagramErrorIncoming::ConnectionError(convert_datagram_connection_error(error))
        }
    }
}
