use futures::Stream;

use crate::Error;

/// Pass through type to provide a struct wrapper for the impl Stream.
/// TS is the TlsStream type.
pub(crate) struct TlsIncoming<TS> {
    inner: futures::stream::BoxStream<'static, Result<TS, Error>>,
}

impl<TS> TlsIncoming<TS> {
    /// S is the inner stream to wrap into TlsStream.
    pub fn new<S>(inner: S) -> Self
    where
        S: Stream<Item = Result<TS, Error>> + 'static + Send,
    {
        use futures::StreamExt;
        Self {
            inner: inner.boxed(),
        }
    }
}

impl<TS> Stream for TlsIncoming<TS> {
    type Item = Result<TS, Error>;

    /// Pass through to call the inner poll_next.
    fn poll_next(
        mut self: std::pin::Pin<&mut Self>,
        cx: &mut std::task::Context<'_>,
    ) -> std::task::Poll<Option<Self::Item>> {
        use futures::StreamExt;
        self.inner.poll_next_unpin(cx)
    }
}
