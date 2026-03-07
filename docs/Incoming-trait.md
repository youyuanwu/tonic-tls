# `Incoming` trait

Abstracts a stream of inbound connections so that backends accept any transport,
not just `TcpIncoming`.

## Trait definition

```rust
pub trait Incoming:
    Stream<Item = Result<Self::Io, Self::Error>> + Send + 'static
{
    type Io: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static;
    type Error: Into<crate::Error>;
}
```

Uses `Stream` as a supertrait. The generic `Error` associated type allows implementing
the trait directly on foreign types without a newtype — orphan rules permit implementing
a local trait on a foreign type, and the existing `Stream` impl is reused as-is:

```rust
impl Incoming for tonic::transport::server::TcpIncoming {
    type Io = tokio::net::TcpStream;
    type Error = io::Error;
}
```

## Backend usage

Each backend's `TlsIncoming` is generic over `IO` and accepts `impl Incoming<Io = IO>`:

```rust
pub struct TlsIncoming<IO> { .. }

impl<IO: AsyncRead + AsyncWrite + Send + Sync + Debug + Unpin + 'static> TlsIncoming<IO> {
    pub fn new(incoming: impl Incoming<Io = IO>, acceptor: ..) -> Self { .. }
}
```

Users can pass `TcpIncoming` directly (as before) or a custom `Incoming` impl for
Unix sockets, VSOCK, etc.
