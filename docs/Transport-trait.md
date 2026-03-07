# `Transport` trait

Abstracts the transport connection step so that backends can connect over any
transport, not just TCP (e.g. Unix sockets, VSOCK, named pipes).

## Trait definition

```rust
pub trait Transport: Clone + Send + 'static {
    type Io: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static;
    type Error: Into<crate::Error>;

    fn connect(
        &self,
        uri: &Uri,
    ) -> impl Future<Output = Result<Self::Io, Self::Error>> + Send;
}
```

Produces a connected IO stream from a URI. The TLS layer then wraps that stream.

### Default TCP implementation

`TcpTransport` does DNS resolution, TCP connect, and applies TCP options
(keepalive, nodelay) — the logic previously hardcoded in `connector_inner`.

```rust
impl Transport for TcpTransport {
    type Io = TcpStream;
    type Error = io::Error;
}
```

## `connector_inner`

```rust
pub fn connector_inner<T, C, TS>(
    transport: T,
    ssl_conn: C,
    arg: C::Arg,
) -> TlsBoxedService<TS>
where
    T: Transport,
    C: TlsConnector<T::Io, TlsStream = TS>,
    TS: AsyncRead + AsyncWrite + Send + Sync + Unpin + 'static,
```

## Backend changes

Each backend's internal `TlsConnector` trait impl widens to generic IO,
and the public `TlsConnector` struct becomes `TlsConnector<IO>`.
`TlsConnector::new` takes `impl Transport<Io = IO>` instead of `&Endpoint`.

## Usage

For TCP:

```rust
let transport = TcpTransport::from_endpoint(&endpoint);
let conn = openssl::TlsConnector::new(transport, ssl, "localhost".into());
endpoint.connect_with_connector(conn).await?;
```

For custom transport:

```rust
let transport = MyUnixTransport::new("/tmp/grpc.sock");
let conn = openssl::TlsConnector::new(transport, ssl, "localhost".into());
endpoint.connect_with_connector(conn).await?;
```
