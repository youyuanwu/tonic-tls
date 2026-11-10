# tonic-tls-xds

Reload client certificates, trusted CAs, and certificate revocation lists (CRLs)
without restarting your application or rebuilding a tonic channel.
With rustls, also rotate server identities, trusted client CAs, and client CRLs
without restarting the listener.

This crate provides xDS-style certificate providers for
[tonic-tls](../README.md), not the xDS discovery protocol. The built-in TLS
client adapters support **rustls** and **OpenSSL**. The built-in server adapter
supports **rustls only**.

## Installation

No TLS backend is enabled by default. Enable `rustls`:

```toml
tonic = "0.14"
tokio-rustls = "0.26"
tonic-tls = { version = "0.8", default-features = false }
tonic-tls-xds = { version = "0.1", features = ["rustls"] }
```

For OpenSSL, enable `openssl` instead.
OpenSSL 1.1.1 or newer and its development libraries are required.

## Watching certificate files

Use a file watcher with your tonic endpoint and base rustls configuration:

```rust
use std::{sync::Arc, time::Duration};
use tokio_rustls::rustls::ClientConfig;
use tonic::transport::{Channel, Endpoint};
use tonic_tls_xds::{FileWatcherConfig, FileWatcherProvider, ReloadableTlsConnector};

async fn connect(
    endpoint: Endpoint,
    mut config: ClientConfig,
    server_name: &str,
) -> Result<Channel, tonic_tls::Error> {
    config.alpn_protocols = vec![tonic_tls::ALPN_H2.to_vec()];

    let watcher_config = FileWatcherConfig::default()
        .with_ca_certificate_file("ca.pem")
        .with_identity_files("client.pem", "client.key")
        .with_refresh_interval(Duration::from_secs(60));
    let provider = Arc::new(FileWatcherProvider::new(watcher_config).await?);

    let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(
        Arc::new(config),
        server_name.to_owned().try_into()?,
    );
    let transport = tonic_tls::TcpTransport::from_endpoint(&endpoint);
    let connector = ReloadableTlsConnector::new(transport, provider, factory)?;
    Ok(endpoint.connect_with_connector(connector).await?)
}
```

- Run inside a Tokio runtime with time enabled. The default polling interval is
  **600 seconds**; custom intervals must be nonzero.
- Configure roots, identity, or both. Omit `with_identity_files` if you do not need
  to rotate a client identity. Identity files must contain a PEM certificate
  chain (leaf first) and its matching unencrypted private key. Password-protected
  keys are rejected; there is no password callback or interactive prompting.
- Omitted material keeps the **original base configuration**, not a previous
  update. Supplied roots replace the base verifier with standard rustls chain
  and hostname verification; they do not preserve custom verifier checks.
- Dropping the last owner of the provider stops polling.

### OpenSSL

Use the same file watcher with an OpenSSL factory:

```rust
use tonic_tls_xds::{
    openssl::{ClientConfig, TlsConnectorFactory},
    ReloadableTlsConnector,
};

let config = ClientConfig::default();
let factory = TlsConnectorFactory::new(config, "localhost".to_owned());
let transport = tonic_tls::TcpTransport::from_endpoint(&endpoint);
let connector = ReloadableTlsConnector::new(transport, provider, factory)?;
let channel = endpoint.connect_with_connector(connector).await?;
```

`ClientConfig` exposes only these settings:

| Method | Purpose | Default |
|---|---|---|
| `with_ca_certificates(pem)` | Base PEM trust bundle. | OpenSSL system trust paths. |
| `with_identity(identity)` | Base client certificate chain and key. | No client identity. |
| `with_alpn_protocols(protocols)` | ALPN names in preference order. | `h2`. |

Supplied snapshot roots replace the base trust bundle; supplied identity replaces
the entire base chain and key. Omitted material uses the original config, not the
previous snapshot. Empty or invalid effective PEM fails construction.

The crate creates a **fresh context for each changed snapshot**, including
CRL-only updates. Unchanged snapshots reuse the cached context. Each connection
creates a new `SSL`; established connections keep their previous context.

TLS 1.2 or newer, peer/hostname verification, and full handshakes are enforced.
Session caching and tickets are disabled, and no saved session is installed.
Arbitrary OpenSSL builders, contexts, callbacks, PSK authentication, and verification
flags are not exposed. Their hooks cannot bypass snapshot checks or restore an
old identity.

### Rotation and failures

Updates apply to **new TLS connections**, including automatic reconnects of the
same tonic channel. Existing connections and RPC streams remain open. If you
need a bounded cutover time, your application must retire old connections.
New connections perform full TLS handshakes: rustls disables resumption, and
OpenSSL never installs a saved session.

| Situation | Behavior |
|---|---|
| Invalid configuration or initial file-read failure | Provider construction returns an error. |
| Invalid initial certificate, key, or CRL contents | Connector construction returns an error. |
| File-read failure during refresh | Logs `WARN` and retains the last successfully read snapshot. |
| Readable but invalid updated contents | New connections fail; no fallback to older credentials. Valid updates allow recovery. |
| Unchanged contents | Reuses cached material without reparsing; each connection still performs TLS verification. |

Reads across multiple files are not atomic. Publish related files atomically
where possible, or use a custom provider that validates a complete update before
publishing it.

## Server rotation (rustls)

Reuse `FileWatcherProvider`, `CertificateProvider`, and `CertificateData` with
`ReloadableTlsAcceptor`. One snapshot supplies the server's identity and the
roots/CRLs used to authenticate **clients**. The server does not check its own
identity against those client roots.

Given a bound `tcp_incoming`, a tonic `greeter` service, and an explicit rustls
`Arc<CryptoProvider>` named `crypto`:

```rust
use std::sync::Arc;
use tonic_tls_xds::{
    ClientAuth, CrlSource, FileWatcherConfig, FileWatcherProvider,
    ReloadableTlsAcceptor, ServerConfig,
};

let files = FileWatcherConfig::default()
    .with_identity_files("server.pem", "server.key")
    .with_ca_certificate_file("client-ca.pem")
    .with_crl_source(CrlSource::Directory("client-crls".into()));
let provider = Arc::new(FileWatcherProvider::new(files).await?);
let config = ServerConfig::default().with_client_auth(ClientAuth::Required);
let factory = tonic_tls_xds::rustls::TlsAcceptorFactory::new(config, crypto);
let acceptor = ReloadableTlsAcceptor::new(provider, factory)?;
let incoming = acceptor.incoming(tcp_incoming);

tonic::transport::Server::builder()
    .add_service(greeter)
    .serve_with_incoming(incoming)
    .await?;
```

The `rustls` feature enables TLS 1.2 and TLS 1.3, but does not choose a crypto
provider or install a process-wide default for you. The factory uses the explicit
provider to build fresh native server configurations. Arbitrary native server
configs, authentication callbacks, and protocol/cipher overrides are not accepted
by the built-in factory.

### Server settings and client authentication

`ServerConfig` has private fields and these setters:

| Method | Purpose | Default |
|---|---|---|
| `with_identity(identity)` | Base server chain and unencrypted key. | None; a snapshot identity is then required. |
| `with_ca_certificates(pem)` | Base CAs trusted to authenticate clients. | None; no implicit system roots. |
| `with_client_auth(policy)` | Whether to request/require client certificates. | `ClientAuth::Disabled`. |
| `with_alpn_protocols(protocols)` | ALPN names in server preference order. | `h2`. |

| Policy | No client certificate | Presented certificate |
|---|---|---|
| `Disabled` | Accepted; no certificate is requested. | Not used for authentication. Configured client roots/CRLs are errors. |
| `Optional` | Accepted anonymously. | Must pass client-chain validation. |
| `Required` | Rejected. | Must pass client-chain validation. |

For server-authenticated TLS without mTLS, omit client roots/CRLs and leave
`ClientAuth::Disabled`. `Optional` and `Required` require explicit nonempty
effective client roots. Both validate signatures, chain validity, and applicable
client-authentication usage; neither does hostname verification on clients.
Explicitly trusted intermediate CAs may terminate a chain. CA-name hints come
from the selected client trust bundle.

Validation authenticates the peer; it does not authorize RPCs. Read certificates
from `tonic_tls::rustls::SslConnectInfo<TcpConnectInfo>` in request extensions
and apply application identity/permission checks. Certificate SAN extraction
requires parsing the exposed DER; no normalized principal API is provided.
Tonic obtains connection info per connection and clones it into requests.
Applications should evaluate current permissions per RPC.

ALPN names must contain 1-255 bytes and the length-prefixed list must fit in
65535 bytes. An empty list disables ALPN. With a nonempty configured list, an
offered list without overlap fails negotiation; omission of ALPN is allowed.

### Server snapshots and failures

Snapshot identity replaces the **entire** server chain and key. Snapshot roots
replace base client roots without merging. Omitted material uses the original
base settings, never those of the previous snapshot. For example, an
identity-only snapshot cannot retain roots/CRLs from a previous snapshot.

CRLs are optional and require roots in the same snapshot. When supplied, the
[CRL policy below](#crl-checking) applies to client leaves and intermediates,
excluding the trust anchor: revoked certificates, unknown status, bad signatures,
and expired CRLs fail the handshake. Omitted CRLs mean no revocation checking.
Client trust, identity, and selected CRLs always come from one snapshot/base
overlay; they are not sampled independently.

`ReloadableTlsAcceptor::new` validates initial material without accepting IO.
Each accept samples the provider when its future starts executing. Unchanged
snapshot `Arc`s reuse the parsed acceptor; any changed snapshot, including a
CRL-only update, builds a fresh complete configuration. Clones share that cache.
Selection is serialized, but no cache lock is held during the TLS handshake.

Provider/build failures reject new accepts without falling back to an old
configuration or anonymous TLS. The incoming loop logs individual failures and
continues accepting; later valid snapshots allow recovery. File-read failures
retain the watcher's last successfully read snapshot, as on the client side;
readable invalid contents are published and cause accepts to fail.

All new connections perform full handshakes: stateful sessions, stateless
tickets, and early data are disabled. CRL expiration is checked during each
handshake even when the configuration is reused. Already-selected handshakes
and established streams retain their configuration. Existing connections/RPCs
are not revalidated or disconnected; bounded cutover requires application-managed
connection retirement. Handshake concurrency, timeouts, and shutdown behavior
remain those of the existing core incoming loop.

### Raw server streams

Use the same cache for raw Tokio IO by importing the core trait:

```rust
use tonic_tls::TlsAcceptor;

let factory = tonic_tls_xds::rustls::TlsAcceptorFactory::new(config, crypto);
let acceptor = tonic_tls_xds::ReloadableTlsAcceptor::new(provider, factory)?;
let tls_stream = acceptor.accept(tcp_stream).await?;
```

For a single manually selected snapshot, use
`tonic_tls_xds::rustls::TlsAcceptor::new(&config, &snapshot, crypto)`.
The resulting streams use the existing core rustls wrapper and its `Connected`
implementation. Custom transports can use `incoming` by implementing
`tonic_tls::Incoming`. A custom `TlsAcceptorFactory` is responsible for preserving
the identity, verification, CRL, and full-handshake guarantees.

## CRL checking

Add a CRL file or directory to the watcher configuration:

```rust
use tonic_tls_xds::{CrlSource, FileWatcherConfig};

let watcher_config = FileWatcherConfig::default()
    .with_ca_certificate_file("ca.pem")
    // For a single PEM bundle, use CrlSource::File("crls.pem".into()).
    .with_crl_source(CrlSource::Directory("crls".into()));
```

CRLs require a CA certificate file. Each CRL file may contain multiple PEM
`X509 CRL` blocks; no generated bundle or hashed filenames are required.
Directories are scanned nonrecursively in filename order, with CRLs within each
file processed in PEM order. All regular files are read regardless of extension.
File symlinks are followed; subdirectories are ignored. Broken symlinks and other
file types fail the refresh. Keep unrelated files outside the CRL directory.

When enabled, CRL checking:

- Checks peer leaves and intermediates, excluding the trust anchor: server
  certificates on client connectors, client certificates on server acceptors.
- Rejects revoked certificates, unknown revocation status, and expired CRLs
  (`nextUpdate`). Supply an applicable CRL for each issuer in the checked chain.
- Rejects empty directories, empty files, and malformed CRLs rather than
  disabling checking. A valid signed CRL with no revoked certificates is accepted.
- Applies additions, changes, and removals on subsequent connections. Expiry is
  checked at handshake time even if the CRL files have not changed.

Both client backends and the rustls server backend implement these rules.
OpenSSL also rejects CRLs whose `thisUpdate`
is in the future and requires `nextUpdate`. It uses the current verification time
and does not enable delta/indirect CRLs or flags that bypass time or
critical-extension checks. Errors use the selected backend's native error types.

### Trust anchors

The trust anchor is the CA explicitly trusted by your configuration where the
verified chain ends, usually a root CA. Explicitly configured intermediate CAs
can also be anchors. We exclude **that certificate** from
revocation checks, not CRLs issued by it: a root's CRL still checks intermediate
certificates issued by that root. Remove a compromised anchor from the trusted
CA bundle to withdraw trust in it.

This matches rustls and the
[gRPC C++ CRL-provider path](https://github.com/grpc/grpc/blob/952c8d46d90530ddc497d22bdf4b4ccfce4e903c/src/core/tsi/ssl_transport_security.cc#L1802).
Our policy is stricter about missing CRLs: we reject unknown revocation status,
whereas that C++ provider path allows it. The older C++ `crl_directory` option
uses a different verification path.

OpenSSL's native full-chain CRL check includes the anchor. Our callback exempts
only anchor CRL errors; other certificate validation failures still reject the
connection.

### Multiple CRLs from the same issuer

| Source | Selection |
|---|---|
| Single file or custom snapshot | First CRL per issuer wins; duplicates log at `ERROR`. |
| Directory | Last CRL per issuer wins, in filename/PEM order. |

Selection uses the DER-encoded issuer, not signing-key identifiers or
distribution-point scope. All supplied CRLs must parse, including duplicates.
There is no fallback if the selected CRL fails verification.

**Keep one current CRL per issuer and replace it atomically.** Selection does not
choose the newest CRL or merge revoked serials; keeping old and new CRLs together
can leave an older CRL in effect.

CRL checking here validates servers on client connections. It does not add
server-side client-certificate checking, automatic CRL downloads, or OCSP support.

## Custom certificate sources

Implement `CertificateProvider` to load credentials from a secret manager or
another source. Return an `Arc<CertificateData>` from `snapshot()`, reusing that
same `Arc` until the material changes. Refresh outside the connection path and
report refresh failures through your application's logging or monitoring.

Create snapshots with `CertificateData::new(roots, identity, crls)?`, using raw PEM
bytes and `Identity::from_pem(chain, key)` for the identity. At least roots or
identity must be supplied; CRLs require roots. These constructors check the
combination of fields, not their contents. TLS validation happens before use.

Snapshots are complete updates, not incremental changes. Supplying roots with
`crls: None` replaces any previous snapshot's CRL-enabled verifier with one without
CRL checking. An empty CRL collection (`Some(Vec::new())`) is invalid, not a way
to disable checking. Omitted roots retain the original base verifier.

Non-exportable private keys require backend-specific configuration and cannot
be represented by this PEM API.

## Custom TLS configuration

Set ordinary TLS options on the base rustls configuration. For adjustments that
must happen after applying a snapshot, implement `TlsConnectorFactory` using
[`rustls::build_client_config`](https://docs.rs/tonic-tls-xds/latest/tonic_tls_xds/rustls/fn.build_client_config.html).
It returns an owned `ClientConfig` that you can customize, then wrap with
`rustls::TlsConnector::from(Arc::new(config))` and return with your server name.

For OpenSSL, configure `openssl::ClientConfig` using the methods above. Build a
snapshot connector with `openssl::TlsConnector::new(&config, &snapshot)?`.
Its OpenSSL context is private; raw streams use the same verified handshake path
as tonic. Broader backend customization requires your own `TlsConnectorFactory`
and handshake connector, which are responsible for the snapshot contract.

Always build from the original base configuration, not the previous snapshot's
result. Factories run when snapshots change; unchanged snapshots reuse the
cached connector and argument. Custom factories that replace verification or
identity settings, or enable resumption, can undo CRL and rotation guarantees.

### Raw Tokio streams

For a connection without tonic, read a fresh snapshot before each TLS handshake
and build the configuration yourself:

```rust
let snapshot = provider.snapshot()?;
let config = tonic_tls_xds::rustls::build_client_config(&base, &snapshot)?;
let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(config));
let stream = connector.connect(server_name, tcp_stream).await?;
```

For OpenSSL:

```rust
use tonic_tls_xds::openssl::{ClientConfig, TlsConnector};

let config = ClientConfig::default()
    .with_alpn_protocols(vec![b"my-protocol".to_vec()]);
let snapshot = provider.snapshot()?;
let connector = TlsConnector::new(&config, &snapshot)?;
let stream = connector.connect("localhost", tcp_stream).await?;
```

Keep the file watcher alive across connections. This manual path reparses the
snapshot and builds a context each time rather than using the reloadable
connector's cache.
Existing streams keep their authenticated identity and trust decision.

## Diagnostics and reference

This crate uses `tracing`. With a subscriber and environment filtering configured,
enable `RUST_LOG=tonic_tls_xds=debug` to see refreshes, configuration rebuilds,
and provider/factory failures. A successful rebuild does not guarantee that a
subsequent TLS handshake will succeed.

- [API reference](https://docs.rs/tonic-tls-xds)
- [Server certificate rotation](../docs/Cert-rotation.md)
- [Provider-driven server rotation design](../docs/Server-cert-rotation-design.md)
- [Custom TLS backend API](https://docs.rs/tonic-tls-xds/latest/tonic_tls_xds/trait.TlsConnectorFactory.html)
