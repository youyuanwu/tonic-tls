# tonic-tls-xds

xDS-style certificate providers, file watching, and reloadable TLS connectors
for [tonic-tls](../README.md). This crate does not implement the xDS discovery
protocol.

## Features

No TLS backend is enabled by default. Enable `rustls` for the built-in factory:

```toml
tonic-tls = { version = "0.8", default-features = false }
tonic-tls-xds = { version = "0.1", features = ["rustls"] }
```

`tonic-tls` continues to provide the transport and backend handshake traits.
The provider APIs and reloadable connector live in `tonic-tls-xds`.

## Client certificate rotation

The public `CertificateProvider` trait supplies backend-neutral PEM snapshots:

```rust
pub trait CertificateProvider: Send + Sync {
    fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error>;
}
```

`CertificateData` contains `RootsOnly`, `IdentityOnly`, or `Both`. `Identity`
pairs a PEM certificate chain (leaf first) with its PEM private key.
Neither the provider API nor the public `ReloadableTlsConnector<IO, C>` requires a
TLS backend feature. `C` selects a backend by implementing
`tonic_tls::TlsConnector<IO>`, with its associated `Arg` and `TlsStream` types.
The generic connector implements `Service<Uri>` for use directly with tonic.

Its factory implements `TlsConnectorFactory<IO>`, selecting a `Connector` that
implements `TlsConnector<IO>`. The `build_connector(&self, data)` method returns
the connector and its associated argument type together. Factories retain the
base configuration and connection settings needed to build each new snapshot.

The connector and argument are cached and replaced together. This covers both
stable server-name arguments and arguments containing rotating credentials.
The argument type does not identify the backend: multiple backends can share
an argument type.

Rustls provides `rustls::TlsConnectorFactory::new(config, domain)` as a named
factory retaining an `Arc<ClientConfig>` and the server name. It produces a
`rustls::TlsConnector`, which implements the `tonic_tls::TlsConnector` handshake
trait. Use this
factory with `ReloadableTlsConnector::new(transport, provider, factory)?` as the
canonical rotation API. Other built-in backends do not yet have provider
factories, but applications can implement the factory trait and handshake trait
for custom backends.

### Providing and updating certificates

Applications can use the built-in file watcher below or implement their own
refresh scheduling and error reporting. For example, with an application
dependency on `arc-swap`:

```rust
use std::sync::Arc;
use arc_swap::ArcSwap;
use tonic_tls_xds::{CertificateData, CertificateProvider, Identity, ReloadableTlsConnector};

struct Certificates(ArcSwap<CertificateData>);

impl CertificateProvider for Certificates {
    fn snapshot(&self) -> Result<Arc<CertificateData>, tonic_tls::Error> {
        Ok(self.0.load_full())
    }
}

let provider = Arc::new(Certificates(ArcSwap::from_pointee(
    CertificateData::IdentityOnly {
        identity: Identity::from_pem(
            std::fs::read("client.pem")?,
            std::fs::read("client.key")?,
        ),
    },
)));

// `config` is your usual rustls ClientConfig, including server trust and h2 ALPN.
let transport = tonic_tls::TcpTransport::from_endpoint(&endpoint);
let domain = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")?;
let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(Arc::new(config), domain);
let connector = ReloadableTlsConnector::new(transport, provider.clone(), factory)?;
let channel = endpoint.connect_with_connector(connector).await?;

// Publish the cert and key together once both have been obtained and validated.
provider.0.store(Arc::new(CertificateData::IdentityOnly {
    identity: Identity::from_pem(new_certificate_pem, new_private_key_pem),
}));
```

`Identity::from_pem` only stores bytes; it does not validate them. A refresh
routine should validate before publishing if it wants to keep serving with the
last known-good material after a bad update. Report refresh failures rather
than silently ignoring them. The rustls adapter validates snapshot material
before using it and rejects invalid PEM, empty certificate bundles, and
certificate/key mismatches.

### Watching PEM files

`FileWatcherProvider` implements `CertificateProvider` without requiring a TLS
backend feature. Its constructor takes only a `FileWatcherConfig`, reads the
initial files, and starts polling. Certificate validation belongs to the
connector's TLS factory, not the file source.

For rustls:

```rust
use std::sync::Arc;
use std::time::Duration;
use tonic_tls_xds::{FileWatcherConfig, FileWatcherProvider, ReloadableTlsConnector};

let domain = "localhost".try_into()?;
let factory = tonic_tls_xds::rustls::TlsConnectorFactory::new(Arc::new(config), domain);
let provider = Arc::new(FileWatcherProvider::new(FileWatcherConfig {
    ca_certificate_file: Some("ca.pem".into()),
    certificate_file: Some("client.pem".into()),
    private_key_file: Some("client.key".into()),
    refresh_interval: Duration::from_secs(60),
}).await?);
let transport = tonic_tls::TcpTransport::from_endpoint(&endpoint);
let connector = ReloadableTlsConnector::new(transport, provider, factory)?;
let channel = endpoint.connect_with_connector(connector).await?;
```

- Configure roots, identity, or both. The certificate and private-key paths must
  be supplied together; an empty file configuration is rejected.
- The default polling interval is 600 seconds. Zero or unrepresentable intervals
  are rejected. The first refresh waits for a full interval.
- Construction is async and requires a Tokio runtime with time enabled. Initial
  and refresh file reads use `tokio::fs`. Configuration and initial read errors are
  returned without starting a polling task.
- The watcher publishes raw bytes without parsing certificates or checking key
  pairs. `ReloadableTlsConnector::new` validates the initial snapshot through its
  factory; changed snapshots are validated before use on later connection attempts.
- Unchanged file contents retain the same snapshot `Arc`,
  so neither a file rewrite with identical contents nor a poll forces a rebuild.
- Changed contents are published together after all configured files are read.
  Read failures log `WARN`, retain the last successfully read snapshot, and retry
  on the polling schedule. `snapshot()` continues returning that snapshot.
- Readable but invalid updates are published, including malformed certificates,
  empty roots, and mismatched certificate/key pairs. New connection attempts fail
  validation until valid material is published; cached credentials are not used
  as a fallback. Existing connections are unaffected.
- Reads across separate files are not an atomic filesystem operation. The
  watcher can publish a half-applied update; publish related files atomically
  where possible, or use a custom validating provider for last-good retention.
- Share the provider through `Arc`. Dropping the last owner aborts polling using
  Tokio's standard task cancellation. The provider does not open network
  connections or retire existing TLS connections.

### Connection and error semantics

- `ReloadableTlsConnector::new` returns a `Result`: it requests the initial
  snapshot, validates it through the factory, and caches the resulting pair
  without opening a connection. The provider must have an initial snapshot ready.
  Factory construction itself does not request or validate a snapshot.
- Construction validates local material, not peer acceptance or handshake
  success; those still require a TLS connection.
- The provider's `snapshot()` is called before every TLS handshake, including tonic's
  internal reconnects of an existing channel. No channel rebuild is required.
- Return the same `Arc<CertificateData>` until the material changes. Connector
  clones share the provider, factory, and cached `(connector, argument)` pair.
  The factory runs only on a cache miss, not for every handshake.
- With the rustls factory, snapshots overlay the
  **original** rustls configuration, not the previous
  snapshot: omitted roots retain the original server verifier; omitted identity
  retains the original client certificate resolver.
- Supplied roots **replace** the trust configuration with rustls's standard
  certificate-chain and hostname verifier. They do not extend the old roots or
  preserve a custom verifier's additional checks.
- Other base settings, such as ALPN and protocol versions, are preserved.
  The rustls factory disables session resumption so each new connection
  authenticates with current credentials and trust. Custom factories must
  implement their own validation and session-resumption policies.
- Snapshot retrieval or factory errors fail construction or the connection attempt. The wrapper does not
  silently reuse its cache, fall back to the base identity, or omit client
  authentication after an error. A later valid snapshot can recover.
- Existing TLS connections and gRPC streams are unchanged. An application that
  needs a bounded cutover time must also arrange to retire old connections.
- The non-rotating connectors in `tonic-tls` retain their behavior, including session
  resumption configuration. No file watcher or background task is installed by
  either connector constructor; `FileWatcherProvider` explicitly owns polling.

The PEM provider is portable across TLS libraries. The shared wrapper delegates
transport establishment through `Transport` and the cached argument through the
backend's `TlsConnector::connect` method. It releases its cache lock before
awaiting the handshake. A factory can retain the backend's
base configuration and stable arguments without exposing its type in
`ReloadableTlsConnector`'s public generics. Factories need not implement `Clone`;
connector clones share the same factory and cache.

Non-exportable private keys require backend-specific configuration and cannot
be represented by this PEM API.

### Tracing

The shared connector emits `DEBUG` events under the
`tonic_tls_xds::reloadable_tls_connector` target:

- Snapshot retrieval failure: `stage = "snapshot"` and `error`.
- Factory failure: `stage = "build_connector"` and `error`.
- Successful cache update: "TLS connector rebuilt from certificate snapshot",
  with `replaced = false` for the initial build or `true` for a replacement.

Errors still propagate unchanged. Cache hits and successful handshakes are not
logged here. A cache-update event does not mean the subsequent handshake
succeeded or that existing connections have switched credentials.

The connector does not log certificate material, backend configurations, or
connection arguments. Provider and factory errors are formatted with `Display`,
so their error messages should not contain private keys or other secrets.

Background refresh failures that retain the previous snapshot must be reported
by the provider itself, typically at `WARN`; they are not visible to the
connector. Applications can enable the connector's diagnostics with a tracing
filter such as `tonic_tls_xds::reloadable_tls_connector=debug`.

`FileWatcherProvider` reports refresh failures at `WARN` and changed snapshots
at `DEBUG` under `tonic_tls_xds::file_watcher`. Unchanged polls are not logged.
Invalid certificate contents are reported by the connector when it validates
the snapshot, not by the watcher.

## Tests

Client integration tests live in the shared test crate:
[tonic-tls-tests/src/xds_tests.rs](../tonic-tls-tests/src/xds_tests.rs).

- **`rustls_client_identity_rotates_on_channel_reconnect`** verifies the actual
  client certificate observed by an mTLS server before and after rotation,
  reusing the same tonic channel. It explicitly shuts down the first accepted
  socket after publishing the update; replacement connections are not aged out.
- **`rustls_client_file_watcher_rotates_identity`** updates PEM files and verifies
  initial invalid material is rejected by connector construction, a half-applied
  update fails new connections without disrupting existing ones, and a valid
  rotated certificate is observed by an mTLS server.
- **`rustls_client_provider_rotates_roots_and_preserves_base_identity`** verifies
  replacement of trusted server CAs while retaining the base client identity.
- **`rustls_client_provider_errors_do_not_fall_back_to_cached_credentials`**
  verifies rejection of provider failures and an invalid snapshot through tonic,
  followed by a successful authenticated RPC after restoring valid material.
- **`rustls_client_connector_rejects_invalid_material_at_construction`** checks
  malformed PEM, mismatched keys, and empty roots through the public constructor
  using named, table-driven cases without a server or open sockets.
- **`rustls_client_factory_rejects_empty_chain_with_unknown_key_consistency`**
  checks that missing identity certificates are rejected even when a custom
  crypto provider cannot expose a public key for rustls's key-pair check.

Shared connector unit tests in
[src/reloadable_tls_connector.rs](src/reloadable_tls_connector.rs) cover
construction-time validation without transport IO, initial cache reuse across
clones, argument-only rotation, stream
forwarding, error propagation, and recovery without fallback to cached credentials.

File-watcher unit tests in [src/file_watcher.rs](src/file_watcher.rs) cover all file combinations, invalid configuration,
startup read errors, unchanged snapshot reuse, read-failure recovery, raw publication,
polling deadlines with a paused clock, and cancellation after the last owner drops.
