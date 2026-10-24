# tonic-tls-xds

Reload client certificates, trusted CAs, and certificate revocation lists (CRLs)
without restarting your application or rebuilding a tonic channel.

This crate provides xDS-style certificate providers for
[tonic-tls](../README.md), not the xDS discovery protocol. The built-in TLS
adapter supports **rustls**.

## Installation

No TLS backend is enabled by default. Enable `rustls`:

```toml
tonic = "0.14"
tokio-rustls = "0.26"
tonic-tls = { version = "0.8", default-features = false }
tonic-tls-xds = { version = "0.1", features = ["rustls"] }
```

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
  chain (leaf first) and its matching private key.
- Omitted material keeps the **original base configuration**, not a previous
  update. Supplied roots replace the base verifier with standard rustls chain
  and hostname verification; they do not preserve custom verifier checks.
- Dropping the last owner of the provider stops polling.

### Rotation and failures

Updates apply to **new TLS connections**, including automatic reconnects of the
same tonic channel. Existing connections and RPC streams remain open. If you
need a bounded cutover time, your application must retire old connections.
Session resumption is disabled so new connections use current credentials.

| Situation | Behavior |
|---|---|
| Invalid configuration or initial file-read failure | Provider construction returns an error. |
| Invalid initial certificate, key, or CRL contents | Connector construction returns an error. |
| File-read failure during refresh | Logs `WARN` and retains the last successfully read snapshot. |
| Readable but invalid updated contents | New connections fail; no fallback to older credentials. Valid updates allow recovery. |
| Unchanged contents | No TLS configuration rebuild. |

Reads across multiple files are not atomic. Publish related files atomically
where possible, or use a custom provider that validates a complete update before
publishing it.

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

- Checks server certificates and intermediates, excluding the trust anchor.
- Rejects revoked certificates, unknown revocation status, and expired CRLs
  (`nextUpdate`). Supply an applicable CRL for each issuer in the checked chain.
- Rejects empty directories, empty files, and malformed CRLs rather than
  disabling checking. A valid signed CRL with no revoked certificates is accepted.
- Applies additions, changes, and removals on subsequent connections. Expiry is
  checked at handshake time even if the CRL files have not changed.

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

## Diagnostics and reference

This crate uses `tracing`. With a subscriber and environment filtering configured,
enable `RUST_LOG=tonic_tls_xds=debug` to see refreshes, configuration rebuilds,
and provider/factory failures. A successful rebuild does not guarantee that a
subsequent TLS handshake will succeed.

- [API reference](https://docs.rs/tonic-tls-xds)
- [Server certificate rotation](../docs/Cert-rotation.md)
- [Custom TLS backend API](https://docs.rs/tonic-tls-xds/latest/tonic_tls_xds/trait.TlsConnectorFactory.html)
