# Provider-driven server TLS rotation

Status: **Implemented for rustls and OpenSSL**.
Source comparisons verified on 2026-11-10. See the
[server usage guide](../tonic-tls-xds/README.md#server-rotation) for the
implemented API and policies.

## Summary

Provide server-side rotation in `tonic-tls-xds` for rustls and OpenSSL. Reuse
`CertificateProvider`, `CertificateData`, and `FileWatcherProvider`, but build and
cache a complete immutable server acceptor for each published snapshot.

The recommended design:

- Select one snapshot before creating TLS state for each new connection.
- Rotate the server identity, trusted client CAs, and client-certificate CRLs
  together, without restarting the listener.
- Keep existing connections and already-started handshakes on their selected
  configuration.
- Own built-in server configuration construction, with explicit client
  authentication policy and no inherited authentication callbacks.
- Fail new accepts on provider or configuration errors; never silently use an
  older acceptor or downgrade client authentication.
- Disable session resumption so every new connection authenticates against the
  selected snapshot.

This follows the lifecycle of the gRPC C++ server handshaker and the provider
separation in upstream `tonic-xds`, without copying their behavior wholesale.

## Current state

Our [provider API](../tonic-tls-xds/src/provider/mod.rs) is backend-neutral, and
the [reloadable client connector](../tonic-tls-xds/src/client/mod.rs)
caches parsed configurations by snapshot `Arc` identity. The
[reloadable server acceptor](../tonic-tls-xds/src/server/acceptor.rs)
uses the same provider contract, with built-in rustls and OpenSSL server factories.

The core crate already exports `TlsAcceptor`, `Incoming`, and `incoming_inner`.
Its [incoming loop](../tonic-tls/src/server.rs) clones an acceptor for each
connection, runs handshakes concurrently, logs per-connection TLS failures, and
continues accepting. The rustls and OpenSSL stream wrappers implement tonic's
`Connected` trait.

The existing [server rotation guide](Cert-rotation.md) and
[tests](../tonic-tls-tests/src/cert_rotation_tests.rs) demonstrate manual
identity rotation using native callbacks. They do not provide coordinated
rotation of server identity, client trust, and CRLs.

## Lessons from upstream

| Source | Observed behavior | Design consequence |
|---|---|---|
| [gRPC C++ server][cpp-server] | Certificate-provider watchers update stored material and rebuild the server handshaker factory. New handshakers use the selected factory. | Replace a complete acceptor/configuration rather than mutating the context of existing connections. |
| [C++ TLS options][cpp-options] | Server identity is required; watching client trust roots is separate and optional. | Require an effective server identity and make client authentication an explicit policy. |
| [C++ file provider][cpp-files] | Polls identity and root files; callers must arrange safe publication of related files. | Reuse our watcher and document publication boundaries instead of treating several filesystem reads as one transaction. |
| [Upstream tonic-xds][tonic-api] | Provides client channels and TLS integration, not an application-server rotation API. Its provider model nevertheless represents roots and identities. | Borrow its provider/transport separation, not a nonexistent server implementation. |
| [tonic-xds watcher][tonic-files] | Validates certificate/key pairs before publication and retains previous material after refresh failures. | Recognize the availability benefit, but preserve our existing backend-neutral, raw-snapshot contract in this proposal. |
| [tonic-xds client connector][tonic-connect] | Fetches provider identity when constructing TLS connection configuration; its error path can omit the identity. | Read current material at the server handshake boundary, but never copy the identity-omission fallback into required mTLS. |
| [C++ CRL provider path][cpp-crls] | Performs custom revocation checks after native chain verification, skips the terminal anchor, and permits missing CRLs. | Preserve anchor exclusion, but retain our stricter missing-CRL policy and native CRL verification. |

C++ providers can update roots and identity independently. Our single snapshot
is a useful stronger boundary: one accept must not combine material from two
published snapshots. This does not make the file watcher's underlying reads
atomic.

### Goals and non-goals

Both implementations support one server identity per acceptor, optional or
required mTLS, client CA rotation, CRL rotation, tonic incoming streams, and raw
Tokio streams. Both existing backend features remain optional.

It does not add xDS discovery/SDS, SNI-based multi-identity routing, encrypted
keys, remote CRL fetching, separate live CRL providers, other TLS backends,
connection draining, or a new handshake scheduling framework. It does not change
the existing client connector's API or failure semantics.

## API

The common API and both backend factories below are implemented.

### Common server settings

Introduce a backend-neutral `ServerConfig` with private fields and fluent
setters, rather than accepting arbitrary native server configurations:

```rust
pub enum ClientAuth {
    Disabled,
    Optional,
    Required,
}

// ServerConfig::default()
//     .with_identity(identity)
//     .with_ca_certificates(client_ca_pem)
//     .with_client_auth(ClientAuth::Required)
//     .with_alpn_protocols(vec![b"h2".to_vec()])
```

Defaults are no base identity, no client roots, `ClientAuth::Disabled`, and
ALPN `h2`. The effective identity must be supplied by the snapshot or base config.
TLS 1.2 and TLS 1.3 are supported; arbitrary protocol/cipher settings are not
part of the initial built-in API.

| Client authentication | Required inputs | Handshake behavior |
|---|---|---|
| `Disabled` | Server identity only. Reject configured client roots or supplied CRLs rather than ignoring them. | Do not request client certificates. |
| `Optional` | Server identity and nonempty explicit client roots. | Request a certificate; accept absence, but reject an invalid certificate if presented. |
| `Required` | Server identity and nonempty explicit client roots. | Require and validate a client certificate. |

Never use operating-system trust roots implicitly for client authentication.
Roots authorize client issuers, not server names. Do not apply hostname
verification to client certificates; use the backend's client-authentication
certificate validation, including applicable key-usage/EKU checks.

`Optional` deliberately permits anonymous clients. A client may withhold a
certificate, including when its issuer is not advertised by the server.
Applications requiring authenticated identities must use `Required` and still
perform application-level authorization.

Client-authentication mode and ALPN are fixed for the lifetime of a factory;
certificate data cannot turn mTLS off. ALPN uses the existing name/list length
limits and defaults to `h2`; an empty list is useful for raw TLS. For a nonempty
configured list, select an offered protocol in server preference order and
reject an offered list with no overlap. Absence of the ALPN extension is not
itself a certificate-validation failure.

### Factories and the reloadable acceptor

Mirror the existing connector factory with an acceptor factory:

```rust
pub trait TlsAcceptorFactory<IO>: Send + Sync + 'static
where
    IO: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    type Acceptor: tonic_tls::TlsAcceptor<IO>;

    fn build_acceptor(
        &self,
        data: &CertificateData,
    ) -> Result<Self::Acceptor, tonic_tls::Error>;
}
```

Add `ReloadableTlsAcceptor<IO, F>` implementing `tonic_tls::TlsAcceptor<IO>`:

- `new(provider, factory) -> Result<Self, tonic_tls::Error>` selects and
  validates the initial snapshot synchronously, without accepting a connection.
- Clones share the provider, factory, and parsed-acceptor cache.
- `accept(io)` selects the current acceptor and performs a handshake.
- `incoming(self, incoming)` delegates to `tonic_tls::incoming_inner`, returning
  a tonic-compatible stream. No second accept loop is introduced.

The built-in factories are `rustls::TlsAcceptorFactory` and
`openssl::TlsAcceptorFactory`, both taking the common `ServerConfig`. The rustls
factory additionally takes an explicit `Arc<rustls::crypto::CryptoProvider>`,
avoiding implicit installation of a process-wide crypto provider.

Sketch of required mTLS with rotation:

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
let factory = tonic_tls_xds::rustls::TlsAcceptorFactory::new(
    config,
    crypto_provider,
);
let acceptor = ReloadableTlsAcceptor::new(provider, factory)?;
let incoming = acceptor.incoming(tcp_incoming);

tonic::transport::Server::builder()
    .add_service(greeter)
    .serve_with_incoming(incoming)
    .await?;
```

Here `crypto_provider`, `tcp_incoming`, and `greeter` are application inputs.
For OpenSSL, use `openssl::TlsAcceptorFactory::new(config)` instead.
For ordinary server-authenticated TLS,
omit client roots/CRLs and retain `ClientAuth::Disabled`.

Raw-stream callers use the same reloadable acceptor's `TlsAcceptor::accept`
method; they do not have to reparse material manually.

### Snapshot interpretation

Keep the existing `CertificateData` constructors and provider contract:

| Component | Snapshot supplies it | Snapshot omits it |
|---|---|---|
| Identity | Replace the entire leaf, explicit chain, and key. | Use the original base identity; fail if absent. |
| Client roots | Replace the base trust bundle, without merging. | Use original base roots; fail if client authentication needs roots and none exist. |
| CRLs | Apply to client-certificate verification; roots must be in the same snapshot. | No CRL checking for this snapshot; never reuse previous CRLs. |

Snapshots are complete overlays on the original base, not patches to the last
acceptor. For example, an identity-only update cannot inherit client roots or
CRLs from an earlier roots-and-CRLs snapshot. A provider must republish all of
its currently intended rotating material together.

Empty supplied identity, roots, or CRL collections remain errors. Every supplied
component must be applied or rejected; `Disabled` must not silently discard a
roots/CRL snapshot. Only the effective identity and roots are parsed when a
snapshot replaces base material.

An unencrypted key is required. Parse PEM without entering OpenSSL's interactive
password reader, as the existing client adapter does. Key/certificate pairing
is validated during construction. A successful build does not prove that the
server certificate is trusted, unexpired, or suitable for every client's name;
clients make those decisions during their handshakes.

## Selection, caching, and concurrency

Use the existing client's simple `Arc`-identity cache pattern, with a server-side
selection boundary that serializes sampling and cache replacement:

1. When an accept future starts executing, acquire the shared selection mutex.
2. Obtain exactly one `provider.snapshot()`. Retrieval must be prompt and use
   cached data, not perform filesystem or network work.
3. If `Arc::ptr_eq` matches the cached snapshot, clone its immutable acceptor.
4. Otherwise, build a complete acceptor from that snapshot and the original
   base settings. Publish the cache entry only after a successful build.
5. Release the mutex before creating/awaiting the TLS handshake.

Sampling under the selection mutex prevents an earlier sampled snapshot from
overwriting a newer cache entry because of task scheduling. There is no mutex
held across an await and no mutation of an acceptor already in use.

This is the selection boundary, not the instant the kernel accepted the TCP
socket or received ClientHello. An update published after selection does not
restart that handshake. Concurrent handshakes may legitimately use different
snapshots; each must use one coherent configuration.

The cache holds at most one successfully built snapshot/acceptor. Unchanged
snapshots avoid reparsing. Changed snapshots, including CRL-only updates, rebuild
the complete configuration. A provider that publishes a fresh `Arc` for
unchanged data causes unnecessary rebuilds.

Do not use the old cache entry when retrieval or rebuilding fails. Keeping it
allocated is not authorization to use stale material. Version one need not
cache build failures: later attempts retry, matching the client adapter and
allowing custom factories to recover. Repeated invalid updates can therefore
cause repeated parsing; providers should publish validated complete updates
where possible, and operators must monitor failures.

Selected acceptors and native TLS objects retain the configuration references
needed for in-flight handshakes and established streams. Subsequent replacement
or provider drop must not invalidate those streams. Dropping the incoming stream
keeps the existing core loop's pending-task cancellation behavior.

## Backend construction

### rustls

Build a fresh native `rustls::ServerConfig` for each changed snapshot, using the
factory's explicit crypto provider. Do not clone a caller's native server config:
unlike the public certificate resolver field, its client verifier is not a
publicly replaceable field. Building through the standard builder makes the
effective identity and client trust unambiguous.

- Use `with_no_client_auth` for `Disabled`.
- For mTLS, build `WebPkiClientVerifier` from explicit effective roots.
  `Optional` adds `allow_unauthenticated`; `Required` does not.
- Reuse backend CRL parsing/selection; enable full-chain checking with unknown
  status denied and `enforce_revocation_expiration`. Do not enable leaf-only
  checking or unknown-status acceptance.
- Install one validated server certificate/key and the explicit supplied chain.
- Disable stateful session storage, keep the fresh builder's stateless ticketer
  disabled, set `send_tls13_tickets` to zero, and disable early data.
- Return the existing core rustls stream wrapper to preserve `Connected` and
  peer-certificate information.

See the pinned rustls [server configuration][rustls-server] and
[client verifier builder][rustls-client-verifier] for the relevant APIs.

### OpenSSL

Create a fresh crate-owned `SslAcceptor`/`SSL_CTX` for each changed snapshot.
Accept no native context, builder, verification callback, PSK callback, or
client-certificate callback through the built-in configuration.

- Require TLS 1.2 or newer and install only the effective identity and explicit
  chain. Disable automatic chain completion, as in the client backend.
- `Disabled` uses `SslVerifyMode::NONE`. `Optional` uses `PEER`. `Required`
  uses `PEER | FAIL_IF_NO_PEER_CERT`. Invalid presented certificates fail in
  both mTLS modes.
- Build the verification store solely from effective client roots. Retain the
  existing explicit-intermediate trust-anchor policy.
- Configure client CA-name hints from the effective roots, not stale roots.
  Treat these as selection hints, not an authorization check.
- Reuse in-memory CRL insertion, duplicate selection, native verification flags,
  and the narrowly scoped trust-anchor CRL exception.
- Disable the session cache, TLS 1.2 tickets, TLS 1.3 ticket issuance, and early
  data. Install no external PSK authentication hooks.
- Create a new `SSL` for each accept and return the existing core OpenSSL stream
  wrapper.

Only the existing CRL-insertion FFI should be needed; context rebuilding avoids
new per-SSL identity/store overrides and callback sanitization machinery.

### Resumption is a server-side requirement

Rebuilding a context alone is not the complete guarantee: resumption within an
unchanged snapshot can also skip certificate exchange and fresh revocation
checks. Disable resumption on both backends, even before the first rotation.
Clients offering an old session must perform a full handshake or fail; they
must not retain an old client-authentication decision or avoid the new server
identity. Test TLS 1.2 and TLS 1.3 independently.

## Client-certificate revocation policy

Reuse our existing [CRL contract](../tonic-tls-xds/README.md#crl-checking), now
applied to the peer's **client** certificate chain:

- Check the leaf and intermediates, excluding the terminal trust anchor.
- Reject revoked certificates, missing applicable CRLs, invalid signatures, and
  expired revocation status. Verify at handshake time even for a cached acceptor.
- Preserve backend-specific time validation, including OpenSSL's `thisUpdate`
  checks and required `nextUpdate`; do not claim new cross-backend equivalence.
- Parse all supplied CRLs, including duplicates. Keep first-per-issuer selection
  for custom/single-file snapshots and last-per-issuer selection for directory
  snapshots. Do not select by date, merge serials, or fall back to another CRL.
- Add no OCSP, CRL downloads, delta-CRL, or indirect-CRL support.

A root's CRL still checks certificates it issued. Removing a trust anchor from
the client-root bundle withdraws trust in the anchor itself.

Do not port the C++ custom revocation loop as part of server rotation. Our
OpenSSL path deliberately lets native verification attempt full-chain CRL
checking, then overrides only listed CRL failures at the terminal anchor.
It preserves non-CRL anchor failures and all non-anchor failures. This avoids
taking ownership of a second CRL-validation implementation and avoids copying
C++'s permissive missing-CRL behavior.

These CRLs do not revoke the server's own certificate locally. Clients need
their own trust/revocation updates to reject a revoked server certificate.

## Failure behavior and operational cutover

| Event | Required behavior |
|---|---|
| Missing initial identity, invalid effective material, or provider error | Return an error from `ReloadableTlsAcceptor::new`; do not start an incoming stream. |
| File-read failure during refresh | Existing watcher logs `WARN` and continues publishing its last successfully read snapshot. |
| Readable but malformed/mismatched refreshed material | New accepts fail. Do not serve the previously cached acceptor. |
| Provider returns an error during an accept | Fail that connection, including when a cached acceptor exists. |
| Client certificate or CRL verification fails | Fail that connection; never retry anonymously. |
| Later valid snapshot | New accepts recover without listener restart. |
| Unchanged snapshot | Reuse parsing/configuration, but still perform a full handshake and time-sensitive verification. |

Per-connection selection/build errors are returned through `TlsAcceptor::accept`.
The existing incoming loop logs TLS errors and continues; they must not terminate
the listener as incoming transport errors would. Preserve native error sources.
Add structured `tracing` stages for snapshot retrieval and acceptor construction,
matching client diagnostics. Never log PEM/key contents. A rebuild log indicates
configuration construction, not successful peer authentication.

Do not silently change our watcher to tonic-xds's validated last-known-good
publication model. That is a separate provider-policy change affecting both
clients and servers. To avoid a temporary outage from split file updates, use
a publication scheme/custom provider that yields a consistent cert/key and
trust/CRL set. Renaming several files, or changing a directory symlink between
separate reads, does not by itself guarantee one coherent read transaction.

Existing HTTP/2 connections and RPCs are not reauthenticated or disconnected
after identity, CA, or CRL changes. A bounded distrust deadline requires
application-managed connection retirement. The adapter does not provide it.
Likewise, it inherits the core incoming loop's handshake concurrency and timeout
behavior; it is not a new resource-limiting or slow-client protection layer.

For planned CA changes, distribute overlapping trust first, rotate identities
second, and remove old trust after the intended overlap and connection-retirement
policy. Server identity issuers trusted by clients and client identity issuers
trusted by the server are separate rollout directions.

## Implementation and validation

1. Add common server settings, the acceptor factory trait, and reloadable acceptor
   in `tonic-tls-xds`. Reuse the core accept loop; do not refactor the existing
   client cache merely to make both paths generic.
2. Add rustls/OpenSSL server adapters. Reuse their backend-local PEM, CRL,
   identity, and anchor-exception helpers where appropriate.
3. Forward the xDS `rustls` and `openssl` features to the matching `tonic-tls`
   features if using the core stream wrappers. Those types are feature-gated;
   current client adapters do not need this forwarding.
4. Add shared server scenarios using the existing
   [backend test pattern](../tonic-tls-tests/src/xds_tests/support/backend.rs), with
   concrete native stream types and backend-specific error assertions. Keep
   native-only tests separate and retain manual rotation tests.
5. Update the crate description, API docs, and user guide when implemented.
   The common API and both adapters are implemented. Existing native/manual
   server APIs are unchanged.

Required coverage:

| Area | Evidence required |
|---|---|
| Server identity | Observe the new leaf/explicit chain on a fresh handshake; old-only trust fails and new trust succeeds; an established RPC connection still works. |
| Client CA rotation | Old/new client CAs behave correctly across replacement and overlap; identity-only snapshots use original base roots, not previous snapshot roots. |
| Authentication modes | Anonymous clients pass only `Disabled`/`Optional`; valid clients pass mTLS; actually presented invalid clients fail both mTLS modes. Include positive controls proving certificate presentation. |
| CRLs | Client leaf and intermediate revocation, missing CRLs, bad signatures, expiry without rebuild, CRL-only rotation, and recovery. Preserve source-specific duplicate selection. |
| Trust anchor | Missing/invalid anchor CRLs do not fail solely for anchor revocation; issuer CRLs still check the next certificate; unrelated chain failures remain fatal. |
| Invalid updates | Missing identity, mismatched key, empty effective inputs, encrypted keys, provider errors, and unsupported roots/CRLs under `Disabled`. Valid controls must reach the intended validation stage. |
| Cache/concurrency | Exact build counts for unchanged/changed successful snapshots; clone sharing; a slow handshake does not hold the cache lock; an update cannot mix old identity with new trust. |
| Lifetimes | An in-flight old handshake retains its selected snapshot; later accepts use the update; dropping/replacing configuration does not invalidate established streams. |
| Resumption/bypasses | TLS 1.2 and TLS 1.3 session attempts do not resume, before or after rotation; mTLS/CRLs are rechecked; no PSK-only authentication or inherited callbacks. |
| Integration | Real loopback tonic RPCs, automatic client reconnect to the same listener, raw-stream accepts, `Connected` peer information, and at least one cross-backend client/server pairing. |
| Settings | ALPN negotiation, bounds, and no-overlap behavior; explicit client CA hints; whole-chain/key-algorithm replacement without legacy identity fallback. |

Generate certificates and CRLs in memory with existing helpers; do not introduce
filesystem fixture abstractions. Use bounded connection/RPC deadlines and
deterministic synchronization, not startup sleeps. Reuse the file-watcher helpers
for one end-to-end file rotation test.

Implementation validation should use targeted server tests, existing client
rotation regression tests, feature-isolated checks, doctests, formatting, and
strict Clippy. No special per-backend CI steps are proposed. Native OpenSSL
1.1.1/3.x and supported Windows configurations need explicit validation rather
than assuming Linux/OpenSSL 3.x coverage proves portability.

## Alternatives considered

- **Identity-only native resolvers:** useful for the existing manual examples,
  but do not by themselves atomically rotate client trust and CRLs. Do not make
  them the provider-backed server architecture.
- **Mutate a shared OpenSSL context or patch each SSL:** risks inherited hooks,
  incomplete identity replacement, and inconsistent configuration ownership.
  Fresh owned contexts are simpler.
- **C++-style live CRL provider:** avoids rebuilding contexts for CRL-only
  updates, but adds a second update/lifetime mechanism and custom revocation
  policy. Not needed for the initial snapshot model.
- **Automatic fallback after invalid publication:** improves availability but
  can keep trusting credentials explicitly removed by a published update.
  Leave last-known-good publication to an explicit provider policy.
- **Accept arbitrary native server configs:** more flexible, but cannot provide
  the same built-in guarantees. Custom `TlsAcceptorFactory` implementations
  remain the extension point and must document/preserve the rotation contract.

## Source references

These links are pinned so the observed upstream behavior remains reviewable:

[cpp-server]: https://github.com/grpc/grpc/blob/ec36b58a9b9ba773c19bd98c224016d34215b9e7/src/core/credentials/transport/tls/tls_security_connector.cc#L748
[cpp-options]: https://github.com/grpc/grpc/blob/ec36b58a9b9ba773c19bd98c224016d34215b9e7/include/grpcpp/security/tls_credentials_options.h#L202
[cpp-files]: https://github.com/grpc/grpc/blob/ec36b58a9b9ba773c19bd98c224016d34215b9e7/include/grpcpp/security/tls_certificate_provider.h#L96
[cpp-crls]: https://github.com/grpc/grpc/blob/ec36b58a9b9ba773c19bd98c224016d34215b9e7/src/core/tsi/ssl_transport_security.cc#L1802
[tonic-api]: https://github.com/grpc/grpc-rust/blob/1f3c81e4190c0bcb1040702a046b1e42a66e6a8d/tonic-xds/src/lib.rs#L291
[tonic-files]: https://github.com/grpc/grpc-rust/blob/1f3c81e4190c0bcb1040702a046b1e42a66e6a8d/tonic-xds/src/xds/cert_provider/file_watcher.rs#L103
[tonic-connect]: https://github.com/grpc/grpc-rust/blob/1f3c81e4190c0bcb1040702a046b1e42a66e6a8d/tonic-xds/src/xds/cluster_discovery.rs#L249
[rustls-server]: https://github.com/rustls/rustls/blob/v/0.23.46/rustls/src/server/server_conn.rs#L297
[rustls-client-verifier]: https://github.com/rustls/rustls/blob/v/0.23.46/rustls/src/webpki/client_verifier.rs#L99
