# tonic-xds custom connector integration

Status: **Explicitly configured TLS integration and EDS endpoint-update coverage
implemented. Automatic CDS TLS-policy translation remains deferred.**

Current-state review: 2026-11-25. The supported upstream dependency is pinned in
the [workspace manifest](../Cargo.toml). Upstream references below target
`tonic-xds` 0.1.0-alpha.5 rather than the earlier alpha.4 proposal.

## Scope and ownership

`tonic-tls-xds` connects an application-configured TLS URI service to upstream's
gRPC channel builder. Applications do not implement upstream connector traits.

| Responsibility | Owner |
|---|---|
| ADS, resource discovery, routing, retries, deadlines, circuit breaking, and load balancing | Upstream `tonic-xds`. |
| Registering one cluster and constructing its lazy endpoint channels | Our configured connector factory. |
| Raw connections and custom transports | `tonic-tls::Transport`. |
| TLS backend, trust, server name, client identity, and ALPN | The application's supplied TLS connector. |
| Optional credential refresh and configuration caching | Existing `tonic-tls-xds` providers and reloadable connector. |
| Control-plane transport | Upstream ADS over plaintext, using `insecure` bootstrap credentials. |

The integration does not enable upstream TLS, infer TLS policy from CDS, or
provide an automatic A29 verifier. Control-plane TLS is out of scope.

## Source of truth

Keep API signatures, generic bounds, configuration values, and runnable examples
in their source files rather than duplicating them here.

| Source | Contents |
|---|---|
| [Configured connector module](../tonic-tls-xds/src/xds.rs) | Public `ConfiguredMakeConnector`, private endpoint connector, liveness settings, and compiled rustls/reloadable usage example. |
| [Companion manifest](../tonic-tls-xds/Cargo.toml) | Optional integration dependencies and the `xds`, `rustls`, and `openssl` features. |
| [Workspace manifest](../Cargo.toml) | Exact upstream pre-release pin and disabled default features. |
| [Core client implementation](../tonic-tls/src/client.rs) | `Transport`, `TlsConnector`, and their composition into a URI service. |
| [Reloadable connector](../tonic-tls-xds/src/client/mod.rs) | Eager initial validation, per-handshake snapshot selection, and connector-pair cache. |
| [Provider implementation](../tonic-tls-xds/src/provider/mod.rs) | Certificate snapshots, provider contract, and failure semantics. |
| [Rustls client implementation](../tonic-tls-xds/src/rustls/client.rs) | Existing client factory, PEM application, verifier replacement, and resumption policy. |
| [Integration tests](../tonic-tls-tests/src/xds_tests/transport.rs) | Static mTLS connectivity, EDS endpoint replacement, and unregistered-cluster rejection. |
| [ADS fixture](../tonic-tls-tests/src/xds_tests/support/ads.rs) | Plaintext control plane, static LDS/CDS resources, and mutable EDS snapshots. |
| [gRPC fixtures](../tonic-tls-tests/src/test_support/grpc.rs) | Authenticated test servers, optional server-identifying replies, and shared server setup used by discovery and reloadable TLS tests. |

The [usage guide](../tonic-tls-xds/README.md#upstream-xds-custom-connectors)
describes installation and the focused test command. The module's compiled
example is the authoritative end-to-end application example.

## Implemented API

`ConfiguredMakeConnector` registers one cluster name and an already configured,
cloneable TLS URI service. Its constructor does not connect or validate TLS
credentials. Applications using `ReloadableTlsConnector` construct and validate
that connector first.

The factory implements upstream [MakeConnector][make-connector]. For the
registered cluster it returns a private implementation of upstream
[Connector][connector]; any other cluster name produces an explicit
invalid-input error. Upstream logs and rejects failed connector updates.

The endpoint service is upstream's `EndpointChannel<tonic::transport::Channel>`,
the same shape used by its default gRPC factory. Applications pass the factory
to [build_grpc_channel_with_connector][grpc-builder] and give the returned
`XdsChannelGrpc` to their generated tonic client.

This keeps body adaptation, load accounting, and gRPC-specific behavior in
upstream. There is no local endpoint-channel wrapper, body adapter, generic
transport-builder integration, or Hyper-frame test harness.

### Features

The optional `xds` feature enables the factory without selecting a TLS backend.
Enable the existing backend feature separately when needed. Rustls applications
also configure their crypto provider through their TLS configuration.

The integration does not activate `tonic-xds/tls-ring`,
`tonic-xds/tls-aws-lc`, or `_tls-any`. There are no combined `xds-ring` or
`xds-aws-lc` features. A non-rustls application must not acquire rustls merely
to use our factory.

### Connection lifecycle

1. The application configures its transport and TLS backend, including peer
   verification, server name, identity, and ALPN.
2. It registers the resulting URI service with the configured factory.
3. Upstream discovers a cluster and requests its connector. Unknown cluster
   names fail rather than selecting a default or insecure connector.
4. For each endpoint, our connector builds a lazy tonic channel using the
   primary discovered address and a clone of the supplied URI service.
5. Tonic drives connection attempts and reconnects through that service.
   The service establishes the transport and performs TLS.
6. Upstream handles request dispatch and gRPC retry policy; our factory adds
   neither a retry loop nor another request-service layer.

The connector uses only the primary address, matching upstream's default
dialing choice. Alternate addresses and the xDS endpoint hostname are not used.
The supplied connector owns SNI and authorization; these must not be inferred
from the HTTP authority or confused with the discovery target.

Connection timeout and HTTP/2 keepalive settings match upstream's fixed gRPC
defaults. Their exact values are documented and applied in the
[connector implementation](../tonic-tls-xds/src/xds.rs). TCP socket settings
remain the supplied transport's responsibility.

### Apply TLS exactly once

The URI service already returns an encrypted stream. Our internal connection
URI therefore uses `http`, while the endpoint's request origin uses `https`.
These represent different layers: the former selects connection plumbing;
the latter supplies the HTTP request scheme and authority.

Do not configure an additional tonic TLS layer. Another dependency may enable
tonic TLS through Cargo feature unification; this URI/origin separation still
prevents a second handshake. See tonic's [connection wrapper][tonic-connector]
and [origin handling][tonic-origin] for the upstream behavior being accommodated.

This is not a plaintext fallback. The supplied URI service must perform TLS,
and connection or authentication errors propagate through the channel.

### Credential rotation remains delegated

The factory never reads certificate files or rebuilds TLS configurations.
Clones preserve the supplied URI service's own sharing semantics.

When that service is the existing reloadable connector, its provider and cache
are shared across clones. New handshakes select the current snapshot; unchanged
snapshot identities reuse parsed configuration. Provider/build errors fail the
attempt without selecting an older cached pair. Existing connections remain
unaffected.

The public reloadable constructor remains eager. No deferred constructor,
provider-composition adapter, or new verifier has been added. Backend behavior
such as resumption and CRL checking remains governed by the selected backend,
not overridden by this factory.

## Endpoint-update test infrastructure

The [ADS fixture](../tonic-tls-tests/src/xds_tests/support/ads.rs) is an in-process
SotW control plane. It keeps LDS/CDS resources static and exposes an
`EndpointUpdates` handle for replacing the cluster's advertised EDS addresses.

Updates are published through a Tokio watch channel. Each ADS stream maintains
its EDS subscription, sends the latest snapshot on subscription, and pushes
later changes with increasing resource versions and fresh response nonces.
ACKs do not trigger another response; NACKs and unsupported subscriptions
produce explicit errors. Delta ADS is not implemented by this fixture.

The [named-server fixture](../tonic-tls-tests/src/test_support/grpc.rs)
distinguishes servers by their reply while still authenticating the client's
certificate. Existing callers retain the original peer-certificate-index
response behavior.

### Implemented coverage

All integration cases are defined in the
[transport test file](../tonic-tls-tests/src/xds_tests/transport.rs):

| Test | What it establishes |
|---|---|
| `rustls_xds_uses_configured_tls_connector` | Plaintext ADS discovery reaches a static mTLS service through our configured transport and factory. |
| `rustls_xds_switches_endpoints_after_eds_update` | The same client/channel switches from A to B after an EDS replacement, subsequent replies stay on B, and a direct RPC proves A remains healthy. |
| `configured_factory_rejects_unregistered_clusters_before_connecting` | An unregistered cluster produces the factory's invalid-input error before any data-plane connection attempt. |

The EDS test keeps server and client TLS credentials fixed. It uses a bounded
wait driven by RPC results, not a fixed sleep, and checks that the new endpoint
is reached through the configured transport.

Certificate rotation, provider-error recovery, and TLS-session behavior belong
in the existing [client connector tests](../tonic-tls-tests/src/reloadable_tests/client/)
and [provider implementation tests](../tonic-tls-xds/src/provider/), not in
xDS-channel tests. Do not duplicate Hyper framing or upstream load-counter tests.

Validation includes the focused integration tests with and without tonic TLS
feature unification, the related shared-fixture suites, the compiled usage
example, feature-isolation checks, Clippy, and formatting.

## Deferred: automatic CDS TLS policy

There is no automatic `RustlsMakeConnector` API today. The current factory uses
application-owned TLS policy, even when CDS advertises different security
settings. It must not be presented as automatically enforcing A29.

### Upstream metadata prerequisite

In the pinned alpha.5 release, the [cluster security view][cluster-config] and
provider APIs are gated behind upstream TLS features. Its public
[TLS view][cluster-tls] exposes a rustls verifier rather than a complete
backend-neutral authorization policy.

Automatic translation needs TLS mode, CA/identity provider references, and SAN
matcher policy without enabling upstream TLS. Automatic bootstrap provider
setup also needs ungated provider declarations or backend-neutral handles.
Until these APIs exist, do not enable upstream TLS as a workaround, inspect
private fields, or treat inaccessible security metadata as plaintext.

### Requirements for a future backend adapter

- Keep configuration and handshakes in our backend, using an explicit crypto
  provider for rustls. Do not install a global provider as a side effect.
- Enforce native certificate-chain verification plus [A29 SAN authorization][a29],
  including CA-only authorization for an empty matcher list. Ordinary hostname
  verification is not a substitute.
- Resolve our providers by their declared CA/identity roles. Require roots and,
  for mTLS, an identity; never omit required material after an error.
- Reuse a single source snapshot when one provider supplies both roles. Cache
  compositions by source snapshot identity and keep locks out of handshakes.
- Disable resumption for the rotating policy path so new connections
  reauthenticate. Reject unsupported material explicitly, including CRLs if
  that path does not implement their policy.
- Preserve eager validation in the existing public reloadable constructor.
  If automatic endpoint construction requires deferred validation, add only a
  private path reusing the existing cache and allowing later snapshot recovery.

The current [rustls factory](../tonic-tls-xds/src/rustls/client.rs) installs
standard hostname verification when supplied roots. It must not be reused
unchanged as an A29 policy factory. Existing non-xDS CRL and rotation support
must remain unchanged.

These are deferred design constraints, not implemented types, constructor
signatures, or guarantees of the current configured factory.

### CDS policy changes are not EDS address changes

The implemented EDS test proves address replacement, not replacement of TLS
policy on an unchanged endpoint.

Alpha.5's [ClusterConnector][upstream-cluster-connector] republishes connectors
after accepted CDS updates and retains the prior connector when construction
fails. Its [EndpointManager][upstream-endpoints] retains services for unchanged
endpoints on that discovery path. Rebuilding a cluster connector alone therefore
must not be assumed to update a retained tonic channel's TLS policy.

Before claiming dynamic CDS security support, verify provider-reference, SAN,
and TLS-mode changes with unchanged endpoint addresses under the supported
load-balancer path. This may require upstream lifecycle changes. Do not add a
second local CDS watcher or global mutable-policy registry as a shortcut.

## Out of scope

- Control-plane TLS, SDS, or application-server xDS discovery.
- Automatic backend-neutral CDS policy translation before the upstream APIs
  above exist.
- Forced connection draining or a bounded cutover time for established sessions.
- New xDS address types or additional-address/hostname dialing behavior.
- A custom retry engine, body adapter, or load-accounting implementation.
- Certificate-rotation tests through an xDS channel.

## References

- [Transport design](Transport-trait.md).
- [Companion usage guide](../tonic-tls-xds/README.md).
- [Upstream connector traits][make-connector] and [endpoint connector][connector].
- [Upstream gRPC custom-connector builder][grpc-builder].
- [Upstream cluster metadata][cluster-config] and [TLS metadata][cluster-tls].
- [Upstream CDS connector lifecycle][upstream-cluster-connector] and
  [endpoint discovery][upstream-endpoints].

[make-connector]: https://docs.rs/tonic-xds/0.1.0-alpha.5/tonic_xds/trait.MakeConnector.html
[connector]: https://docs.rs/tonic-xds/0.1.0-alpha.5/tonic_xds/trait.Connector.html
[grpc-builder]: https://docs.rs/tonic-xds/0.1.0-alpha.5/tonic_xds/struct.XdsChannelBuilder.html#method.build_grpc_channel_with_connector
[cluster-config]: https://docs.rs/tonic-xds/0.1.0-alpha.5/tonic_xds/struct.ClusterConfig.html
[cluster-tls]: https://docs.rs/tonic-xds/0.1.0-alpha.5/tonic_xds/struct.ClusterTlsConfig.html
[upstream-cluster-connector]: https://docs.rs/tonic-xds/0.1.0-alpha.5/src/tonic_xds/xds/connector.rs.html
[upstream-endpoints]: https://docs.rs/tonic-xds/0.1.0-alpha.5/src/tonic_xds/xds/endpoint_manager.rs.html
[a29]: https://github.com/grpc/proposal/blob/master/A29-xds-tls-security.md
[tonic-connector]: https://docs.rs/tonic/0.14.9/src/tonic/transport/channel/service/connector.rs.html
[tonic-origin]: https://docs.rs/tonic/0.14.9/src/tonic/transport/channel/service/add_origin.rs.html
