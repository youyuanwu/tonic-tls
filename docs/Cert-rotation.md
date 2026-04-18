# Certificate Rotation

## Problem

TLS certificates expire and need to be rotated without restarting the server.
`TlsIncoming::new()` captures the acceptor once at construction time and
clones it per connection — there is no built-in way to swap in a new
certificate after the server starts.

## Approach

Both rustls and openssl provide per-handshake callbacks that fire
unconditionally and allow setting the cert/key dynamically. This requires
**no changes to tonic-tls itself** — users configure the underlying
`ServerConfig` or `SslAcceptor` with a dynamic resolver before passing
it to `TlsIncoming::new()`.

For backends without native resolver support (schannel, native-tls),
an `ArcSwap`-based acceptor wrapper can be used instead.

### rustls: `ResolvesServerCert`

Rustls calls `ResolvesServerCert::resolve()` on **every** handshake
unconditionally. Implement it with an `ArcSwap<CertifiedKey>`:

```rust
struct ReloadableResolver {
    certified_key: ArcSwap<CertifiedKey>,
}

impl ResolvesServerCert for ReloadableResolver {
    fn resolve(&self, _hello: ClientHello<'_>) -> Option<Arc<CertifiedKey>> {
        Some(self.certified_key.load_full())
    }
}

// Setup
let resolver = Arc::new(ReloadableResolver::new(initial_key));
let config = ServerConfig::builder()
    .with_no_client_auth()
    .with_cert_resolver(resolver.clone());
let incoming = TlsIncoming::new(tcp, Arc::new(config));

// Rotate at any time
resolver.update(new_certified_key);
```

### openssl: `SSL_CTX_set_cert_cb`

OpenSSL's cert callback fires on **every** handshake regardless of SNI.
The Rust `openssl` crate does not expose this API, so it requires unsafe
FFI against `openssl-sys`:

```rust
unsafe extern "C" {
    fn SSL_CTX_set_cert_cb(
        ctx: *mut SSL_CTX,
        cb: Option<unsafe extern "C" fn(*mut SSL, *mut c_void) -> c_int>,
        arg: *mut c_void,
    );
}
```

A safe wrapper (`set_cert_cb`) can be written following the same pattern
as the `openssl` crate's other callback wrappers: leak a `Box<F>` via
`Box::into_raw`, pass the pointer as the `arg`, and use a monomorphized
trampoline to cast it back.

```rust
let certs = Arc::new(ArcSwap::new(Arc::new(CertKeyPair { cert, key })));
let cb_certs = certs.clone();
set_cert_cb(&mut acceptor, move |ssl| {
    let current = cb_certs.load();
    ssl.set_certificate(&current.cert).is_ok()
        && ssl.set_private_key(&current.key).is_ok()
});
let incoming = TlsIncoming::new(tcp, acceptor.build());

// Rotate at any time
certs.store(Arc::new(CertKeyPair { cert: new_cert, key: new_key }));
```

Note: `set_certificate` / `set_private_key` at acceptor build time are
not needed when using `set_cert_cb` — the callback sets them on every
handshake.

### Other openssl callbacks (not recommended)

| API | Fires without SNI | Notes |
|-----|-------------------|-------|
| `SSL_CTX_set_cert_cb` | **Yes** | Best for rotation |
| `set_servername_callback` | No | SNI-dependent, skipped if client omits SNI |
| `set_client_hello_cb` | **Yes** | Very early, low-level |

### Fallback: `ArcSwap` on the acceptor

For backends without native resolver support, wrap the acceptor in
`Arc<ArcSwap<A>>` and implement `TlsAcceptor` to load the current value
on each `accept()`. This reconstructs the acceptor on rotation but works
uniformly across all backends.

## Test Coverage

Tests in `tonic-tls-tests/src/cert_rotation_tests.rs`:

- **`rustls_cert_rotation`** — `ResolvesServerCert` + `ArcSwap<CertifiedKey>`.
- **`openssl_cert_rotation`** — `SSL_CTX_set_cert_cb` via safe FFI wrapper +
  `ArcSwap<CertKeyPair>`, with `LeakedCb` guard for cleanup.

Both verify the full rotation flow:
1. Server starts with cert1, client trusting cert1 succeeds.
2. Server rotates to cert2 at runtime.
3. Client trusting cert1 fails (cert mismatch).
4. Client trusting cert2 succeeds.
