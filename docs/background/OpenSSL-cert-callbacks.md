# OpenSSL Certificate and CRL Callbacks

Background research on OpenSSL APIs available for dynamic cert/key
selection and CRL rotation during TLS handshakes.

## Per-handshake callbacks

| C API | Rust `openssl` crate | Fires without SNI | Safe API | OpenSSL version |
|---|---|---|---|---|
| `SSL_CTX_set_client_hello_cb` | `set_client_hello_callback` | **Yes** | **Yes** | 1.1.1+ |
| `SSL_CTX_set_cert_cb` | Not exposed | **Yes** | No | 1.0.2+ |
| `SSL_CTX_set_tlsext_servername_callback` | `set_servername_callback` | No | **Yes** | 1.0.0+ |

### `set_client_hello_callback`

Fires immediately after the ClientHello is received, before any
processing. Receives `&mut SslRef` and can set cert/key, swap the
cert store, or abort the handshake.

```rust
acceptor.set_client_hello_callback(move |ssl, _alert| {
    ssl.set_certificate(&cert)?;
    ssl.set_private_key(&key)?;
    Ok(ClientHelloResponse::SUCCESS)
});
```

- Can return `ClientHelloResponse::RETRY` to pause the handshake
  (e.g., for async cert lookup), then resume later.
- Closure lifetime is managed by the `openssl` crate via `SSL_CTX`
  ex_data — automatically freed when the context is dropped.

### `SSL_CTX_set_cert_cb`

Fires during cert selection, after protocol version negotiation has
started. Not exposed by the Rust `openssl` crate; requires unsafe FFI
via `openssl-sys`.

- Cannot pause the handshake (must return synchronously).
- The Rust `openssl` crate does not register a free callback for the
  `arg` pointer, so the caller must manage the closure lifetime
  manually (e.g., `Box::into_raw` + a cleanup guard).
- Available since OpenSSL 1.0.2, so useful if 1.1.1 is not available.

### `set_servername_callback`

Fires only when the client sends an SNI extension. Not suitable as the
sole mechanism for cert rotation since non-SNI clients bypass it.

## CRL handling

### In-memory (`add_crl`)

```rust
let crl = X509CRL::from_pem(&pem_bytes)?;
store_builder.add_crl(crl)?;
store_builder.set_flags(X509VerifyFlags::CRL_CHECK)?;
```

- CRL is loaded once into the `X509Store` and stays in memory.
- Lookup cost: hash table lookup (~nanoseconds).
- No automatic reload — store is frozen after `build()`.

### Directory-based (CApath)

```rust
acceptor.load_verify_locations(None, Some(Path::new("/etc/ssl/crl.d/")))?;
```

- OpenSSL looks up CRL files on demand during verification using
  hashed filenames (`<hash>.r0`, `<hash>.r1`, etc.).
- Files are re-read from disk on each verification — dropping a new
  CRL file into the directory takes effect without any reload.
- Generate hash links: `c_rehash /etc/ssl/crl.d/`
- Cost: filesystem `stat()` + `open()` + `read()` + PEM parse per
  verification (~10-100μs depending on filesystem and cache state).
- Suitable for low-traffic servers or tmpfs-backed directories
  (e.g., Kubernetes secret mounts).

### Per-handshake store swap

`ssl.set_verify_cert_store()` swaps the `X509Store` on the `SSL`
handle. Internally this is a pointer swap with a ref count increment
(~10ns). Combined with `ArcSwap`, this enables CRL rotation with
in-memory verification speed:

```rust
let store: Arc<ArcSwap<X509Store>> = /* rotated periodically */;

acceptor.set_client_hello_callback(move |ssl, _alert| {
    // ... set cert/key ...
    let current_store = store.load();
    ssl.set_verify_cert_store((**current_store).clone())?;
    Ok(ClientHelloResponse::SUCCESS)
});
```

## Performance comparison

| Approach | Per-handshake cost | Reload mechanism |
|---|---|---|
| `ArcSwap` + callback (cert/key) | ~1-10ns | `store()` from any thread |
| `ssl.set_verify_cert_store()` | ~10ns | `ArcSwap` pointer swap |
| Directory (CApath) | ~10-100μs | Drop files into directory |
| Rebuild entire `SslAcceptor` | ~100μs-1ms | Full reconstruction |

## Closure lifetime in the `openssl` crate

The `openssl` crate stores callback closures via `SSL_CTX` ex_data:

1. `Box::into_raw(Box::new(callback))` → raw pointer stored via
   `SSL_CTX_set_ex_data`.
2. Each closure type `F` gets a unique ex_data slot via
   `TypeId::of::<F>()` → `cached_ex_index`.
3. `free_data_box::<T>` is registered as the free callback when the
   ex_data index is created. OpenSSL calls it when the `SSL_CTX` is
   freed, reclaiming the `Box`.
4. The trampoline function is monomorphized per `F`, so it can cast
   the `void*` arg back to the correct type without runtime dispatch.

This means closures passed to `set_client_hello_callback`,
`set_servername_callback`, etc. have their lifetime tied to the
`SslContext` — no manual cleanup needed.

## How .NET handles CRL on Linux

.NET's `OpenSslX509ChainProcessor` does **not** delegate CRL checking
to OpenSSL's built-in verification. Instead it manages CRL/OCSP at the
application level on top of OpenSSL primitives:

1. **Per-cert CRL download** — For each cert in the chain,
   `OpenSslCrlCache.AddCrlForCertificate()` downloads the CRL from the
   certificate's CRL Distribution Point (CDP) extension and caches it
   to a local directory.

2. **Store mutation per chain build** — Downloaded CRLs are added to
   the `X509Store` before re-running verification via
   `X509StoreCtxRebuildChain()`. The store is mutated per chain build,
   not at TLS acceptor construction time.

3. **OCSP as fallback** — If CRL is unavailable or expired, .NET falls
   back to OCSP:
   - Checks for stapled OCSP first (`X509ChainHasStapledOcsp`).
   - Then tries online OCSP via HTTP GET to the AIA OCSP endpoint.
   - Caches OCSP responses to disk.

4. **Verify callback for error collection** — Uses
   `X509StoreCtxSetVerifyCallback` to collect all errors (always
   returns 1 to continue), then processes them in managed C# code to
   decide what to report. This allows .NET to implement its own
   revocation logic (e.g., treating expired CRL differently from
   missing CRL).

5. **Revocation modes**:
   - `NoCheck` — skip revocation checking entirely.
   - `Online` — download CRLs/OCSP if not cached.
   - `Offline` — only use previously cached CRLs/OCSP.

### Store build cost

.NET creates a fresh `X509Store` per `X509Chain.Build()` call, which
runs during the TLS handshake when client certs are required. The
per-chain store references cached system trust certs
(`OpenSslCachedSystemStoreProvider`) via ref count bump, not deep copy.

| Operation | Cost |
|---|---|
| `X509_STORE_new()` + init | ~100ns |
| Add ~150 system root CAs (ref count per cert) | ~1-5μs |
| `X509_STORE_CTX_new()` + init | ~100ns |
| `add_crl()` per cert (in-memory) | ~100ns per CRL |
| CRL from disk cache | ~10-100μs |
| CRL download (cache miss) | ~50-500ms (network) |

Total per-handshake cost with client cert validation:

| Scenario | Cost |
|---|---|
| No client cert | 0 (no chain build) |
| Client cert, no revocation check | ~5-10μs |
| Client cert, CRL cached on disk | ~20-100μs |
| Client cert, CRL cache miss | ~50-500ms |

### Comparison with `ArcSwap` + `set_verify_cert_store()`

.NET creates a fresh store per chain build, adds CRLs to it, then
discards it. Our proposal pre-builds the store with current CRLs and
swaps it into each handshake via `ArcSwap`.

| | .NET | `ArcSwap` proposal |
|---|---|---|
| Store lifetime | Per chain build | Shared, swapped periodically |
| CRL loading | Download + add per cert | Pre-loaded, swapped in batch |
| Concurrency | No sharing, each chain owns its store | Shared across connections, lock-free |
| Per-handshake cost | ~5-100μs | ~10ns |
| CRL freshness | Per-handshake (if Online) | Depends on reload interval |

Both approaches agree: **don't rely on a frozen store from acceptor
construction time**.

### Key takeaways

- .NET does **not** use OpenSSL's `CApath` directory-based CRL lookup.
  It manages its own download cache.
- CRL logic is implemented in C# on top of OpenSSL primitives, not
  delegated to OpenSSL's built-in revocation checking.
- Per-request store mutation (adding CRLs to `X509Store` per chain
  build) is a valid production pattern used by a major runtime.
- This confirms that managing CRL state at the application level
  (rather than relying on OpenSSL's frozen `X509Store`) is viable.
  The `set_client_hello_callback` + `ssl.set_verify_cert_store()`
  approach follows the same spirit.
