# tonic-tls
![ci](https://github.com/youyuanwu/tonic-tls/actions/workflows/CI.yml/badge.svg)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://raw.githubusercontent.com/youyuanwu/tonic-tls/main/LICENSE)
[![Crates.io](https://img.shields.io/crates/v/tonic-tls)](https://crates.io/crates/tonic-tls)
[![Documentation](https://docs.rs/tonic-tls/badge.svg)](https://docs.rs/tonic-tls)
[![codecov](https://codecov.io/gh/youyuanwu/tonic-tls/graph/badge.svg?token=770RTTJ6R4)](https://codecov.io/gh/youyuanwu/tonic-tls)

`tonic-tls` provides various tls backend plugins for grpc crate [tonic](https://github.com/hyperium/tonic).

* [native-tls](https://github.com/sfackler/rust-native-tls)
* [rustls](https://github.com/rustls/rustls)
* [openssl](https://github.com/sfackler/rust-openssl)
* [schannel](https://github.com/steffengy/schannel-rs)

## Get Started
Add to Cargo.toml of your project.
Choose openssl backend:
```toml
tonic-tls = { version="*" , default-features = false, features = ["openssl"] }
# change features to "rustls" etc to enable other backends.
```

## Examples
For full examples see [examples](./tonic-tls-tests/examples/)
```rs
// Server example for openssl:
async fn run_openssl_tonic_server(
    tcp_s: tonic::transport::server::TcpIncoming,
    tls_acceptor: openssl::ssl::SslAcceptor,
) {
    let incoming = tonic_tls::openssl::TlsIncoming::new(tcp_s, tls_acceptor);
    let greeter = OpensslGreeter {};
    tonic::transport::Server::builder()
        .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
        .serve_with_incoming(incoming)
        .await
        .unwrap();
}
```

```rs
// client example for openssl:
async fn connect_tonic_channel(ssl_conn: openssl::ssl::SslConnector) {
    let ch: tonic::transport::Channel= tonic_tls::new_endpoint()
        .connect_with_connector(tonic_tls::openssl::TlsConnector::new(
            "https://localhost:12345".parse().unwrap(),
            ssl_conn,
            "localhost".to_string(),
        ))
        .await.unwrap();
}
```

# License
This project is licensed under the MIT license.