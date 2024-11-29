pub mod openssl_gen;

#[cfg(test)]
mod tests {
    use std::net::SocketAddr;

    pub mod helloworld {
        tonic::include_proto!("helloworld");
    }

    // creates a listener on a random port from os, and return the addr.
    pub async fn create_listener_server() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        (listener, local_addr)
    }

    fn make_test_cert(subject_alt_names: Vec<String>) -> (rcgen::Certificate, rcgen::KeyPair) {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(subject_alt_names).unwrap();
        (cert, key_pair)
    }

    /// ring does not support RSA so rcgen does not support it. Windows does not support elliplica curve?
    /// So we use openssl to generate.
    fn make_test_cert2(
        subject_alt_names: Vec<String>,
    ) -> (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ) {
        let (cert, key) = crate::openssl_gen::mk_self_signed_cert(subject_alt_names).unwrap();
        // println!("debug: {}", key.private_key_to_pem_pkcs8().unwrap());
        (cert, key)
    }

    mod rustls_test {
        use std::{net::SocketAddr, sync::Arc};

        use super::helloworld::{self, HelloReply, HelloRequest};
        use rustls::pki_types::{CertificateDer, PrivateKeyDer};
        use tokio_stream::wrappers::TcpListenerStream;
        use tokio_util::sync::CancellationToken;
        use tonic::{
            transport::server::TcpConnectInfo, transport::Channel, Request, Response, Status,
        };
        pub struct RustlsGreeter {}

        #[tonic::async_trait]
        impl helloworld::greeter_server::Greeter for RustlsGreeter {
            async fn say_hello(
                &self,
                request: Request<HelloRequest>,
            ) -> Result<Response<HelloReply>, Status> {
                let remote_addr = request
                    .extensions()
                    .get::<tonic_tls::rustls::SslConnectInfo<TcpConnectInfo>>()
                    .and_then(|info| info.get_ref().remote_addr());
                println!("Got a request from {:?}", remote_addr);

                let reply = HelloReply {
                    message: format!("Hello {}!", request.into_inner().name),
                };
                Ok(Response::new(reply))
            }
        }

        async fn connect_rustls_tonic_channel(
            cert: &CertificateDer<'static>,
            addr: SocketAddr,
        ) -> Result<Channel, tonic_tls::Error> {
            use tokio_rustls::rustls::{pki_types::ServerName, ClientConfig, RootCertStore};

            let url = format!("https://{}", addr).parse().unwrap();
            let mut root_cert_store = RootCertStore::empty();
            root_cert_store.add(cert.clone()).unwrap();
            let config = ClientConfig::builder()
                .with_root_certificates(root_cert_store)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(Arc::new(config));
            let dnsname = ServerName::try_from("localhost").unwrap();

            tonic_tls::new_endpoint()
                .connect_with_connector(tonic_tls::rustls::connector(url, connector, dnsname))
                .await
                .map_err(tonic_tls::Error::from)
        }

        fn make_test_cert_rustls(
            subject_alt_names: Vec<String>,
        ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
            let (cert, key_pair) = super::make_test_cert(subject_alt_names);
            let cert = CertificateDer::from(cert);
            use rustls::pki_types::pem::PemObject;
            let key = PrivateKeyDer::from_pem(
                rustls::pki_types::pem::SectionKind::PrivateKey,
                key_pair.serialize_der().into(),
            )
            .unwrap();
            (cert, key)
        }

        pub fn create_rustls_acceptor(
            cert: &CertificateDer<'static>,
            key: &PrivateKeyDer<'static>,
        ) -> tokio_rustls::TlsAcceptor {
            let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
                tokio_rustls::rustls::crypto::ring::default_provider().into(),
            )
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(vec![cert.clone()], key.clone_key())
            .unwrap();
            tokio_rustls::TlsAcceptor::from(Arc::new(config))
        }

        // Run the tonic server on the current thread until token is cancelled.
        async fn run_rustls_tonic_server(
            token: CancellationToken,
            tcp_s: TcpListenerStream,
            tls_acceptor: tokio_rustls::TlsAcceptor,
        ) {
            let incoming = tonic_tls::rustls::incoming(tcp_s, tls_acceptor);

            let greeter = RustlsGreeter {};
            tonic::transport::Server::builder()
                .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
                .serve_with_incoming_shutdown(incoming, async move { token.cancelled().await })
                .await
                .unwrap();
        }

        #[tokio::test]
        async fn rustls_test() {
            // Generate a certificate that's valid for "localhost" and "hello.world.example"
            let (cert, key) = make_test_cert_rustls(vec![
                "hello.world.example".to_string(),
                "localhost".to_string(),
            ]);
            let (cert2, _) = make_test_cert_rustls(vec![
                "hello.world.example2".to_string(),
                "localhost2".to_string(),
            ]);
            // let cert2_cp = cert.clone();

            // get a random port on localhost from os
            let (listener, addr) = super::create_listener_server().await;

            let sv_token = CancellationToken::new();
            let sv_token_cp = sv_token.clone();

            let acceptor = create_rustls_acceptor(&cert, &key);
            // start server in background
            let sv_h = tokio::spawn(async move {
                run_rustls_tonic_server(sv_token_cp, TcpListenerStream::new(listener), acceptor)
                    .await
            });

            println!("running server on {addr}");

            // wait a bit for server to boot up.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // send a request with a wrong cert and verify it fails
            {
                let e = connect_rustls_tonic_channel(&cert2, addr)
                    .await
                    .expect_err("unexpected success");
                // there is a double wrappring of the error of ssl Error
                let src = e.source().unwrap().source().unwrap();
                // println!("debug error: {src:?}");
                let ssl_e = src.downcast_ref::<std::io::Error>().unwrap();
                assert_eq!(ssl_e.kind(), std::io::ErrorKind::InvalidData);
                let ssl_e = ssl_e
                    .get_ref()
                    .unwrap()
                    .downcast_ref::<rustls::Error>()
                    .unwrap();
                // check cert is invalid
                assert!(matches!(ssl_e, rustls::Error::InvalidCertificate(_)));
            }

            // get client and send request
            let ch = connect_rustls_tonic_channel(&cert, addr)
                .await
                .expect("cannot connect");
            let mut client = helloworld::greeter_client::GreeterClient::new(ch);
            let request = tonic::Request::new(helloworld::HelloRequest {
                name: "Tonic".into(),
            });
            let resp = client.say_hello(request).await.unwrap();
            println!("RESPONSE={:?}", resp);

            // stop server
            sv_token.cancel();
            sv_h.await.unwrap();
        }
    }

    mod ntls_test {
        use std::net::SocketAddr;

        use super::helloworld::{self, HelloReply, HelloRequest};
        use tokio_native_tls::native_tls;
        use tokio_stream::wrappers::TcpListenerStream;
        use tokio_util::sync::CancellationToken;
        use tonic::{
            transport::server::TcpConnectInfo, transport::Channel, Request, Response, Status,
        };
        pub struct NtlsGreeter {}

        #[tonic::async_trait]
        impl helloworld::greeter_server::Greeter for NtlsGreeter {
            async fn say_hello(
                &self,
                request: Request<HelloRequest>,
            ) -> Result<Response<HelloReply>, Status> {
                let remote_addr = request
                    .extensions()
                    .get::<tonic_tls::native::SslConnectInfo<TcpConnectInfo>>()
                    .and_then(|info| info.get_ref().remote_addr());
                println!("Got a request from {:?}", remote_addr);

                let reply = HelloReply {
                    message: format!("Hello {}!", request.into_inner().name),
                };
                Ok(Response::new(reply))
            }
        }
        fn make_test_cert_ntls(
            subject_alt_names: Vec<String>,
        ) -> (native_tls::Certificate, native_tls::Identity) {
            // Seems like rcgen cert with schannel does not work.
            let (cert, key) = super::make_test_cert2(subject_alt_names);
            let cert2 =
                native_tls::Certificate::from_pem(cert.to_pem().unwrap().as_slice()).unwrap();
            //let pkcs8 =
            let key = native_tls::Identity::from_pkcs8(
                cert.to_pem().unwrap().as_slice(),
                key.private_key_to_pem_pkcs8().unwrap().as_ref(),
            )
            .unwrap();
            (cert2, key)
        }

        pub fn create_ntls_acceptor(key: &native_tls::Identity) -> tokio_native_tls::TlsAcceptor {
            tokio_native_tls::TlsAcceptor::from(
                native_tls::TlsAcceptor::builder(key.clone())
                    .build()
                    .unwrap(),
            )
        }

        async fn connect_ntls_tonic_channel(
            cert: &native_tls::Certificate,
            addr: SocketAddr,
        ) -> Result<Channel, tonic_tls::Error> {
            let tc = native_tls::TlsConnector::builder()
                .disable_built_in_roots(true)
                .add_root_certificate(cert.clone())
                .build()
                .unwrap();
            let connector = tokio_native_tls::TlsConnector::from(tc);
            let url = format!("https://{}", addr).parse().unwrap();
            let dnsname = "localhost".to_string();
            tonic_tls::new_endpoint()
                .connect_with_connector(tonic_tls::native::connector(url, connector, dnsname))
                .await
                .map_err(tonic_tls::Error::from)
        }

        async fn run_ntls_tonic_server(
            token: CancellationToken,
            tcp_s: TcpListenerStream,
            tls_acceptor: tokio_native_tls::TlsAcceptor,
        ) {
            let incoming = tonic_tls::native::incoming(tcp_s, tls_acceptor);

            let greeter = NtlsGreeter {};
            tonic::transport::Server::builder()
                .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
                .serve_with_incoming_shutdown(incoming, async move { token.cancelled().await })
                .await
                .unwrap();
        }
        #[tokio::test]
        async fn ntls_test() {
            // Generate a certificate that's valid for "localhost" and "hello.world.example"
            let (cert, key) = make_test_cert_ntls(vec![
                "hello.world.example".to_string(),
                "localhost".to_string(),
            ]);
            let (cert2, _) = make_test_cert_ntls(vec![
                "hello.world.example2".to_string(),
                "localhost2".to_string(),
            ]);

            // get a random port on localhost from os
            let (listener, addr) = super::create_listener_server().await;

            let sv_token = CancellationToken::new();
            let sv_token_cp = sv_token.clone();

            let acceptor = create_ntls_acceptor(&key);
            // start server in background
            let sv_h = tokio::spawn(async move {
                run_ntls_tonic_server(sv_token_cp, TcpListenerStream::new(listener), acceptor).await
            });

            println!("running server on {addr}");

            // wait a bit for server to boot up.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // send a request with a wrong cert and verify it fails
            {
                let e = connect_ntls_tonic_channel(&cert2, addr)
                    .await
                    .expect_err("unexpected success");
                // there is a double wrappring of the error of ssl Error
                let src = e.source().unwrap().source().unwrap();
                println!("debug error: {src:?}");
                // depends on the platform the ntls error is different,
                // so we don't check it here.
                // let ssl_e = src.downcast_ref::<std::io::Error>().unwrap();
            }

            // get client and send request
            let ch = connect_ntls_tonic_channel(&cert, addr)
                .await
                .expect("cannot connect");
            let mut client = helloworld::greeter_client::GreeterClient::new(ch);
            let request = tonic::Request::new(helloworld::HelloRequest {
                name: "Tonic".into(),
            });
            let resp = client.say_hello(request).await.unwrap();
            println!("RESPONSE={:?}", resp);

            // stop server
            sv_token.cancel();
            sv_h.await.unwrap();
        }
    }

    mod openssl_test {
        use super::helloworld::{self, HelloReply, HelloRequest};
        use super::*;
        use tokio_stream::wrappers::TcpListenerStream;
        use tokio_util::sync::CancellationToken;
        use tonic::{
            transport::server::TcpConnectInfo, transport::Channel, Request, Response, Status,
        };

        pub struct OpensslGreeter {}

        #[tonic::async_trait]
        impl helloworld::greeter_server::Greeter for OpensslGreeter {
            async fn say_hello(
                &self,
                request: Request<HelloRequest>,
            ) -> Result<Response<HelloReply>, Status> {
                let remote_addr = request
                    .extensions()
                    .get::<tonic_tls::openssl::SslConnectInfo<TcpConnectInfo>>()
                    .and_then(|info| info.get_ref().remote_addr());
                println!("Got a request from {:?}", remote_addr);

                let reply = HelloReply {
                    message: format!("Hello {}!", request.into_inner().name),
                };
                Ok(Response::new(reply))
            }
        }
        async fn connect_openssl_tonic_channel(
            cert: &openssl::x509::X509,
            addr: SocketAddr,
        ) -> Result<Channel, tonic_tls::Error> {
            let mut connector =
                openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
            connector.cert_store_mut().add_cert(cert.clone()).unwrap();
            connector.add_client_ca(cert).unwrap();
            connector.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |ok, ctx| {
                if !ok {
                    let e = ctx.error();
                    println!("verify failed : {}", e);
                }
                ok
            });
            connector
                .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
                .unwrap();
            let connector = connector.build();
            let url = format!("https://{}", addr).parse().unwrap();
            let dnsname = "localhost".to_string();
            tonic_tls::new_endpoint()
                .connect_with_connector(tonic_tls::openssl::connector(url, connector, dnsname))
                .await
                .map_err(tonic_tls::Error::from)
        }
        pub fn create_openssl_acceptor(
            cert: &openssl::x509::X509,
            key: &openssl::pkey::PKey<openssl::pkey::Private>,
        ) -> openssl::ssl::SslAcceptor {
            let mut acceptor =
                openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                    .unwrap();
            acceptor.set_private_key(key).unwrap();
            acceptor.set_certificate(cert).unwrap();
            acceptor.cert_store_mut().add_cert(cert.clone()).unwrap();
            acceptor.check_private_key().unwrap();
            acceptor.set_alpn_select_callback(|_ssl, alpn| {
                openssl::ssl::select_next_proto(tonic_tls::openssl::ALPN_H2_WIRE, alpn)
                    .ok_or(openssl::ssl::AlpnError::NOACK)
            });
            // require client to present cert with matching subject name.
            acceptor.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |ok, ctx| {
                if !ok {
                    let e = ctx.error();
                    println!("verify failed : {}", e);
                }
                ok
            });
            acceptor.build()
        }

        async fn run_openssl_tonic_server(
            token: CancellationToken,
            tcp_s: TcpListenerStream,
            tls_acceptor: openssl::ssl::SslAcceptor,
        ) {
            let incoming = tonic_tls::openssl::incoming(tcp_s, tls_acceptor);

            let greeter = OpensslGreeter {};
            tonic::transport::Server::builder()
                .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
                .serve_with_incoming_shutdown(incoming, async move { token.cancelled().await })
                .await
                .unwrap();
        }
        #[tokio::test]
        async fn openssl_test() {
            // Generate a certificate that's valid for "localhost" and "hello.world.example"
            let (cert, key) = make_test_cert2(vec![
                "hello.world.example".to_string(),
                "localhost".to_string(),
            ]);
            let (cert2, _) = make_test_cert2(vec![
                "hello.world.example2".to_string(),
                "localhost2".to_string(),
            ]);

            // get a random port on localhost from os
            let (listener, addr) = create_listener_server().await;

            let sv_token = CancellationToken::new();
            let sv_token_cp = sv_token.clone();

            let acceptor = create_openssl_acceptor(&cert, &key);
            // start server in background
            let sv_h = tokio::spawn(async move {
                run_openssl_tonic_server(sv_token_cp, TcpListenerStream::new(listener), acceptor)
                    .await
            });

            println!("running server on {addr}");

            // wait a bit for server to boot up.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // send a request with a wrong cert and verify it fails
            {
                let e = connect_openssl_tonic_channel(&cert2, addr)
                    .await
                    .expect_err("unexpected success");
                // there is a double wrappring of the error of ssl Error
                let src = e.source().unwrap().source().unwrap();
                let ssl_e = src.downcast_ref::<openssl::ssl::Error>().unwrap();
                // Check generic ssl error. The detail of the error should be server cert untrusted, which is unimportant,
                // since the test case here only aims to cause an ssl failure between client and server.
                assert_eq!(ssl_e.code(), openssl::ssl::ErrorCode::SSL);
                let inner_e = ssl_e.ssl_error().unwrap().errors();
                assert_eq!(inner_e.len(), 1);
            }

            // get client and send request
            let ch = connect_openssl_tonic_channel(&cert, addr)
                .await
                .expect("cannot connect");
            let mut client = helloworld::greeter_client::GreeterClient::new(ch);
            let request = tonic::Request::new(helloworld::HelloRequest {
                name: "Tonic".into(),
            });
            let resp = client.say_hello(request).await.unwrap();
            println!("RESPONSE={:?}", resp);

            // stop server
            sv_token.cancel();
            sv_h.await.unwrap();
        }
    }

    #[cfg(target_os = "windows")]
    mod schannel_test {
        use std::net::SocketAddr;

        use super::helloworld::{self, HelloReply, HelloRequest};

        use tokio_stream::wrappers::TcpListenerStream;
        use tokio_util::sync::CancellationToken;
        use tonic::{
            transport::server::TcpConnectInfo, transport::Channel, Request, Response, Status,
        };

        pub struct SchannelGreeter {}

        #[tonic::async_trait]
        impl helloworld::greeter_server::Greeter for SchannelGreeter {
            async fn say_hello(
                &self,
                request: Request<HelloRequest>,
            ) -> Result<Response<HelloReply>, Status> {
                let remote_addr = request
                    .extensions()
                    .get::<tonic_tls::schannel::SslConnectInfo<TcpConnectInfo>>()
                    .and_then(|info| info.get_ref().remote_addr());
                println!("Got a request from {:?}", remote_addr);

                let reply = HelloReply {
                    message: format!("Hello {}!", request.into_inner().name),
                };
                Ok(Response::new(reply))
            }
        }

        fn make_test_cert_schannel(
            subject_alt_names: Vec<String>,
        ) -> (
            schannel::cert_context::CertContext,
            schannel::cert_context::CertContext,
        ) {
            // Seems like rcgen cert with schannel does not work.
            let (cert, key) = super::make_test_cert2(subject_alt_names);
            let bytes = cert.to_pem().unwrap();
            let key_bytes = key.private_key_to_pem_pkcs8().unwrap();
            let cert = schannel::cert_context::CertContext::from_pem(
                std::str::from_utf8(bytes.as_ref()).unwrap(),
            )
            .unwrap();
            let key = in_mem_key(&bytes, &key_bytes).unwrap();
            (cert, key)
        }

        // The name of the container must be unique to have multiple active keys.
        fn gen_container_name() -> String {
            use std::sync::atomic::{AtomicUsize, Ordering};
            static COUNTER: AtomicUsize = AtomicUsize::new(0);
            format!("tonic-tls-test-{}", COUNTER.fetch_add(1, Ordering::Relaxed))
        }

        /// modified from native tls.
        pub fn in_mem_key(
            pem: &[u8],
            key: &[u8],
        ) -> Result<schannel::cert_context::CertContext, std::io::Error> {
            if !key.starts_with(b"-----BEGIN PRIVATE KEY-----") {
                return Err(std::io::Error::new(
                    std::io::ErrorKind::InvalidInput,
                    "not a PKCS#8 key",
                )
                .into());
            }

            let mut store = schannel::cert_store::Memory::new()?.into_store();

            let cert = schannel::cert_context::CertContext::from_pem(
                std::str::from_utf8(pem).map_err(|_| {
                    std::io::Error::new(
                        std::io::ErrorKind::InvalidInput,
                        "leaf cert contains invalid utf8",
                    )
                })?,
            )?;
            let name = gen_container_name();
            let mut options = schannel::crypt_prov::AcquireOptions::new();
            options.container(&name);
            let type_ = schannel::crypt_prov::ProviderType::rsa_full();

            let mut container = match options.acquire(type_) {
                Ok(container) => container,
                Err(_) => options.new_keyset(true).acquire(type_)?,
            };
            container.import().import_pkcs8_pem(&key)?;

            cert.set_key_prov_info()
                .container(&name)
                .type_(type_)
                .keep_open(true)
                .key_spec(schannel::cert_context::KeySpec::key_exchange())
                .set()?;
            let context = store.add_cert(&cert, schannel::cert_store::CertAdd::Always)?;
            Ok(context)
        }

        async fn connect_schannel_tonic_channel(
            root: &schannel::cert_context::CertContext,
            addr: SocketAddr,
        ) -> Result<Channel, tonic_tls::Error> {
            let mut builder = schannel::tls_stream::Builder::new();
            builder.verify_callback(|ctx| {
                if let Err(e) = ctx.result() {
                    println!("schannel client verify error: {e}");
                }
                ctx.result()
            });
            builder.domain("localhost");
            // trust roots.
            let mut cert_store = schannel::cert_store::Memory::new().unwrap().into_store();
            cert_store
                .add_cert(root, schannel::cert_store::CertAdd::Always)
                .unwrap();
            builder.cert_store(cert_store);

            let connector = tokio_schannel::TlsConnector::new(builder);
            let url = format!("https://{}", addr).parse().unwrap();
            let creds = schannel::schannel_cred::SchannelCred::builder()
                .acquire(schannel::schannel_cred::Direction::Outbound)
                .unwrap();
            tonic_tls::new_endpoint()
                .connect_with_connector(tonic_tls::schannel::connector(url, connector, creds))
                .await
                .map_err(tonic_tls::Error::from)
        }
        pub fn create_schannel_acceptor() -> tokio_schannel::TlsAcceptor {
            let mut builder = schannel::tls_stream::Builder::new();
            builder.verify_callback(|ctx| {
                match ctx.result() {
                    Ok(_) => {}
                    Err(e) => {
                        println!("schannel server accept error {e}");
                        panic!("acceptor error")
                    }
                };
                Ok(())
            });
            // TODO: peer cert validation is missing in schannel crate?
            // Possibly this: https://github.com/steffengy/schannel-rs/issues/91
            builder.domain("localhost");
            tokio_schannel::TlsAcceptor::new(builder)
        }

        async fn run_schannel_tonic_server(
            token: CancellationToken,
            tcp_s: TcpListenerStream,
            tls_acceptor: tokio_schannel::TlsAcceptor,
            creds: schannel::schannel_cred::SchannelCred,
        ) {
            let incoming = tonic_tls::schannel::incoming(tcp_s, tls_acceptor, creds);

            let greeter = SchannelGreeter {};
            tonic::transport::Server::builder()
                .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
                .serve_with_incoming_shutdown(incoming, async move { token.cancelled().await })
                .await
                .unwrap();
        }
        #[tokio::test]
        async fn schannel_test() {
            // Generate a certificate that's valid for "localhost" and "hello.world.example"
            let (cert, key) = make_test_cert_schannel(vec![
                "hello.world.example".to_string(),
                "localhost".to_string(),
            ]);
            let (cert2, _key2) = make_test_cert_schannel(vec![
                "hello.world.example2".to_string(),
                "localhost2".to_string(),
            ]);

            // get a random port on localhost from os
            let (listener, addr) = super::create_listener_server().await;

            let sv_token = CancellationToken::new();
            let sv_token_cp = sv_token.clone();

            // TODO: server verify cert chain is missing?
            let creds = schannel::schannel_cred::SchannelCred::builder()
                .cert(key.clone())
                .acquire(schannel::schannel_cred::Direction::Inbound)
                .unwrap();
            let acceptor = create_schannel_acceptor();
            // start server in background
            let sv_h = tokio::spawn(async move {
                run_schannel_tonic_server(
                    sv_token_cp,
                    TcpListenerStream::new(listener),
                    acceptor,
                    creds,
                )
                .await
            });

            println!("running server on {addr}");

            // wait a bit for server to boot up.
            tokio::time::sleep(std::time::Duration::from_secs(1)).await;

            // TODO: server root chain is not configured.
            // send a request with a wrong cert and verify it fails
            {
                let e = connect_schannel_tonic_channel(&cert2, addr)
                    .await
                    .expect_err("unexpected success");
                // there is a double wrappring of the error of ssl Error
                let src = e.source().unwrap().source().unwrap();
                let ssl_e = src.downcast_ref::<std::io::Error>().unwrap();
                let raw_error = 0x800b0109_u32; // server cert not trusted.
                assert_eq!(ssl_e.raw_os_error().unwrap(), raw_error as i32);
            }

            // get client and send request
            let ch = connect_schannel_tonic_channel(&cert, addr)
                .await
                .expect("cannot connect");
            let mut client = helloworld::greeter_client::GreeterClient::new(ch);
            let request = tonic::Request::new(helloworld::HelloRequest {
                name: "Tonic".into(),
            });
            let resp = client.say_hello(request).await.unwrap();
            println!("RESPONSE={:?}", resp);

            // stop server
            sv_token.cancel();
            sv_h.await.unwrap();
        }

        // TODO: move
        // #[tokio::test]
        // async fn test_schannel() {
        //     let (_, key) = make_test_cert_schannel(vec![
        //         "hello.world.example".to_string(),
        //         "localhost".to_string(),
        //     ]);
        //     // open listener
        //     let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        //     let addr = listener.local_addr().unwrap();

        //     // run server
        //     let server_h = tokio::spawn(async move {
        //         let creds = schannel::schannel_cred::SchannelCred::builder()
        //             .cert(key)
        //             .acquire(schannel::schannel_cred::Direction::Inbound)
        //             .unwrap();
        //         let builder = schannel::tls_stream::Builder::new();
        //         let mut acceptor = tokio_schannel::TlsAcceptor::new(builder);
        //         let (tcp_stream, _) = listener.accept().await.unwrap();
        //         let mut tls_stream = acceptor.accept(creds, tcp_stream).await.unwrap();
        //         let mut buf = [0_u8; 1024];
        //         let len = tokio::io::AsyncReadExt::read(&mut tls_stream, &mut buf)
        //             .await
        //             .unwrap();
        //         assert_eq!(len, 3);
        //         assert_eq!(buf[..3], [1, 2, 3]);
        //     });

        //     // sleep wait for server
        //     tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        //     // run client
        //     let client_h = tokio::spawn(async move {
        //         let stream = tokio::net::TcpStream::connect(&addr).await.unwrap();
        //         let creds = schannel::schannel_cred::SchannelCred::builder()
        //             .acquire(schannel::schannel_cred::Direction::Outbound)
        //             .unwrap();
        //         let mut builder = schannel::tls_stream::Builder::new();
        //         builder.verify_callback(|_| {
        //             // ignore errors
        //             Ok(())
        //         });
        //         builder.domain("localhost");
        //         let mut tls_connector = tokio_schannel::TlsConnector::new(builder);

        //         let mut tls_stream = tls_connector.connect(creds, stream).await.unwrap();
        //         let len = tokio::io::AsyncWriteExt::write(&mut tls_stream, &[1, 2, 3])
        //             .await
        //             .unwrap();
        //         assert_eq!(len, 3);
        //     });

        //     client_h.await.unwrap();
        //     server_h.await.unwrap();
        // }
    }
}
