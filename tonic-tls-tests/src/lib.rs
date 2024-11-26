pub mod openssl_gen;

#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use helloworld::{HelloReply, HelloRequest};
    use rustls::pki_types::{CertificateDer, PrivateKeyDer};
    use tokio_native_tls::native_tls;
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_util::sync::CancellationToken;
    use tonic::{
        transport::{server::TcpConnectInfo, Channel},
        Request, Response, Status,
    };

    pub mod helloworld {
        tonic::include_proto!("helloworld");
    }

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
        let connector = TlsConnector::from(Arc::new(config));
        let dnsname = ServerName::try_from("localhost").unwrap();

        tonic_tls::new_endpoint()
            .connect_with_connector(tonic_tls::rustls::connector(url, connector, dnsname))
            .await
            .map_err(tonic_tls::Error::from)
    }

    async fn connect_ntls_tonic_channel(
        cert: &native_tls::Certificate,
        addr: SocketAddr,
    ) -> Result<Channel, tonic_tls::Error> {
        let tc = native_tls::TlsConnector::builder()
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

    // creates a listener on a random port from os, and return the addr.
    pub async fn create_listener_server() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        (listener, local_addr)
    }

    pub fn create_rustls_acceptor(
        cert: &CertificateDer<'static>,
        key: &PrivateKeyDer<'static>,
    ) -> TlsAcceptor {
        let config = tokio_rustls::rustls::ServerConfig::builder_with_provider(
            tokio_rustls::rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.clone_key())
        .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    pub fn create_ntls_acceptor(key: &native_tls::Identity) -> tokio_native_tls::TlsAcceptor {
        tokio_native_tls::TlsAcceptor::from(
            native_tls::TlsAcceptor::builder(key.clone())
                .build()
                .unwrap(),
        )
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

    fn make_test_cert(subject_alt_names: Vec<String>) -> (rcgen::Certificate, rcgen::KeyPair) {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(subject_alt_names).unwrap();
        (cert, key_pair)
    }

    fn make_test_cert_rustls(
        subject_alt_names: Vec<String>,
    ) -> (CertificateDer<'static>, PrivateKeyDer<'static>) {
        let (cert, key_pair) = make_test_cert(subject_alt_names);
        let cert = CertificateDer::from(cert);
        use rustls::pki_types::pem::PemObject;
        let key = PrivateKeyDer::from_pem(
            rustls::pki_types::pem::SectionKind::PrivateKey,
            key_pair.serialize_der().into(),
        )
        .unwrap();
        (cert, key)
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

    fn make_test_cert_ntls(
        subject_alt_names: Vec<String>,
    ) -> (native_tls::Certificate, native_tls::Identity) {
        // Seems like rcgen cert with schannel does not work.
        let (cert, key) = make_test_cert2(subject_alt_names);
        let cert2 = native_tls::Certificate::from_pem(cert.to_pem().unwrap().as_slice()).unwrap();
        //let pkcs8 =
        let key = native_tls::Identity::from_pkcs8(
            cert.to_pem().unwrap().as_slice(),
            key.private_key_to_pem_pkcs8().unwrap().as_ref(),
        )
        .unwrap();
        (cert2, key)
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
        let (listener, addr) = create_listener_server().await;

        let sv_token = CancellationToken::new();
        let sv_token_cp = sv_token.clone();

        let acceptor = create_rustls_acceptor(&cert, &key);
        // start server in background
        let sv_h = tokio::spawn(async move {
            run_rustls_tonic_server(sv_token_cp, TcpListenerStream::new(listener), acceptor).await
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
        let (listener, addr) = create_listener_server().await;

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
            run_openssl_tonic_server(sv_token_cp, TcpListenerStream::new(listener), acceptor).await
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
