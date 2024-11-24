#[cfg(test)]
mod tests {
    use std::{net::SocketAddr, sync::Arc};

    use helloworld::{HelloReply, HelloRequest};
    use rustls::{
        pki_types::{pem::PemObject, CertificateDer, PrivateKeyDer, ServerName},
        ClientConfig, RootCertStore,
    };
    use tokio::net::TcpListener;
    use tokio_rustls::{TlsAcceptor, TlsConnector};
    use tokio_stream::wrappers::TcpListenerStream;
    use tokio_util::sync::CancellationToken;
    use tonic::{
        transport::{server::TcpConnectInfo, Channel},
        Request, Response, Status,
    };
    use tonic_rustls::SslConnectInfo;

    pub mod helloworld {
        tonic::include_proto!("helloworld");
    }

    pub struct MyGreeter {}

    #[tonic::async_trait]
    impl helloworld::greeter_server::Greeter for MyGreeter {
        async fn say_hello(
            &self,
            request: Request<HelloRequest>,
        ) -> Result<Response<HelloReply>, Status> {
            let remote_addr = request
                .extensions()
                .get::<SslConnectInfo<TcpConnectInfo>>()
                .and_then(|info| info.get_ref().remote_addr());
            println!("Got a request from {:?}", remote_addr);

            let reply = HelloReply {
                message: format!("Hello {}!", request.into_inner().name),
            };
            Ok(Response::new(reply))
        }
    }

    async fn connect_test_tonic_channel(
        cert: &CertificateDer<'static>,
        addr: SocketAddr,
    ) -> Channel {
        let url = format!("https://{}", addr).parse().unwrap();
        let mut root_cert_store = RootCertStore::empty();
        root_cert_store.add(cert.clone()).unwrap();
        let config = ClientConfig::builder()
            .with_root_certificates(root_cert_store)
            .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(config));
        let dnsname = ServerName::try_from("localhost").unwrap();

        tonic_rustls::new_endpoint()
            .connect_with_connector(tonic_rustls::connector(url, connector, dnsname))
            .await
            .expect("cannot connect")
    }

    // creates a listener on a random port from os, and return the addr.
    pub async fn create_listener_server() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        (listener, local_addr)
    }

    pub fn create_tls_acceptor(
        cert: &CertificateDer<'static>,
        key: &PrivateKeyDer<'static>,
    ) -> TlsAcceptor {
        let config = rustls::ServerConfig::builder_with_provider(
            rustls::crypto::ring::default_provider().into(),
        )
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.clone()], key.clone_key())
        .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    // Run the tonic server on the current thread until token is cancelled.
    async fn run_tonic_server(
        token: CancellationToken,
        listener: TcpListener,
        cert: &CertificateDer<'static>,
        key: &PrivateKeyDer<'static>,
    ) {
        let greeter = MyGreeter {};
        // build acceptor
        let acceptor = create_tls_acceptor(cert, key);

        let incoming = tonic_rustls::incoming(TcpListenerStream::new(listener), acceptor);

        tonic::transport::Server::builder()
            .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
            .serve_with_incoming_shutdown(incoming, async move { token.cancelled().await })
            .await
            .unwrap();
    }

    #[tokio::test]
    async fn basic() {
        use rcgen::{generate_simple_self_signed, CertifiedKey};
        // Generate a certificate that's valid for "localhost" and "hello.world.example"
        let subject_alt_names = vec!["hello.world.example".to_string(), "localhost".to_string()];

        let CertifiedKey { cert, key_pair } =
            generate_simple_self_signed(subject_alt_names).unwrap();
        let cert = CertificateDer::from(cert);
        let key = PrivateKeyDer::from_pem(
            rustls::pki_types::pem::SectionKind::PrivateKey,
            key_pair.serialize_der().into(),
        )
        .unwrap();
        let cert_cp = cert.clone();
        // println!("{}", cert.pem());
        // println!("{}", key_pair.serialize_pem());

        // get a random port on localhost from os
        let (listener, addr) = create_listener_server().await;

        let sv_token = CancellationToken::new();
        let sv_token_cp = sv_token.clone();
        // start server in background
        let sv_h =
            tokio::spawn(
                async move { run_tonic_server(sv_token_cp, listener, &cert_cp, &key).await },
            );

        println!("running server on {addr}");

        // wait a bit for server to boot up.
        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        // TODO: enable this once the failure check is upstreamed.
        // send a request with a wrong cert and verify it fails
        // {
        //     let e = connect_test_tonic_channel(addr, &test_ca, &test_cert, &test_key)
        //         .await
        //         .expect_err("unexpected success");
        //     // there is a double wrappring of the error of ssl Error
        //     let src = e.source().unwrap().source().unwrap();
        //     let ssl_e = src.downcast_ref::<openssl::ssl::Error>().unwrap();
        //     // Check generic ssl error. The detail of the error should be server cert untrusted, which is unimportant,
        //     // since the test case here only aims to cause an ssl failure between client and server.
        //     assert_eq!(ssl_e.code(), openssl::ssl::ErrorCode::SSL);
        //     let inner_e = ssl_e.ssl_error().unwrap().errors();
        //     assert_eq!(inner_e.len(), 1);
        // }

        // get client and send request
        let ch = connect_test_tonic_channel(&cert, addr).await;
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
