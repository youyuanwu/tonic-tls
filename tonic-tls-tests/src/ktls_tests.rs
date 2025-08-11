//! Ktls based tests.
//! Ktls is not enabled, because some systems does not have openssl compiled with ktls flag.
//! The ktls streams should work without ktls enabled.
use std::net::SocketAddr;

use super::*;
use crate::helloworld::{self, HelloReply, HelloRequest};
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{Channel, server::TcpIncoming},
};

pub struct OpensslKtlsGreeter {}

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for OpensslKtlsGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let conn_info = request
            .extensions()
            .get::<tonic_tls::openssl_ktls::SslConnectInfo>();
        let remote_addr = conn_info.as_ref().and_then(|i| i.get_ref().remote_addr());
        let peer_certs = conn_info.and_then(|i| i.peer_certs());
        let ktls_recv_enabled = conn_info.is_some_and(|i| i.ktls_recv_enabled());
        let ktls_send_enabled = conn_info.is_some_and(|i| i.ktls_send_enabled());
        println!(
            "Got a request from {remote_addr:?} with certs: {peer_certs:?}, ktls_recv_enabled: {ktls_recv_enabled}, ktls_send_enabled: {ktls_send_enabled}"
        );

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}
async fn connect_openssl_ktls_tonic_channel(
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
            println!("verify failed : {e}");
        }
        ok
    });
    connector
        .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
        .unwrap();
    let connector = connector.build();
    // use dns to test resolve
    let url = format!("https://localhost:{}", addr.port());
    let dnsname = "localhost".to_string();
    let ep = tonic::transport::Endpoint::from_shared(url).unwrap();
    ep.connect_with_connector(tonic_tls::openssl_ktls::TlsConnector::new(
        &ep, connector, dnsname,
    ))
    .await
    .map_err(tonic_tls::Error::from)
}
pub fn create_openssl_ktls_acceptor(
    cert: &openssl::x509::X509,
    key: &openssl::pkey::PKey<openssl::pkey::Private>,
) -> openssl::ssl::SslAcceptor {
    let mut acceptor =
        openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls()).unwrap();
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
            println!("verify failed : {e}");
        }
        ok
    });
    acceptor.build()
}

async fn run_openssl_ktls_tonic_server(
    token: CancellationToken,
    tcp_s: TcpIncoming,
    tls_acceptor: openssl::ssl::SslAcceptor,
) {
    let incoming = tonic_tls::openssl_ktls::TlsIncoming::new(tcp_s, tls_acceptor);
    let greeter = OpensslKtlsGreeter {};
    tonic::transport::Server::builder()
        .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
        .serve_with_incoming_shutdown(incoming, async move { token.cancelled().await })
        .await
        .unwrap();
}
#[tokio::test]
async fn openssl_ktls_test() {
    // Generate a certificate that's valid for "localhost" and "hello.world.example"
    let (cert, key) = tests::make_test_cert2(vec![
        "hello.world.example".to_string(),
        "localhost".to_string(),
    ]);
    let (cert2, _) = tests::make_test_cert2(vec![
        "hello.world.example2".to_string(),
        "localhost2".to_string(),
    ]);

    // get a random port on localhost from os
    let (listener, addr) = tests::create_listener_server().await;

    let sv_token = CancellationToken::new();
    let sv_token_cp = sv_token.clone();

    let acceptor = create_openssl_ktls_acceptor(&cert, &key);
    // start server in background
    let sv_h = tokio::spawn(async move {
        run_openssl_ktls_tonic_server(sv_token_cp, TcpIncoming::from(listener), acceptor).await
    });

    println!("running server on {addr}");

    // wait a bit for server to boot up.
    tokio::time::sleep(std::time::Duration::from_secs(1)).await;

    // send a request with a wrong cert and verify it fails
    {
        let e = connect_openssl_ktls_tonic_channel(&cert2, addr)
            .await
            .expect_err("unexpected success");
        // there is a double wrappring of the error of ssl Error
        let src = e.source().unwrap().source().unwrap();
        let ssl_e = src.downcast_ref::<::openssl_ktls::error::Error>().unwrap();
        // Check generic ssl error. The detail of the error should be server cert untrusted, which is unimportant,
        // since the test case here only aims to cause an ssl failure between client and server.
        assert_eq!(ssl_e.code(), openssl::ssl::ErrorCode::SSL);
        let inner_e = ssl_e.ssl_error().unwrap().errors();
        assert_eq!(inner_e.len(), 1);
    }

    // get client and send request
    let ch = connect_openssl_ktls_tonic_channel(&cert, addr)
        .await
        .expect("cannot connect");
    let mut client = helloworld::greeter_client::GreeterClient::new(ch);
    let request = tonic::Request::new(helloworld::HelloRequest {
        name: "Tonic".into(),
    });
    let resp = client.say_hello(request).await.unwrap();
    println!("RESPONSE={resp:?}");

    // stop server
    sv_token.cancel();
    sv_h.await.unwrap();
}
