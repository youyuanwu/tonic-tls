use std::{net::SocketAddr, time::Duration};

use crate::helloworld::{self, HelloReply, HelloRequest};
use tokio_native_tls::native_tls;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{
        Channel,
        server::{TcpConnectInfo, TcpIncoming},
    },
};

pub struct NtlsGreeter {}

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for NtlsGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let conn_info = request
            .extensions()
            .get::<tonic_tls::native::SslConnectInfo<TcpConnectInfo>>();
        let remote_addr = conn_info.as_ref().and_then(|i| i.get_ref().remote_addr());
        let peer_certs = conn_info.and_then(|i| i.peer_certs());
        println!(
            "Got a request from {remote_addr:?} with certs: {}",
            peer_certs.is_some()
        );

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
    let (cert, key) = crate::tests::make_test_cert2(subject_alt_names);
    let cert2 = native_tls::Certificate::from_pem(cert.to_pem().unwrap().as_slice()).unwrap();
    let key = native_tls::Identity::from_pkcs8(
        cert.to_pem().unwrap().as_slice(),
        key.private_key_to_pem_pkcs8().unwrap().as_ref(),
    )
    .unwrap();
    (cert2, key)
}

pub fn create_ntls_acceptor(
    key: &native_tls::Identity,
) -> tokio_native_tls::native_tls::TlsAcceptor {
    // TODO: native tls does not support server side alpn.
    native_tls::TlsAcceptor::builder(key.clone())
        .build()
        .unwrap()
}

async fn connect_ntls_tonic_channel(
    cert: &native_tls::Certificate,
    addr: SocketAddr,
) -> Result<Channel, tonic_tls::Error> {
    let tc = native_tls::TlsConnector::builder()
        .disable_built_in_roots(true)
        .add_root_certificate(cert.clone())
        .request_alpns(&[std::str::from_utf8(tonic_tls::ALPN_H2).unwrap()])
        .build()
        .unwrap();
    let url = format!("https://{addr}");
    let dnsname = "localhost".to_string();
    let ep = tonic::transport::Endpoint::from_shared(url)
        .unwrap()
        .tcp_keepalive(Some(Duration::from_secs(5)))
        .tcp_keepalive_interval(Some(Duration::from_secs(3)))
        .tcp_keepalive_retries(Some(3));
    let transport = tonic_tls::TcpTransport::from_endpoint(&ep);
    ep.connect_with_connector(tonic_tls::native::TlsConnector::new(transport, tc, dnsname))
        .await
        .map_err(tonic_tls::Error::from)
}

async fn run_ntls_tonic_server(
    token: CancellationToken,
    tcp_s: TcpIncoming,
    tls_acceptor: tokio_native_tls::native_tls::TlsAcceptor,
) {
    let incoming = tonic_tls::native::TlsIncoming::new(tcp_s, tls_acceptor);

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
    let (listener, addr) = crate::tests::create_listener_server().await;

    let sv_token = CancellationToken::new();
    let sv_token_cp = sv_token.clone();

    let acceptor = create_ntls_acceptor(&key);
    // start server in background
    let sv_h = tokio::spawn(async move {
        run_ntls_tonic_server(sv_token_cp, TcpIncoming::from(listener), acceptor).await
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
    println!("RESPONSE={resp:?}");

    // stop server
    sv_token.cancel();
    sv_h.await.unwrap();
}
