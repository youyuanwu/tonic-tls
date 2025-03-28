use tonic::{Request, Response, Status};
use tonic_tls_tests::helloworld::{HelloReply, HelloRequest};

#[derive(Default)]
pub struct MyGreeter {}

#[tonic::async_trait]
impl tonic_tls_tests::helloworld::greeter_server::Greeter for MyGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        println!("Got a request from {:?}", request.remote_addr());

        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}

pub fn create_openssl_acceptor(
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
    // Accept all client requests
    acceptor.set_verify_callback(openssl::ssl::SslVerifyMode::NONE, |ok, ctx| {
        if !ok {
            let e = ctx.error();
            println!("verify failed in server: {}", e);
        }
        true
    });
    acceptor.build()
}

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // generate test cert
    let (cert, key) =
        tonic_tls_tests::openssl_gen::mk_self_signed_cert(vec!["localhost".to_string()]).unwrap();
    // create tls
    let tls_acceptor = create_openssl_acceptor(&cert, &key);

    let addr = "[::1]:50051".parse().unwrap();
    let greeter = MyGreeter::default();

    println!("GreeterServer listening on {}", addr);
    let tcp_incoming = tonic::transport::server::TcpIncoming::bind(addr).unwrap();
    let incoming = tonic_tls::openssl::TlsIncoming::new(tcp_incoming, tls_acceptor);

    tonic::transport::Server::builder()
        .add_service(tonic_tls_tests::helloworld::greeter_server::GreeterServer::new(greeter))
        .serve_with_incoming_shutdown(incoming, async {
            tokio::signal::ctrl_c().await.unwrap();
        })
        .await?;
    Ok(())
}
