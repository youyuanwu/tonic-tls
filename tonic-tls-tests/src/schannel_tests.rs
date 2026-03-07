use std::net::SocketAddr;

use crate::helloworld::{self, HelloReply, HelloRequest};

use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{
        Channel,
        server::{TcpConnectInfo, TcpIncoming},
    },
};

pub struct SchannelGreeter {}

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for SchannelGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let conn_info = request
            .extensions()
            .get::<tonic_tls::schannel::SslConnectInfo<TcpConnectInfo>>();
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

fn make_test_cert_schannel(
    subject_alt_names: Vec<String>,
) -> (
    schannel::cert_context::CertContext,
    schannel::cert_context::CertContext,
) {
    // Seems like rcgen cert with schannel does not work.
    let (cert, key) = crate::tests::make_test_cert2(subject_alt_names);
    let bytes = cert.to_pem().unwrap();
    let key_bytes = key.private_key_to_pem_pkcs8().unwrap();
    let cert =
        schannel::cert_context::CertContext::from_pem(std::str::from_utf8(bytes.as_ref()).unwrap())
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
        ));
    }

    let mut store = schannel::cert_store::Memory::new()?.into_store();

    let cert =
        schannel::cert_context::CertContext::from_pem(std::str::from_utf8(pem).map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "leaf cert contains invalid utf8",
            )
        })?)?;
    let name = gen_container_name();
    let mut options = schannel::crypt_prov::AcquireOptions::new();
    options.container(&name);
    let type_ = schannel::crypt_prov::ProviderType::rsa_full();

    let mut container = match options.acquire(type_) {
        Ok(container) => container,
        Err(_) => options.new_keyset(true).acquire(type_)?,
    };
    container.import().import_pkcs8_pem(key)?;

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
    builder.request_application_protocols(&[tonic_tls::ALPN_H2]);

    let url = format!("https://{addr}");
    let creds = schannel::schannel_cred::SchannelCred::builder()
        .acquire(schannel::schannel_cred::Direction::Outbound)
        .unwrap();
    let ep = tonic::transport::Endpoint::from_shared(url).unwrap();

    let transport = tonic_tls::TcpTransport::from_endpoint(&ep);
    ep.connect_with_connector(tonic_tls::schannel::TlsConnector::new(
        transport, builder, creds,
    ))
    .await
    .map_err(tonic_tls::Error::from)
}
pub fn create_schannel_acceptor() -> schannel::tls_stream::Builder {
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
    builder.request_application_protocols(&[tonic_tls::ALPN_H2]);
    // TODO: peer cert validation is missing in schannel crate?
    // Possibly this: https://github.com/steffengy/schannel-rs/issues/91
    builder.domain("localhost");
    builder
}

async fn run_schannel_tonic_server(
    token: CancellationToken,
    tcp_s: TcpIncoming,
    tls_acceptor: schannel::tls_stream::Builder,
    creds: schannel::schannel_cred::SchannelCred,
) {
    let incoming = tonic_tls::schannel::TlsIncoming::new(tcp_s, tls_acceptor, creds);

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
    let (listener, addr) = crate::tests::create_listener_server().await;

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
        run_schannel_tonic_server(sv_token_cp, TcpIncoming::from(listener), acceptor, creds).await
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
    println!("RESPONSE={resp:?}");

    // stop server
    sv_token.cancel();
    sv_h.await.unwrap();
}
