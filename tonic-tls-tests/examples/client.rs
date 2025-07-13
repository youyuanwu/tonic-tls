use tonic_tls_tests::helloworld;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), tonic_tls::Error> {
    // Create ssl connector
    let ssl_conn = make_ssl_conn();
    // Connect to remote
    let ch = connect_tonic_channel(ssl_conn).await?;
    let mut client = helloworld::greeter_client::GreeterClient::new(ch);
    // Send request
    let request = tonic::Request::new(helloworld::HelloRequest {
        name: "Tonic".into(),
    });
    let resp = client.say_hello(request).await.unwrap();
    println!("RESPONSE={resp:?}");
    Ok(())
}

async fn connect_tonic_channel(
    ssl_conn: openssl::ssl::SslConnector,
) -> Result<tonic::transport::Channel, tonic_tls::Error> {
    let ep = tonic::transport::Endpoint::from_static("https://localhost:50051");
    ep.connect_with_connector(tonic_tls::openssl::TlsConnector::new(
        &ep,
        ssl_conn,
        "localhost".to_string(), // server has cert with dns localhost
    ))
    .await
    .map_err(tonic_tls::Error::from)
}

fn make_ssl_conn() -> openssl::ssl::SslConnector {
    let mut connector =
        openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
    // ignore server cert validation errors.
    connector.set_verify_callback(openssl::ssl::SslVerifyMode::PEER, |ok, ctx| {
        if !ok {
            let e = ctx.error();
            println!("verify failed : {e}");
        }
        true
    });
    connector
        .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
        .unwrap();
    connector.build()
}
