use super::backend::TestBackend;
use crate::helloworld::{self, HelloRequest};
use std::{sync::Arc, time::Duration};
use tonic::{
    Status,
    transport::{Channel, Endpoint},
};
use tonic_tls_xds::CertificateProvider;

pub(in crate::reloadable_tests) fn connector<B: TestBackend>(
    endpoint: &Endpoint,
    factory: B::Factory,
    provider: Arc<dyn CertificateProvider>,
) -> tonic_tls_xds::ReloadableTlsConnector<tokio::net::TcpStream, B::Connector> {
    tonic_tls_xds::ReloadableTlsConnector::new(
        tonic_tls::TcpTransport::from_endpoint(endpoint),
        provider,
        factory,
    )
    .unwrap()
}

pub(in crate::reloadable_tests) async fn peer_identity(
    client: &mut helloworld::greeter_client::GreeterClient<Channel>,
) -> Result<String, Status> {
    Ok(client
        .say_hello(HelloRequest {
            name: "rotation".into(),
        })
        .await?
        .into_inner()
        .message)
}

pub(in crate::reloadable_tests) async fn await_peer_identity(
    client: &mut helloworld::greeter_client::GreeterClient<Channel>,
    expected: &str,
) {
    let mut attempts = 0;
    let mut last_error = None;
    let result = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            attempts += 1;
            match peer_identity(client).await {
                Ok(peer) => {
                    assert_eq!(peer, expected);
                    break;
                }
                Err(status) => {
                    // The first RPC can race with tonic noticing the closed connection.
                    assert!(
                        status.code() == tonic::Code::Unavailable
                            || (matches!(
                                status.code(),
                                tonic::Code::Unknown | tonic::Code::Cancelled
                            ) && std::error::Error::source(&status).is_some()),
                        "unexpected reconnect error: {status:?}",
                    );
                    last_error = Some(status);
                    tokio::time::sleep(Duration::from_millis(10)).await;
                }
            }
        }
    })
    .await;
    assert!(
        result.is_ok(),
        "same channel did not reconnect with identity {expected} after {attempts} attempts; last error: {last_error:?}",
    );
}
