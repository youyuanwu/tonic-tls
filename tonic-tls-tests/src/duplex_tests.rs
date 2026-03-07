use std::pin::Pin;
use std::task::{Context, Poll};

use futures::Stream;
use tokio::io::DuplexStream;
use tokio::sync::mpsc;
use tonic_tls::{Incoming, Transport};

/// In-memory transport using [`tokio::io::DuplexStream`].
/// Each `connect` creates a duplex pair and sends the server half
/// through a channel so that [`DuplexIncoming`] can yield it.
#[derive(Clone)]
pub struct DuplexTransport {
    tx: mpsc::Sender<DuplexStream>,
}

impl Transport for DuplexTransport {
    type Io = DuplexStream;
    type Error = std::io::Error;

    async fn connect(&self, _uri: &tonic::transport::Uri) -> Result<Self::Io, Self::Error> {
        let (client, server) = tokio::io::duplex(1024);
        self.tx
            .send(server)
            .await
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::ConnectionRefused))?;
        Ok(client)
    }
}

/// In-memory incoming stream backed by a channel of [`DuplexStream`].
pub struct DuplexIncoming {
    rx: mpsc::Receiver<DuplexStream>,
}

impl Stream for DuplexIncoming {
    type Item = Result<DuplexStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.rx.poll_recv(cx).map(|opt| opt.map(Ok))
    }
}

impl Incoming for DuplexIncoming {
    type Io = DuplexStream;
    type Error = std::io::Error;
}

/// Create a paired duplex transport and incoming.
fn duplex_pair() -> (DuplexTransport, DuplexIncoming) {
    let (tx, rx) = mpsc::channel(16);
    (DuplexTransport { tx }, DuplexIncoming { rx })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::helloworld;
    use crate::tests::make_test_cert2;

    use tonic::{Request, Response, Status};

    pub struct GreeterImpl;

    #[tonic::async_trait]
    impl helloworld::greeter_server::Greeter for GreeterImpl {
        async fn say_hello(
            &self,
            request: Request<helloworld::HelloRequest>,
        ) -> Result<Response<helloworld::HelloReply>, Status> {
            Ok(Response::new(helloworld::HelloReply {
                message: format!("Hello {}!", request.into_inner().name),
            }))
        }
    }

    #[tokio::test]
    async fn openssl_duplex_test() {
        let (cert, key) = make_test_cert2(vec!["localhost".to_string()]);

        // Build acceptor
        let acceptor = {
            let mut builder =
                openssl::ssl::SslAcceptor::mozilla_intermediate(openssl::ssl::SslMethod::tls())
                    .unwrap();
            builder.set_private_key(&key).unwrap();
            builder.set_certificate(&cert).unwrap();
            builder.check_private_key().unwrap();
            builder.set_alpn_select_callback(|_ssl, alpn| {
                openssl::ssl::select_next_proto(tonic_tls::openssl::ALPN_H2_WIRE, alpn)
                    .ok_or(openssl::ssl::AlpnError::NOACK)
            });
            builder.build()
        };

        // Build client connector
        let mut connector_builder =
            openssl::ssl::SslConnector::builder(openssl::ssl::SslMethod::tls()).unwrap();
        connector_builder
            .cert_store_mut()
            .add_cert(cert.clone())
            .unwrap();
        connector_builder
            .set_alpn_protos(tonic_tls::openssl::ALPN_H2_WIRE)
            .unwrap();
        let ssl_connector = connector_builder.build();

        let (transport, incoming) = duplex_pair();

        // Start server
        let token = tokio_util::sync::CancellationToken::new();
        let token_cp = token.clone();
        let server_handle = tokio::spawn(async move {
            let tls_incoming = tonic_tls::openssl::TlsIncoming::new(incoming, acceptor);
            tonic::transport::Server::builder()
                .add_service(helloworld::greeter_server::GreeterServer::new(GreeterImpl))
                .serve_with_incoming_shutdown(
                    tls_incoming,
                    async move { token_cp.cancelled().await },
                )
                .await
                .unwrap();
        });

        // Connect client
        let ep = tonic::transport::Endpoint::from_static("https://localhost");
        let channel = ep
            .connect_with_connector(tonic_tls::openssl::TlsConnector::new(
                transport,
                ssl_connector,
                "localhost".to_string(),
            ))
            .await
            .expect("failed to connect");

        // Send RPC
        let mut client = helloworld::greeter_client::GreeterClient::new(channel);
        let resp = client
            .say_hello(Request::new(helloworld::HelloRequest {
                name: "Duplex".into(),
            }))
            .await
            .unwrap();

        assert_eq!(resp.into_inner().message, "Hello Duplex!");

        // Shutdown
        token.cancel();
        server_handle.await.unwrap();
    }
}
