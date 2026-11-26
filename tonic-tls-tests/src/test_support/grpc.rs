use super::backend::{Rustls, ServerBackend};
use crate::{
    helloworld::{self, HelloReply, HelloRequest},
    tests::create_listener_server,
};
use futures::Stream;
use rustls::pki_types::CertificateDer;
use std::{
    net::TcpStream,
    pin::Pin,
    task::{Context, Poll},
    time::Duration,
};
use tokio::sync::oneshot;
use tokio_util::sync::CancellationToken;
use tonic::{
    Request, Response, Status,
    transport::{Endpoint, server::TcpIncoming},
};

pub(crate) struct TestIncoming {
    pub inner: TcpIncoming,
    pub first_connection: Option<oneshot::Sender<TcpStream>>,
}

impl Stream for TestIncoming {
    type Item = Result<tokio::net::TcpStream, std::io::Error>;

    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        let next = std::task::ready!(Pin::new(&mut self.inner).poll_next(cx));
        Poll::Ready(next.map(|stream| {
            let stream = stream?;
            let Some(sender) = self.first_connection.take() else {
                return Ok(stream);
            };
            // Both handles refer to the same socket, allowing a test-triggered shutdown.
            let stream = stream.into_std()?;
            sender
                .send(stream.try_clone()?)
                .expect("test must receive the first accepted connection");
            tokio::net::TcpStream::from_std(stream)
        }))
    }
}

impl tonic_tls::Incoming for TestIncoming {
    type Io = tokio::net::TcpStream;
    type Error = std::io::Error;
}

struct PeerGreeter<B> {
    clients: Vec<CertificateDer<'static>>,
    name: Option<&'static str>,
    backend: std::marker::PhantomData<B>,
}

#[tonic::async_trait]
impl<B: ServerBackend> helloworld::greeter_server::Greeter for PeerGreeter<B> {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let leaf = B::peer_leaf(&request)?;
        // Report the expected-cert index of the actual TLS peer's leaf certificate.
        // With [first, second], "0" means original and "1" means rotated.
        let index = self
            .clients
            .iter()
            .position(|cert| cert == &leaf)
            .ok_or_else(|| Status::unauthenticated("unexpected client certificate"))?;
        Ok(Response::new(HelloReply {
            message: self.name.map_or_else(|| index.to_string(), str::to_owned),
        }))
    }
}

pub(crate) async fn start_server(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    clients: &[&rcgen::Certificate],
    first_connection: Option<oneshot::Sender<TcpStream>>,
) -> (Endpoint, CancellationToken, tokio::task::JoinHandle<()>) {
    start_server_for::<Rustls>(cert, key, clients, first_connection).await
}

pub(crate) async fn start_server_for<B: ServerBackend>(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    clients: &[&rcgen::Certificate],
    first_connection: Option<oneshot::Sender<TcpStream>>,
) -> (Endpoint, CancellationToken, tokio::task::JoinHandle<()>) {
    start_server_inner::<B>(cert, key, clients, first_connection, None).await
}

pub(crate) async fn start_named_server<B: ServerBackend>(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    clients: &[&rcgen::Certificate],
    name: &'static str,
) -> (Endpoint, CancellationToken, tokio::task::JoinHandle<()>) {
    start_server_inner::<B>(cert, key, clients, None, Some(name)).await
}

async fn start_server_inner<B: ServerBackend>(
    cert: &rcgen::Certificate,
    key: &rcgen::KeyPair,
    clients: &[&rcgen::Certificate],
    first_connection: Option<oneshot::Sender<TcpStream>>,
    name: Option<&'static str>,
) -> (Endpoint, CancellationToken, tokio::task::JoinHandle<()>) {
    let greeter = PeerGreeter::<B> {
        clients: clients.iter().map(|cert| cert.der().clone()).collect(),
        name,
        backend: std::marker::PhantomData,
    };
    let (listener, addr) = create_listener_server().await;
    let shutdown = CancellationToken::new();
    let signal = shutdown.clone();
    let incoming = B::incoming(
        TestIncoming {
            inner: TcpIncoming::from(listener),
            first_connection,
        },
        cert,
        key,
        Some(clients),
    );
    let task = tokio::spawn(async move {
        tonic::transport::Server::builder()
            .add_service(helloworld::greeter_server::GreeterServer::new(greeter))
            .serve_with_incoming_shutdown(incoming, signal.cancelled_owned())
            .await
            .unwrap();
    });
    let endpoint = Endpoint::from_shared(format!("https://{addr}"))
        .unwrap()
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(5));
    (endpoint, shutdown, task)
}
