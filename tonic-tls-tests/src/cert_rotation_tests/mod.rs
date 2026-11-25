use crate::helloworld::{self, HelloReply, HelloRequest};
use tonic::{Request, Response, Status, transport::Channel};

mod openssl;
mod rustls;

pub struct RotationGreeter {}

#[tonic::async_trait]
impl helloworld::greeter_server::Greeter for RotationGreeter {
    async fn say_hello(
        &self,
        request: Request<HelloRequest>,
    ) -> Result<Response<HelloReply>, Status> {
        let reply = HelloReply {
            message: format!("Hello {}!", request.into_inner().name),
        };
        Ok(Response::new(reply))
    }
}

async fn assert_hello(channel: Channel, name: &str) {
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    let response = client
        .say_hello(Request::new(HelloRequest { name: name.into() }))
        .await
        .unwrap();
    assert_eq!(response.into_inner().message, format!("Hello {name}!"));
}
