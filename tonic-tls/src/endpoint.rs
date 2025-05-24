use std::time::Duration;

use hyper::Uri;

pub(crate) struct TcpOpt {
    pub(crate) uri: Uri,
    // interval is not supported in tonic yet.
    pub(crate) keep_alive_duration: Option<Duration>,
    pub(crate) no_delay: bool,
}

impl TcpOpt {
    pub(crate) fn from_ep(ep: &tonic::transport::Endpoint) -> Self {
        Self {
            keep_alive_duration: ep.get_tcp_keepalive(),
            no_delay: ep.get_tcp_nodelay(),
            uri: ep.uri().clone(),
        }
    }

    // apply the tcp options to stream.
    pub(crate) fn apply_opt(&self, tcp: &tokio::net::TcpStream) -> std::io::Result<()> {
        if self.no_delay {
            tcp.set_nodelay(true)?;
        }
        if let Some(keep_alive_duration) = self.keep_alive_duration {
            let ka = socket2::TcpKeepalive::new().with_time(keep_alive_duration);
            let sf = socket2::SockRef::from(&tcp);
            sf.set_tcp_keepalive(&ka)?
        }
        Ok(())
    }
}
