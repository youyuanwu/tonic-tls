use std::time::Duration;

use hyper::Uri;

/// Data and options needed from [Endpoint](tonic::transport::Endpoint)
/// in tls connector layer.
pub(crate) struct TcpOpt {
    pub(crate) uri: Uri,
    pub(crate) keep_alive_duration: Option<Duration>,
    pub(crate) tcp_keepalive_interval: Option<Duration>,
    pub(crate) tcp_keepalive_retries: Option<u32>,
    pub(crate) no_delay: bool,
}

impl TcpOpt {
    /// Extract relevant info from endpoint.
    pub(crate) fn from_ep(ep: &tonic::transport::Endpoint) -> Self {
        Self {
            keep_alive_duration: ep.get_tcp_keepalive(),
            tcp_keepalive_interval: ep.get_tcp_keepalive_interval(),
            tcp_keepalive_retries: ep.get_tcp_keepalive_retries(),
            no_delay: ep.get_tcp_nodelay(),
            uri: ep.uri().clone(),
        }
    }

    /// Apply the tcp options to stream.
    pub(crate) fn apply_opt(&self, tcp: &tokio::net::TcpStream) -> std::io::Result<()> {
        if self.no_delay {
            tcp.set_nodelay(true)?;
        }
        if let Some(keepalive) = Self::make_keepalive(
            self.keep_alive_duration,
            self.tcp_keepalive_interval,
            self.tcp_keepalive_retries,
        ) {
            let sf = socket2::SockRef::from(&tcp);
            sf.set_tcp_keepalive(&keepalive)?
        }
        Ok(())
    }

    fn make_keepalive(
        keepalive_time: Option<Duration>,
        keepalive_interval: Option<Duration>,
        keepalive_retries: Option<u32>,
    ) -> Option<socket2::TcpKeepalive> {
        let mut dirty = false;
        let mut keepalive = socket2::TcpKeepalive::new();
        if let Some(t) = keepalive_time {
            keepalive = keepalive.with_time(t);
            dirty = true;
        }
        if let Some(t) = keepalive_interval {
            keepalive = keepalive.with_interval(t);
            dirty = true;
        }
        if let Some(r) = keepalive_retries {
            keepalive = keepalive.with_retries(r);
            dirty = true;
        }
        dirty.then_some(keepalive)
    }
}
