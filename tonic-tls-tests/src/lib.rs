pub mod openssl_gen;
pub mod helloworld {
    tonic::include_proto!("helloworld");
}
/// Only run this on linux
#[cfg(all(test, target_os = "linux"))]
mod ktls_tests;

#[cfg(test)]
mod duplex_tests;

#[cfg(test)]
mod rustls_tests;

#[cfg(test)]
mod ntls_tests;

#[cfg(test)]
mod openssl_tests;

#[cfg(test)]
mod cert_rotation_tests;

#[cfg(all(test, target_os = "windows"))]
mod schannel_tests;

#[cfg(test)]
pub(crate) mod tests {
    // creates a listener on a random port from os, and return the addr.
    pub async fn create_listener_server() -> (tokio::net::TcpListener, std::net::SocketAddr) {
        let addr: std::net::SocketAddr = "127.0.0.1:0".parse().unwrap();
        let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
        let local_addr = listener.local_addr().unwrap();
        (listener, local_addr)
    }

    pub fn make_test_cert(subject_alt_names: Vec<String>) -> (rcgen::Certificate, rcgen::KeyPair) {
        use rcgen::generate_simple_self_signed;
        let key_pair = generate_simple_self_signed(subject_alt_names).unwrap();
        (key_pair.cert, key_pair.signing_key)
    }

    /// ring does not support RSA so rcgen does not support it. Windows does not support elliplica curve?
    /// So we use openssl to generate.
    pub fn make_test_cert2(
        subject_alt_names: Vec<String>,
    ) -> (
        openssl::x509::X509,
        openssl::pkey::PKey<openssl::pkey::Private>,
    ) {
        let (cert, key) = crate::openssl_gen::mk_self_signed_cert(subject_alt_names).unwrap();
        (cert, key)
    }

    // run examples
    #[tokio::test]
    async fn example_test() {
        let curr_dir = std::env::current_dir().unwrap();
        println!("curr_dir: {curr_dir:?}");

        println!("launching server");

        let mut child_server = std::process::Command::new("cargo")
            .arg("run")
            .arg("--example")
            .arg("helloworld-server")
            .stderr(std::process::Stdio::piped())
            .stdout(std::process::Stdio::piped())
            .spawn()
            .expect("Couldn't run server");

        tokio::time::sleep(std::time::Duration::from_secs(1)).await;

        println!("run client");
        let child_client = std::process::Command::new("cargo")
            .arg("run")
            .arg("--example")
            .arg("helloworld-client")
            .arg("--")
            .arg("--nocapture")
            .output()
            .expect("Couldn't run client");
        assert!(child_client.status.success());
        println!("client output: {child_client:?}");

        child_server.kill().expect("!kill");
        let server_out = child_server.wait_with_output().unwrap();
        // server kill may exit with code 1.
        println!("server output: {server_out:?}");
    }
}
