use super::support::{
    TestProvider,
    backend::{CountingFactory, OpenSsl, Rustls, TestBackend},
    certs::identity,
    grpc::{await_peer_identity, connector, peer_identity, start_server},
    wait_for_snapshot,
};
use crate::{helloworld, tests::make_test_cert};
use std::{
    net::Shutdown,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::sync::oneshot;
use tonic::transport::Endpoint;
use tonic_tls_xds::{CertificateData, Identity};

mod crl;
mod openssl;
mod raw_tcp;
mod rustls;

async fn client_identity_rotates_on_channel_reconnect<B: TestBackend>() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let (first, first_key) = make_test_cert(vec!["client-1".into()]);
    let (second, second_key) = make_test_cert(vec!["client-2".into()]);
    let (first_connection_tx, first_connection_rx) = oneshot::channel();
    let (endpoint, shutdown, task) = start_server(
        &server,
        &server_key,
        &[&first, &second],
        Some(first_connection_tx),
    )
    .await;
    let provider = TestProvider::new(
        CertificateData::new(None, Some(identity(&first, &first_key)), None).unwrap(),
    );
    let connector = connector::<B>(&endpoint, B::factory(&[&server], None), provider.clone());
    let channel = endpoint.connect_with_connector(connector).await.unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    let first_connection = first_connection_rx.await.unwrap();

    provider.data.store(Arc::new(
        CertificateData::new(None, Some(identity(&second, &second_key)), None).unwrap(),
    ));

    // Close only the authenticated first connection after publishing the update.
    // Reuse the original channel; replacement connections are never aged out.
    first_connection.shutdown(Shutdown::Both).unwrap();
    drop(first_connection);
    await_peer_identity(&mut client, "1").await;
    drop(client);
    shutdown.cancel();
    task.await.unwrap();
}

async fn client_file_watcher_rotates_identity<B: TestBackend>() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let (first, first_key) = make_test_cert(vec!["client-1".into()]);
    let (second, second_key) = make_test_cert(vec!["client-2".into()]);
    let dir = tempfile::tempdir().unwrap();
    let cert_path = dir.path().join("client.pem");
    let key_path = dir.path().join("client.key");
    std::fs::write(&cert_path, b"").unwrap();
    std::fs::write(&key_path, first_key.serialize_pem()).unwrap();
    let (tx, rx) = oneshot::channel();
    let (endpoint, shutdown, task) =
        start_server(&server, &server_key, &[&first, &second], Some(tx)).await;
    let factory = B::factory(&[&server], None);
    let provider = Arc::new(
        tonic_tls_xds::FileWatcherProvider::new(tonic_tls_xds::FileWatcherConfig {
            certificate_file: Some(cert_path.clone()),
            private_key_file: Some(key_path.clone()),
            refresh_interval: Duration::from_millis(20),
            ..Default::default()
        })
        .await
        .unwrap(),
    );

    // The watcher accepts readable bytes; connector construction rejects the empty chain.
    let error = tonic_tls_xds::ReloadableTlsConnector::new(
        tonic_tls::TcpTransport::from_endpoint(&endpoint),
        provider.clone(),
        factory.clone(),
    )
    .err()
    .expect("connector construction must reject an empty identity chain");
    B::assert_empty_identity(&error);

    std::fs::write(&cert_path, first.pem()).unwrap();
    let expected = identity(&first, &first_key);
    wait_for_snapshot(provider.as_ref(), "the initial identity", |data| {
        data.identity() == Some(&expected)
    })
    .await;
    let builds = Arc::new(AtomicUsize::new(0));
    let connector = tonic_tls_xds::ReloadableTlsConnector::new(
        tonic_tls::TcpTransport::from_endpoint(&endpoint),
        provider.clone(),
        CountingFactory {
            inner: factory,
            builds: builds.clone(),
        },
    )
    .unwrap();
    let channel = endpoint
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    let first_connection = rx.await.unwrap();
    let channel = endpoint
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut other = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut other).await.unwrap(), "0");
    drop(other);
    assert_eq!(
        builds.load(Ordering::Relaxed),
        1,
        "unchanged snapshots must reuse the connector"
    );

    // A half-applied update is published, but cannot fall back to the cached pair.
    std::fs::write(&cert_path, second.pem()).unwrap();
    let expected = identity(&second, &first_key);
    wait_for_snapshot(provider.as_ref(), "the half-updated identity", |data| {
        data.identity() == Some(&expected)
    })
    .await;
    assert!(
        endpoint
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    // Wait for both files, then confirm the actual peer identity after recovery.
    std::fs::write(&key_path, second_key.serialize_pem()).unwrap();
    let expected = identity(&second, &second_key);
    wait_for_snapshot(provider.as_ref(), "the rotated identity", |data| {
        data.identity() == Some(&expected)
    })
    .await;
    first_connection.shutdown(Shutdown::Both).unwrap();
    drop(first_connection);
    await_peer_identity(&mut client, "1").await;
    drop(client);
    drop(provider);
    shutdown.cancel();
    task.await.unwrap();
}

// Trust must switch servers without changing the client's mTLS identity.
async fn client_provider_rotates_roots_and_preserves_base_identity<B: TestBackend>() {
    let (server1, server1_key) = make_test_cert(vec!["localhost".into()]);
    let (server2, server2_key) = make_test_cert(vec!["localhost".into()]);
    let (client_cert, client_key) = make_test_cert(vec!["client".into()]);
    let (endpoint1, shutdown1, task1) =
        start_server(&server1, &server1_key, &[&client_cert], None).await;
    let (endpoint2, shutdown2, task2) =
        start_server(&server2, &server2_key, &[&client_cert], None).await;
    let factory = B::factory(&[&server2], Some(identity(&client_cert, &client_key)));
    let provider = TestProvider::new(
        CertificateData::new(Some(server1.pem().into_bytes()), None, None).unwrap(),
    );
    let connector = connector::<B>(&endpoint1, factory, provider.clone());

    let channel = endpoint1
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    assert!(
        endpoint2
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );

    provider.fail.store(true, Ordering::Relaxed);
    assert!(
        endpoint1
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );
    provider.fail.store(false, Ordering::Relaxed);
    provider.data.store(Arc::new(
        CertificateData::new(Some(b"bad roots".to_vec()), None, None).unwrap(),
    ));
    assert!(
        endpoint1
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");

    provider.data.store(Arc::new(
        CertificateData::new(Some(server2.pem().into_bytes()), None, None).unwrap(),
    ));
    let channel = endpoint2
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut second_client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut second_client).await.unwrap(), "0");
    assert!(endpoint1.connect_with_connector(connector).await.is_err());
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    drop(client);
    drop(second_client);
    shutdown1.cancel();
    shutdown2.cancel();
    task1.await.unwrap();
    task2.await.unwrap();
}

// Prime the cache, reject unavailable/invalid snapshots, then verify recovery.
async fn client_provider_errors_do_not_fall_back_to_cached_credentials<B: TestBackend>() {
    let (server, server_key) = make_test_cert(vec!["localhost".into()]);
    let (client_cert, client_key) = make_test_cert(vec!["client".into()]);
    let (endpoint, shutdown, task) =
        start_server(&server, &server_key, &[&client_cert], None).await;
    let provider = TestProvider::new(
        CertificateData::new(
            Some(server.pem().into_bytes()),
            Some(identity(&client_cert, &client_key)),
            None,
        )
        .unwrap(),
    );
    let good = provider.data.load_full();
    let connector = connector::<B>(&endpoint, B::factory(&[&server], None), provider.clone());
    let channel = endpoint
        .connect_with_connector(connector.clone())
        .await
        .unwrap();
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    drop(client);

    provider.fail.store(true, Ordering::Relaxed);
    assert!(
        endpoint
            .connect_with_connector(connector.clone())
            .await
            .is_err()
    );
    provider.fail.store(false, Ordering::Relaxed);

    provider.data.store(Arc::new(
        CertificateData::new(
            None,
            Some(Identity::from_pem(client_cert.pem(), b"not a key")),
            None,
        )
        .unwrap(),
    ));
    assert!(
        endpoint
            .connect_with_connector(connector.clone())
            .await
            .is_err(),
        "invalid snapshot should fail, not reuse the cached configuration",
    );
    provider.data.store(good);
    let channel = endpoint
        .connect_with_connector(connector)
        .await
        .expect("a valid snapshot should recover after an error");
    let mut client = helloworld::greeter_client::GreeterClient::new(channel);
    assert_eq!(peer_identity(&mut client).await.unwrap(), "0");
    drop(client);
    shutdown.cancel();
    task.await.unwrap();
}

// Construction checks parsing and key pairing without opening sockets.
fn client_connector_rejects_invalid_material_at_construction<B: TestBackend>() {
    let (cert, key) = make_test_cert(vec!["client".into()]);
    let wrong_key = rcgen::KeyPair::generate().unwrap();
    let endpoint = Endpoint::from_static("https://localhost");
    let factory = B::factory(&[&cert], None);
    let valid = CertificateData::new(None, Some(identity(&cert, &key)), None).unwrap();
    assert!(
        tonic_tls_xds::ReloadableTlsConnector::new(
            tonic_tls::TcpTransport::from_endpoint(&endpoint),
            TestProvider::new(valid),
            factory.clone(),
        )
        .is_ok(),
        "valid identity-only material must construct with the same base roots",
    );

    for (name, data) in [
        (
            "empty certificate chain",
            CertificateData::new(
                None,
                Some(Identity::from_pem(b"", key.serialize_pem())),
                None,
            )
            .unwrap(),
        ),
        (
            "mismatched certificate and key",
            CertificateData::new(None, Some(identity(&cert, &wrong_key)), None).unwrap(),
        ),
        (
            "malformed certificate",
            CertificateData::new(
                None,
                Some(Identity::from_pem(
                    b"not a certificate",
                    key.serialize_pem(),
                )),
                None,
            )
            .unwrap(),
        ),
        (
            "malformed private key",
            CertificateData::new(
                None,
                Some(Identity::from_pem(cert.pem(), b"not a key")),
                None,
            )
            .unwrap(),
        ),
        (
            "empty roots",
            CertificateData::new(Some(Vec::new()), None, None).unwrap(),
        ),
        (
            "malformed roots",
            CertificateData::new(Some(b"not a CA certificate".to_vec()), None, None).unwrap(),
        ),
    ] {
        let result = tonic_tls_xds::ReloadableTlsConnector::new(
            tonic_tls::TcpTransport::from_endpoint(&endpoint),
            TestProvider::new(data),
            factory.clone(),
        );
        assert!(result.is_err(), "{name} should be rejected at construction");
    }
}

macro_rules! rotation_tests {
    ($module:ident, $backend:ty) => {
        mod $module {
            use super::*;

            #[tokio::test]
            async fn identity_rotates_on_channel_reconnect() {
                client_identity_rotates_on_channel_reconnect::<$backend>().await;
            }

            #[tokio::test]
            async fn file_watcher_rotates_identity() {
                client_file_watcher_rotates_identity::<$backend>().await;
            }

            #[tokio::test]
            async fn roots_rotate_preserving_base_identity() {
                client_provider_rotates_roots_and_preserves_base_identity::<$backend>().await;
            }

            #[tokio::test]
            async fn provider_errors_do_not_fall_back() {
                client_provider_errors_do_not_fall_back_to_cached_credentials::<$backend>().await;
            }

            #[test]
            fn invalid_material_fails_at_construction() {
                client_connector_rejects_invalid_material_at_construction::<$backend>();
            }
        }
    };
}

rotation_tests!(rustls_rotation, Rustls);
rotation_tests!(openssl_rotation, OpenSsl);
