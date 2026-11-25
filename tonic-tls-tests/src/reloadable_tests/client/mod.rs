use super::support::backend::{OpenSsl, Rustls};

mod crl;
mod grpc;
mod openssl;
mod raw_tcp;
mod rustls;

macro_rules! rotation_tests {
    ($module:ident, $backend:ty) => {
        mod $module {
            use super::*;

            #[tokio::test]
            async fn identity_rotates_on_channel_reconnect() {
                grpc::client_identity_rotates_on_channel_reconnect::<$backend>().await;
            }

            #[tokio::test]
            async fn file_watcher_rotates_identity() {
                grpc::client_file_watcher_rotates_identity::<$backend>().await;
            }

            #[tokio::test]
            async fn roots_rotate_preserving_base_identity() {
                grpc::client_provider_rotates_roots_and_preserves_base_identity::<$backend>().await;
            }

            #[tokio::test]
            async fn provider_errors_do_not_fall_back() {
                grpc::client_provider_errors_do_not_fall_back_to_cached_credentials::<$backend>()
                    .await;
            }

            #[test]
            fn invalid_material_fails_at_construction() {
                grpc::client_connector_rejects_invalid_material_at_construction::<$backend>();
            }
        }
    };
}

rotation_tests!(rustls_rotation, Rustls);
rotation_tests!(openssl_rotation, OpenSsl);
