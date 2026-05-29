// Crate is disabled on Windows (see lib.rs `#![cfg(not(windows))]`) and the
// gRPC-rust build-deps are gated out for `cfg(windows)` targets in
// Cargo.toml, so there is nothing to generate on Windows.
#[cfg(windows)]
fn main() {}

#[cfg(not(windows))]
fn main() {
    use std::path::PathBuf;

    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=protos/helloworld.proto");

    // Server-side stubs: standard tonic + prost.
    tonic_prost_build::configure()
        .build_client(false)
        .compile_protos(&["protos/helloworld.proto"], &["protos"])
        .unwrap();

    // Client-side stubs for the grpc-rust crate. grpc-protobuf-build emits
    // protobuf-rust messages (not prost) and gRPC client stubs that take a
    // `grpc::client::Channel`. Output is placed under a dedicated subdir of
    // OUT_DIR so the file names don't collide with the tonic codegen above.
    let out_dir = PathBuf::from(std::env::var_os("OUT_DIR").unwrap());
    let grpc_out = out_dir.join("grpc_gen");
    std::fs::create_dir_all(&grpc_out).unwrap();
    grpc_protobuf_build::CodeGen::new()
        .output_dir(&grpc_out)
        .input("helloworld.proto")
        .include("protos")
        .client_only()
        .compile()
        .unwrap();
}
