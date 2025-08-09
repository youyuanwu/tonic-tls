fn main() {
    tonic_prost_build::compile_protos("protos/helloworld.proto").unwrap();
}
