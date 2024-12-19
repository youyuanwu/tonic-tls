# Build
On windows install protobuf
```ps1
winget install Google.Protobuf
```
On windows install openssl
```ps1
vcpkg install openssl:x64-windows-static-md
```
# Coverage
Follow the ci yml for how to run coverage
```ps1
cargo install cargo-llvm-cov
```