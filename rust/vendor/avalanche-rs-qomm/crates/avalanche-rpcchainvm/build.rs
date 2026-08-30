use std::io;

fn main() -> io::Result<()> {
    let protoc = protoc_bin_vendored::protoc_bin_path()
        .map_err(|error| io::Error::other(error.to_string()))?;
    std::env::set_var("PROTOC", protoc);
    println!("cargo:rerun-if-changed=proto");
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .include_file("generated.rs")
        .file_descriptor_set_path(
            std::path::PathBuf::from(std::env::var_os("OUT_DIR").expect("OUT_DIR"))
                .join("rpcchainvm_descriptor.bin"),
        )
        .compile_protos(
            &[
                "proto/vm/vm.proto",
                "proto/http/http.proto",
                "proto/http/responsewriter/responsewriter.proto",
                "proto/io/reader/reader.proto",
                "proto/rpcdb/rpcdb.proto",
                "proto/appsender/appsender.proto",
                "proto/vm/runtime/runtime.proto",
            ],
            &["proto"],
        )
        .map_err(|error| io::Error::other(error.to_string()))
}
