//! Compiles `proto/tradr/v1/*.proto` into Rust with `protox` (a pure-Rust protobuf
//! parser) feeding `prost-build`, so no `protoc` binary is required on the machine.

use std::env;
use std::error::Error;
use std::path::Path;

fn main() -> Result<(), Box<dyn Error>> {
    let proto_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../proto");
    let v1_dir = proto_root.join("tradr/v1");

    let proto_files = [
        v1_dir.join("common.proto"),
        v1_dir.join("browse.proto"),
        v1_dir.join("control.proto"),
        v1_dir.join("link.proto"),
        v1_dir.join("transfer.proto"),
        v1_dir.join("brokr.proto"),
    ];

    for file in &proto_files {
        println!("cargo::rerun-if-changed={}", file.display());
    }

    let file_descriptor_set = protox::compile(&proto_files, [&proto_root])?;

    let out_dir = env::var("OUT_DIR")?;
    prost_build::Config::new()
        .out_dir(out_dir)
        .compile_fds(file_descriptor_set)?;
    Ok(())
}
