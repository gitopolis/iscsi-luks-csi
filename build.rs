use std::path::{Path, PathBuf};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("cargo:rerun-if-changed=proto/csi.proto");

    let proto_dir = Path::new("proto");
    let mut includes = vec![proto_dir.to_path_buf()];
    let system_include = PathBuf::from("/usr/include");

    if system_include
        .join("google/protobuf/wrappers.proto")
        .exists()
    {
        includes.push(system_include);
    }

    tonic_prost_build::configure().compile_protos(&[proto_dir.join("csi.proto")], &includes)?;
    Ok(())
}
