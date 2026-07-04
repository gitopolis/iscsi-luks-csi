use std::{fs, path::PathBuf};

use clap::Parser;
use iscsi_luks_csi::api::IscsiLuksVolume;
use kube::CustomResourceExt;

#[derive(Parser, Debug)]
#[command(version, about)]
struct Args {
    #[arg(short, long, default_value = "deploy/crds")]
    output: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    fs::create_dir_all(&args.output)?;
    fs::write(
        args.output.join("storage.nikita.dev_iscsiluksvolumes.yaml"),
        serde_yaml::to_string(&IscsiLuksVolume::crd())?,
    )?;
    Ok(())
}
