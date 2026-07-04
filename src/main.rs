use clap::Parser;
use iscsi_luks_csi::config::{Args, NodeConfig};
use iscsi_luks_csi::csi;
use iscsi_luks_csi::driver::DriverContext;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();
    let config = NodeConfig::load(args.config).await?;

    if args.check {
        let driver = DriverContext::new(config).await?;
        driver.check().await?;
        return Ok(());
    }

    csi::serve(&args.endpoint, config).await
}
