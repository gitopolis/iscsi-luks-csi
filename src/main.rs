use clap::Parser;
use iscsi_luks_csi::config::{Args, NodeConfig};
use iscsi_luks_csi::driver::DriverContext;
use tracing::info;
use tracing_subscriber::{EnvFilter, fmt};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_target(false)
        .init();

    let args = Args::parse();
    let config = NodeConfig::load(args.config).await?;
    let driver = DriverContext::new(config).await?;

    if args.check {
        driver.check().await?;
        return Ok(());
    }

    info!(
        endpoint = %args.endpoint,
        driver = %driver.config.driver_name,
        "CSI server skeleton initialized"
    );
    info!("CSI gRPC service implementation is intentionally pending");

    Ok(())
}
