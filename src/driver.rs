use kube::Client;
use tracing::info;

use crate::config::NodeConfig;

#[derive(Clone)]
pub struct DriverContext {
    pub config: NodeConfig,
    pub kube: Client,
}

impl DriverContext {
    pub async fn new(config: NodeConfig) -> anyhow::Result<Self> {
        let kube = Client::try_default().await?;
        Ok(Self { config, kube })
    }

    pub async fn check(&self) -> anyhow::Result<()> {
        let version = self.kube.apiserver_version().await?;
        info!(
            git_version = %version.git_version,
            driver = %self.config.driver_name,
            "connected to Kubernetes API"
        );
        Ok(())
    }
}
