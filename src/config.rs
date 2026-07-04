use std::path::PathBuf;

use clap::Parser;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Parser)]
#[command(author, version, about)]
pub struct Args {
    /// Path to the CSI Unix domain socket.
    #[arg(long, env = "CSI_ENDPOINT", default_value = "unix:///csi/csi.sock")]
    pub endpoint: String,

    /// Optional path to a node configuration YAML file.
    #[arg(long, env = "ISCSI_LUKS_CSI_CONFIG")]
    pub config: Option<PathBuf>,

    /// Run startup checks and exit without starting the CSI server.
    #[arg(long)]
    pub check: bool,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
#[serde(default, deny_unknown_fields)]
pub struct NodeConfig {
    pub driver_name: String,
    pub node_id: Option<String>,
    pub default_fs_type: String,
    pub mapper_prefix: String,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            driver_name: "dev.gitopolis.iscsi-luks-csi".to_string(),
            node_id: None,
            default_fs_type: "ext4".to_string(),
            mapper_prefix: "iscsi-luks-csi".to_string(),
        }
    }
}

impl NodeConfig {
    pub async fn load(path: Option<PathBuf>) -> anyhow::Result<Self> {
        let Some(path) = path else {
            return Ok(Self::default());
        };

        let bytes = tokio::fs::read(path).await?;
        Ok(serde_yaml::from_slice(&bytes)?)
    }
}
