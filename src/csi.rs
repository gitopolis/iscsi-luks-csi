use std::{
    collections::HashMap,
    os::unix::fs::FileTypeExt,
    path::{Path, PathBuf},
};

use anyhow::{Context, anyhow, bail};
use tokio::net::UnixListener;
use tokio_stream::wrappers::UnixListenerStream;
use tonic::{Request, Response, Status, transport::Server};
use tracing::info;

use crate::config::NodeConfig;

pub mod proto {
    tonic::include_proto!("csi.v1");
}

use proto::{
    GetPluginCapabilitiesRequest, GetPluginCapabilitiesResponse, GetPluginInfoRequest,
    GetPluginInfoResponse, NodeGetCapabilitiesRequest, NodeGetCapabilitiesResponse,
    NodeGetInfoRequest, NodeGetInfoResponse, NodePublishVolumeRequest, NodePublishVolumeResponse,
    NodeServiceCapability, NodeStageVolumeRequest, NodeStageVolumeResponse,
    NodeUnpublishVolumeRequest, NodeUnpublishVolumeResponse, NodeUnstageVolumeRequest,
    NodeUnstageVolumeResponse, ProbeRequest, ProbeResponse,
    identity_server::{Identity, IdentityServer},
    node_server::{Node, NodeServer},
};

#[derive(Clone)]
struct CsiService {
    config: NodeConfig,
}

pub async fn serve(endpoint: &str, config: NodeConfig) -> anyhow::Result<()> {
    let socket = unix_socket_path(endpoint)?;
    prepare_socket(&socket)?;
    let listener = UnixListener::bind(&socket)
        .with_context(|| format!("bind CSI socket {}", socket.display()))?;
    let incoming = UnixListenerStream::new(listener);
    let service = CsiService { config };

    info!(socket = %socket.display(), "serving CSI gRPC");
    Server::builder()
        .add_service(IdentityServer::new(service.clone()))
        .add_service(NodeServer::new(service))
        .serve_with_incoming(incoming)
        .await?;
    Ok(())
}

pub fn unix_socket_path(endpoint: &str) -> anyhow::Result<PathBuf> {
    let path = endpoint
        .strip_prefix("unix://")
        .ok_or_else(|| anyhow!("CSI endpoint must start with unix://"))?;

    if path.is_empty() {
        bail!("CSI endpoint socket path is empty");
    }

    let path = PathBuf::from(path);
    if !path.is_absolute() {
        bail!("CSI endpoint socket path must be absolute");
    }

    Ok(path)
}

fn prepare_socket(path: &Path) -> anyhow::Result<()> {
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("create CSI socket directory {}", parent.display()))?;
    }

    match std::fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_socket() => std::fs::remove_file(path)
            .with_context(|| format!("remove stale CSI socket {}", path.display())),
        Ok(_) => bail!(
            "CSI endpoint exists and is not a socket: {}",
            path.display()
        ),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err).with_context(|| format!("inspect CSI socket {}", path.display())),
    }
}

#[tonic::async_trait]
impl Identity for CsiService {
    async fn get_plugin_info(
        &self,
        _request: Request<GetPluginInfoRequest>,
    ) -> Result<Response<GetPluginInfoResponse>, Status> {
        Ok(Response::new(GetPluginInfoResponse {
            name: self.config.driver_name.clone(),
            vendor_version: env!("CARGO_PKG_VERSION").to_string(),
            manifest: HashMap::new(),
        }))
    }

    async fn get_plugin_capabilities(
        &self,
        _request: Request<GetPluginCapabilitiesRequest>,
    ) -> Result<Response<GetPluginCapabilitiesResponse>, Status> {
        Ok(Response::new(GetPluginCapabilitiesResponse {
            capabilities: Vec::new(),
        }))
    }

    async fn probe(
        &self,
        _request: Request<ProbeRequest>,
    ) -> Result<Response<ProbeResponse>, Status> {
        Ok(Response::new(ProbeResponse { ready: Some(true) }))
    }
}

#[tonic::async_trait]
impl Node for CsiService {
    async fn node_stage_volume(
        &self,
        _request: Request<NodeStageVolumeRequest>,
    ) -> Result<Response<NodeStageVolumeResponse>, Status> {
        Err(Status::unimplemented(
            "NodeStageVolume is not implemented yet",
        ))
    }

    async fn node_unstage_volume(
        &self,
        _request: Request<NodeUnstageVolumeRequest>,
    ) -> Result<Response<NodeUnstageVolumeResponse>, Status> {
        Err(Status::unimplemented(
            "NodeUnstageVolume is not implemented yet",
        ))
    }

    async fn node_publish_volume(
        &self,
        _request: Request<NodePublishVolumeRequest>,
    ) -> Result<Response<NodePublishVolumeResponse>, Status> {
        Err(Status::unimplemented(
            "NodePublishVolume is not implemented yet",
        ))
    }

    async fn node_unpublish_volume(
        &self,
        _request: Request<NodeUnpublishVolumeRequest>,
    ) -> Result<Response<NodeUnpublishVolumeResponse>, Status> {
        Err(Status::unimplemented(
            "NodeUnpublishVolume is not implemented yet",
        ))
    }

    async fn node_get_info(
        &self,
        _request: Request<NodeGetInfoRequest>,
    ) -> Result<Response<NodeGetInfoResponse>, Status> {
        let node_id = self
            .config
            .node_id
            .clone()
            .filter(|node_id| !node_id.is_empty())
            .map(Ok)
            .unwrap_or_else(hostname_from_env_or_kernel)
            .map_err(|err| Status::failed_precondition(err.to_string()))?;

        Ok(Response::new(NodeGetInfoResponse {
            node_id,
            max_volumes_per_node: 0,
            accessible_topology: None,
        }))
    }

    async fn node_get_capabilities(
        &self,
        _request: Request<NodeGetCapabilitiesRequest>,
    ) -> Result<Response<NodeGetCapabilitiesResponse>, Status> {
        Ok(Response::new(NodeGetCapabilitiesResponse {
            capabilities: vec![NodeServiceCapability {
                r#type: Some(proto::node_service_capability::Type::Rpc(
                    proto::node_service_capability::Rpc {
                        r#type: proto::node_service_capability::rpc::Type::StageUnstageVolume
                            as i32,
                    },
                )),
            }],
        }))
    }
}

fn hostname_from_env_or_kernel() -> anyhow::Result<String> {
    if let Ok(node_name) = std::env::var("NODE_NAME")
        && !node_name.is_empty()
    {
        return Ok(node_name);
    }

    let hostname = std::fs::read_to_string("/etc/hostname")
        .map(|hostname| hostname.trim().to_string())
        .context("read /etc/hostname")?;
    if hostname.is_empty() {
        bail!("node id is empty");
    }

    Ok(hostname)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unix_socket_path_accepts_absolute_unix_endpoint() {
        assert_eq!(
            unix_socket_path("unix:///csi/csi.sock").unwrap(),
            PathBuf::from("/csi/csi.sock")
        );
    }

    #[test]
    fn unix_socket_path_rejects_relative_path() {
        assert!(unix_socket_path("unix://csi.sock").is_err());
    }

    #[test]
    fn unix_socket_path_rejects_other_schemes() {
        assert!(unix_socket_path("tcp://127.0.0.1:1234").is_err());
    }
}
