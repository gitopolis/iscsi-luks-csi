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
use crate::ops::{IscsiTarget, StagePlan};

pub mod proto {
    tonic::include_proto!("csi.v1");
}

use proto::{
    GetPluginCapabilitiesRequest, GetPluginCapabilitiesResponse, GetPluginInfoRequest,
    GetPluginInfoResponse, NodeGetCapabilitiesRequest, NodeGetCapabilitiesResponse,
    NodeGetInfoRequest, NodeGetInfoResponse, NodePublishVolumeRequest, NodePublishVolumeResponse,
    NodeStageVolumeRequest, NodeStageVolumeResponse, NodeUnpublishVolumeRequest,
    NodeUnpublishVolumeResponse, NodeUnstageVolumeRequest, NodeUnstageVolumeResponse, ProbeRequest,
    ProbeResponse,
    identity_server::{Identity, IdentityServer},
    node_server::{Node, NodeServer},
    volume_capability,
};

const ATTR_PORTAL: &str = "portal";
const ATTR_IQN: &str = "iqn";
const ATTR_LUN: &str = "lun";
const ATTR_ALLOW_FORMAT: &str = "allowFormat";
const ATTR_LUKS_PASSPHRASE_KEY: &str = "luksPassphraseKey";
const ATTR_CHAP_USERNAME_KEY: &str = "chapUsernameKey";
const ATTR_CHAP_PASSWORD_KEY: &str = "chapPasswordKey";
const DEFAULT_LUKS_PASSPHRASE_KEY: &str = "luksPassphrase";
const DEFAULT_CHAP_USERNAME_KEY: &str = "chapUsername";
const DEFAULT_CHAP_PASSWORD_KEY: &str = "chapPassword";

#[derive(Clone)]
struct CsiService {
    config: NodeConfig,
}

#[derive(Clone, PartialEq, Eq)]
struct SecretValue(String);

impl std::fmt::Debug for SecretValue {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("<redacted>")
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ChapSecrets {
    username: SecretValue,
    password: SecretValue,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct StageRequest {
    plan: StagePlan,
    staging_target_path: PathBuf,
    luks_passphrase: SecretValue,
    chap: Option<ChapSecrets>,
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
        request: Request<NodeStageVolumeRequest>,
    ) -> Result<Response<NodeStageVolumeResponse>, Status> {
        let _stage = stage_request_from_csi(&self.config, request.get_ref())?;
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
            capabilities: Vec::new(),
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

fn stage_request_from_csi(
    config: &NodeConfig,
    request: &NodeStageVolumeRequest,
) -> Result<StageRequest, Status> {
    let volume_id = required_field(&request.volume_id, "volume_id")?;
    let staging_target_path = absolute_path(&request.staging_target_path, "staging_target_path")?;
    let target = IscsiTarget {
        portal: required_context(&request.volume_context, ATTR_PORTAL)?.to_string(),
        iqn: required_context(&request.volume_context, ATTR_IQN)?.to_string(),
        lun: required_context(&request.volume_context, ATTR_LUN)?
            .parse()
            .map_err(|_| Status::invalid_argument("volume_context.lun must be a u32"))?,
    };
    let allow_format = request
        .volume_context
        .get(ATTR_ALLOW_FORMAT)
        .map(|value| {
            value
                .parse()
                .map_err(|_| Status::invalid_argument("volume_context.allowFormat must be bool"))
        })
        .transpose()?
        .unwrap_or(false);
    let fs_type = mount_fs_type(config, request.volume_capability.as_ref())?;
    let luks_passphrase = required_secret(
        &request.secrets,
        context_or_default(
            &request.volume_context,
            ATTR_LUKS_PASSPHRASE_KEY,
            DEFAULT_LUKS_PASSPHRASE_KEY,
        ),
        "missing LUKS passphrase secret",
    )?;
    let chap = chap_secrets(&request.secrets, &request.volume_context)?;
    let plan = StagePlan::new(
        target,
        &config.mapper_prefix,
        volume_id,
        fs_type,
        allow_format,
    )
    .map_err(|err| Status::invalid_argument(err.to_string()))?;

    Ok(StageRequest {
        plan,
        staging_target_path,
        luks_passphrase,
        chap,
    })
}

fn required_field<'a>(value: &'a str, name: &str) -> Result<&'a str, Status> {
    if value.is_empty() {
        Err(Status::invalid_argument(format!("{name} is required")))
    } else {
        Ok(value)
    }
}

fn absolute_path(value: &str, name: &str) -> Result<PathBuf, Status> {
    let value = required_field(value, name)?;
    let path = PathBuf::from(value);
    if path.is_absolute() {
        Ok(path)
    } else {
        Err(Status::invalid_argument(format!("{name} must be absolute")))
    }
}

fn required_context<'a>(
    context: &'a HashMap<String, String>,
    key: &str,
) -> Result<&'a str, Status> {
    context
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .ok_or_else(|| Status::invalid_argument(format!("volume_context.{key} is required")))
}

fn context_or_default<'a>(
    context: &'a HashMap<String, String>,
    key: &str,
    default: &'a str,
) -> &'a str {
    context
        .get(key)
        .filter(|value| !value.is_empty())
        .map(String::as_str)
        .unwrap_or(default)
}

fn required_secret(
    secrets: &HashMap<String, String>,
    key: &str,
    missing_message: &str,
) -> Result<SecretValue, Status> {
    secrets
        .get(key)
        .filter(|value| !value.is_empty())
        .cloned()
        .map(SecretValue)
        .ok_or_else(|| Status::invalid_argument(missing_message))
}

fn chap_secrets(
    secrets: &HashMap<String, String>,
    context: &HashMap<String, String>,
) -> Result<Option<ChapSecrets>, Status> {
    let username_key =
        context_or_default(context, ATTR_CHAP_USERNAME_KEY, DEFAULT_CHAP_USERNAME_KEY);
    let password_key =
        context_or_default(context, ATTR_CHAP_PASSWORD_KEY, DEFAULT_CHAP_PASSWORD_KEY);
    match (secrets.get(username_key), secrets.get(password_key)) {
        (Some(username), Some(password)) if !username.is_empty() && !password.is_empty() => {
            Ok(Some(ChapSecrets {
                username: SecretValue(username.clone()),
                password: SecretValue(password.clone()),
            }))
        }
        (None, None) => Ok(None),
        _ => Err(Status::invalid_argument(
            "CHAP username and password secrets must be provided together",
        )),
    }
}

fn mount_fs_type(
    config: &NodeConfig,
    capability: Option<&proto::VolumeCapability>,
) -> Result<String, Status> {
    let capability =
        capability.ok_or_else(|| Status::invalid_argument("volume_capability is required"))?;
    let Some(access_mode) = capability.access_mode else {
        return Err(Status::invalid_argument(
            "volume_capability.access_mode is required",
        ));
    };
    let mode = volume_capability::access_mode::Mode::try_from(access_mode.mode)
        .unwrap_or(volume_capability::access_mode::Mode::Unknown);
    match mode {
        volume_capability::access_mode::Mode::SingleNodeWriter
        | volume_capability::access_mode::Mode::SingleNodeSingleWriter => {}
        _ => {
            return Err(Status::invalid_argument(
                "only single-node writer access is supported",
            ));
        }
    }

    match capability.access_type.as_ref() {
        Some(volume_capability::AccessType::Mount(mount)) => {
            if mount.fs_type.is_empty() {
                Ok(config.default_fs_type.clone())
            } else {
                Ok(mount.fs_type.clone())
            }
        }
        Some(volume_capability::AccessType::Block(_)) => Err(Status::invalid_argument(
            "block volume capability is not supported",
        )),
        None => Err(Status::invalid_argument(
            "volume_capability.access_type is required",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proto::VolumeCapability;
    use volume_capability::{AccessMode, AccessType, MountVolume, access_mode::Mode};

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

    #[test]
    fn stage_request_from_csi_parses_minimal_mount_request() {
        let request = stage_request();
        let got = stage_request_from_csi(&NodeConfig::default(), &request).unwrap();

        assert_eq!(
            got.staging_target_path,
            PathBuf::from("/var/lib/kubelet/stage")
        );
        assert_eq!(got.plan.target.portal, "192.0.2.10:3260");
        assert_eq!(got.plan.target.iqn, "iqn.2026-07.dev.nikita:test");
        assert_eq!(got.plan.target.lun, 1);
        assert_eq!(got.plan.mapper_name, "iscsi-luks-csi-media");
        assert_eq!(got.plan.fs_type, "ext4");
        assert!(!got.plan.allow_format);
        assert_eq!(got.chap.unwrap().username, SecretValue("chap-user".into()));
    }

    #[test]
    fn stage_request_from_csi_rejects_block_volume() {
        let mut request = stage_request();
        request.volume_capability = Some(VolumeCapability {
            access_mode: Some(AccessMode {
                mode: Mode::SingleNodeWriter as i32,
            }),
            access_type: Some(AccessType::Block(volume_capability::BlockVolume {})),
        });

        let got = stage_request_from_csi(&NodeConfig::default(), &request).unwrap_err();

        assert_eq!(got.code(), tonic::Code::InvalidArgument);
    }

    #[test]
    fn stage_request_from_csi_requires_luks_secret() {
        let mut request = stage_request();
        request.secrets.remove(DEFAULT_LUKS_PASSPHRASE_KEY);

        let got = stage_request_from_csi(&NodeConfig::default(), &request).unwrap_err();

        assert_eq!(got.message(), "missing LUKS passphrase secret");
    }

    #[test]
    fn stage_request_redacts_secret_debug() {
        let request = stage_request();
        let got = stage_request_from_csi(&NodeConfig::default(), &request).unwrap();
        let debug = format!("{got:?}");

        assert!(debug.contains("<redacted>"));
        assert!(!debug.contains("luks-secret"));
        assert!(!debug.contains("chap-pass"));
    }

    fn stage_request() -> NodeStageVolumeRequest {
        NodeStageVolumeRequest {
            volume_id: "media".into(),
            publish_context: HashMap::new(),
            staging_target_path: "/var/lib/kubelet/stage".into(),
            volume_capability: Some(VolumeCapability {
                access_mode: Some(AccessMode {
                    mode: Mode::SingleNodeWriter as i32,
                }),
                access_type: Some(AccessType::Mount(MountVolume {
                    fs_type: String::new(),
                    mount_flags: Vec::new(),
                })),
            }),
            secrets: HashMap::from([
                (DEFAULT_LUKS_PASSPHRASE_KEY.into(), "luks-secret".into()),
                (DEFAULT_CHAP_USERNAME_KEY.into(), "chap-user".into()),
                (DEFAULT_CHAP_PASSWORD_KEY.into(), "chap-pass".into()),
            ]),
            volume_context: HashMap::from([
                (ATTR_PORTAL.into(), "192.0.2.10:3260".into()),
                (ATTR_IQN.into(), "iqn.2026-07.dev.nikita:test".into()),
                (ATTR_LUN.into(), "1".into()),
            ]),
        }
    }
}
