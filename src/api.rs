use kube::CustomResource;
use schemars::JsonSchema;
use serde::{Deserialize, Serialize};

#[derive(CustomResource, Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
#[kube(
    group = "storage.nikita.dev",
    version = "v1alpha1",
    kind = "IscsiLuksVolume",
    plural = "iscsiluksvolumes",
    derive = "Default",
    namespaced,
    shortname = "ilv",
    status = "IscsiLuksVolumeStatus",
    doc = "IscsiLuksVolume describes one static iSCSI LUN opened through LUKS on a node",
    printcolumn = r#"{"name":"Phase","jsonPath":".status.phase","type":"string"}"#,
    printcolumn = r#"{"name":"PV","jsonPath":".status.persistentVolumeName","type":"string"}"#,
    printcolumn = r#"{"name":"Capacity","jsonPath":".spec.capacity","type":"string"}"#,
    printcolumn = r#"{"name":"Target","jsonPath":".spec.target.iqn","type":"string"}"#
)]
pub struct IscsiLuksVolumeSpec {
    pub target: IscsiTargetSpec,
    pub capacity: String,
    pub luks_secret_ref: SecretKeyRef,
    pub chap_secret_ref: Option<ChapSecretRef>,
    pub storage_class_name: Option<String>,
    #[serde(default = "default_fs_type")]
    #[schemars(default = "default_fs_type")]
    pub fs_type: String,
    #[serde(default)]
    #[schemars(default)]
    pub allow_format: bool,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IscsiTargetSpec {
    pub portal: String,
    pub iqn: String,
    pub lun: u32,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct SecretKeyRef {
    pub name: String,
    pub key: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct ChapSecretRef {
    pub name: String,
    #[serde(default = "default_chap_username_key")]
    #[schemars(default = "default_chap_username_key")]
    pub username_key: String,
    #[serde(default = "default_chap_password_key")]
    #[schemars(default = "default_chap_password_key")]
    pub password_key: String,
}

#[derive(Deserialize, Serialize, Clone, Debug, Default, JsonSchema)]
#[serde(rename_all = "camelCase")]
pub struct IscsiLuksVolumeStatus {
    pub observed_generation: Option<i64>,
    pub phase: Option<String>,
    pub persistent_volume_name: Option<String>,
    pub message: Option<String>,
}

fn default_fs_type() -> String {
    "ext4".to_string()
}

fn default_chap_username_key() -> String {
    "username".to_string()
}

fn default_chap_password_key() -> String {
    "password".to_string()
}
