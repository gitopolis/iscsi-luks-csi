use thiserror::Error;

#[derive(Debug, Error)]
pub enum SafetyError {
    #[error("volume id is empty")]
    EmptyVolumeId,
}

pub fn safe_mapper_name(prefix: &str, volume_id: &str) -> Result<String, SafetyError> {
    if volume_id.is_empty() {
        return Err(SafetyError::EmptyVolumeId);
    }

    let mut safe = String::with_capacity(prefix.len() + 1 + volume_id.len());
    safe.push_str(prefix);
    safe.push('-');

    for byte in volume_id.bytes() {
        let ch = byte as char;
        if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' || ch == '.' {
            safe.push(ch);
        } else {
            safe.push('_');
        }
    }

    Ok(safe)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IscsiTarget {
    pub portal: String,
    pub iqn: String,
    pub lun: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagePlan {
    pub target: IscsiTarget,
    pub mapper_name: String,
    pub fs_type: String,
    pub allow_format: bool,
}

impl StagePlan {
    pub fn new(
        target: IscsiTarget,
        mapper_prefix: &str,
        volume_id: &str,
        fs_type: impl Into<String>,
        allow_format: bool,
    ) -> Result<Self, SafetyError> {
        Ok(Self {
            target,
            mapper_name: safe_mapper_name(mapper_prefix, volume_id)?,
            fs_type: fs_type.into(),
            allow_format,
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SecretSlot {
    ChapUsername,
    ChapPassword,
    LuksPassphrase,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CommandArg {
    Literal(String),
    Secret(SecretSlot),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostCommand {
    pub program: String,
    pub args: Vec<CommandArg>,
    pub stdin: Option<SecretSlot>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageDeviceState {
    pub device_path: String,
    pub device_matches_target: bool,
    pub luks_header: bool,
    pub mapper_open: bool,
    pub filesystem: Option<String>,
    pub staged: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("resolved device does not match requested iSCSI target and LUN")]
    DeviceMismatch,
    #[error("device has no LUKS header and allowFormat is false")]
    MissingLuksHeader,
    #[error("device has no filesystem and allowFormat is false")]
    MissingFilesystem,
    #[error("device filesystem {found} does not match requested filesystem {expected}")]
    FilesystemMismatch { found: String, expected: String },
    #[error("unsupported filesystem type {0}")]
    UnsupportedFilesystem(String),
}

pub fn stage_host_commands(
    plan: &StagePlan,
    state: &StageDeviceState,
    staging_target_path: &str,
    use_chap: bool,
) -> Result<Vec<HostCommand>, PlanError> {
    if !state.device_matches_target {
        return Err(PlanError::DeviceMismatch);
    }
    if !state.luks_header && !plan.allow_format {
        return Err(PlanError::MissingLuksHeader);
    }
    if state.filesystem.is_none() && !plan.allow_format {
        return Err(PlanError::MissingFilesystem);
    }
    if let Some(found) = &state.filesystem
        && found != &plan.fs_type
    {
        return Err(PlanError::FilesystemMismatch {
            found: found.clone(),
            expected: plan.fs_type.clone(),
        });
    }
    if plan.fs_type != "ext4" {
        return Err(PlanError::UnsupportedFilesystem(plan.fs_type.clone()));
    }

    let mut commands = Vec::new();
    commands.extend(iscsi_commands(&plan.target, use_chap));

    if !state.luks_header {
        commands.push(HostCommand {
            program: "cryptsetup".to_string(),
            args: literals([
                "luksFormat",
                "--type",
                "luks2",
                &state.device_path,
                "--key-file",
                "-",
            ]),
            stdin: Some(SecretSlot::LuksPassphrase),
        });
    }

    if !state.mapper_open {
        commands.push(HostCommand {
            program: "cryptsetup".to_string(),
            args: literals([
                "open",
                &state.device_path,
                &plan.mapper_name,
                "--type",
                "luks2",
                "--key-file",
                "-",
            ]),
            stdin: Some(SecretSlot::LuksPassphrase),
        });
    }

    let mapper_path = format!("/dev/mapper/{}", plan.mapper_name);
    if state.filesystem.is_none() {
        commands.push(HostCommand {
            program: "mkfs.ext4".to_string(),
            args: literals([mapper_path.as_str()]),
            stdin: None,
        });
    }

    if !state.staged {
        commands.push(HostCommand {
            program: "mount".to_string(),
            args: literals([mapper_path.as_str(), staging_target_path]),
            stdin: None,
        });
    }

    Ok(commands)
}

fn iscsi_commands(target: &IscsiTarget, use_chap: bool) -> Vec<HostCommand> {
    let mut commands = Vec::new();
    if use_chap {
        commands.push(iscsi_update(
            target,
            "node.session.auth.authmethod",
            CommandArg::Literal("CHAP".to_string()),
        ));
        commands.push(iscsi_update(
            target,
            "node.session.auth.username",
            CommandArg::Secret(SecretSlot::ChapUsername),
        ));
        commands.push(iscsi_update(
            target,
            "node.session.auth.password",
            CommandArg::Secret(SecretSlot::ChapPassword),
        ));
    }

    commands.push(HostCommand {
        program: "iscsiadm".to_string(),
        args: iscsi_base_args(target, ["--login"]),
        stdin: None,
    });
    commands
}

fn iscsi_update(target: &IscsiTarget, name: &str, value: CommandArg) -> HostCommand {
    let mut args = iscsi_base_args(target, ["--op", "update", "--name", name, "--value"]);
    args.push(value);
    HostCommand {
        program: "iscsiadm".to_string(),
        args,
        stdin: None,
    }
}

fn iscsi_base_args<'a, const N: usize>(
    target: &IscsiTarget,
    tail: [&'a str; N],
) -> Vec<CommandArg> {
    let mut args = literals([
        "--mode",
        "node",
        "--targetname",
        target.iqn.as_str(),
        "--portal",
        target.portal.as_str(),
    ]);
    args.extend(
        tail.into_iter()
            .map(|arg| CommandArg::Literal(arg.to_string())),
    );
    args
}

fn literals<const N: usize>(args: [&str; N]) -> Vec<CommandArg> {
    args.into_iter()
        .map(|arg| CommandArg::Literal(arg.to_string()))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mapper_name_keeps_safe_ascii() {
        let got = safe_mapper_name("iscsi-luks-csi", "pvc-abc_123.test").unwrap();
        assert_eq!(got, "iscsi-luks-csi-pvc-abc_123.test");
    }

    #[test]
    fn mapper_name_replaces_unsafe_bytes() {
        let got = safe_mapper_name("iscsi-luks-csi", "media/data:0").unwrap();
        assert_eq!(got, "iscsi-luks-csi-media_data_0");
    }

    #[test]
    fn mapper_name_rejects_empty_volume_id() {
        assert!(matches!(
            safe_mapper_name("iscsi-luks-csi", ""),
            Err(SafetyError::EmptyVolumeId)
        ));
    }

    #[test]
    fn stage_commands_refuse_destructive_work_without_allow_format() {
        let plan = stage_plan(false);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/ip-192.0.2.10:3260-iscsi-iqn-test-lun-1".to_string(),
            device_matches_target: true,
            luks_header: false,
            mapper_open: false,
            filesystem: None,
            staged: false,
        };

        let got = stage_host_commands(&plan, &state, "/stage", true).unwrap_err();

        assert_eq!(got, PlanError::MissingLuksHeader);
    }

    #[test]
    fn stage_commands_refuse_destructive_work_on_device_mismatch() {
        let plan = stage_plan(true);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/wrong".to_string(),
            device_matches_target: false,
            luks_header: false,
            mapper_open: false,
            filesystem: None,
            staged: false,
        };

        let got = stage_host_commands(&plan, &state, "/stage", true).unwrap_err();

        assert_eq!(got, PlanError::DeviceMismatch);
    }

    #[test]
    fn stage_commands_plan_first_use_format_open_mkfs_and_mount() {
        let plan = stage_plan(true);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/ip-192.0.2.10:3260-iscsi-iqn-test-lun-1".to_string(),
            device_matches_target: true,
            luks_header: false,
            mapper_open: false,
            filesystem: None,
            staged: false,
        };

        let got = stage_host_commands(&plan, &state, "/stage", true).unwrap();

        assert_eq!(got.len(), 8);
        assert_eq!(got[0].program, "iscsiadm");
        assert_eq!(
            got[2].args.last(),
            Some(&CommandArg::Secret(SecretSlot::ChapPassword))
        );
        assert_eq!(got[4].program, "cryptsetup");
        assert!(
            got[4]
                .args
                .contains(&CommandArg::Literal("luksFormat".into()))
        );
        assert_eq!(got[4].stdin, Some(SecretSlot::LuksPassphrase));
        assert_eq!(got[6].program, "mkfs.ext4");
        assert_eq!(got[7].program, "mount");
    }

    #[test]
    fn stage_commands_skip_ready_steps() {
        let plan = stage_plan(false);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/ip-192.0.2.10:3260-iscsi-iqn-test-lun-1".to_string(),
            device_matches_target: true,
            luks_header: true,
            mapper_open: true,
            filesystem: Some("ext4".to_string()),
            staged: true,
        };

        let got = stage_host_commands(&plan, &state, "/stage", false).unwrap();

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].program, "iscsiadm");
        assert!(got[0].args.contains(&CommandArg::Literal("--login".into())));
    }

    fn stage_plan(allow_format: bool) -> StagePlan {
        StagePlan::new(
            IscsiTarget {
                portal: "192.0.2.10:3260".to_string(),
                iqn: "iqn-test".to_string(),
                lun: 1,
            },
            "iscsi-luks-csi",
            "media",
            "ext4",
            allow_format,
        )
        .unwrap()
    }
}
