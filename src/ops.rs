use std::{
    io::Write,
    path::{Path, PathBuf},
    process::{Command, Stdio},
};

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

impl HostCommand {
    pub fn redacted_args(&self) -> Vec<String> {
        self.args
            .iter()
            .map(|arg| match arg {
                CommandArg::Literal(value) => value.clone(),
                CommandArg::Secret(_) => "<redacted>".to_string(),
            })
            .collect()
    }

    pub fn redacted_argv(&self) -> Vec<String> {
        let mut argv = Vec::with_capacity(self.args.len() + 1);
        argv.push(self.program.clone());
        argv.extend(self.redacted_args());
        argv
    }

    fn redacted_command_line(&self) -> String {
        self.redacted_argv().join(" ")
    }

    fn materialized_args(&self, secrets: &SecretValues) -> Result<Vec<String>, CommandRunError> {
        self.args
            .iter()
            .map(|arg| match arg {
                CommandArg::Literal(value) => Ok(value.clone()),
                CommandArg::Secret(slot) => secrets
                    .get(*slot)
                    .map(str::to_string)
                    .ok_or(CommandRunError::MissingSecret { slot: *slot }),
            })
            .collect()
    }

    fn stdin_value<'a>(
        &self,
        secrets: &'a SecretValues,
    ) -> Result<Option<&'a str>, CommandRunError> {
        self.stdin
            .map(|slot| {
                secrets
                    .get(slot)
                    .ok_or(CommandRunError::MissingSecret { slot })
            })
            .transpose()
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SecretValues {
    pub chap_username: Option<String>,
    pub chap_password: Option<String>,
    pub luks_passphrase: Option<String>,
}

impl SecretValues {
    fn get(&self, slot: SecretSlot) -> Option<&str> {
        match slot {
            SecretSlot::ChapUsername => self.chap_username.as_deref(),
            SecretSlot::ChapPassword => self.chap_password.as_deref(),
            SecretSlot::LuksPassphrase => self.luks_passphrase.as_deref(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CommandOutput {
    pub status: Option<i32>,
    pub stdout: String,
    pub stderr: String,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum CommandRunError {
    #[error("missing secret for {slot:?}")]
    MissingSecret { slot: SecretSlot },
    #[error("failed to spawn {command}: {message}")]
    Spawn { command: String, message: String },
    #[error("failed to write stdin for {command}: {message}")]
    Stdin { command: String, message: String },
    #[error("failed to wait for {command}: {message}")]
    Wait { command: String, message: String },
}

pub trait HostRunner {
    fn output(
        &self,
        command: &HostCommand,
        secrets: &SecretValues,
    ) -> Result<CommandOutput, CommandRunError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct ProcessHostRunner;

impl HostRunner for ProcessHostRunner {
    fn output(
        &self,
        command: &HostCommand,
        secrets: &SecretValues,
    ) -> Result<CommandOutput, CommandRunError> {
        let redacted_command = command.redacted_command_line();
        let mut child = Command::new(&command.program)
            .args(command.materialized_args(secrets)?)
            .stdin(if command.stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .map_err(|err| CommandRunError::Spawn {
                command: redacted_command.clone(),
                message: err.to_string(),
            })?;

        if let Some(stdin) = command.stdin_value(secrets)? {
            child
                .stdin
                .as_mut()
                .expect("stdin is piped when command.stdin is Some")
                .write_all(stdin.as_bytes())
                .map_err(|err| CommandRunError::Stdin {
                    command: redacted_command.clone(),
                    message: err.to_string(),
                })?;
        }

        let output = child
            .wait_with_output()
            .map_err(|err| CommandRunError::Wait {
                command: redacted_command,
                message: err.to_string(),
            })?;

        Ok(CommandOutput {
            status: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FilesystemState {
    Unknown,
    Missing,
    Present(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StageDeviceState {
    pub device_path: String,
    pub device_matches_target: bool,
    pub luks_header: bool,
    pub raw_filesystem: Option<String>,
    pub mapper_open: bool,
    pub filesystem: FilesystemState,
    pub staged: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishPlan {
    pub staging_target_path: String,
    pub target_path: String,
    pub readonly: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PublishState {
    pub target_mounted: bool,
    pub target_readonly: bool,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PlanError {
    #[error("resolved device does not match requested iSCSI target and LUN")]
    DeviceMismatch,
    #[error("device has no LUKS header and allowFormat is false")]
    MissingLuksHeader,
    #[error("device has plaintext filesystem {0}; refusing LUKS initialization")]
    PlaintextFilesystem(String),
    #[error("device has no filesystem and allowFormat is false")]
    MissingFilesystem,
    #[error("device filesystem {found} does not match requested filesystem {expected}")]
    FilesystemMismatch { found: String, expected: String },
    #[error("unsupported filesystem type {0}")]
    UnsupportedFilesystem(String),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum PublishPlanError {
    #[error("target is already mounted read-only but request is read-write")]
    ReadonlyMismatch,
}

pub fn stage_host_commands(
    plan: &StagePlan,
    state: &StageDeviceState,
    staging_target_path: &str,
) -> Result<Vec<HostCommand>, PlanError> {
    if !state.device_matches_target {
        return Err(PlanError::DeviceMismatch);
    }
    if !state.luks_header
        && let Some(found) = &state.raw_filesystem
    {
        return Err(PlanError::PlaintextFilesystem(found.clone()));
    }
    if !state.luks_header && !plan.allow_format {
        return Err(PlanError::MissingLuksHeader);
    }
    match &state.filesystem {
        FilesystemState::Missing if !plan.allow_format => {
            return Err(PlanError::MissingFilesystem);
        }
        FilesystemState::Present(found) if found != &plan.fs_type => {
            return Err(PlanError::FilesystemMismatch {
                found: found.clone(),
                expected: plan.fs_type.clone(),
            });
        }
        _ => {}
    }
    if plan.fs_type != "ext4" {
        return Err(PlanError::UnsupportedFilesystem(plan.fs_type.clone()));
    }

    let mut commands = Vec::new();

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
    if state.filesystem == FilesystemState::Missing {
        commands.push(HostCommand {
            program: "mkfs.ext4".to_string(),
            args: literals([mapper_path.as_str()]),
            stdin: None,
        });
    }

    let filesystem_ready = match state.filesystem {
        FilesystemState::Present(_) => true,
        FilesystemState::Missing => plan.allow_format,
        FilesystemState::Unknown => false,
    };
    if !state.staged && filesystem_ready {
        commands.push(HostCommand {
            program: "mount".to_string(),
            args: literals([mapper_path.as_str(), staging_target_path]),
            stdin: None,
        });
    }

    Ok(commands)
}

pub fn iscsi_login_commands(target: &IscsiTarget, use_chap: bool) -> Vec<HostCommand> {
    let mut commands = vec![HostCommand {
        program: "iscsiadm".to_string(),
        args: literals([
            "--mode",
            "discovery",
            "--type",
            "sendtargets",
            "--portal",
            target.portal.as_str(),
        ]),
        stdin: None,
    }];
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

pub fn publish_host_commands(
    plan: &PublishPlan,
    state: &PublishState,
) -> Result<Vec<HostCommand>, PublishPlanError> {
    if state.target_mounted && state.target_readonly && !plan.readonly {
        return Err(PublishPlanError::ReadonlyMismatch);
    }

    let mut commands = Vec::new();
    if !state.target_mounted {
        commands.push(HostCommand {
            program: "mount".to_string(),
            args: literals(["--bind", &plan.staging_target_path, &plan.target_path]),
            stdin: None,
        });
    }
    if plan.readonly && !state.target_readonly {
        commands.push(HostCommand {
            program: "mount".to_string(),
            args: literals(["-o", "remount,bind,ro", &plan.target_path]),
            stdin: None,
        });
    }
    Ok(commands)
}

pub fn unmount_host_commands(path: &str, mounted: bool) -> Vec<HostCommand> {
    if mounted {
        vec![HostCommand {
            program: "umount".to_string(),
            args: literals([path]),
            stdin: None,
        }]
    } else {
        Vec::new()
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HostPaths {
    pub by_path_dir: PathBuf,
    pub mapper_dir: PathBuf,
    pub mountinfo_path: PathBuf,
}

impl Default for HostPaths {
    fn default() -> Self {
        Self {
            by_path_dir: PathBuf::from("/dev/disk/by-path"),
            mapper_dir: PathBuf::from("/dev/mapper"),
            mountinfo_path: PathBuf::from("/proc/self/mountinfo"),
        }
    }
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum DeviceResolveError {
    #[error("read {path}: {message}")]
    ReadDir { path: String, message: String },
    #[error("no device matches requested iSCSI target and LUN")]
    NotFound,
    #[error("multiple devices match requested iSCSI target and LUN: {0:?}")]
    Multiple(Vec<String>),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum InspectError {
    #[error(transparent)]
    Resolve(#[from] DeviceResolveError),
    #[error(transparent)]
    Command(#[from] CommandRunError),
    #[error("host command {command} exited with status {status:?}")]
    CommandStatus {
        command: String,
        status: Option<i32>,
    },
    #[error("read mountinfo {path}: {message}")]
    MountInfo { path: String, message: String },
}

pub fn resolve_iscsi_device_path(
    by_path_dir: &Path,
    target: &IscsiTarget,
) -> Result<PathBuf, DeviceResolveError> {
    let entries = std::fs::read_dir(by_path_dir).map_err(|err| DeviceResolveError::ReadDir {
        path: by_path_dir.display().to_string(),
        message: err.to_string(),
    })?;
    let mut matches = Vec::new();

    for entry in entries {
        let entry = entry.map_err(|err| DeviceResolveError::ReadDir {
            path: by_path_dir.display().to_string(),
            message: err.to_string(),
        })?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            continue;
        };
        if iscsi_by_path_name_matches(name, target) {
            matches.push(entry.path());
        }
    }

    match matches.len() {
        0 => Err(DeviceResolveError::NotFound),
        1 => Ok(matches.remove(0)),
        _ => Err(DeviceResolveError::Multiple(
            matches
                .into_iter()
                .map(|path| path.display().to_string())
                .collect(),
        )),
    }
}

fn iscsi_by_path_name_matches(name: &str, target: &IscsiTarget) -> bool {
    let Some(rest) = name.strip_prefix("ip-") else {
        return false;
    };
    let Some((portal, rest)) = rest.split_once("-iscsi-") else {
        return false;
    };
    let Some((iqn, lun)) = rest.rsplit_once("-lun-") else {
        return false;
    };
    portal == target.portal && iqn == target.iqn && lun.parse::<u32>() == Ok(target.lun)
}

pub fn inspect_stage_device<R: HostRunner>(
    plan: &StagePlan,
    staging_target_path: &Path,
    paths: &HostPaths,
    runner: &R,
) -> Result<StageDeviceState, InspectError> {
    let device_path = resolve_iscsi_device_path(&paths.by_path_dir, &plan.target)?;
    let luks_header = cryptsetup_is_luks(runner, &device_path)?;
    let raw_filesystem = if luks_header {
        None
    } else {
        filesystem_type(runner, &device_path)?
    };
    let mapper_path = paths.mapper_dir.join(&plan.mapper_name);
    let mapper_open = mapper_path.exists();
    let filesystem = if mapper_open {
        filesystem_type(runner, &mapper_path)?
            .map(FilesystemState::Present)
            .unwrap_or(FilesystemState::Missing)
    } else if !luks_header && raw_filesystem.is_none() {
        FilesystemState::Missing
    } else {
        FilesystemState::Unknown
    };
    let mountinfo =
        std::fs::read_to_string(&paths.mountinfo_path).map_err(|err| InspectError::MountInfo {
            path: paths.mountinfo_path.display().to_string(),
            message: err.to_string(),
        })?;

    Ok(StageDeviceState {
        device_path: device_path.display().to_string(),
        device_matches_target: true,
        luks_header,
        raw_filesystem,
        mapper_open,
        filesystem,
        staged: mountinfo_entry(&mountinfo, staging_target_path).is_some(),
    })
}

pub fn inspect_publish_state(
    target_path: &Path,
    paths: &HostPaths,
) -> Result<PublishState, InspectError> {
    let mountinfo =
        std::fs::read_to_string(&paths.mountinfo_path).map_err(|err| InspectError::MountInfo {
            path: paths.mountinfo_path.display().to_string(),
            message: err.to_string(),
        })?;
    let entry = mountinfo_entry(&mountinfo, target_path);
    Ok(PublishState {
        target_mounted: entry.is_some(),
        target_readonly: entry
            .as_ref()
            .is_some_and(|entry| entry.options.iter().any(|option| option == "ro")),
    })
}

fn cryptsetup_is_luks<R: HostRunner>(runner: &R, device_path: &Path) -> Result<bool, InspectError> {
    let device_path = device_path.display().to_string();
    let command = HostCommand {
        program: "cryptsetup".to_string(),
        args: literals(["isLuks", device_path.as_str()]),
        stdin: None,
    };
    let output = runner.output(&command, &SecretValues::default())?;
    match output.status {
        Some(0) => Ok(true),
        Some(1) => Ok(false),
        status => Err(InspectError::CommandStatus {
            command: command.redacted_command_line(),
            status,
        }),
    }
}

fn filesystem_type<R: HostRunner>(
    runner: &R,
    device_path: &Path,
) -> Result<Option<String>, InspectError> {
    let device_path = device_path.display().to_string();
    let command = HostCommand {
        program: "blkid".to_string(),
        args: literals(["-o", "value", "-s", "TYPE", device_path.as_str()]),
        stdin: None,
    };
    let output = runner.output(&command, &SecretValues::default())?;
    match output.status {
        Some(0) => Ok(Some(output.stdout.trim().to_string()).filter(|value| !value.is_empty())),
        Some(2) => Ok(None),
        status => Err(InspectError::CommandStatus {
            command: command.redacted_command_line(),
            status,
        }),
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct MountInfoEntry {
    options: Vec<String>,
}

fn mountinfo_entry(mountinfo: &str, target: &Path) -> Option<MountInfoEntry> {
    let target = target.display().to_string();
    mountinfo.lines().find_map(|line| {
        let fields: Vec<_> = line.split_whitespace().collect();
        let mount_point = fields.get(4).map(|value| decode_mountinfo_path(value))?;
        if mount_point == target {
            Some(MountInfoEntry {
                options: fields
                    .get(5)
                    .map(|options| options.split(',').map(str::to_string).collect())
                    .unwrap_or_default(),
            })
        } else {
            None
        }
    })
}

fn decode_mountinfo_path(value: &str) -> String {
    let bytes = value.as_bytes();
    let mut decoded = String::with_capacity(value.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'\\' && index + 3 < bytes.len() {
            let code = &value[index + 1..index + 4];
            match code {
                "011" => {
                    decoded.push('\t');
                    index += 4;
                    continue;
                }
                "012" => {
                    decoded.push('\n');
                    index += 4;
                    continue;
                }
                "040" => {
                    decoded.push(' ');
                    index += 4;
                    continue;
                }
                "134" => {
                    decoded.push('\\');
                    index += 4;
                    continue;
                }
                _ => {}
            }
        }
        decoded.push(bytes[index] as char);
        index += 1;
    }
    decoded
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
    use std::{
        collections::HashMap,
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

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
            raw_filesystem: None,
            mapper_open: false,
            filesystem: FilesystemState::Missing,
            staged: false,
        };

        let got = stage_host_commands(&plan, &state, "/stage").unwrap_err();

        assert_eq!(got, PlanError::MissingLuksHeader);
    }

    #[test]
    fn stage_commands_refuse_destructive_work_on_device_mismatch() {
        let plan = stage_plan(true);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/wrong".to_string(),
            device_matches_target: false,
            luks_header: false,
            raw_filesystem: None,
            mapper_open: false,
            filesystem: FilesystemState::Missing,
            staged: false,
        };

        let got = stage_host_commands(&plan, &state, "/stage").unwrap_err();

        assert_eq!(got, PlanError::DeviceMismatch);
    }

    #[test]
    fn stage_commands_plan_first_use_format_open_mkfs_and_mount() {
        let plan = stage_plan(true);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/ip-192.0.2.10:3260-iscsi-iqn-test-lun-1".to_string(),
            device_matches_target: true,
            luks_header: false,
            raw_filesystem: None,
            mapper_open: false,
            filesystem: FilesystemState::Missing,
            staged: false,
        };

        let got = stage_host_commands(&plan, &state, "/stage").unwrap();

        assert_eq!(got.len(), 4);
        assert_eq!(got[0].program, "cryptsetup");
        assert!(
            got[0]
                .args
                .contains(&CommandArg::Literal("luksFormat".into()))
        );
        assert_eq!(got[0].stdin, Some(SecretSlot::LuksPassphrase));
        assert_eq!(got[2].program, "mkfs.ext4");
        assert_eq!(got[3].program, "mount");
    }

    #[test]
    fn stage_commands_refuse_luks_init_over_plaintext_filesystem() {
        let plan = stage_plan(true);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/ip-192.0.2.10:3260-iscsi-iqn-test-lun-1".to_string(),
            device_matches_target: true,
            luks_header: false,
            raw_filesystem: Some("ext4".to_string()),
            mapper_open: false,
            filesystem: FilesystemState::Unknown,
            staged: false,
        };

        let got = stage_host_commands(&plan, &state, "/stage").unwrap_err();

        assert_eq!(got, PlanError::PlaintextFilesystem("ext4".to_string()));
    }

    #[test]
    fn stage_commands_open_existing_luks_before_filesystem_plan() {
        let plan = stage_plan(false);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/ip-192.0.2.10:3260-iscsi-iqn-test-lun-1".to_string(),
            device_matches_target: true,
            luks_header: true,
            raw_filesystem: None,
            mapper_open: false,
            filesystem: FilesystemState::Unknown,
            staged: false,
        };

        let got = stage_host_commands(&plan, &state, "/stage").unwrap();

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].program, "cryptsetup");
        assert!(got[0].args.contains(&CommandArg::Literal("open".into())));
    }

    #[test]
    fn stage_commands_skip_ready_steps() {
        let plan = stage_plan(false);
        let state = StageDeviceState {
            device_path: "/dev/disk/by-path/ip-192.0.2.10:3260-iscsi-iqn-test-lun-1".to_string(),
            device_matches_target: true,
            luks_header: true,
            raw_filesystem: None,
            mapper_open: true,
            filesystem: FilesystemState::Present("ext4".to_string()),
            staged: true,
        };

        let got = stage_host_commands(&plan, &state, "/stage").unwrap();

        assert!(got.is_empty());
    }

    #[test]
    fn iscsi_login_commands_include_chap_when_requested() {
        let got = iscsi_login_commands(&stage_plan(false).target, true);

        assert_eq!(got.len(), 5);
        assert_eq!(got[0].program, "iscsiadm");
        assert_eq!(
            got[0].args,
            literals([
                "--mode",
                "discovery",
                "--type",
                "sendtargets",
                "--portal",
                "192.0.2.10:3260",
            ])
        );
        assert_eq!(
            got[3].args.last(),
            Some(&CommandArg::Secret(SecretSlot::ChapPassword))
        );
        assert!(got[4].args.contains(&CommandArg::Literal("--login".into())));
    }

    #[test]
    fn resolve_iscsi_device_path_matches_target_by_path_name() {
        let dir = temp_dir("by-path-match");
        let expected = dir.join("ip-192.0.2.10:3260-iscsi-iqn-test-lun-1");
        fs::write(&expected, "").unwrap();
        fs::write(dir.join("ip-192.0.2.10:3260-iscsi-iqn-test-lun-2"), "").unwrap();

        let got = resolve_iscsi_device_path(&dir, &stage_plan(false).target).unwrap();

        assert_eq!(got, expected);
        fs::remove_dir_all(dir).unwrap();
    }

    #[test]
    fn inspect_stage_device_reports_closed_luks_filesystem_unknown() {
        let root = temp_dir("inspect-closed");
        let by_path_dir = root.join("by-path");
        let mapper_dir = root.join("mapper");
        fs::create_dir_all(&by_path_dir).unwrap();
        fs::create_dir_all(&mapper_dir).unwrap();
        let device = by_path_dir.join("ip-192.0.2.10:3260-iscsi-iqn-test-lun-1");
        fs::write(&device, "").unwrap();
        let mountinfo_path = root.join("mountinfo");
        fs::write(&mountinfo_path, "").unwrap();
        let runner = FakeRunner::default().with(
            vec![
                "cryptsetup".to_string(),
                "isLuks".to_string(),
                device.display().to_string(),
            ],
            command_output(Some(0), ""),
        );
        let paths = HostPaths {
            by_path_dir,
            mapper_dir,
            mountinfo_path,
        };

        let got =
            inspect_stage_device(&stage_plan(false), Path::new("/stage"), &paths, &runner).unwrap();

        assert!(got.luks_header);
        assert!(!got.mapper_open);
        assert_eq!(got.filesystem, FilesystemState::Unknown);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn inspect_stage_device_reports_blank_new_device_missing_filesystem() {
        let root = temp_dir("inspect-blank");
        let by_path_dir = root.join("by-path");
        let mapper_dir = root.join("mapper");
        fs::create_dir_all(&by_path_dir).unwrap();
        fs::create_dir_all(&mapper_dir).unwrap();
        let device = by_path_dir.join("ip-192.0.2.10:3260-iscsi-iqn-test-lun-1");
        fs::write(&device, "").unwrap();
        let mountinfo_path = root.join("mountinfo");
        fs::write(
            &mountinfo_path,
            "36 29 0:32 / /stage rw,relatime - ext4 /dev/mapper/media rw\n",
        )
        .unwrap();
        let runner = FakeRunner::default()
            .with(
                vec![
                    "cryptsetup".to_string(),
                    "isLuks".to_string(),
                    device.display().to_string(),
                ],
                command_output(Some(1), ""),
            )
            .with(
                vec![
                    "blkid".to_string(),
                    "-o".to_string(),
                    "value".to_string(),
                    "-s".to_string(),
                    "TYPE".to_string(),
                    device.display().to_string(),
                ],
                command_output(Some(2), ""),
            );
        let paths = HostPaths {
            by_path_dir,
            mapper_dir,
            mountinfo_path,
        };

        let got =
            inspect_stage_device(&stage_plan(true), Path::new("/stage"), &paths, &runner).unwrap();

        assert!(!got.luks_header);
        assert_eq!(got.raw_filesystem, None);
        assert_eq!(got.filesystem, FilesystemState::Missing);
        assert!(got.staged);
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn mountinfo_matches_escaped_mount_path() {
        let mountinfo =
            "36 29 0:32 / /var/lib/kubelet/stage\\040one rw,relatime - ext4 /dev/x rw\n";

        assert!(mountinfo_entry(mountinfo, Path::new("/var/lib/kubelet/stage one")).is_some());
    }

    #[test]
    fn publish_commands_bind_and_remount_readonly() {
        let plan = PublishPlan {
            staging_target_path: "/stage".to_string(),
            target_path: "/target".to_string(),
            readonly: true,
        };
        let state = PublishState {
            target_mounted: false,
            target_readonly: false,
        };

        let got = publish_host_commands(&plan, &state).unwrap();

        assert_eq!(got.len(), 2);
        assert_eq!(got[0].args, literals(["--bind", "/stage", "/target"]));
        assert_eq!(got[1].args, literals(["-o", "remount,bind,ro", "/target"]));
    }

    #[test]
    fn publish_commands_skip_already_mounted_readwrite() {
        let plan = PublishPlan {
            staging_target_path: "/stage".to_string(),
            target_path: "/target".to_string(),
            readonly: false,
        };
        let state = PublishState {
            target_mounted: true,
            target_readonly: false,
        };

        let got = publish_host_commands(&plan, &state).unwrap();

        assert!(got.is_empty());
    }

    #[test]
    fn publish_commands_reject_readonly_mount_for_readwrite_request() {
        let plan = PublishPlan {
            staging_target_path: "/stage".to_string(),
            target_path: "/target".to_string(),
            readonly: false,
        };
        let state = PublishState {
            target_mounted: true,
            target_readonly: true,
        };

        let got = publish_host_commands(&plan, &state).unwrap_err();

        assert_eq!(got, PublishPlanError::ReadonlyMismatch);
    }

    #[test]
    fn inspect_publish_state_reads_mountinfo_options() {
        let root = temp_dir("publish-state");
        let mountinfo_path = root.join("mountinfo");
        fs::write(
            &mountinfo_path,
            "36 29 0:32 / /target ro,relatime - ext4 /dev/x rw\n",
        )
        .unwrap();
        let paths = HostPaths {
            mountinfo_path,
            ..HostPaths::default()
        };

        let got = inspect_publish_state(Path::new("/target"), &paths).unwrap();

        assert_eq!(
            got,
            PublishState {
                target_mounted: true,
                target_readonly: true,
            }
        );
        fs::remove_dir_all(root).unwrap();
    }

    #[test]
    fn unmount_commands_only_when_mounted() {
        assert!(unmount_host_commands("/target", false).is_empty());

        let got = unmount_host_commands("/target", true);

        assert_eq!(got.len(), 1);
        assert_eq!(got[0].program, "umount");
        assert_eq!(got[0].args, literals(["/target"]));
    }

    #[test]
    fn process_runner_redacts_secret_args_in_errors() {
        let command = HostCommand {
            program: "/definitely/missing/iscsiadm".to_string(),
            args: vec![CommandArg::Secret(SecretSlot::ChapPassword)],
            stdin: None,
        };
        let secrets = SecretValues {
            chap_password: Some("chap-secret".to_string()),
            ..SecretValues::default()
        };

        let got = ProcessHostRunner.output(&command, &secrets).unwrap_err();
        let message = got.to_string();

        assert!(message.contains("<redacted>"));
        assert!(!message.contains("chap-secret"));
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

    #[derive(Default)]
    struct FakeRunner {
        outputs: HashMap<Vec<String>, CommandOutput>,
    }

    impl FakeRunner {
        fn with(mut self, argv: Vec<String>, output: CommandOutput) -> Self {
            self.outputs.insert(argv, output);
            self
        }
    }

    impl HostRunner for FakeRunner {
        fn output(
            &self,
            command: &HostCommand,
            _secrets: &SecretValues,
        ) -> Result<CommandOutput, CommandRunError> {
            self.outputs
                .get(&command.redacted_argv())
                .cloned()
                .ok_or_else(|| CommandRunError::Spawn {
                    command: command.redacted_command_line(),
                    message: "missing fake output".to_string(),
                })
        }
    }

    fn command_output(status: Option<i32>, stdout: &str) -> CommandOutput {
        CommandOutput {
            status,
            stdout: stdout.to_string(),
            stderr: String::new(),
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let dir = std::env::temp_dir().join(format!(
            "iscsi-luks-csi-{name}-{}-{unique}",
            std::process::id()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }
}
