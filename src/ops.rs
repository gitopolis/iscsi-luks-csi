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
}
