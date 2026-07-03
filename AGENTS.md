# AGENTS.md

This repository implements a CSI driver that can touch block devices. Treat it
as storage-control-plane software, not as a normal web service.

## Safety

- Never format, wipe, partition, or initialize LUKS on a device unless the code
  checks an explicit opt-in flag and verifies that the resolved device matches
  the requested iSCSI target and LUN.
- Never rely on transient `/dev/sdX` names for destructive operations. Prefer
  stable `/dev/disk/by-path` or equivalent identifiers.
- Never log CHAP passwords, LUKS passphrases, Kubernetes Secret data, or derived
  encryption keys.
- Keep CSI node operations idempotent. Kubelet may retry calls after partial
  success or restart while a device is already attached, opened, or mounted.
- Treat cleanup failures as recoverable. Avoid making unstage/unpublish paths
  more destructive than necessary.

## Scope

- The first supported use case is a static NAS iSCSI LUN with node-side LUKS.
- Dynamic provisioning, snapshots, expansion, multipath, and Windows nodes are
  out of scope until the static path is reliable.
- Code should make unsafe future work hard to do by accident.

## Development

- Use Rust with `kube.rs` for Kubernetes interactions and `tonic` for CSI gRPC.
- Prefer small, testable command-planning functions before wiring host commands.
- Add tests for device matching, mapper-name generation, and destructive-action
  guardrails before implementing real formatting paths.
