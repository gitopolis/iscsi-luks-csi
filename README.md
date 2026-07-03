# iSCSI LUKS CSI

`iscsi-luks-csi` is an experimental CSI node driver for a narrow home-lab use
case: attach a manually-created iSCSI LUN, open a node-side LUKS/dm-crypt layer,
and publish the decrypted filesystem to Kubernetes pods.

The project exists because generic iSCSI CSI drivers usually stop at mounting
the iSCSI device, while maintained encrypted CSI stacks tend to own the storage
backend. This driver keeps the storage backend simple and remote while moving
encryption CPU and key control to the Kubernetes node.

## Initial Goals

- Static PVs only.
- Linux nodes only.
- iSCSI with CHAP.
- LUKS2 on the node.
- Filesystem volumes first.
- Strong guardrails around first-use initialization.

## Non-Goals

- Dynamic LUN provisioning.
- Multi-node RWX semantics.
- Snapshots and clones.
- Volume expansion.
- Generic storage backend abstraction.

## Current State

The repository is scaffolded. The first implementation milestone is a dry-run
node command planner for:

1. iSCSI login and device resolution.
2. LUKS header detection/opening.
3. Filesystem detection/creation.
4. Stage and publish mount planning.

The actual CSI gRPC service will be added after the command planner and safety
tests are in place.
