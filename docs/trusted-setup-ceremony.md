# Trusted Setup Ceremony

This repository has two deliberately separate Groth16 setup paths:

- `proof-tool setup-ceremony` is a reproducible, signed, single-actor local
  setup.
- `cmd/mpc-ceremony` is the two-phase multi-party engine. Relay's
  [coordinator runbook](https://github.com/zksecurity/relay/blob/main/docs/roles/coordinator.md)
  and [role runbook](https://github.com/zksecurity/relay/blob/main/docs/README.md)
  document the distributed transport and operator workflow.

The commands, transcripts, and trust claims are not interchangeable.

The `mpc-ceremony` binary is also released independently of transport tools.
Its reproducibility and CLI checks do not fetch or pin a Relay commit. A
coordinated ceremony kit selects independently verified releases, tests the
exact binaries together, and records their hashes as described in
[`mpc-ceremony-release.md`](mpc-ceremony-release.md).

A v2 ceremony may authorize both released Linux CPU targets in one signed
definition. The running binary is included automatically; the coordinator adds
the other exact executable at initialization with `--allowed-binary FILE`.
Every participant still verifies that its current executable is an exact
allowlist member, and every contribution attestation records the digest that
actually ran. A v1 definition is intentionally interpreted as a singleton
allowlist.

Production Mac and Linux contributors use guided Docker cleanup and participant
confirmation. Whole-machine wiping and separate post-wipe records are not
required. This accepts residual host/VM memory and storage risk; container
removal does not establish that no secret copy survived.

## Single-Actor Local Setup

Run the local path with:

```sh
go run ./cmd/proof-tool setup-ceremony \
  --out-dir output/ceremony/ownership-v1-YYYYMMDD \
  --signature-key-id proof-helper-release-YYYYMMDD \
  --signing-key /secure/path/proof-helper-release.ed25519.private.hex \
  --require-clean-git \
  --acknowledge-single-actor
```

The command writes `ownership.pk`, `ownership.vk`, `manifest.json`,
`manifest.sig`, `manifest-public-key.hex`, `setup-transcript.json`,
`TOXIC-WASTE-HANDLING.md`, `README.md`, and `checksums.sha256`.

The manifest is signed with Ed25519 over the exact `manifest.json` bytes. Verify
a bundle with a trusted public key:

```sh
go run ./cmd/proof-tool verify-key-bundle \
  --keys-dir output/ceremony/ownership-v1-YYYYMMDD \
  --manifest-public-key-file /trusted/path/proof-helper-release.ed25519.public.hex \
  --signature-key-id proof-helper-release-YYYYMMDD
```

For local integrity checks only, `verify-key-bundle` can fall back to the
bundled `manifest-public-key.hex`. Production installers should pin the public
key and expected `signature_key_id` out of band.

## Trust Boundary

`setup-ceremony` documents a single-actor gnark Groth16 setup. It does not turn
the setup into a public multi-party ceremony. Public users must either trust the
named setup operator and release signing key, or require a true public MPC
ceremony or a transparent proof system.

For a signed rehearsal or explicitly trusted single-operator release, run from
a clean tagged commit with
`--require-clean-git`, record the operator and host controls in release notes,
publish the signed bundle and transcript, and keep the Ed25519 private signing
key outside the published bundle. Do not label such a bundle "multi-party",
"trustless", or production MPC evidence.

The dedicated MPC command uses gnark's BLS12-381 `mpcsetup` package, requires
ordered contributions in both phases, uses separate future public beacons for
Phase 1 and Phase 2, and supports full independent transcript replay. Software
verification alone is still insufficient: participant independence, host
controls, entropy quality, erasure, public archival, and independent audits are
operational requirements. See Relay's
[coordinator runbook](https://github.com/zksecurity/relay/blob/main/docs/roles/coordinator.md)
and [role runbook](https://github.com/zksecurity/relay/blob/main/docs/README.md)
for the deployed workflow. Relay's bundled rehearsal is test-only and does not
constitute production approval; each production ceremony requires an explicit,
independently reviewed go/no-go record before any ceremony binary or artifact
is used.

## Beacon relay evidence

Final release requires matching, cryptographically verified responses from at
least **two distinct relay operators** for each phase's committed drand round.
Relay IDs and endpoint digests must also differ; multiple hostnames belonging
to one operator do not count as different operators. Every supplied response
must verify against the pinned network and exact committed round.

This reduces the operational minimum from three operators to two, trading one
source of retrieval redundancy for availability during a relay outage. It does
not change drand's cryptographic threshold, the future-round requirement, or
the other signed operational-evidence and release checks. Operator identities
remain authenticated coordinator claims, not proof of organizational independence.

Existing three-operator evidence remains valid. Older binaries still require
three; use an explicitly reviewed compatible release. Do not edit an existing
signed ceremony's software allowlist or replace its pinned binary to force an
in-progress ceremony through a changed verifier policy.

## Toxic Waste Handling

gnark samples the Groth16 trapdoor in process memory during `groth16.Setup`.
This tool does not write ptau, zkey, toxic-waste, or trapdoor transcript files.
After the command exits, the process memory is released back to the operating
system, but Go does not provide a ceremony-grade zeroization proof.

For stronger production hygiene, use an ephemeral controlled host, disable or
destroy swap, avoid persistent crash dumps, publish `TOXIC-WASTE-HANDLING.md`,
and destroy the ceremony host or VM after the artifacts are signed and copied.

The MPC path narrows the trust assumption to require at least one honest
independent contributor in each phase, but it does not cryptographically prove
that a contributor erased its randomness. Every accepted participant must use
and attest to the host controls in the MPC runbook.

The v2 contribution environment describes contributor-scoped swap, dump, and
telemetry controls. Both the environment and signed cleanup record require
`host_remnants_not_excluded: true`. The cleanup record authenticates process
termination, logical ephemeral-environment removal, and the participant's
confirmation of no deliberate retained copies. It is not secure physical
erasure evidence. Relay checks Docker lifecycle facts; proof-tool verifies the
signed claims and their binding to the contribution, output, and timestamp.
Host/VM swap, backups, snapshots, or a compromised host may retain secrets even
when honest participants follow every instruction. Dedicated controlled
environments can reduce risk but cannot undo an earlier leak.
