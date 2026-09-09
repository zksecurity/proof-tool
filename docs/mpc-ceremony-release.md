# Releasing `mpc-ceremony`

`mpc-ceremony` is an independently released ceremony engine. Its release gate
must not check out, pin, or depend on a Relay source commit. This keeps the
ceremony parser, cryptographic implementation, and release decision owned by
proof-tool.

The repository's `MPC ceremony release validation` workflow checks the
following proof-tool properties:

- the approved Go toolchain and module identity;
- the patched vendor tree;
- two byte-for-byte reproducible unsigned rehearsal packages containing the
  canonical Linux/amd64 binary and its Linux/arm64 counterpart;
- the downloadable tiny rehearsal initializer and authenticated definition
  projection; and
- absence of production signatures from rehearsal packages.

## Protected-main CI releases

The protected `main` branch is the release gate. Each merge to `main` runs
`Publish MPC ceremony release`, builds the Linux/amd64 and Linux/arm64 package
twice, compares them byte-for-byte, publishes the complete package as a GitHub
Release, and attaches GitHub build provenance. The generated distribution tag
(`mpc-ci-<commit>`) is a delivery label, not a source-approval signature.

Coordinators verify that provenance against the expected repository, workflow,
and exact `main` commit before using a package. There is no GPG source-tag
signer, offline build-signing key, or manual release-signer step in this model.
Protect `main` with required review, required CI checks, CODEOWNERS review for
release workflows, no direct pushes, and no force pushes. GitHub Actions is
therefore part of the trusted release boundary.

New ceremony definitions use schema v2. The coordinator runs either released
binary and passes the other with repeated `--allowed-binary FILE` flags during
`init` (or `rehearsal init`). Initialization reads the embedded Go build
metadata and rejects different source commits, dependency versions, Go
versions, compiler/build policies, dirty states, or multiple binaries for one
platform. The signed definition records the full exact-digest allowlist;
legacy v1 definitions remain one-binary ceremonies.

Contribution and cleanup attestations use schema v2 with contributor-scoped
controls and explicit acknowledgement of unexcluded host/VM remnants. Whole-
machine wipe policies and separate wipe records are removed, without legacy
support. Release signing still recursively verifies signed cleanup records,
contribution binding, timing, audits, witnesses, mirrors, and beacon evidence.
Use matching new Relay/proof-tool binaries and regenerate environment inputs;
old attestation schemas and removed wipe fields are rejected.

Tiny rehearsals can complete final release signing and verification through
`mpc-ceremony`. The tiny profile is selected only after authenticating a
rehearsal-mode ceremony definition. Ordinary application key-bundle verification
still rejects it; it is not registered as a production prover/verifier profile.
Native file hashes, release signatures, audits and operational evidence remain
mandatory. A tiny release cannot satisfy the production K=21 decision gate.

## Coordinated distribution

Guided enrollment and receipt signing requires the commands `ops prepare-enrollment`
and `ops sign`. The former derives the frozen ceremony/roster bindings; the latter
accepts enrollment, public-witness, mirror-receipt and evidence-bundle records, authenticates
the definition, and checks the owner key. Enrollment signing also verifies the
accompanying disclosure. Helpers can bind approval to displayed bytes with
`--reviewed-sha256`. These are signed owner claims, not proof of independent
people, publication observations, retained storage or physical erasure. Complete
operational-bundle verification remains required before release.

`ops prepare-bundle` discovers original public records below an explicit evidence
root, reports missing/conflicting evidence by phase and turn, and exports an
unsigned bundle only after full evidence verification. It does not author
missing custody records or recreate observations. Bundle signing requires
`--evidence-root` and repeats verification before accessing the coordinator key.
The signed bundle remains mandatory for release; unsigned preparation is not
release authorization.

Release proof-tool first, then update the downstream Relay proof-tool pins and
retest that published pairing. Local development-image tests are not release
provenance and must not be presented as verification of published assets.

Read-only guided-journey metadata is included in JSON inspection results.
`inspect definition` reports every required roster enrollment and labels observer
minimums as operational-verifier rules, not extra fields of signed policy.
`inspect` reports authenticated closure IDs, beacon times and the latest allowed
witness observation time. This is local retained state, not proof of global
freshness, actual observations, independent operators, or release authorization.

Compatibility with Relay is tested after both projects have released
independently. The ceremony-kit process receives the exact approved Relay and
`mpc-ceremony` repositories, tags, binaries, and SHA-256 hashes. It runs the
binary-only tiny-rehearsal compatibility gate, including a real phase 1
contribution, erasure attestation, coordinator acceptance, and accepted-chain
inspection, and records the tested hashes in the kit's `compatibility.json`.

That downstream gate may reject a proposed pairing without invalidating either
independent release. Updating Relay never requires changing proof-tool's CI,
and releasing proof-tool never requires selecting a Relay commit.
