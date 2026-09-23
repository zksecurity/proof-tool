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

New ceremony definitions use schema v3. The coordinator runs either released
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
mandatory. A rehearsal-mode run cannot receive production GO. A production-mode
run using a test circuit can receive GO only for its exact signed circuit and
release; its keys cannot prove ownership.

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

Use `--out-dir EVIDENCE_ROOT/operational`. This directory may already contain
collected evidence; preparation preserves it and adds only `evidence-bundle.json`
and `signing-request.json`. Existing bundle, signature, or request files block
preparation rather than being overwritten. Inspect retained outputs after an
interruption before retrying. Release verification requires this exact bundle
location; other signing exports still require fresh directories.

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

## Experimental optional controls

The storage-first design introduces definition v3 with a signed
`assurance_policy`. Witnesses, mirrors, ceremony audits, and external security
audit signoffs each have an explicit minimum and may independently be zero.
The policy is repeated and checked across checkpoints, operational evidence,
the final transcript, and the production decision. Legacy schemas retain their
previous minimums. See [Optional ceremony controls](single-observer-minimum.md).

The same signed definition contains the beacon lead. Rehearsal and production
both accept a positive configured value; 300 seconds and 24 hours respectively
are tooling defaults, not verifier-enforced mode floors. A shorter production
lead reduces the time available for public observation and review, so the
coordinator-facing tool must warn before signing it. When production witnesses
are enabled, close validation also reserves the fixed witness-observation
window in addition to the configured lead.

Storage-first verification requires Relay to place the canonical accepted
artifact tree in a private local staging directory and prevent other local
processes from changing it during verification. Checkpoint metadata reads use
descriptor-relative, no-follow access on Linux and macOS. The existing large
transcript replay path still reopens files by pathname, so the system does not
claim protection against a malicious local process or compromised host racing
the verifier. Signed hashes and full replay continue to detect backend
corruption and ordinary local changes.

The signed checkpoint graph uses the same canonical Phase 1 paths consumed by
Phase 2 (`phase1/chain-NNNN.*`, `phase1/closure/*`, `phase1/beacon/*`, and
`phase1/sealed/*`). Checkpoint creation rejects alternate aliases, so a fully
verified Phase 1 graph cannot depend on hidden duplicate files before Phase 2.
The next checkpoint fully replays that sealed Phase 1 state and accepts only
the deterministic zero-contribution Phase 2 tree at
`phase2/chain-0000.json`, `phase2/chain-0000.sig`, and
`phase2/genesis.bin`. Merely uploading files with those names is insufficient.
For released V1–V3 definitions, Phase 2 participant checkpoints use the same ordered
outbound-handoff, signed-receipt, and accepted-candidate transitions as Phase 1.
Each accepted candidate is fully replayed against the sealed Phase 1 commons.
After the configured minimum is met, the graph accepts the canonical signed
Phase 2 closure and then the canonical signed beacon record plus its raw drand
response. Both edges preserve the exact Phase 1 seal, Phase 2 head, and all
submission results; stored verification replays that complete ancestry.
The next guarded edge independently replays both phases and accepts only the
closed `final/candidate` tree: the coordinator-signed candidate, exact checksum
inventory, final keys, Phase 2 seal, and public proof-verification evidence.
Extra, missing, symbolic-link, nonregular or changed files are rejected.

For released V3 definitions, release signing also independently replays both
phases on the release signer's machine even when ceremony audits are disabled.
Definition V4 instead requires the release signer to verify the coordinator's
exact full-replay binding and final files; an additional signer replay is optional.
The following checkpoint accepts only the strictly verified closed
`final/release` tree, including its release-signer manifest signature,
operational evidence, explicit audit inventory, transcript, keys and checksums.
It rejects missing, extra, symbolic-link, nonregular or changed entries.
GO/NO-GO authorization and public publication remain later, separate states.
