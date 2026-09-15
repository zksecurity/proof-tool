# Ceremony compatibility baseline

Verified against released commit `47bec5663d04a4f8ac330fc38f126e6e7c1140f1`
(PR #31, September 15, 2026). These meanings are frozen. The trusted-coordinator
revision is not implemented by this inventory.

| Boundary | Released versions | Preserve |
| --- | --- | --- |
| Ceremony definition | `proof-tool-mpc-ceremony-definition-v1/v2/v3` | V1 single binary; V2 allowlist; V1/V2 implicit assurance minima; V3 explicit optional assurance policy |
| Checkpoint | `proof-tool-mpc-checkpoint-v1/v2/v3` | V1 legacy definition; V2 optional assurance and early Phase 1; V3 both phases through final release |
| Checkpoint workflow | `storage-first-v1` | Allocated attempts and manifest keys; signed participant envelopes and coordinator acknowledgements |
| Submission | `proof-tool-mpc-submission-envelope-v1`, `proof-tool-mpc-submission-acknowledgement-v1` | Exact identity, phase, turn, parent, attempt, manifest and payload binding |
| Operational bundle | `proof-tool-mpc-operational-evidence-bundle-v2/v3` | V2 legacy minima; V3 exact assurance projection and explicit empty disabled collections |
| Component records | Enrollment/handoff/receipt/witness/beacon-evidence/mirror/governance V1; contribution/erasure V2 | Existing signed claims, identities and exact file bindings |
| Final candidate | `proof-tool-mpc-release-candidate-v2` | Coordinator replay and exact final file inventory |
| Final transcript | `proof-tool-mpc-final-transcript-v1/v2` | V1 requires audit; V2 explicit assurance policy and audit list |
| Release manifest | `proof-tool-key-manifest-v1` | Existing application bundle format; Definition V3 ceremony signing additionally requires signer replay |
| Signed release ID | `proof-tool/mpc-ceremony/signed-release/v1` | Exact existing signed-release binding |
| Production decision and draft | `proof-tool-mpc-production-decision-v1/v2`, corresponding `-draft-v1/v2` | V1 audit requirements; V2 exact optional-assurance gates |
| Decision signature | `proof-tool-mpc-production-decision-signature-v1` | Existing signed decision identity and bytes |

Coordinator `PrepareFinalization` and `Finalize` already required `replayAll`
in `c1f177ee486fd555fac0dc4d9812b86737fccdfd` (July 31). PR #31 added the
additional signer replay requirement for Definition V3. Do not remove that
check by changing the meaning of V3 or a generic "current schema" constant.

## New-version implementation gate

Current draft: opt-in V4 construction, structural checkpoints and real-artifact
verification through final-candidate recording exist in the library. The Linux
integration test uses real tiny contributions in both phases, signed custody
records, genuine historical drand responses and complete coordinator replay.
Final-candidate authoring binds the exact executable and closed file inventory. Its
environment and cleanup claims are test fixtures, not physical assurance.
Audit collection verifies each signed record and keeps the full release quorum.
Operational bundle preparation derives the unchanged v3 bundle only from exact
checkpointed records, including all required enrollments and per-turn custody.
It runs the existing bundle verifier without signing or repeating mathematics.
Its source-checkpoint metadata must be rebound at final release; it is not an
extra field in the signed legacy bundle. Linux tests reject missing enrollments,
loose uncommitted records and corrupted retained evidence.
V4 governance uses the existing signed records with stricter explicit
coordinator/current-head checks. Informational incidents enter the bundle;
abort/restart are terminal and cannot prepare a release bundle. An authorized
restart points to an exact signed V4 definition; the new definition alone does
not establish lineage. Historical inspection rechecks these governance edges
against their exact predecessor, not just the record signature.
The read-only V4 final-review API now binds an exact review checkpoint,
coordinator replay checkpoint, closed candidate inventory, signed/rederived
bundle and checkpoint-derived audit quorum. It authenticates lifecycle records,
verifies key exports and the public proof, but does not replay contributions or
regenerate keys. Existing V1–V3 replay/verification gates are unchanged.
V4 operational verification checks historical payload references through signed
records rather than requiring the large genesis/contribution bytes themselves.
It still checks all required custody, cleanup, enrollment, observer and beacon
evidence. The final-review gate separately requires the coordinator replay claim;
checking an operational bundle alone does not establish that replay. V1–V3
continue requiring and hashing every historical payload. The review's sorted
dependency list is tested by copying only those files and re-verifying from the
copied definition and signature, without historical contribution binaries.
The V4 library now signs and verifies a local package with an inline exact review
in FinalTranscript V3, while preserving the application manifest V1 and root-level
key files. Only the fixed candidate filename set is relocated; all other logical
names remain unchanged. Independent copies, exact file inventories, copied-byte
review, and destination verification also cover exact retries. The output must
be outside the source tree. Transcript V3 alone has a dedicated 64 MiB bound;
ordinary signed JSON remains limited to 16 MiB. Package time is not proof of
upload, and package signing is not a production GO decision.
Final-release checkpoint authoring verifies that complete package and binds its
exact review predecessor. The checkpoint adds only five canonical bootstrap
references under `final/release/`; a typed inventory returns all package-relative
files separately from that prefix. `VerifyStoredCheckpointV4` remains structural
inspection; `VerifyFinalReleaseCheckpointV4` additionally verifies package bytes.
Recording this edge means a signed private package, not public publication or GO.
Only this edge has five reserved artifact slots and the exact transcript and
checksum size exceptions. Released checkpoint formats keep their limits.
The Decision V3 library now binds that compact release checkpoint, derives the
exact auditor signer set from its package, and preserves all production gates.
It requires a production-mode Definition V4 and the exact K21 circuit; tiny or
rehearsal-mode definitions cannot receive production approval. Source evidence
is a bounded report under `decision/evidence/`, not an obsolete GPG tag or a
private URL. Proof-tool binds the source commit/report and decision signatures;
the delivery tool must verify and display CI provenance before approval.
Package-derived gates are checked facts; external gates remain reviewed claims.
An independently reloaded package must match the initially authenticated
definition exactly. Legacy decision structs, gates and hash domains are unchanged.
Current tests cover the new record/binding/signature/evidence rules and reject a
missing package. A full public-API positive with a real K21 package is pending;
these tests do not establish an actual production GO or operational assurances.
Decision prepare/sign/verify now dispatch from the authenticated definition.
V4 requires a local evidence root even for post-package NO-GO, checks evidence
before loading the signing key, and keeps decision outputs outside the immutable
release package. Early stops use the existing authenticated abort procedure.
Old decision behavior remains unchanged; only V4 accepts evidence-root during
preparation. CLI tests cover signed format dispatch, missing roots, evidence
failure before key loading, and output containment including symlink aliases.
Release sign now accepts an exact review checkpoint pair for V4 instead of
legacy candidate/audit/replay flags; mixing the two input forms is rejected.
Metadata references are root-confined and size-bounded. The signing library
rechecks the running executable against its authenticated definition before
loading the release key. Release verify selects the V4 package verifier from
the signed definition. These commands create/check local packages, not public
publication or production authorization; legacy V3 signer replay is unchanged.
Normal initialization still emits V3. Do not release this slice alone: remaining
production integration and normal storage-first CLI guidance are incomplete.
An explicit `init --release-verification coordinator-full-replay-v1` now opts a
fresh ceremony into V4; it never upgrades an existing definition. The separate
`checkpoint prepare-v4`, `sign-v4`, and `verify-stored-v4` commands leave legacy
parsers unchanged. Signing repeats preparation and preserves exact canonical
bytes before key loading. Only the six mathematical transition types load the
authenticated stored R1CS. Structural inspection emits a versioned projection
with explicit false artifact/replay/freshness claims. Prepared and signed local
proposals are not published current heads. The tiny executable regression creates
V3 and V4 ceremonies, then prepares/signs/inspects initial V4 state and rejects
changed genesis before signing; this is not yet a whole storage-backed role journey.
Proposal/output paths cannot enter closed candidate/release/rejection trees,
including symlink aliases. Private rejected candidates must be disjoint from
the public artifact root. Existing output files are retained for inspection.
These tests are not a complete user ceremony.

- Reserve Definition V4, Checkpoint V4 and `storage-first-v2` for the changed
  trust and submission rules; do not emit them until the whole verifier path
  exists and has negative tests.
- Give the changed ceremony release claim final transcript V3, with explicit
  policy and the exact signed coordinator final-candidate checkpoint references.
  Keep key manifest V1: its signed setup_transcript_hash binds the new transcript
  without changing ordinary application key-bundle verification or adding a
  second authorization signature. Include the checkpoint pair in the closed
  ceremony release inventory.
- Explicitly dispatch Definition V4 to final transcript V3 and Decision V3.
  Decision V2's enumerated tree and bounds cannot represent every V4 package;
  do not widen its released limits or fall through to legacy policy. Reuse component
  evidence/candidate formats only where their
  exact signed meaning stays unchanged.
- Keep old signing and verification dispatch intact. Unknown versions fail
  closed; missing fields do not select the simplified path.
- Coordinator replay stays mandatory. Release signer stays required; only its
  duplicate mathematical replay becomes optional in the new path.

V4 delivery history retains terminal dispositions. Its per-turn
`contribution_result_id` hashes the ceremony, phase, index, participant,
predecessor and fixed candidate-file labels/digests, not upload attempts or
paths. Retired delivery permits the same bytes to be redelivered; rejected
results cannot be accepted through replacement attempts. The signed history is
bounded to 16 attempts per logical submission and a separate 4,096-slot budget
across the ceremony. Validators reject excess history rather than dropping old
rejections. Retirement/rejection need not allocate a replacement, so exhausting
the budget does not prevent terminal retirement. Closure still requires the
signed contribution minimum. `VerifyCheckpointEdgeV4` compares the exact
predecessor record and signature; structural validation alone cannot do that.

The runtime has no dependency on a downstream delivery application's version.
Provider keys, buckets and upload manifests belong outside proof-tool. Existing
released coupling remains legacy behavior; new protocol outputs use logical
artifact names and hashes only.
