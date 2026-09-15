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
Normal initialization still emits V3. Do not release this slice alone: remaining
audit/governance evidence, final-release authoring and the new release/decision verification path
are incomplete. These tests are not the normal CLI journey or a full ceremony.

- Reserve Definition V4, Checkpoint V4 and `storage-first-v2` for the changed
  trust and submission rules; do not emit them until the whole verifier path
  exists and has negative tests.
- Give the changed ceremony release claim final transcript V3, with explicit
  policy and the exact signed coordinator final-candidate checkpoint references.
  Keep key manifest V1: its signed setup_transcript_hash binds the new transcript
  without changing ordinary application key-bundle verification or adding a
  second authorization signature. Include the checkpoint pair in the closed
  ceremony release inventory.
- Explicitly dispatch Definition V4 to final transcript V3. Decision V2 may
  retain its structure if exact definition/release binding and V4 verification
  are enforced; it must not fall through to legacy policy. Reuse component
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
