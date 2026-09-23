# End-to-end ceremony redundancy audit

Historical source/implementation notes: this document includes decisions from
before the latest operator revision. For current requirements use the
[optimization specification](ceremony-optimization-specification.md),
[implementation plan](ceremony-optimization-implementation-plan.md) and
[deferred-task register](ceremony-optimization-deferred-tasks.md). In particular,
participants now omit historical mathematical replay in both phases, persistent
calculation caching is deferred, and only the full V5-definition workflow is a
release requirement. Historical V4 test logs and earlier runtime observations
remain evidence of those runs; they are not instructions to retain the old policy.


Status: in progress; not an exhaustive or release-complete claim. Audit the
optimized branch as well as the frozen baseline 80f1692. Removal of a repeated
calculation must preserve exact consumed-file binding, independent actor checks,
private state ownership and failure/recovery behavior.

| Step | Observed expensive work | Reuse decision / remaining work |
| --- | --- | --- |
| Initial preparation | Circuit compilation/binding and Phase 1 genesis creation; checkpoint initialization authenticates genesis/evidence again | Trace launcher and checkpoint initialization end to end; distinguish native decoding/hash cost from mathematical replay. |
| Phase 1 contribution | `CreateContributionCandidate` authenticates chain files; `ContributePhase1Loaded` independently replays predecessors and contributes | Participant's independent mathematics stays. Audit repeated file decoding and recovery preflight ordering. |
| Phase 1 acceptance | Authenticate accepted evidence, load head, verify candidate transition; checkpoint preparation authenticates accepted chain again | Existing acceptance-record trust remains. Same-command projection duplication removed; exact chain/ref double-read fix under validation. Full reads/hashes need cost accounting. |
| Phase 1 close/seal | Coordinator can use authenticated acceptance evidence; explicit full replay remains available | Acceptance-evidence path already optimized. Latest design avoids default post-beacon full replay using authenticated acceptance history plus independently checked beacon application; retain explicit troubleshooting replay and independent participant/final checks. Do not label acceptance receipts as full replay. |
| Sealed Phase 1 checkpoint | `VerifyPhase1SealFiles` independently replays Phase 1 and derives commons | Candidate for private coordinator receipt reuse with complete input binding. No ordinary seal signature as substitute. |
| Phase 2 initialization | `InitializePhase2Files` replays sealed Phase 1 then derives starting parameters | Coordinator-only cross-command Phase 1 reuse proposed; actual derivation remains required. |
| Phase 2 starting checkpoint | Baseline verifies genesis twice; each check initialized twice | Existing branch reduces four initializations to one, preserving authoritative checkpoint validation. Phase 1 cross-command reuse still pending. |
| Phase 2 contribution | `CreateContributionCandidate` calls `loadVerifiedPhase2Files`, deriving genesis; `ContributePhase2Loaded` initializes again before replay | Confirmed same-command duplicate in released code. Reuse privately owned genesis while retaining participant's complete independent replay and fresh contribution entropy. An unpublished local patch and focused tests exist; full release qualification remains pending. |
| Phase 2 acceptance | `loadVerifiedPhase2Files` derives genesis; first contribution additionally calls `InitializePhase2` for its predecessor | NEW confirmed first-contribution duplicate. Reuse verified genesis as predecessor; later contributions load actual authenticated head. Preserve candidate cloning and error classification. |
| Accepted Phase 2 checkpoint | Full sealed Phase 1 verification, genesis derivation and all Phase 2 edges | Branch already reuses genesis within replay. Coordinator cross-command receipt scope and reuse of just-verified candidate work require audit; cannot drop the authoritative check blindly. |
| Phase 2 closure | Sealed Phase 1 verification plus complete Phase 2 replay (policy branches need tracing) | Genesis reuse implemented in replay helper; acceptance-evidence/full-replay policy must remain explicit. |
| Final key reconstruction | `replayAll` verifies deterministic genesis via `InitializePhase2`, then `SealPhase2Loaded` initializes again | NEW confirmed duplicate. Reuse must include fresh correctly owned evaluations needed for sealing; simply reusing state without evaluations is insufficient. |
| Final preparation and finalization | `PrepareFinalization`, `VerifyPreliminaryFinalKeys`, `Finalize` and callers can reconstruct keys | Trace invocation counts and exact handoffs; required functional proof/negative checks remain. Not yet fully audited. |
| Review/sign/public verification | Role/schema-dependent independent verification | Audit V1–V3 versus V4 paths separately. Never replace independent participant/reviewer authority with coordinator cache. |
| Recovery | Existing output and interrupted-operation paths may repeat verification before deciding to resume/refuse | Trace every durable boundary. Do not re-sample contribution secrets, overwrite signed outputs, or infer invalid candidates from operational failures. Not yet fully audited. |

Counts here describe inspected call sites, not runtime instrumentation. Remaining
work includes role-specific launcher command sequences, all finalization/review/
signing paths, retry paths, payload reads and R1CS recompilation. Every proposed
removal needs an equivalence/negative test and measured memory effect. Keep the
fresh full same-device ceremony as an independent end-to-end release requirement.

## Finalization trace

Relay `runWorkflowV4FinalizeLifecycle` (in `workflow_v4_phase_lifecycle.go`) runs
`finalize-preliminary`, `finalize-complete`, then `record-final-candidate` as
separate retained operations. Proof-tool `PrepareFinalization` and `Finalize`
each call `replayAll`; recording the final candidate reaches
`VerifyFinalCandidateCheckpoint` -> `verifyCandidateReplay` -> `replayAll`.
Thus the baseline coordinator sequence reconstructs the full keys three times.
Each baseline `replayAll` initializes Phase 2 twice, making six initializations
across those three operations before any optional independent audit. This is a
static normal-path count, excluding retries, and still needs measured tracing.

The follow-up finalization option `--preliminary-keys-dir` changes the Relay
normal path to two complete replays: preliminary preparation and the independent
final-candidate checkpoint. Completion authenticates the preliminary signature,
every fixed replay input digest, and the key artifacts instead of reconstructing
them again. The baseline count above remains relevant to callers that omit the
option and to older releases. This is not a reusable coordinator receipt for
other commands or independent auditors.

`VerifyPreliminaryFinalKeys` verifies the coordinator signature and referenced
artifact hashes; it does not independently reconstruct the keys. A public
signature on preliminary keys therefore cannot itself authorize skipping a
later independent replay. Cross-command reuse here needs a stronger locally
verified result and binding to the evidence added between preparation and
completion. The sealed-Phase-1 receipt proposal alone does not solve this.

V4 release review checks the signed coordinator replay claim and consistent
records without calling `replayAll` (`verifyReviewLifecycleV4`). This is an
explicit protocol distinction, not an opportunity to remove another replay.
Legacy release signing uses `verifyRequiredReleaseSignerReplay`; preserve the
schema-specific requirements. Auditor/public `ReplayCandidate` independently
reconstructs keys. Within-call duplicate initialization can be removed there,
but coordinator receipts must not replace the auditor's independent work.

## Recovery trace: finalization

The Relay V4 guide skips preliminary generation when its directory already
exists, skips completion when the candidate exists, and skips recording when
its checkpoint exists. These existence checks select the recovery route; they
are not cryptographic success checks. The subsequent authoritative checkpoint
verification and publication authentication must still reject corrupted or
incomplete artifacts. The retained lifecycle timestamp/resources/command record
has no verification authority.

Direct proof-tool `PrepareFinalization` and `Finalize` instead reconstruct into
a new staging directory and use `publishDirectoryNoReplaceOrExact` to accept
only an identical existing output. Therefore a direct retry can repeat the full
mathematics before discovering an output conflict. Do not replace this with
"directory exists, return success". The proposed saved-key receipt covers deterministic reconstruction only; it
does not certify operation success. Timestamps, public evidence, operation
options and exact output inventories remain separately checked by each operation.
They are not added indiscriminately to the saved-key identity. Changed output
files still require actual-byte checks. Existing atomic no-replace and exact-retry
behavior must remain tested. See the detailed specification for the fixed tuple.

This identifies a genuine potential saving for direct retries, but no recovery
shortcut is implemented. Current in-command reuse does not change publication,
retry timestamps, entropy sampling, overwrite policy or error classification.

## Recovery trace: remote final-checkpoint publication

`runWorkflowV4FinalizeLifecycle` ends in `runWorkflowV4CommitCommand`, which invokes
`relay coordinator commit-v4`. `runCoordinatorCommitV4` authenticates the child
checkpoint, publishes its immutable artifacts and signed checkpoint, persists
successful upload verification metadata, and then rereads the remote root.
An exact existing checkpoint/signature pair is an idempotent success. Otherwise,
`storagefirst.CommitRoot` requires the exact predecessor pair, verifies uploaded
checkpoint bytes, conditionally advances storage and confirms the result by an
exact reread. A competing head is not automatically adopted as a new parent.

Preserve this path when adding calculation reuse. The artifact-upload memo can
save retransmission but cannot certify key mathematics; the saved-key receipt
can save mathematics but cannot certify an upload or current remote head.
Local publication fault/retry tests passed on 2026-09-23 together with the new
key-size formula test. These are focused checks, not a full ceremony qualification.

## Revised Phase 1 trust decision

The latest operator-approved proposal permits coordinator reuse based on signed
prior mathematical acceptance records, exact artifact authentication and an
independent recomputation of the beacon application to the accepted head. This
supersedes the earlier full-replay-only receipt requirement. Label that result
`coordinator-acceptance-and-beacon-v1`; never present it as full replay. Participants
and full final reconstruction retain independent mathematics. Keep an explicit
full-replay troubleshooting option. Full generic checkpoint verification must not
inherit the coordinator shortcut accidentally; role/context plumbing is part of
the implementation, not an assumed property of signed checkpoints.

V5 scope clarification: the coordinator acceptance-history method applies to both
V4 and V5. `UsesCoordinatorReplay()` is the existing closed predicate for these
two formats. The contribution checks and checkpoint lifecycle are shared; V5's
production-decision schema and release requirements remain unchanged. Public and
participant verification remain independent for both formats. The workflow test
helper's historical V4 name does not identify its schema: its current constructor
creates V5, so tests must assert the actual signed definition version.

### V4/V5 validation scope and open full-workflow failure

The signed helper now explicitly tests actual V4 and V5 definitions. Its current
constructor emits V5 despite the historical V4 helper name; historical V4 test
setup re-signs only the initial definition and empty chain before contributions.
Both coordinator lifecycle methods are compared against independent preparation,
including matching canonical checkpoint bytes, full override and wrong-key refusal.

The first expanded run reached final review after passing Phase 1, Phase 2,
final candidate and audit stages, then failed with `final review is not deterministic
or exactly bound` for both schemas. This remains an unresolved full-workflow gate;
it is not a pass or established unrelated baseline behavior. Retained node log:
`/home/jason/ceremonies/key-preflight-validation-20260923/phase1-reuse-r4.log`.
The focused Phase 1 test now stops its fixture after initialized-Phase-2 checkpoint
creation. Normal full-workflow fixtures retain their full review/release checks.

Focused signed V4/V5 test passed (15.65 s) in the isolated Linux container:
`phase1-reuse-r7.log` in the same node directory. Both actual schema variants
match independent commons/checkpoint outputs, retain forced replay and wrong-key
refusal, reject changed/missing payloads and evidence, and reject validly signed
commons that differ from the recomputed beacon result. The malformed-result test
asserts that its mutation changes serialized bytes (Tau[0] is implicit in this
format; the test changes Tau[1]). Container exit 0, OOMKilled=false.
Local V4/V5 definition/production-decision gates, replay-option parsing, scoped
vet and diff checks also pass. These results do not clear the earlier full-review
failure, the fabricated signed-invalid-history test, or production qualification.
