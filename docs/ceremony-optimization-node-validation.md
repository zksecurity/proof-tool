# Node validation: 2026-09-23

This note records local implementation evidence. It is not release or live ceremony authorization.

## Production-mode test-circuit decision follow-up

The local V5 decision draft and record now use schema V5 with an
`exact-circuit-rehearsal` gate. The verifier accepts any circuit in the closed,
canonical registry only when its full binding matches the authenticated
production-mode definition. Historical K21 decision schemas retain their
K21-only gate. Relay requires a verified GO for every production-mode archive,
including tiny and K11 test circuits, and names the signed circuit in the
decision check detail. A test-circuit GO does not make its keys usable for
ownership proofs.

On this revision, `go test ./...`, `go vet ./...` and `git diff --check` passed
in both checkouts. Focused decision tests accepted K21, tiny and K11 bindings
and rejected a decision for another canonical circuit, missing evidence and
mixed schema fields. Relay archive tests require GO for all production-mode
circuits and reject NO-GO or a decision for another release. These are local
source tests; a signed decision over a complete test-circuit final package and
the exact published Relay/proof-tool pair remain unqualified.

## Source identity and scope

- Proof-tool: recovered fresh checkout of `optimize/ceremony-verification-reuse` at `b0815c943310a377c249eee83816a0af22ff621c`, plus the `source-recovery/proof-tool-working-tree.tar.gz` overlay. Before edits, its 17 modified and 15 untracked files matched `SOURCE-STATE.md` exactly.
- Relay: isolated checkout at `7e3c73bb12076bfd591c054726767da23d0c1057`; applied the single resource-design patch from source recovery. Before edits, its one modified document matched `SOURCE-STATE.md`.
- Both builds use Go 1.26.6 on linux/amd64. Proof-tool vendor was generated with `scripts/bootstrap-vendor.sh`, retaining the reviewed gnark patches.
- Deferred D1 key preflight prototype files were removed from the implementation checkout. They remain in the source recovery archive. No persistent result cache or standalone D2 durable-attempt feature was connected.

## Executed checks

| Check | Local result |
| --- | --- |
| Proof-tool `go test -timeout 20m ./internal/mpcceremony ./cmd/mpc-ceremony` | Passed: core 250.189 s; CLI 64.140 s, before the final definition-binding and progress-only edits. |
| Signed V5 `TestCheckpointV4RealContributionTurn/(audits-enabled\|audits-over-minimum)` | Passed after the definition-binding edit: 38.78 s and 39.32 s. |
| Signed V5 `TestCoordinatorPhase2ClosureAcceptanceAndDiagnosticReplay` | Passed: 40.36 s. Normal acceptance path emitted no Phase 2 replay load; diagnostic emitted one load. |
| Own-transition test with a mathematically invalid earlier Phase 1 object | Passed: own transition succeeded; independent full replay rejected the earlier edge. This test is at the native boundary, not a complete signed invalid-history fixture. |
| Relay `go test ./cmd/relay ./internal/storagefirst ./internal/upgrade` | Passed after resource heartbeat and wording edits. |
| Both repositories `go vet ./...` | Passed. |
| Proof-tool `go test -timeout 15m ./...` | Passed repository-wide; core package 218.229 s. |
| Proof-tool `go test -timeout 20m ./internal/mpcceremony -count=1` | Passed after the public canonical-genesis replay fix: 248.252 s. |
| Pinned gnark `go test -race -count=1 github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup` | Passed. |
| Proof-tool `go test -race -count=1 -timeout 25m ./internal/mpcceremony` | Passed: 326.706 s. |
| Signed V5 tiny workflow helper with `MPC_WORKFLOW_CHECKPOINT_V4=1 MPC_WORKFLOW_V4_AUDITS=1`, without early stop | Passed final review, release-checkpoint and negative terminal branch. `/usr/bin/time -v`: 37.65 s wall; 29,112 KiB maximum resident set. This is one local process and tiny circuit, not a Relay or production-circuit measurement. |
| Signed V5 happy path with `MPC_WORKFLOW_CHECKPOINT_V4=1 MPC_WORKFLOW_CHECK_P1_REUSE=1`, without early stop | Passed on the final local revision: both allocated contributions with the five truthful progress stages, coordinator acceptance, seal, Phase 2 initialization, final reconstruction, signed package, release checkpoint and final review. The acceptance-based and independent Phase 1 methods produced identical checkpoint bytes. `/usr/bin/time -v`: 40.36 s wall; 29,532 KiB maximum resident set. Signed definition reports `proof-tool-mpc-ceremony-definition-v5`, `rehearsal-tiny-v1`, and `coordinator-full-replay-v1`. |
| Relay `go test ./...` | Passed repository-wide after V5 fixture and resource heartbeat edits. |
| Relay `go test ./cmd/relay` and `go vet ./...` | Passed after the final normal-closure, seal and finalization prompt corrections. |
| Relay `go test ./cmd/relay -run TestWorkflowV4JournalEntropyBeforeOutputCannotRegenerate -count=1` | Passed: durable running state forbids same-attempt regeneration even after entropy was drawn and no output exists. |
| Relay `go test ./...` after the final prompt and recovery-test edits | Passed repository-wide; `cmd/relay` 12.177 s. |
| Both repositories `go build ./...` | Passed. |
| Proof-tool `go test ./cmd/mpc-ceremony -count=1` | Passed after final V5 CLI wording and diagnostic heading changes: 62.316 s. |
| Proof-tool `go test ./cmd/mpc-ceremony -count=1` after five-stage participant copy | Passed: 64.644 s. |
| Proof-tool `go test ./internal/mpcceremony -run '^TestCheckpointV4RealContributionTurn/observers-disabled$' -count=1` | Passed: 31.813 s; asserts all five stages in both allocated phases. |
| Relay `go test ./cmd/relay -count=1` after participant confirmation update | Passed: 12.657 s. |
| Final proof-tool `go test -timeout 20m ./...` | Passed repository-wide after the five-stage participant edit; core package 219.070 s. |
| Final Relay `go test ./...` | Passed repository-wide after participant confirmation update; `cmd/relay` 12.077 s. |
| Local Docker stats format probe | Passed with a disposable `alpine:3.22` container (`--network none`, 64 MiB, 0.25 CPU): Docker emitted `CPUPerc: 0.00%` and `MemUsage: 1.488MiB / 64MiB`, matching the parser's supported format. The container was stopped and auto-removed. This does not test a guided role's live heartbeat. |
| Proof-tool `bash scripts/check-vendor-drift.sh` | Passed: vendor tree matches reviewed patches. |
| `git diff --check` | Passed in both implementation checkouts. |

Local, unpublished validation binaries:

- Proof-tool `/tmp/ceremony-optimization-mpc-ceremony`: SHA-256 `ad81dd6f3195fe3b90e4da0e5ba7fa874bbd2cd7d92feaef60379ea6ab51d1ee`.
- Signed V5 workflow helper `/tmp/ceremony-optimization-workflow-helper`: SHA-256 `6926c86dfb90b59b47ab574d80832df51bcf7ae7e3ed61829be9dc193a354779`.
- Relay `/tmp/ceremony-optimization-relay`: SHA-256 `6d67520d29089ff42d233ce9baf79bc99c968bfc39f14edaa242b650f6da3683`.

## Gate status

| Gate | Evidence and remaining work |
| --- | --- |
| G1 native helper | Generated challenge is checked before native Verify; native Verify receives a clone. Byte-preservation and shape tests pass for both phases. |
| G2 assignment | Allocated wrapper authenticates active attempt, phase, participant, schedule, checkpoint scope, input refs and destination before randomness. Signed tiny workflow and wrong-assignment tests pass. A retired-offline Relay end-to-end fixture remains to be recorded. |
| G3 canonical genesis | Canonical Phase 1 construction/hash is retained. A signed native-valid wrong-genesis fixture passes evidence authentication but is rejected by both the participant canonical check and public independent Phase 1 replay. |
| G4 call-path counts | Source paths now show no historical transition replay or Phase 2 genesis derivation in allocated participant and allocated acceptance preparation, and no Phase 2 replay in normal coordinator closure. The signed closure callback test covers the normal/diagnostic difference. Complete sync, publication and recovery counters remain unmeasured. At the user's request on 2026-09-23, skip production K21 timing/peak-memory measurements; no production performance claim is qualified by the tiny/K11 measurements. |
| G5 final reconstruction | Task 0 audit-count correction and signed V5 full workflow passed. Finalization retains independent replay of both phases and beacon/output checks. A signed structurally consistent bad-history fixture beyond wrong genesis remains to be added. |
| G6 recovery | Relay journal tests cover prepared, entropy-before-output, interrupted child, return/save and publication boundaries. Cleanup and upload have separate resume tests. A single end-to-end injected recovery matrix remains unrun. |
| G7 persistent keys | Deferred D1; no cache code is in this implementation checkout. |

Recovery evidence already exercised by Relay's package tests:

| Boundary | Existing fixture | Limit |
| --- | --- | --- |
| Prepared, before launch | `TestWorkflowV4JournalPreparedAndSuccessfulBoundaries` | Exact prepared plan retained; no entropy drawn. |
| Running, including entropy before any output directory | `TestWorkflowV4JournalEntropyBeforeOutputCannotRegenerate`, `TestWorkflowV4JournalFailedSaveStopsSameProcess` | Journal durability prevents relaunch even when output is absent. |
| Generated, before cleanup | `TestWorkflowV4JournalRestartDoesNotReplay`, `TestWorkflowV4ErasureExecutionDoesNotReplay` | Ambiguous computation requires retained-output verification. |
| Cleanup, before upload | `TestWorkflowV4ErasureExecutionDoesNotReplay`, `TestWorkflowV4UploadExactResumePublishesManifestLast` | Exact retained candidate is reused. |
| Interrupted upload | `TestWorkflowV4UploadExactResumePublishesManifestLast`, `TestWorkflowV4UploadRejectsReplacementAttemptForRetainedCandidate` | Exact attempt and immutable objects are checked on resume. |

These are separate fault and journal tests, not one instrumented end-to-end recovery run.

The following is a source-path count, not an instrumented end-to-end benchmark:

| Authoring path | Historical native transitions | Own native transition checks | Phase 2 genesis derivations |
| --- | ---: | ---: | ---: |
| Allocated V5 Phase 1 participant, first or later | 0 | 1 | 0 |
| Allocated V5 Phase 2 participant, first or later | 0 | 1 | 0 |
| Allocated V5 Phase 2 coordinator acceptance and checkpoint projection | 0 | 1 for the new edge | 0 |
| V5 coordinator Phase 2 closure and checkpoint record, normal mode | 0 | 0 new edges | 0 |
| Final reconstruction | Every accepted edge in both phases | All edges are checked again | 1 owned derivation within the invocation |

Read-only G4 follow-up traced Relay sync through `inspect-signed-v4` and
`inspect-enrollments-v4`; both are structural. Coordinator publication
authenticates the recorded child through `verify-stored-v4`, then immutable
upload and compare-and-swap, without native transition math. Retry repeats
structural authentication and exact-head reconciliation. The generic direct
Phase 2 acceptance itself derives genesis and checks the new edge; its generic
checkpoint projection then replays historical Phase 2 transitions and derives
genesis again. The optimized zero-history count above applies to allocated
acceptance and its projection only.
Phase 2 initialization derives genesis once, and a later checkpoint-record
invocation independently derives it once again. These are source-path counts,
not instrumented counters from one exact Relay/proof-tool process pair.

Happy-path handoff trace:

| Step | Actual entry points | Evidence |
| --- | --- | --- |
| Relay sync and snapshot | `storagefirst.SyncV4` → transcript checkpoint discovery and guidance inspection | Relay package tests pass; this is structural/evidence inspection, with no native transition replay in these source paths. The local helper fixture cannot be inspected by a different same-platform executable because of its signed software binding. |
| Allocated participant, both phases | Relay `prepareWorkflowV4Contribution` → proof-tool `CreateAllocatedContributionCandidateV4` → `CreateContributionCandidate` | Signed V5 helper passed Phase 1 and Phase 2 with actual generated contributions and cleanup. Relay plan/guide tests pass separately. |
| Coordinator acceptance and checkpoint | `VerifyAndAcceptAllocatedCandidateV4` → acceptance-derived checkpoint validation | Signed V5 helper passed exact acceptance, checkpoint publication preparation and retry checks. |
| Phase 1 seal and Phase 2 start | `SealPhase1Files`, `InitializePhase2Files`, `PrepareCoordinatorRecordedCheckpointV4` | Full signed V5 helper with `MPC_WORKFLOW_CHECK_P1_REUSE=1` passed; acceptance-based and independent methods produced identical checkpoint bytes. |
| Phase 2 close and final | `ClosePhaseFiles`, `PrepareFinalization` → `replayAll` | Signed V5 helper completed both beacons, full final reconstruction, public proof checks, review and release-checkpoint validation. A separate signed closure test distinguishes normal and diagnostic replay loads. |

The helper drives proof-tool APIs directly. Relay's published role image still contains its older proof-tool pin, so the two binaries have not been qualified as one runnable release pair.

The Phase 1 canonical-genesis construction/hash is separate from historical transition replay. Normal Phase 2 paths still authenticate the full signed evidence inventory and independently validate the Phase 1 beacon/commons result. The diagnostic `--full-replay` path intentionally adds complete historical mathematics.

Relay's managed contributor now samples the actual Docker container CPU and memory on its elapsed heartbeat. Guided Docker roles derive the exact retained role-launch identity and sample that container during the parent heartbeat, including when the child has replaced itself with `docker start --attach`. If Docker stats or daemon identity inspection fails, the heartbeat reports usage unavailable and leaves the operation result unchanged. These are local code/test checks; live container sampling has not been qualified on this node. The proof-tool CLI and Relay's normal coordinator lifecycle prompts now label allocated participant stages, acceptance-based closure/seal, final reconstruction and diagnostic replay by the work actually selected.

Exact production-circuit resource qualification is still pending. No proof-tool release, Relay pin update, deployment, or live ceremony operation was performed.

The current Relay release manifest still pins its previously released proof-tool binary. The local V5 workflow above exercises the recovered proof-tool implementation directly; it does not qualify a cross-repository release pair or a live provider journey.
An attempted local handoff from the signed workflow-helper fixture to the separately built `mpc-ceremony` executable was rejected by the signed software allowlist, as designed. The fixture binds the helper executable on linux/amd64; a second same-platform binary cannot be added to that allowlist. This is not evidence that the new Relay/proof-tool pair ran together. A release-pair qualification must use the exact approved proof-tool artifact after it exists.

## Additional circuit choices requested on this node

The reviewed K11 test circuit compiles to 1,030 constraints, an exact 2^11
domain and a 38,601-byte serialized R1CS. The existing tiny circuit is five
constraints at domain 2^3. Production-mode definitions now pin the exact
serialized identities of both test circuits. The V5 production decision now
binds the exact signed circuit, including either test circuit, while requiring
the same production-mode evidence and signature threshold. This code change
still needs an end-to-end decision run on the eventual release pair.

The local signed V5 K11 workflow helper completed contributions, both beacon
applications, final replay, audits, signed package, final release checkpoint
and final review with `MPC_WORKFLOW_CHECKPOINT_V4=1 MPC_WORKFLOW_K11=1`.
`/usr/bin/time -v` reported 1:00.92 wall and 36,944 KiB peak resident memory.
The standalone `mpc-ceremony finalize rehearsal-evidence` command generated
and verified the K11 public test proof from its preliminary keys. The signed
V5 tiny-circuit workflow had passed earlier on this node. These local runs do
not establish a compatible published Relay/proof-tool release pair or live
ceremony behavior.

A separate local integration test signed and initialized a V5 production-mode
definition for each test circuit with a three-person, all-required participant
schedule. It reloaded the signature and authenticated the frozen R1CS against
the signed circuit binding. This verifies production-mode initialization; the
complete K11 workflow above used rehearsal mode, so it does not qualify a full
production-mode run through an approved release.

After these circuit changes, `go test ./...` and `go vet ./...` passed in both
proof-tool and Relay. Both `git diff --check` invocations passed. Relay's test
suite covers guided circuit selection, production-mode test-circuit decision
applicability, and public archive verification without a GO record for those
test circuits. The current release pins were not changed.
