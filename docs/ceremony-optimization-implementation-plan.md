# Ceremony optimization implementation plan

Status: review draft, 2026-09-23. Documentation only. This plan does not authorize
implementation, release, deployment or restarting a ceremony. Existing dirty-tree
prototypes must be inventoried and reviewed, not assumed to satisfy this plan.

## Authority and settled decisions

Read the [operator review](ceremony-optimization-review.md) and
[detailed specification](ceremony-optimization-specification.md) first. The
specification defines security, input and recovery contracts (future cache work
is scoped by the [deferred-task register](ceremony-optimization-deferred-tasks.md)); this file
maps them to work packages. If a conflict remains, identify it before implementing
the affected package rather than silently choosing a behavior.

- First real release; require only the complete V5-definition ceremony workflow.
- Remove historical V4-definition test cases, compatibility matrices and fixture
  switches. Preserve security/recovery coverage by moving shared cases to V5.
- No migration machinery for prior participant expectations.
- Honest coordinator and trusted delivery service; exact signatures, hashes,
  circuit/ceremony binding, current assignment and file checks remain mandatory.
- BOTH participant phases start from authenticated assigned input, skip historical
  mathematical replay, use fresh randomness, check their own contribution and
  perform cleanup. Phase 2 also skips Phase 1 replay and genesis reconstruction.
- No participant independent-verification switch or new consent gate.
- Coordinator checks every new transition before accepting it. Checkpoint creation
  can consume an already-signed acceptance; no ordinary-path bypass was found.
- Phase 1 post-beacon preparation uses authenticated acceptance history plus beacon
  verification/application and output comparison. Phase 2 closure uses acceptance
  evidence. Explicit coordinator diagnostic full replay remains available.
- After the Phase 2 beacon, full replay of BOTH phases and final-key reconstruction
  remain mandatory. Key/proof/rejection tests and exact release checks follow.
- Release signer follows the existing coordinator-replay protocol; preserve other
  schema-specific signer rules. Auditor/public full replay remains independent.

## Source map and baseline

Proof-tool paths below are relative to this repository. Relay paths are relative
to the sibling `relay-ceremony-optimization` repository. Reconfirm symbols on the
implementation commit; do not copy line numbers from an old review.

| Area | Principal source locations |
| --- | --- |
| Participant input and acceptance | `internal/mpcceremony/workflow.go`: `CreateContributionCandidate`, `VerifyAndAcceptContribution`, signed-chain/native-file loaders |
| Mathematical helpers | `internal/mpcceremony/phase1.go`, `phase2.go`: replay, contribution, transition checks, owned initialization |
| Allocated turns/checkpoints | `checkpoint_v4_turn.go`, `checkpoint_v4_files.go`, `checkpoint_v4_record.go`, `checkpoint_v4_lifecycle.go` under `internal/mpcceremony` |
| Closure/seal/genesis | `workflow.go`: `ClosePhaseFiles`, `SealPhase1Files`, `InitializePhase2Files`, `loadPhase1CommonsWithMethod` |
| Final reconstruction | `internal/mpcceremony/finalize.go`: `PrepareFinalization`, `Finalize`, `loadReplay`, `replayAll`; `audit.go` |
| Proof-tool command wiring | `cmd/mpc-ceremony/{parse,types,executor,usage,checkpoint_v4}.go` |
| Relay participant/coordinator | `cmd/relay/workflow_v4_participant_guide.go`, `workflow_v4_coordinator_guide.go`, `workflow_v4_phase_lifecycle.go` |
| Relay publication/retry | `cmd/relay/coordinator_commit_v4.go`, `internal/storagefirst/commit.go`, `internal/transcript/inspect_v4.go` |
| Relay resources/progress | `cmd/relay/{guided_resources,guided_resource_policy,guided_resource_suggestion,docker_runtime_limits,workflow_v4_resources,workflow_v4_lifecycle_resources,progress}.go` |

Before editing production implementation, record both repository HEADs, dirty files, actual
schema versions, exact approved binary/image identities, current call counts and
existing test results. Preserve unrelated work. The prior full-workflow error was traced to an incorrect audit-count assertion
in the test helper; see the [final-review investigation](ceremony-final-review-investigation.md). Correct the
fixture in an authorized test-maintenance step and retain full-workflow gates.

## Validation gates before changing production paths

Read the [adversarial review log](ceremony-optimization-adversarial-review.md).
These checks are ordered by the work they block, not by release urgency. Existing
source inspection is evidence of current behavior, not proof the new paths work.

| Gate | Required evidence before dependent implementation | Blocks |
| --- | --- | --- |
| G1: native helper contract | Inspect pinned `Contribute`/`Verify`/serialization in both phases; fixture proof that generated challenge matches predecessor before verification, self-check uses a clone, shapes/points remain checked, retained bytes are unchanged | B |
| G2: assignment authority | Map direct CLI → allocated wrapper → raw helper and Relay snapshot/upload/acceptance; prove phase/participant/index/attempt binding (including explicit CLI phase and participant ID), no entropy before preflight, and handling of retirement during offline work | A/B integration |
| G3: canonical Phase 1 genesis | Explicitly retain one construction/hash comparison against signed/archived genesis; signed wrong genesis rejects. Keep this counter separate from historical replay | B |
| G4: complete call-path counts | Record baseline and target for matrix below, including synchronization, checkpoint preparation, publication and recovery; identify any full replay hidden outside the contribution/close function | A–E integration |
| G5: final reconstruction baseline | Apply the independently validated audit-count fixture correction and rerun signed full workflows; continue proving signed bad history cannot produce final success | D and end-to-end qualification |
| G6: recovery | Fixtures for prepared/unstarted, entropy drawn before directory creation, generated-but-not-cleaned, cleaned-but-not-uploaded and interrupted upload; durable started state prevents same-attempt regeneration | B/E |
| G7: persistent keys | Exact tuple equality at all consumers, native bounds, real peak memory, authentication/read/mutation and crash behavior | F only; does not block A–E |

G1/G2/G3/G4/G6 need targeted tests or isolated validation harnesses before replacing
production behavior. Test/harness work itself is not authorization to deploy or
connect the new paths. No such new harness has been executed by this documentation
review. Keep the existing passing baseline while developing regression fixtures.

| End-to-end path | Required target counters / checks |
| --- | --- |
| V5 participant direct CLI with allocation, both phases | Authenticate captured assignment; zero historical transitions; one own check; Phase 1 canonical genesis once; Phase 2 derivation zero |
| Raw contribution API | No new production shortcut based only on optional scope; document established contract separately |
| Relay participant sync → prepared invocation → contribution | Sync/inspection must not indirectly invoke full genesis verification/replay; preserve snapshot evidence checks |
| Participant resume before execution | Reuse exact attempt/snapshot; generate only with durable evidence generation never started. Absent output is insufficient |
| Participant resume after completed contribution/cleanup/upload | Zero new randomness and zero regeneration; validate exact retained artifacts/current acceptance eligibility |
| Coordinator new acceptance, direct and allocated | Mandatory new-edge math before passing record; separately count existing generic Phase 2 replay, do not claim it removed without scoped change/tests |
| Phase 1 sealed checkpoint → Phase 2 init/checkpoint | Acceptance+beacon basis; no full Phase 1 replay; count each command and internal invocation, not an assumed cross-command cache |
| Phase 2 close → checkpoint record → publication → retry | Zero full replay in normal coordinator authoring path; no hidden Phase 2 genesis derivation; preserve all evidence/time/head checks |
| Final cold reconstruction and public/auditor replay | Both phases and both beacons fully checked; independent Phase 2 initialization retained |
| Deferred D1/F only: final cache hit | Zero reconstruction allowed only with full-reconstruction provenance; evidence/proof/publication checks always run |

For each row record actual functions, counts and fixture outcomes. An offline
checkpoint proves assignment within its snapshot, not continued global freshness.
Relay must fetch the current head before preparing work, and reject retired attempts
when uploading/accepting. Do not introduce a network dependency into the isolated
contribution process or silently retarget a stale attempt.

## Ordered work packages

Each package ends with a scoped diff, test evidence and remaining limitations.
Current scope is tasks 0/0a and A–E. The operator explicitly deferred persistent
coordinator caching (F), including saved final keys, to later work. Do not implement
cache reads/writes, keys, mounts or cache UI in this scope.

### 0. Correct the final-review test baseline

This is a test-only prerequisite, not a production verification fix. See the
[confirmed investigation and Linux evidence](ceremony-final-review-investigation.md).

Target: `internal/mpcceremony/testdata/workflowhelper/checkpoint_v4_review.go`,
`runCheckpointV4Review`; extend related fixture tests as needed.

1. Split the combined assertion into independent checks for deterministic canonical
   output, exact checkpoint binding and exact audit inventory. Give each a specific
   failure message.
2. Compare the returned audit references against the exact reports the fixture
   committed, not against `PassingCeremonyAudits`. That policy value is a minimum.
   Retain a separate minimum check; do not just replace equality with `>=` and lose
   detection of a missing extra audit report.
3. Exercise disabled audits (zero reports), exactly the required minimum, and more
   valid reports than the minimum. Preserve rejection of insufficient, duplicate,
   invalidly signed and wrong-candidate audits. Do not change production quorum,
   verification, report inclusion or signer rules.
4. Rerun the complete signed V5 tiny workflow on Linux, without
   the Phase-1-only early-stop flag, including final review/release and negative
   evidence checks. Record exact source/binary identities and outcomes.

Done when the correction is in the repository and these tests pass. The temporary
clone already demonstrated the cause and candidate correction; it does not count
as the repository fix being applied. Keep this diff separately reviewable and
establish the corrected baseline before changing production behavior in A–E.
The documentation-only hold remains in effect; task 0 is not yet implemented.

### 0a. Remove historical V4-definition tests

The release requires a full V5 ceremony workflow only. Inventory proof-tool and
Relay tests by the actual signed DEFINITION schema, not filename or symbol suffix.
Remove V4-definition compatibility cases and `MPC_WORKFLOW_HISTORICAL_V4` fixture
branching; change V4/V5 parameterized workflow matrices to V5 only. Where a V4
fixture uniquely tests quorum, signatures, corruption, retry or release binding,
port that coverage to V5 before removing the old fixture. Never delete the only
negative test for a shared invariant merely because its name contains V4.

V5 still uses V4-named workflow APIs, commands and checkpoint formats. Keep tests
of those components when they exercise V5 ceremony definitions. Add explicit
`DefinitionSchemaV5` assertions; rename misleading test labels where useful.
Do not rename public checkpoint schemas or commands as part of test cleanup.
Do not equate `CheckpointSchemaV4` with `DefinitionSchemaV4`.

Done when no historical V4-definition workflow test or success/compatibility
expectation remains, full V5 coverage includes the removed cases' relevant
invariants, and CI/release instructions require the full V5 workflow only.
Archived V4 investigation logs remain historical evidence, not required reruns.
This task documents future test cleanup; no tests are removed in this doc update.

### A. Separate authentication from mathematical reconstruction

1. Inventory direct, allocated, generic checkpoint, public verification and retry
   callers. Mark each as producer of a new acceptance or consumer of signed evidence.
2. Extract private authenticated input/head loaders in `workflow.go`. Capture signed
   roots once; return owned decoded objects and references from those exact reads.
3. Preserve full history/evidence/file-integrity checks. This package does not
   authorize reducing the downloaded snapshot or skipping earlier file hashes.
4. For Phase 2 preserve explicit `ComputePhaseID` binding to the authenticated
   Phase 1 seal: `Chain.ValidateAgainstDefinition` alone is insufficient.
5. Distinguish authenticated head from independently reconstructed state in types
   or private constructors. Do not let arbitrary passing JSON construct full-replay
   authority. Preserve bounded native decoding, circuit-derived sizes and challenge
   rules. Existing public full-verification APIs retain their semantics.

Done when specification T1/T2/T10 and R1–R3 reject wrong roots, shapes, signatures,
files and stale scopes, including replacements between reads. No changed public
artifact format is needed. Review existing primitives before introducing new ones.

### B. Participants contribute from authenticated heads in BOTH phases

Depends on A. Change both branches of `CreateContributionCandidate` and verify the
allocation-aware caller's preflight order, including command-phase matching. Introduce private contribute-from-head
helpers in `phase1.go`/`phase2.go`; do not use helpers which internally replay history.

- Index one uses authenticated genesis; later indices use the exact accepted head.
- Check roster, schedule, phase/index, allocation active in the captured checkpoint, signing identity, circuit,
  input digest and destination before randomness. Never fetch a new head midway.
- Preserve an unmodified predecessor; mutate a private copy with fresh randomness.
  Check the generated challenge against the exact predecessor digest before native
  verification; verify a throwaway output clone and preserve input/output bytes
  for attestation. Never persist entropy or reuse it on retry.
- Keep cleanup and exact candidate inventory behavior; a failed self-check must
  not produce a successful candidate or acceptance result.
- Do not derive Phase 2 genesis, compute its private evaluation data or replay
  Phase 1 on the participant path. Do not weaken native point/shape validation.

Done when T3/T5/T9/T10/T13/T14 cover both phases, index one and later participants, plus T15/T16 mutation and assignment
boundary cases.
Counters show zero historical transition replay and one successful own-transition
check per generated contribution; Phase 2 initialization count is zero. Count the retained canonical Phase 1 genesis
construction separately; it is not historical transition replay. Signed
invalid history may pass authentication by design; invalid own transitions fail.
Use injected deterministic entropy only in tests for equivalence against full
replay reference heads. Production entropy remains fresh.

Before integration, pass the command's expected phase and participant ID to the
allocated boundary and reject disagreement with authenticated scope before entropy.
Return phase labels from authenticated output. Preserve Relay's durable
prepared → running-before-launch journal; ambiguous started attempts require
inspection or explicit retirement/reallocation. Per operator decision, adding an
equivalent durable-start mechanism for standalone direct CLI invocation is deferred
and does not block the Relay-managed scope. G6 still validates Relay recovery.
Do not claim standalone crash-safe retry support or infer unstarted state from a
missing directory; validate that the supported Relay flow retains its journal.

### C. Coordinator Phase 1 reuse and Phase 2 closure

Depends on A; review existing unpublished Phase 1 prototypes before adding code.

- Route sealed Phase 1 checkpoint and Phase 2 preparation through authenticated
  complete acceptance history, closure/beacon validation, independent beacon
  application and exact commons comparison. Return the actual verification basis.
- Derive Phase 2 genesis once per authoritative preparation operation. Provisional
  checkpoint projection must not trigger another authoritative reconstruction.
- Change the Phase 2 closure branch to authenticate accepted evidence, exact head,
  completion, current checkpoint and future-beacon policy without replaying both
  phases or deriving genesis inside a shared loader.
- Propagate private coordinator context through authoritative checkpoint validation
  and retries. Public full-verification callers must not inherit it implicitly.
- Preserve signing-key matching, minimum beacon lead time, distinct-round rules,
  time check before publication and original closure on exact retry.
- Keep coordinator `--full-replay` diagnostics. Specify each supported command and
  transition in parsing/help/tests; unsupported uses fail rather than being ignored.

Done when T2/T4/T7/T8/T11/T12/T13 pass. Direct and allocated acceptance continue to
verify new transitions before passing-record construction. Generic checkpoint
preparation requires existing authentic evidence; no redundant Phase 1 check is
added merely to record that evidence. Missing evidence blocks closure.

### D. Final reconstruction and within-command reuse

Depends on A/C. Preserve `replayAll` as the complete mathematical source of final
keys: canonical Phase 1 genesis, every edge in both phases, both beacons, independent
Phase 2 derivation and retained-output comparison. Authenticate all descendants;
`loadReplay` alone does not currently replace every check inside `replayAll`.

Use owned genesis/commons/evaluations within the invocation to eliminate duplicate
initialization. Evaluations are consumed once; do not share mutable key backing
arrays with another invocation. Keep proof and rejection tests, reports, candidate
inventories, signer rules and publication checks independent of calculation reuse.

Done when T5/T6/T13 and signed tiny finalization workflows reject signed invalid
history or wrong genesis, regardless of passing acceptance records/closure. Full
replay must not consume participant or acceptance-based results as math authority.

### E. Relay integration and role-specific CLI copy

Depends on the behavior being exposed; resource-only changes can be developed
independently. Use Relay's `docs/maintainer/resource-allocation-design.md` for
admission, caps, operation identity and concurrency rather than inventing a second
allocator. Map new proof-tool arguments only to compatible pinned binaries.

The [CLI contract](ceremony-optimization-cli-contract.md) supplies exact wording,
flag coverage and error/retry behavior. The table below is a role inventory; the
contract takes precedence for detailed copy. Adapt layout to existing CLI style.
Never report a stage as completed before the corresponding checks actually pass.

| Role/location | Required behavior and proposed wording |
| --- | --- |
| Participant setup/help, both phases | “The coordinator checks earlier contributions. You authenticate your assigned input and check your own contribution.” No mode choice or extra consent screen. |
| Participant contribution stages | “Checking assigned input and records” → “Creating your contribution” → “Checking your contribution” → existing cleanup/upload stages. No historical replay stage. |
| Participant result | “Assigned input authenticated; your contribution checked.” Do not say the entire ceremony was verified. |
| Coordinator acceptance | “Checking this contribution against the accepted input.” Do not promise replay of every earlier contribution. |
| Coordinator Phase 1 close | “Checking accepted records and committing the closure.” Replace current “Replay every accepted Phase 1 contribution” wording. |
| Coordinator Phase 1 seal/checkpoint | “Checking accepted records and beacon” → “Applying beacon and comparing output.” Label reuse basis, not full replay. |
| Coordinator Phase 2 start | “Checking sealed Phase 1” → “Deriving Phase 2 starting parameters” → “Recording checkpoint.” Avoid repeated initialization messages. |
| Coordinator Phase 2 close | “Checking accepted records and completion” → “Committing the future beacon round.” Diagnostic replay must display its actual method. |
| Coordinator final preparation | “Verifying both phases and reconstructing final keys.” Full reconstruction is part of final verification, not another separate run afterward. |
| Coordinator/delivery retry | Distinguish “Resuming publication,” “Checking exact published result” and successful completion; preserve current-head reconciliation. |
| Release reviewer/signer | Preserve existing package/evidence checks and signer requirements; distinguish full coordinator verification from earlier acceptance-based preparation. No new signing choice. |
| Auditor/public verifier | Preserve full-replay behavior and honest progress reporting. No acceptance-based substitute. |
| All computational roles | Show available capacity, validated suggested allocation, adjustment and saved caps before new work; actual CPU/memory and stage elapsed heartbeat while running. No live resize or unsupported ETA. |

Capture CLI text/JSON behavior in tests without adding implementation details to
operator prompts. Preserve structured output compatibility or explicitly review
any additive diagnostic fields. Test direct commands and guided workflow retries.
Do not add a participant independent-replay flag, including through an environment
variable. Do not label component benchmark time as participant completion time.

### F. Persistent coordinator results — deferred

Package F/G7 is tracked as D1 in the [deferred-task register](ceremony-optimization-deferred-tasks.md). Do not
implement its cache reads/writes, keys, mounts or UI in the current scope. Its
future technical contracts remain in the specification. The current release makes
no cross-command three-to-one final-key reconstruction claim.

Standalone direct-CLI durable attempt tracking is D2 in the same register. It does
not remove G6 validation for Relay's managed contribution/recovery path.

## Validation and evidence handoff

- Use existing signed tiny workflow fixtures, direct-acceptance boundary tests,
  Phase 2 reuse tests and Relay guide/resource/publication tests as starting points.
  Add tests for changed behavior; do not weaken an assertion to make a fixture pass.
- Build a matrix by phase, role, first/later contribution, direct/allocated entry,
  normal/retry path. Assert actual signed definition V5 in every ceremony fixture;
  a V4-named helper or checkpoint schema does not imply a V4 ceremony definition.
- For mathematical negatives, create validly signed, structurally consistent bad
  histories so failures are not merely hash failures. Participant non-detection of
  earlier math faults is an expected trust-boundary result, not a universal promise
  that malformed inputs can produce contributions. Final replay must reject them.
- Keep entropy and production signing keys out of test logs. No production ceremony
  is restarted or altered for qualification without separate authorization.
- Record commands, commit/binary/image identities, fixture schema, outcomes, call
  counts, exact deterministic hashes, elapsed times and peak memory. Distinguish
  inspected source, executed tests and production-circuit measurements.
- Existing 96/49/33-minute results at 2/4/6 CPUs are starting-parameter reconstruction
  component timings only. Measure both participant phases and full operations;
  remaining contribution/verification costs were not separately measured.
- Run appropriate repository/cross-repository release gates on the final revision.
  No release readiness claim until the diagnosed test-helper correction is applied,
  the full V5 workflow passes and end-to-end qualification succeeds.

## Settled scope, implementation details and release handoff

| Item | Required resolution |
| --- | --- |
| Release order — decided | Release proof-tool first; then one Relay release with the verified new proof-tool pin plus compatible resource/UI changes. No separate Relay-only release. |
| Standalone tracking — decided | D2 is deferred. Relay journal/recovery validation remains required; standalone crash-safe retry support is not claimed. |
| Persistent cache scope — decided | F is deferred. Its memory/receipt/recovery qualification does not block A–E; no persistent-cache integration ships in current scope. |
| Command/help details — drafted | Implement and test the [CLI contract](ceremony-optimization-cli-contract.md), including diagnostic allowlist, exact role-specific wording and recovery/resource messages. |
| Runtime qualification | Correct the diagnosed final-review test assertion, complete recovery tests and measure full operations on exact approved builds. |

The Relay release must consume attested proof-tool release artifacts and include
the compatible resource/UI changes together with its pin update. Version numbers in
existing designs are provisional. After authorized releases, start a fresh ceremony
with its approved software binding; do not swap binaries inside an active operation.
No PR merge, release publication or deployment is authorized by this document.

## Completion checklist for the implementing agent

- [ ] Task 0 test-only correction applied and signed V5 baseline passes; historical V4-definition tests removed.
- [ ] Baseline recorded; approved two-stage proof-tool → Relay release sequence retained.
- [ ] G1–G4/G6 gates passed for the supported Relay-managed paths; standalone
  direct-CLI durable-start work is explicitly deferred. G5 remains current; G7/F belong only to deferred D1.
- [ ] A–D contracts implemented and meaningful tests pass for both phases.
- [ ] E copy and structured output match actual execution, including retries.
- [x] F explicitly deferred by the operator; exclude persistent-cache implementation and UI from current scope.
- [ ] No participant history replay or mode switch remains in the contribution path.
- [ ] Coordinator acceptance and final full replay cannot be bypassed by weaker results.
- [ ] Final operator summary separates implemented work, evidence and remaining gates.

## Documentation readiness check — 2026-09-23

Cross-document and independent review found no remaining current product-scope
decision. The two-stage release order, V5-only workflow qualification, both-phase
participant trust path, required coordinator/final verification, CLI contract and
D1/D2 deferrals agree. Stale historical-fixture and participant-replay wording in
referenced notes is explicitly superseded; persistent receipt tests are D1 only.

This is documentation readiness, not evidence of passed implementation gates.
Next work remains task 0's repository test-helper correction and signed V5 baseline,
task 0a test cleanup, then G1–G6 validation as scoped to the affected A–E packages.
G7/F is deferred. Exact release versions are selected under repository policy
later; they do not block writing the implementation plan. Production implementation
and releases remain on hold until separately authorized.
