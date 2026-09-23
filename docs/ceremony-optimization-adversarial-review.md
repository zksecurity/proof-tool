# Ceremony optimization adversarial review log

Date: 2026-09-23. Scope: operator review, specification and implementation plan;
source inspection of local proof-tool and Relay worktrees. No production code
changes, release or ceremony operations are authorized or performed by this review.

The accepted trust model is not under reconsideration: participants in both phases
trust earlier coordinator acceptance, authenticate their exact assigned input and
check their own contribution. Full final coordinator replay remains mandatory.

## Review loop

Round 1 used an independent reviewer alongside local source tracing. Findings
were revised into the specification and implementation plan. Round 2 rechecks the
revised contracts for contradictions and uncaught implementation hazards. Findings
below distinguish observed source behavior from proposed validation still pending.

| Finding | Evidence and impact | Resolution / validation gate |
| --- | --- | --- |
| High: self-check may mutate generated output | Pinned native Phase1/Phase2 `Verify` assign `next.Challenge`; current own-check helpers pass the new output directly. A nonempty wrong challenge is rejected today, but an empty challenge can be filled by native verification; wrapper checks must remain before it. | Require exact generated challenge against predecessor digest before verification, verify a clone, and assert unchanged retained bytes. G1/T15 before helper replacement. This is a refactor hazard, not proof of a current accepted bad candidate. |
| High: assignment freshness claim exceeds offline authority | `CreateAllocatedContributionCandidateV4` checks active allocation in captured signed ancestry; raw `CreateContributionCandidate` only has paths and optional scope. Neither queries the latest remote head. | Restrict new production shortcut to private allocation-authenticated context; Relay obtains current snapshot and rejects retired attempts on upload/acceptance. No global-freshness claim from offline checks. G2/T16. |
| Medium: command phase versus allocation phase | `executeContribution(phase, ...)` takes a phase, but its V4/V5 branch calls allocated helper without passing it; that helper uses the allocation's phase. | Source confirms phase is omitted at the boundary and output is labeled from the command; pass expected phase/participant ID, compare before entropy, and label from authenticated output. Do not silently contribute to the other phase. G2/T16. |
| Medium: canonical Phase 1 genesis could be lost | `loadVerifiedPhase1FilesExact` authenticates signed genesis but canonical construction lives in the mathematical path being removed. | Explicitly retain canonical Phase 1 genesis construction/hash comparison once, separate from history replay; signed wrong genesis must fail. G3. |
| Medium: native pointer is insufficient input authority | Both phases have mutable native state; head loading and caller-provided optional scope could be confused with authenticated assignment. | Private result binds definition/circuit/phase/index/participant/input/chain/checkpoint/attempt and owns decoded head. Constructor enforces first/later challenge and shape invariants. G1/G2. |
| Medium: hidden expensive calls | `verifyAcceptedCandidateV4` currently fully replays Phase 2 via `VerifyAcceptedPhase2Chain`; lifecycle verification can similarly repeat work outside the visible command. | Full workflow matrix with counters for sync, preparation, generation, closure/checkpoint, publication and retry. Do not claim acceptance replay removed merely because participants changed. G4. |
| Medium: a successful retry can accidentally regenerate entropy | New helper extraction crosses generation and recovery boundaries. Current Relay can inspect/reuse completed output; source inspection is not fault-injection coverage. | Include crash after entropy but before directory creation; durable started state, no same-attempt regeneration after ambiguous start, exact attempt/output retention. Relay already journals running before launch; standalone direct CLI tracking is subsequently deferred; G6 retains Relay recovery validation. |
| Diagnosed fixture issue: final verification baseline | Subsequent Linux reproduction proved deterministic output and correct checkpoint binding; the test wrongly expected audit count to equal the policy minimum. See [final-review investigation](ceremony-final-review-investigation.md). | Apply the test-only correction and rerun full repository qualification; production quorum and report binding remain unchanged. G5. |
| Existing blocker: persistent key memory and provenance | File-size limits alone do not bound native allocation or concurrent object lifetime; cached keys can accidentally replace final replay claims. | Exact input tuple/decoder/peak-memory and fault-injection evidence before cache integration. G7 blocks F only. |

Source anchors: `internal/mpcceremony/{workflow,phase1,phase2,files,contribution_allocation_v4,checkpoint_v4_files,finalize}.go`,
`cmd/mpc-ceremony/executor.go`, pinned
`vendor/github.com/consensys/gnark/backend/groth16/bls12-381/mpcsetup/phase{1,2}.go`,
and Relay participant/coordinator guide, transcript inspection and storage commit paths.

## What is NOT a finding

- No normal acceptance-producer bypass was found. Generic Phase 1 checkpoint
  preparation consumes a coordinator-signed chain; it does not create its passing
  receipt. Do not add historical math merely to defend against a dishonest
  coordinator fabricating its own signatures under the accepted trust model.
- A participant may not detect signed invalid historical mathematics. This is the
  intended tradeoff. Some bad histories will still fail own-check/native validation;
  tests must not assume every invalid history can produce a contribution.
- Authentication still reads/checks historical evidence and retained files. This
  revision does not authorize shrinking snapshots or skipping file hashes.
- Full public/auditor verification and schema-specific signer rules remain separate
  from the single participant contribution path.

## Before implementation versus later qualification

Complete G1–G4/G6 targeted fixture/harness checks before replacing the affected
production paths. The gates describe validation work to do; they are not all
satisfied by this review. Test development and an isolated prototype can precede
production wiring. Preserve a baseline and report actual results.

G5 blocks finalization/end-to-end qualification, not independent work on input
loaders. G7 blocks persistent-cache integration, not the no-cache participant and
closure work. The operator resolved release order: proof-tool release first,
then one Relay release with updated pins and compatible resource/UI changes.

Production-size participant memory and full-operation performance are release
qualification requirements. The existing 96/49/33-minute measurements cannot
establish complete participant duration, cache-hit memory or new clone overhead.

## Executed checks in this review

- Source traced both native contribution/verifier implementations, allocation CLI
  and helper boundary, accepted-chain loaders and final-key verification entrypoints.
- Ran existing Go tests with vendored dependencies. The combined selection reached
  `TestVerifyAcceptedPhase1ChainCheckpointBoundary` but failed before signed workflow
  execution: production executable identity requires Linux `/proc/self/exe`, while
  this host is Darwin. This is an environment limitation, not a passing acceptance
  test or evidence of a new mathematics failure. Re-run on the approved isolated
  Linux validation setup; no remote ceremony was touched here.
- Portable tests PASSED on Darwin with vendored dependencies:
  `go test -mod=vendor ./internal/mpcceremony -run '^(TestVerifiedGenesisReplayMatchesIndependentReplay|TestOwnedPhase2SealMatchesIndependentKeys)$' -count=1 -v`
  (package 1.644s). Cases include 0–3 contributions, invalid edges, bad shapes,
  challenges and loader failures, and independent versus owned final-key equality.
  These exercise existing primitives, not the proposed participant shortcut.
- No new entropy/assignment/fault-injection harness was created in this review.
  Those remain explicit preimplementation gates.

## Round 2 result and revisions

The second independent pass found the CLI phase-label mismatch and the ambiguous
started-attempt recovery wording. Both are now precise requirements in the plan
and specification, with phase/participant mismatch rejected before entropy and
absence of output explicitly insufficient to justify regeneration. The current
Relay journal already persists running before invoking its child; retain that
behavior. Equivalent standalone direct-invocation protection was subsequently deferred by
the operator; Relay recovery validation remains required.
Round 1 helper, ownership, canonical-genesis and offline-freshness requirements
were accepted by the second reviewer. Final consistency pass follows these edits.

## Final consistency pass

The independent reviewer found no further blocking design contradiction after
round 2 revisions. The design is ready for the listed preimplementation validation
work, not for an unconditional implementation/release claim. G1–G4/G6 fixtures,
standalone direct CLI tracking is deferred; the Linux signed-workflow requirement
is addressed separately by the follow-up investigation below;
final-review baseline and persistent-cache gates retain their scoped blockers.
This review did not modify production code or release artifacts.

Follow-up investigation resolved the cause of the final-review error as a fixture
audit-count assertion. See [final-review investigation](ceremony-final-review-investigation.md) for Linux evidence
and the remaining repository test-maintenance step. Earlier descriptions of an
unexplained finalization failure are superseded by that finding.

Operator scope decision: persistent coordinator caching is deferred. G7 and
cache-only recovery/decoder work remain gates for that future feature, not current
A–E delivery. Standalone direct-CLI durable tracking is also deferred as noted above.

Deferred scope and future resumption criteria are consolidated in the
[deferred-task register](ceremony-optimization-deferred-tasks.md). D1/G7 is cache-only; D2 is standalone
tracking only. Relay-managed recovery and current-operation memory checks remain.
