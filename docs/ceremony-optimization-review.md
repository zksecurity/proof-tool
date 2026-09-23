# Ceremony optimization design for operator review

Status: documentation-only revision, 2026-09-23. No implementation or release
is authorized by this update. Existing unpublished prototypes remain unqualified.
This revision adopts the honest-coordinator and trusted-delivery-service model;
signatures, exact hashes, ceremony/circuit binding and file integrity remain mandatory.

The detailed implementation contract and adversarial findings are in
[`ceremony-optimization-specification.md`](ceremony-optimization-specification.md).
That specification refines the broad summary below, including excluding the
final Phase 2 seal from the reconstruction-input tuple and distinguishing valid
new inputs (cache miss) from invalid referenced bytes (operation error).

Implementation work packages and CLI acceptance criteria are in the
[implementation plan](ceremony-optimization-implementation-plan.md).

## Intended result

Do expensive calculations once per set of unchanged inputs on the coordinator.
Keep each participant’s own contribution check and mandatory final coordinator
replay. Participants in both phases use their authenticated assigned input. Make
resource limits and progress visible. Restart with a fresh ceremony after the releases, rather than
replace software in the stopped ceremony.

## 1. Remove repetition inside a command

| Operation | Current released behavior | Proposed behavior |
| --- | --- | --- |
| Save Phase 2 starting checkpoint | Four initializations, with repeated Phase 1 verification | One authoritative verification and one initialization |
| First Phase 2 acceptance | Initialize while checking input, then initialize predecessor again | Reuse the checked starting state; verify the new contribution normally |
| Check Phase 2 chain | Initialize while authenticating genesis and again for replay | One initialization, every contribution still checked |
| Reconstruct final keys | Initialize for checking genesis and again for sealing | Keep genesis and its matching private evaluation data together, then consume them once |
| Build acceptance checkpoint | Full check for preliminary projection and authoritative preparation | Construct projection from authenticated records; retain authoritative validation |
| Initial Phase 1 checkpoint | Authenticate genesis files twice | Apply the same projection/authoritative-validation separation, subject to review and tests |

Also return each parsed record and its exact references from the same read;
never combine a checked record with references obtained by reopening it later.
The existing Phase 1 close/seal acceptance-evidence optimization stays in place.
Do not repeat all Phase 1 mathematics by default after the beacon. Authenticate
acceptance history, independently apply the beacon to the accepted head and compare
the resulting commons. Retain an explicit full-replay troubleshooting option, as
requested in the latest design; auditor checks remain.
It is not an independent full mathematical replay.

Removing these duplicate calculations preserves verification coverage. The
separate participant policy in section 3 deliberately changes the trust boundary.

## 2. Acceptance-history reuse now; persistent saved results deferred

For the revised Phase 1 path, first reuse the existing signed history and seal:
authenticate them on each invocation, recompute beacon application and pass owned
commons directly to Phase 2. No new persistent cache is required for that first
implementation.

Persistent Phase 1 calculation receipts and final-key caching are deferred under
D1 in the [deferred-task register](ceremony-optimization-deferred-tasks.md). Their private-key, decoder, memory,
atomic-publication and recovery contracts are retained in the specification for
future work. They do not block the current no-cache release. Do not add cache UI,
mounts or commands, or claim three-to-one reconstruction across separate commands.

Standalone direct-CLI durable attempt tracking is deferred under D2. Relay's
existing durable journal and recovery checks remain current requirements.

## 3. Recovery and independent checks

A saved result never means "an output directory exists, therefore success."
Retain exact timestamps, no-overwrite publication, complete output inventories,
file integrity checks and refusal of conflicting partial output. Never repeat
contribution randomness merely to reconstruct a lost operation.

In both phases, participants authenticate their exact assigned input, ceremony,
circuit, allocation within the authenticated snapshot, signed acceptance history and required file hashes.
They add fresh randomness, check their own contribution and perform cleanup. They
do not replay earlier contributions in either phase. Phase 2 participants also
skip Phase 1 mathematical replay and independent starting-parameter reconstruction.

They trust the coordinator's mathematical checks of earlier contributions and
correct Phase 2 derivation. Their own valid contribution does not prove the input's
history was valid. Final coordinator replay can detect invalid history and block
release, but cannot undo contributions already made. There is no participant
independent-verification option. Signatures and exact file-integrity checks remain.

Existing signed chains already bind starting-file hashes, ceremony and Phase 1
seal, while the signed definition binds the circuit/software. No new genesis
record is proposed. This is the first real release, so there are no deployed
participant expectations to migrate. This is the release's participant path,
without a separate independent-verification option. Explain the coordinator trust
assumption in setup/help and report the actual mode. No new signed policy field,
schema version or separate consent gate is required solely for migration.

Retries retain the same verification requirements and exact attempt/output bindings. Once a ceremony starts, its signed definition, approved tool
pins and exact attempt bindings still apply. Preserve protocol-specific signer
requirements, including V5’s coordinator-replay and production-decision requirements.
Participants never receive coordinator cache authority.

### Coordinator Phase 2 closure

Authenticate the complete accepted history, every exact file and passing record,
contribution order, required completion, current checkpoint/head and future-beacon
commitment. Reuse prior acceptance mathematics instead of replaying all Phase 2
transitions at closure; retain an explicit full-replay option. Preserve future-round
lead time, distinct-round rules and immutable retry behavior.

After the Phase 2 beacon, final-key reconstruction must independently replay both
phases, derive and compare Phase 2 genesis and verify beacon applications. An
acceptance-based closure never satisfies that requirement. The separate saved-key
proposal can reuse only the result of that full post-beacon reconstruction, and
never substitutes for proof tests or publication checks.

### Acceptance audit and adversarial finding

Direct CLI acceptance and allocated V4/V5 acceptance both reach
`VerifyAndAcceptContribution`, which checks the exact new edge before creating a
passing record for either phase. Direct retries check mathematics before comparing
existing output. The signed chain binds the verification record, and loaders check
its fields and all retained files.

Follow-up investigation found no normal command that creates a passing receipt
without checking the contribution first. General checkpoint preparation requires
an already coordinator-signed contribution chain and its passing evidence; it
records that acceptance rather than creating the receipt. The earlier description
of this as a confirmed gap/blocker was incorrect.

Direct retries check mathematics before publishing exact output. Relay can resume
publication of an existing signed checkpoint without repeating mathematics, but
still authenticates the checkpoint/ancestry, publishes exact artifacts and checks
the storage head. Fabricating the underlying signed chain outside these workflows
requires using the coordinator key; that is covered by the honest-coordinator
assumption. Keep regression tests, not an extra redundant Phase 1 replay. This
finding is source inspection of both local worktrees, not a new runtime test run.

## 4. Resources and progress

Relay selects and records CPU/memory allocation before each operation, honors
saved caps, checks host capacity and keeps retries on the original allocation.
Show actual limits and elapsed/stage progress without inventing a percentage or
ETA. No live resizing is proposed.

On the node host, measured Phase 2 component totals were 96, 49 and 33 minutes
at 2, 4 and 6 CPUs; all produced identical genesis and peaked near 3.7–3.8 GiB.
These are Phase 2 starting-parameter reconstruction component measurements, not
full participant timings. Remaining contribution and verification costs were not
separately measured; they do not qualify another host or establish total savings.
More memory testing is required because reusing objects extends their lifetimes.

## 5. Validation and release order

Before release: complete the current call/read audit; test changed evidence,
wrong software/circuit/assignment, contribution self-checks, beacon application,
final replay and all managed recovery/publication boundaries. Compare exact
outputs and run real proof/rejection checks. Measure current full operations on
the production circuit, including peak memory, CPU and elapsed time. Run repository
and cross-repository release gates. Cache-specific tests remain with deferred D1.

Release order is now two stages: first the proof-tool optimization release;
then one Relay release that updates its proof-tool pin and includes compatible
resource/UI/integration changes. No separate Relay-only release is planned.
Qualify the integrated V5 workflow before the Relay release and begin a fresh
ceremony with the approved pairing. Persistent cache integration stays deferred.
Exact versions are assigned under repository version policy when scope is frozen.

## Review decisions and remaining work

The detailed specification separates duplicate calculation removal from the
participant trust change. Future implementation needs authenticated-head loaders
and contribute-from-head paths for both phases, participant UI/CLI wiring, acceptance-based
Phase 2 closure and checkpoint wiring, acceptance-evidence binding,
and strict separation from final replay. Existing signatures supply file binding;
the default needs clear trust documentation, not a new migration record format.

Adversarial review added tests for signed-but-wrong genesis with valid Phase 2
transitions, generic acceptance authoring, stale signed heads and accidental bypass of mandatory final replay.
Also require wrong hashes/circuit/ceremony, missing acceptance evidence, invalid
earlier contributions, altered beacons, wrong beacon application and signed invalid
histories rejected by final reconstruction. These are specified tests, not tests
run in this documentation-only update.

The audit table in `mpc-ceremony-redundancy-audit.md` is historical source evidence,
not current policy. This review, specification, implementation plan, CLI contract
and deferred-task register define the current scope.
Current engineering details include complete read-path coverage, managed
preparation/recovery paths, the CLI contract and full-operation measurement.
Cache schemas, cache-key permissions and native cached-key bounds belong to D1;
standalone durable tracking belongs to D2. No claim is made that
all possible redundant reads or calculations have been found.

Independent review rejected hashing files after verification as cache proof,
required owned captured records and actual-read digest checks, and required
single-use evaluation ownership and indivisible final-key generations. These
are design findings, not certification or completed test evidence.

Release scope: require only the full V5-definition ceremony workflow. Remove
historical V4-definition tests and fixture switches, transferring shared security
and recovery coverage to V5. V5 still uses V4-named workflow code and checkpoint
formats; retain tests of that code with explicit V5 definition assertions. No
public command/schema renaming is implied. Historical V4 investigation logs are
retained as evidence, not as a continuing release requirement.

Outstanding work includes participant CLI/retry handling and full recovery
qualification. The prior final-review failure is a diagnosed test-helper
audit-count assertion; see the [final-review investigation](ceremony-final-review-investigation.md).
The isolated test correction has not been applied to repository source.
Current-operation memory/performance measurements remain release gates.
Persistent-key memory and recovery qualification gate deferred D1 only. Design review is complete for this revision, not certification that
implementation or release gates have passed.

The [adversarial review log](ceremony-optimization-adversarial-review.md) separates
preimplementation checks from release gates. Priority validations are native
self-check mutation/challenge handling, assignment authority and offline freshness,
canonical Phase 1 genesis binding, full workflow call counts and entropy-safe
recovery. Persistent-key memory/decoder validation blocks caching specifically.

The implementation plan now starts with **task 0: correct the final-review test
baseline**. It is a separately reviewable test-only change, with full signed V5
workflow validation before production optimizations. Production quorum and
verification rules do not change.

Persistent caching is explicitly deferred. Its memory and recovery requirements
do not block current no-cache optimizations; do not expose cache UI or promise
cross-command final-key reuse in this release.

Exact role prompts, stage/result/error text and coordinator diagnostic options
are drafted in the [CLI contract](ceremony-optimization-cli-contract.md).
