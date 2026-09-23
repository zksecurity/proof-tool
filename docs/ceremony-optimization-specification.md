# Ceremony optimization specification — review draft

Status: documentation-only design revision, 2026-09-23. Do not implement,
release, upgrade frozen software or restart a ceremony under this instruction.
Existing unpublished prototypes are not evidence that this revised design is
implemented or qualified. The participant and Phase 2 closure policies below supersede earlier requirements
for participant reconstruction, participant replay of earlier contributions in
either phase, and full mathematical replay at Phase 2 closure.

This specification supplements `ceremony-optimization-review.md` and the
historical call-site inventory in `mpc-ceremony-redundancy-audit.md`. Current
behavior is defined here and scoped by the deferred-task register; older audit
policy statements do not override it. Current preimplementation validation gates
remain pending; documentation readiness does not mean implementation readiness.

Implementation work packages and CLI acceptance criteria are in the
[implementation plan](ceremony-optimization-implementation-plan.md).

Scope details and resumption criteria are in the [deferred-task register](ceremony-optimization-deferred-tasks.md).
Scope update: persistent coordinator caching, including final-key caching, is
explicitly deferred. Cache contracts below are retained for future work, not
implementation requirements for the current no-cache release. No persistent
receipt/MAC key, cache mounting or cache UI is enabled in current scope. Cache-only
memory/decoder/crash gates block that future feature, not the other optimizations.
Within-command reuse and acceptance-history verification remain in scope; do not
claim three-to-one key reconstruction across separate commands without caching.

## 1. Goals and limits

First-release assumption: there are no deployed participant expectations to
migrate. Authenticated assigned-input verification in both phases is the participant path,
without a participant independent-verification option; no migration policy schema
is needed.

1. Remove duplicated deterministic calculation inside a command.
2. Reuse only previously verified deterministic results between coordinator
   commands, with unchanged authenticated inputs and approved software.
3. Preserve mandatory mathematical checking of every newly accepted contribution,
   each participant’s own input-to-output transition, all public proof/negative
   checks, exact file binding, signing policy and immutable publication behavior.
4. Under the honest-coordinator and trusted-delivery-service assumption, permit
   participants in both phases to contribute from their authenticated assigned
   input without replaying earlier contributions or deriving Phase 2 genesis. Retain auditor/public full verification and mandatory coordinator replay
   of both phases during final-key reconstruction after the Phase 2 beacon.
5. Expose actual CPU/memory allocation and progress without unsupported ETAs.
6. Qualify the released pairing through a fresh full same-device ceremony.

No saved result represents candidate validity, successful publication, current
storage head, approval by a person, or successful cleanup. No receipt authorizes
new signing identities, changed ceremony definitions or replaced frozen tools.

### Coordinator Phase 1 reuse under the honest-coordinator assumption

The coordinator may rely on its prior mandatory mathematical acceptance checks.
After the Phase 1 beacon, authenticate the complete signed acceptance history,
exact contribution/evidence bytes, order and challenge links; authenticate closure
and beacon including raw beacon cryptography; independently apply that beacon to
a private copy of the accepted final contribution and compare the derived commons
to the exact signed/stored result. Do not replay all Phase 1 transitions by default
in this coordinator-only path or again when using its result to initialize Phase 2.

Call this method `coordinator-acceptance-and-beacon-v1`. It is not an independent
full replay. A signature proves attribution, not that mathematics were checked;
this method explicitly trusts the approved coordinator's earlier acceptance
checks. A coordinator that signs fabricated passing records can defeat this local
shortcut. Auditor/public full verification and final coordinator replay must still
reject invalid mathematics even when all coordinator records are validly signed.

Retain a distinct `independent-full-replay-v1` method and explicit troubleshooting
full-replay option. The latest operator request supersedes the earlier proposal
to delete the seal flag entirely: avoid extra replay in the normal flow, while
preserving an explicit diagnostic route. Never silently downgrade a requested
full replay to acceptance-based validation.

The acceptance-based path may produce a reusable Phase 1 result after the beacon
application and output comparison pass. Its receipt must contain the exact method
and same captured input/verifier/circuit bindings. Consumers requiring independent
full replay must reject that method, even with a valid MAC. Both types may serve
only their explicitly permitted coordinator operations. Ordinary seal creation,
without independent output comparison, does not mint either verification claim.

The first implementation should reuse a private owned verified-commons result
within a coordinator operation and preserve public independent-verification APIs.
Cross-command persistence must retain the existing owned-read, MAC, permission,
publication and method-isolation requirements. Use distinct typed verification policies and explicit entry points; no ambient
boolean may silently override an explicitly requested independent verification. For coordinator Phase 1 reuse, preserve existing signed public artifact schemas;
the participant default below also does not require a new public record format.
Do not change `coordinator-full-replay-v1` protocol IDs.

Proposed first implementation scope (not authorized by this revision): no persistent Phase 1 cache or MAC
receipt is introduced. Existing signed acceptance/seal files are reauthenticated
on each invocation, the beacon application is independently recomputed, and the
owned derived commons are passed directly to Phase 2 initialization. Private
method labels are returned/logged locally; public artifact schemas are unchanged.
Final-key caching remains a separate unqualified proposal. Receipt requirements
below apply only if persistence is subsequently added.

For the V5 release target, coordinator preparation validates its matching signing
key before selecting the acceptance method. Current source also supports older
formats; that observation does not require their historical workflow tests in this
release. V5 production-decision requirements remain unchanged. Context-free public
full-verification APIs keep full replay.
Record-v4's private context binds the same authenticated definition references
through authoritative preparation; changed definition bytes cause refusal.

Required integration coverage: coordinator Phase 1 sealed checkpoint, Phase 2
initialization and its checkpoint must use the intended coordinator context, while
independent audit/public replay and final
reconstruction continue full checks. The single authenticated-assigned-input
participant path below checks the new contribution in either phase, without
replaying earlier transitions. Trace generic checkpoint-reader uses before adding context:
calling the same verifier from a coordinator and participant must not silently
give them the same trust policy. Old Relay pins receive no unsupported arguments.

Required counterexamples: changed or missing acceptance records, changed earlier
payload/evidence, wrong order/predecessor, invalid raw beacon, altered commons,
method-confused invocation/private result, and validly signed but mathematically
invalid history. Persistent receipt-method confusion tests belong to deferred D1.
The latter may pass the acceptance-based trust boundary by design but must fail
independent audit/public replay and final verification. Compare valid-path commons exactly
with full replay. Test the explicit full-replay option independently.

### Acceptance-path audit and limits of the evidence

Source inspection of this working tree finds one production constructor of a
passing `ContributionVerification`: `VerifyAndAcceptContribution` in
`internal/mpcceremony/workflow.go`. Both phase branches verify the exact
predecessor-to-candidate transition before constructing `Passed: true`. The first
predecessor is canonical Phase 1 genesis or checked Phase 2 genesis; later
predecessors are read from the authenticated accepted head. Candidate bytes are
hashed on decoding, matched to the participant attestation, and checked against
the predecessor challenge. The verifier receives a clone because it can mutate
challenge fields; the retained accepted payload must remain the checked bytes.

| Production route | Mathematical acceptance boundary | Retry/import boundary |
| --- | --- | --- |
| Direct Phase 1/2 CLI acceptance (`executeAccept`) | Calls `VerifyAndAcceptContribution` for both phases | Existing exact-output checks run after transition verification; no early output-exists success |
| Allocated V4/V5 acceptance (`VerifyAndAcceptAllocatedCandidateV4`) | Checks authenticated allocation and inventory, then calls the same function | Re-entry repeats that boundary; authoritative checkpoint preparation follows |
| Generic candidate-accepted checkpoint proposal (`PrepareCheckpointV4` → `verifyAcceptedCandidateV4`) | Phase 1 currently authenticates evidence only; Phase 2 currently performs full replay via `VerifyAcceptedPhase2Chain` | Requires an already coordinator-signed chain and passing evidence; creates a checkpoint, not the acceptance receipt |
| Loading an already authenticated published checkpoint | Validates prior evidence, not a new acceptance | May recover exact completed state; must not mint new acceptance merely from existing files |

`ContributionVerification` binds ceremony, phase/phase ID, participant, position,
predecessor payload and record, output, attestation/erasure IDs, coordinator key
and acceptance time. It is transitively authenticated by its exact reference in
the coordinator-signed chain, not by a separate signature on verification JSON.
`verifyChainFiles`, `validateContributionVerification` and
`ValidateAttestationAcceptance` check retained payload hashes, signatures,
record consistency, ordering and predecessor links for the entire prefix.
Missing evidence is an error, not permission to trust just the chain signature.

Follow-up investigation of ordinary commands and retries (2026-09-23) found no
route that creates a passing acceptance receipt without first checking the new
transition. The earlier description of generic checkpoint preparation as a
confirmed acceptance bypass/blocker was incorrect.

The distinction is between creating an acceptance record and recording that
existing acceptance in a checkpoint. `checkpoint prepare-v4` and `sign-v4` call
`verifyAcceptedCandidateV4`, which requires an already coordinator-signed chain
through `LoadSignedChainExact`, the referenced passing verification record and
consistent retained evidence. These commands do not create the chain signature
or passing receipt. The only production `ContributionVerification` constructor
found is in `VerifyAndAcceptContribution`, after the mathematical checks for both
phases. `ops sign` uses a record-type allowlist that excludes chains and
contribution-verification records; it is not an alternate chain-signing command.

Direct acceptance retries run the mathematics before comparing/publishing exact
retry artifacts. Allocated acceptance calls the same checked function before
checkpoint preparation. Relay's coordinator guide invokes `accept-candidate-v4`
when no checkpoint output exists. If it already exists, Relay resumes publication:
`commit-v4` authenticates the checkpoint/signature and ancestry, publishes the
required exact artifact inventory and reconciles the exact storage head. This
reuses an already signed result, not a new passing receipt. Incomplete or altered
unsigned output cannot become accepted merely because a file exists.

Someone using the coordinator key outside the supported acceptance workflow can
fabricate a signed chain and passing evidence. Generic Phase 1 checkpoint
preparation trusts that already-signed history, as intended under the honest-
coordinator assumption. That is not evidence of an accidental normal-command
bypass and does not justify adding repeated transition mathematics here.

Keep regression coverage for direct/allocated acceptance, generic preparation
requiring authentic prior evidence, and interrupted publication. Generic Phase 2
preparation currently does full replay; any later removal must preserve evidence
binding and the acceptance producer's mandatory new-edge check. This investigation
was source/caller tracing in the local proof-tool and Relay worktrees, not a new
fault-injection test run or certification of every possible release binary.

### Participants in both phases: authenticated assigned input

Proposed internal method label: `coordinator-accepted-input-v1`. This is the sole
participant path for the first real release, not a coordinator-cache hit. It
supersedes the earlier design that still replayed preceding Phase 2 contributions.
Participants receive no cache key and have no independent-replay mode switch.

1. Authenticate the signed definition with the configured coordinator trust key,
   bind the actual circuit and approved software, and authenticate the current
   checkpoint/ancestry, participant schedule, phase, index and allocation. A valid
   but unrelated signed chain must not substitute for the assigned attempt.
   Currentness is limited to the authenticated snapshot as detailed below.
2. Authenticate the ordered accepted history and its evidence, signatures, exact
   retained-file hashes and predecessor links. Preserve existing file-integrity
   coverage; this change removes historical transition mathematics, not evidence
   validation or checks of files supplied in the authenticated input snapshot.
3. Select the exact assigned predecessor from the captured signed chain: genesis
   for index one, otherwise the last accepted output. Decode it with the correct
   circuit-derived shape and digest the same bytes used for computation. Validate
   zero challenge for genesis and contribution challenge framing for a later head.
   For Phase 1, retain the canonical genesis check explicitly: construct canonical
   Phase 1 genesis for the signed domain, hash its serialization and compare with
   the definition/archived genesis. Do this once per participant invocation, release
   the extra object, and do not confuse this with historical transition replay. For Phase 2,
   authenticate the published genesis and Phase 1 seal linkage through its phase
   ID, including required closure/beacon/evidence integrity, without replaying
   Phase 1, applying its beacon anew, or independently deriving Phase 2 genesis.
4. Do not mathematically replay any preceding contribution in either phase.
   Retain all deterministic scope, schedule, input, key and destination checks
   before sampling randomness. Create a private copy of the authenticated input,
   generate fresh randomness and contribute. Keep an unmodified predecessor for
   checking the new input-to-output transition; verification may mutate challenge
   fields, so do not let it alter the archived/attested output.
5. Mathematically verify the participant's own contribution in both phases before
   reporting success. Publish exact output and attestation with existing immutable
   rules, perform cleanup and retain required cleanup evidence. A self-check
   failure produces no successful candidate/acceptance claim. Recovery preserves
   the exact attempt/output and never regenerates randomness to guess lost output.

Participants trust the coordinator's previous acceptance checks in both phases,
and additionally its correct Phase 1 beacon processing and Phase 2 derivation.
Checking their own transition does not establish that their predecessor has a
valid history. A signed mathematically invalid earlier contribution or incorrectly
derived genesis can pass input authentication and may permit a valid own transition.
The participant is not required to detect that historical mathematical fault.
Mandatory final coordinator replay and auditor/public full replay must detect it.
Those checks block release but cannot undo contributions already made to bad input.

Logs must say "Authenticated assigned input and checked your contribution", not
"Replayed the ceremony". Final reconstruction and auditor/public verification
remain separate full-replay workflows. No participant full-replay selector is added.

### Participant helper invariants and assignment authority

The private authenticated-input result must bind: ceremony/definition references,
actual circuit identity and domain/shape, phase, index, participant, chain references,
input `ArtifactRef`/digest, predecessor record ID, checkpoint/attempt/scope when
allocated, and one owned decoded head. Construct it only after these values agree.
A bare native pointer plus shape is not assignment authority. Mark its assurance
as authenticated coordinator input, never independently replayed history.

Before the own-transition verifier runs, require the generated output's nonempty
challenge to equal the hash of the exact authenticated predecessor serialization,
using the existing challenge/digest algorithm. Keep the unmodified predecessor
and generated output; run native verification on a throwaway output clone. Compare
serialized retained input/output before and after checking in tests. This avoids
letting `Verify` repair a generation error: pinned native Phase 1 and Phase 2
`Verify` assign `next.Challenge`. Preserve shape, canonical encoding and subgroup
checks; honest-coordinator trust does not disable safe decoding of native points.
Release redundant owned objects promptly and qualify peak memory for these clones.

Production V4/V5 CLI currently requires checkpoint, signature and attempt ID and
calls `CreateAllocatedContributionCandidateV4`. Preserve that boundary. It proves
that an allocation is active IN THE CAPTURED CHECKPOINT. It cannot establish that
an offline snapshot remains globally current. Relay authenticates the delivery
service head before preparing that immutable offline attempt; upload and acceptance
must reject retired/stale attempts against current state. A later retirement while
the participant is offline must not silently redirect its input or regenerate its
randomness. Report the stale attempt when discovered and retain existing recovery.

The raw `CreateContributionCandidate` API accepts caller-supplied transcript paths
and optional scope; it must not claim current delivery assignment. Restrict the
new coordinator-trusting production path to the authenticated allocation wrapper
using private context that raw callers cannot manufacture from optional fields.
Keep raw legacy/test APIs on their established contract or explicitly deprecate
them; this is an API authority boundary, not a participant verification-mode option.
Test direct V5 CLI rejection without an allocation and both phase-specific
commands against mismatched allocated phase. Explicitly bind command phase to
allocation phase before randomness; current executor passes only the allocation
into the allocated helper and labels its result with the command phase. Pass an
expected command phase into that boundary, compare before entropy, and derive the
successful phase label from the authenticated result. The CLI also accepts an
explicit participant ID: compare it with the authenticated scope rather than
silently ignoring it. Test both cross-phase directions and wrong participant ID
with zero entropy draws.

An absent candidate directory does not establish that randomness was never drawn:
`generateContributionWriter` currently runs before `os.Mkdir`. Preserve Relay's
journal rule: persist running before launch, never automatically re-run a started
operation, and inspect exact retained output on recovery. A prepared/unstarted
attempt may generate once. A started attempt with no recoverable complete output
is ambiguous; use explicit retirement/reallocation and new attempt identity,
not automatic regeneration under the same attempt. Crash-test immediately after
entropy and before directory creation. The operator deferred a separate durable
started-attempt mechanism for standalone direct CLI/API invocation. It is not a
blocker for the Relay-managed scope; retain and validate Relay’s journal protection.
Standalone crash-safe retry support is not claimed. An optional scope or absent
output directory does not provide that protection.

### Existing signatures and explicit policy selection

Existing artifacts already provide the genesis integrity/provenance bindings:
`LoadSignedChainExact` verifies the coordinator signature; the chain contains
ceremony ID, phase ID and the exact genesis `ArtifactRef`; Phase 2's phase ID binds
the Phase 1 seal; the signed definition's ceremony ID binds the circuit and
software. Checkpoints/allocations bind the selected chain and turn. Retain all
those checks. `Chain.ValidateAgainstDefinition` alone does not check the Phase 2
seal linkage: the new loader must explicitly retain the `ComputePhaseID` check
currently in `loadVerifiedPhase2FilesWithGenesis`.

No additional genesis signature or contribution acceptance-record format is
needed for these bindings. This is the first real release: there is no deployed
participant expectation to migrate. Make `coordinator-accepted-input-v1`
the single participant verification path in this release, without an independent
full-verification switch. Do not require a new signed definition field, schema
version, migration mechanism or separate consent gate solely to distinguish it
from an unreleased default.

Document the honest-coordinator assumption in participant setup/help and display
the verification basis before computation and in the result. No participant mode
selector or mode acknowledgment is required. Retries keep all authentication and
Phase 2 transition checks; recovery of an already-produced contribution preserves
its exact output and attempt without regenerating randomness.

The approved release implementation defines the default, and the signed software
binding identifies the approved tools. `ReleaseVerification =
coordinator-full-replay-v1` remains a release-verification rule, not a participant
mode selector. No change to existing genesis or acceptance signatures is needed.
Check setup export/import, runtime binding, checkpoint validation and recovery for
consistent participant verification, without adding a new public policy record by default.

This first-release assumption removes the proposed compatibility machinery for
historical participant expectations. It does not relax ceremony integrity: once a
ceremony is started, retain its signed definition, approved tool pins, participant
order and exact attempt bindings. Preserve V5 coordinator-replay and production-
decision requirements. Do not change older public signer semantics incidentally
when editing shared code, but remove historical V4-definition test fixtures as
specified in task 0a; the required full workflow uses an actual V5 definition.

### Coordinator Phase 2 closure

In an explicitly supported coordinator path, authenticate the entire Phase 2
history and reuse the successful checks performed at acceptance; do not replay
all Phase 2 transitions just to close it. Use the same acceptance audit above,
including genesis-to-first and later predecessor-to-candidate checks. Authenticate
published genesis and its circuit/ceremony/seal bindings. This path must not hide
a full Phase 1 replay or Phase 2 genesis derivation inside its input loader.

Before signing closure, check all retained file hashes, participant signatures,
passing verification records and exact field consistency, contribution order,
head identity and the currently authorized checkpoint head, frozen completion
requirements, and matching coordinator signing key. Validate the Phase 1 closure/beacon linkage required for the Phase 2 beacon
policy. Select and commit to a future permitted beacon round after verification;
retain minimum lead time, distinct-round rules and the final pre-publication time
check. On an exact retry, preserve the original closure/round and existing retry
rules; never rewrite a signed closure to choose a more favorable beacon.
Missing or mismatched acceptance evidence blocks closure; do not silently repair
history or downgrade checks. Retain explicit full replay at closure, with no
fallback on failure. The closure result's method is acceptance-based, not a
post-beacon verification result, and never certifies final keys. Generic public
closure verification retains independent semantics; do not select coordinator
authoring context merely because the caller loads a coordinator signature.

After the Phase 2 beacon, final-key reconstruction MUST independently replay both
phases, reconstruct and compare Phase 2 genesis, verify both beacon applications,
and verify exact retained outputs. No acceptance-based checkpoint, closure,
participant-mode result or Phase 1 receipt satisfies this obligation. The separate
final-key cache proposal may reuse only keys produced by that complete post-beacon
reconstruction on identical authenticated inputs; it cannot remove the required
first replay. Proof tests, publication and release checks remain separate and
mandatory on every operation.

### Concrete implementation changes to make later

These are future work, not instructions to implement during this documentation task.

- Split genesis authentication/loading from deterministic reconstruction in
  `workflow.go`; return owned bytes/state with a typed verification basis and
  captured exact references. Keep public independent APIs independent.
- Add participant-specific authenticated-head loading for both branches of
  `CreateContributionCandidate` and its allocated wrapper. Add contribute-from-head
  helpers in `phase1.go` and `phase2.go` which preserve fresh randomness, immutable
  predecessor/output ownership and own-transition verification without historical
  replay. Do not call the existing replaying contribution helpers from this path.
- Provide consistent UI/CLI/retry reporting for both phases without a participant
  verification-mode switch, new signed policy schema or separate consent gate.
- Route coordinator post-beacon Phase 1 checkpoint and Phase 2 preparation through
  acceptance-history plus beacon/output comparison, returning the explicit basis.
- Change the Phase 2 branch of `ClosePhaseFiles` and closure checkpoint validation
  to authenticate acceptance evidence without invoking full replay. Extend the
  explicit full-replay option and propagate context through authoritative
  checkpoint preparation as well as projection/retry paths.
- Keep `finalize.go:replayAll` and final reconstruction isolated from weaker
  contexts. If final-key caching is added later, mint only from its full replay.
- Preserve the checked acceptance producer and authenticated-evidence boundary
  described above; do not add duplicate Phase 1 mathematics to checkpoint recording
  solely because it consumes an already-signed acceptance.
- Preserve direct acceptance mathematics, signer protocols, bounded decoding,
  single-read binding, immutable publication and all existing proof checks.

Duplicate initialization removal retains verification coverage. Coordinator reuse
relies on earlier checks rather than repeating them. Participant omission of historical replay in both phases and
independent Phase 2 reconstruction changes who is trusted for correctness;
it must be reviewed and measured separately from either optimization.

## 2. Trust and authority

The ceremony trust assumption remains current. All local cache-key/receipt/mount
authority requirements in this section are deferred D1 contracts, not current work.

The ceremony shortcut assumes an honest coordinator and trusted delivery service;
all signatures, exact hashes and binding checks still run. This does not give
delivery processes authority to mint private mathematical cache receipts.

The local cache trusts the operator account, its private filesystem and the
approved verifier process. A process that reads the MAC key can forge receipts;
MAC authentication does not enforce which code path minted them. The key must
therefore be available only to explicitly permitted coordinator invocations.
Compromise of that account/process is outside this cache's protection. Public
transcript writers, transport, downloaded files and ordinary coordinator
signatures alone do not gain local cache authority. The acceptance-based Phase 1
method additionally relies on the correctness of the coordinator acceptance
checks represented by authenticated signed history.

Use a new random 32-byte cache key, never a ceremony signing key. Create it with
exclusive creation, mode 0600, inside a private 0700 directory outside public
transcript, trust exports and participant workspaces. Refuse symlink components,
unexpected ownership, non-regular key files, unexpected size and permissive
permissions. Never log key bytes. No implicit key creation while reading a cache.
An explicit setup operation creates it; absence otherwise means uncached work.

Cache roots are local execution configuration. They are not accepted from a
signed public plan, receipt payload, remote URL or artifact path. A cache root
must not overlap public files, signing-key roots or another role's work area.
Changing cache key invalidates prior entries; it does not change ceremony state.

### Permitted entry points (proposed first version)

Enable cache only for the reviewed definition V5 coordinator operations.
The first-release participant default does not require a new definition schema,
so no participant-policy schema extension to this allowlist is proposed. Cache
permissions remain separate from participant mode:

| Operation | Sealed Phase 1 result | Final-key result |
| --- | --- | --- |
| `phase2 init` in explicit V5 coordinator mode | read/mint with explicit Phase 1 method | no |
| `checkpoint record-v4`, Phase 1 sealed transition | read/mint with explicit Phase 1 method | no |
| `checkpoint record-v4`, Phase 2 initialized transition | read/mint with explicit Phase 1 method | no |
| `checkpoint accept-candidate-v4`, Phase 2 coordinator verification | read/mint only with permitted Phase 1 method | no |
| `phase2 close` in explicit coordinator mode | No sealed-result mint required; authenticate acceptance history | no |
| `finalize prepare`, `finalize complete` | no nested cache initially | read/mint |
| `checkpoint record-v4`, final-candidate transition | no nested cache initially | read/mint |

The final-key cold path stays a complete independent local reconstruction; do
not compose it from other cached mathematical claims in the first version.
Acceptance-only close/seal cannot mint independent-full-replay receipts. The
acceptance-history plus beacon/output-comparison path may mint only its distinctly
labelled coordinator result.

Reject cache arguments on participant contribution, audit, public replay,
release signing/review, generic record signing, transport and legacy G1–V3
operations. Keep public verification APIs cache-free; introduce an explicit
private coordinator execution context rather than a process-global setting.
Relay must allowlist command plus transition before mounting the private cache.
An environment variable alone must not enable it. Test direct CLI rejection as
well as missing mounts. Shared read/mint key authority remains an explicit trust
assumption, even with read-only mounts.

## 3. Owned inputs and exact reads

Owned inputs, exact reads and file integrity apply now. References to cache cold/hit
paths and cache identities apply only if deferred D1 is resumed.

Refactor before implementing hit/mint branches. One private input loader serves
both cold and hit paths. It returns owned decoded roots and exact record/signature
references derived from the same bytes that passed authentication.

Do not verify record A and later hash record B. Do not infer immutability from a
read-only bind mount, open descriptor, hard link, size or timestamp. For native
artifacts, check digests from the decoding read itself against captured roots.
Repeated reads must independently match the same expected digest. Never reload a
signed root to discover descendants after the cache identity was constructed.

The actual circuit object's digest must match its signed binding. Existing shape
and binder-marker validation alone is insufficient at a receipt boundary. Derive
software identity from the running approved executable (`/proc/self/exe` plus
validated build metadata), not a supplied executable pathname or version label.
Keep these objects private and unchanged for the operation.

### Dependency matrix

| Input | Source of authority | Cold path | Hit path |
| --- | --- | --- | --- |
| Definition and signature | external coordinator key | authenticate/capture | authenticate/capture |
| External trust key | operator configuration | decode and bind actual bytes | same |
| R1CS | signed definition and actual circuit | validate shape and actual digest | same |
| Ordered phase chains/signatures | captured definition identity | authenticate/capture | same |
| Native genesis/contributions | refs in captured definition/chain | decode/digest plus math | decode/digest; no skipped file integrity |
| Attestations/cleanup/verification records | refs in captured chain | signatures and semantics | same |
| Closure and signature | coordinator plus chain consistency | authenticate/capture/validate | same |
| Beacon and signature | closure/policy plus raw response | authenticate/capture/validate | same |
| Raw drand response | captured beacon ref and signed policy | digest and cryptography | same |
| Phase 1 seal/signature and commons | closure/beacon/seal consistency | authenticate/decode and derive | authenticate/decode and receipt match |
| Final key cache files | local authenticated receipt | produced by full reconstruction | bounded exact-byte authentication and fresh decode |
| Phase 2 final seal/candidate/proof/report | final operation's own checks | always validate | always validate |

Critical source constraint: current `loadReplay` does NOT do every native file
check. Those checks live partly inside `replayAll`. Replacing `replayAll` with a
cache hit after the existing loader is unsafe. Move mandatory non-mathematical
checks into the shared input loader first and test each descendant separately.

## 4. Two receipt contracts

Deferred D1 only. No receipt implementation is included in current scope.

Proposed canonical schemas: `relay-local-sealed-phase1-v1` and
`relay-local-final-keys-v1`. Names are private implementation contracts, not
public ceremony schemas. Use strict canonical JSON with unknown/duplicate keys
rejected, a 64 KiB encoded receipt limit, fixed digest formats, checked integer
ranges and bounded arrays. Never let a receipt supply paths or arbitrary roots.

Each receipt contains only:

- `schema`, `operation`, `verification_method`, `cache_key_id`, `input_id`;
- `verifier` (actual executable digest and validated software binding);
- `circuit` (actual R1CS digest, circuit identity and serialization/curve identity);
- `inputs` (the fixed operation-specific root tuple below);
- `result` (the fixed operation-specific digest/encoding record);
- `mac` (32-byte HMAC-SHA256 encoded as fixed-length hex).

`input_id` is SHA-256 of canonical operation/schema/verification-method/verifier/circuit/input tuple
with a fixed domain prefix. MAC covers every field except `mac`, also with a
fixed distinct domain prefix. `cache_key_id` identifies the local key but grants
no authority. Encoding and domain constants must be committed as golden vectors
before implementation is accepted. No timestamps are needed for validity: a
mathematical result is tied to inputs, not wall-clock age.

### Sealed Phase 1 input tuple/result

Inputs: exact definition/signature digests; decoded external key; exact Phase 1
chain/signature, closure/signature, beacon/signature and seal/signature digests;
logical root roles; verifier and circuit identity. Descendants are transitively
bound by those captured roots, but still checked on every invocation.

Result: exact commons digest, native encoding version and expected shape.
A hit returns owned commons from a digest-checked decoding read of the archive.
It never returns a "verified path" to be reopened unchecked. For `independent-full-replay-v1`, mint only after full transition replay and
independent commons derivation succeed and match the archive. For
`coordinator-acceptance-and-beacon-v1`, require authenticated acceptance history,
independent beacon application and exact output comparison. Never equate these
methods or upgrade an acceptance-based receipt into a full-replay claim.

### Final-key input tuple/result

Inputs: definition/signature and external key; both chain/signature pairs;
both closure/signature pairs; both beacon/signature pairs; Phase 1 seal/signature;
verifier/circuit identity. **Exclude the final Phase 2 seal:** it is produced by
finalization, not an input to deterministic reconstruction. Including it creates
circular identity and prevents preliminary-to-final reuse.

Result: one generation identifier, exact PK and VK digests/sizes, curve, explicit
key encoding and key-shape metadata validated against the circuit. Fixed filenames
are selected by code; no receipt-controlled filesystem paths. Persist no commons
in this cache initially; continue checking archived commons. Remove any unused
return field separately only after checking all callers.

Exclude operation timestamp, public proof evidence, reports, candidate inventory
and checkpoint head from this *key-result* tuple. Each consuming operation must
validate them independently. There is NO operation-success receipt. A failed
public proof can coexist with a valid deterministic-key cache entry. The final
Phase 2 seal must still match the loaded keys and its authenticated beacon.

## 5. Hit/miss/error state machine

Deferred D1 only. Current operations do not perform persistent-cache lookups.

1. Parse explicit local configuration and verify permitted command/schema/role.
2. Load/capture roots; validate all signatures, semantics, actual circuit and
   required descendants. Failure here is an operation error, never a hit.
3. Derive the input identity. Missing entry or a valid different root identity
   is a miss, not invalid ceremony evidence.
4. Validate bounded receipt and MAC. Wrong key/schema/verifier/circuit/MAC or
   malformed cache data is a miss with a local reason; do not trust its sizes.
5. Load the result safely and check exact digests/shape. Cache corruption is a
   miss; a failure reading mandatory ceremony evidence remains a hard error.
6. On miss, execute the explicitly selected verification method from owned
   captured roots. Acceptance-based Phase 1 reconstruction rechecks history and
   beacon application; independent-full-replay performs every transition. Final-key
   reconstruction always retains its full-verification requirement.
7. After successful mathematics, optionally publish the private result. A cache
   write failure may leave computation successful, with a clear warning; it
   must not weaken required public output durability.
8. Run the operation's remaining proof, candidate, signing, inventory,
   predecessor and publication checks regardless of cache outcome.

For the deferred cache feature only, a future cache-bypass diagnostic remains to
be specified. Current no-cache diagnostics use `--full-replay` as defined in the
[CLI contract](ceremony-optimization-cli-contract.md). A future cache bypass
would bypass reads and perform all math.
Whether it refreshes a cache is explicit; default first version: no cache writes
when this diagnostic override is selected. Do not silently retry failed full
mathematics as another cache lookup. Preserve operational-error versus stable
invalid-candidate classification at acceptance boundaries.

## 6. Native key loading and allocation safety

Deferred D1 key-cache decoder/admission contract. Existing native input validation
and memory qualification for current operations are still required.

A byte-count limit alone does not prevent a malicious length prefix from causing
an enormous allocation. A panic wrapper cannot recover OOM. Do not call existing
unbounded native readers directly on cache paths.

Proposed first implementation: authenticate the receipt, derive allowable encoded
size and memory budget from the trusted circuit/format, read into a bounded owned
buffer, verify its exact digest, run allocation-free format preflight, then decode
from that same immutable buffer. Never preflight one mutable file and decode a
later read. If safe buffer plus decoded-object budget cannot be admitted, report
an unsupported cache-hit memory requirement and use full verification; do not
raise limits silently. Measure this fallback rather than assume caching is faster.

Preflight must cover every length and nested allocation in pinned gnark encoding:
FFT domain/cardinality; PK A/B/Z/K and G2-B vectors; wire count and infinity masks;
commitment-key count and nested basis lengths; VK public/commitment basis;
nested public-commitment index lists; all fixed group elements. Use checked
addition/multiplication and reject trailing bytes, truncation and unsupported
encoding. Never use `UnsafeReadFrom`; verify the selected decoder's actual
curve/subgroup behavior, not only its comments.

The source-backed wire-format inventory is in
[`ceremony-key-cache-decoder-audit.md`](ceremony-key-cache-decoder-audit.md).
It identifies allocation sites but does not yet prove admission bounds.

**Blocking detail:** complete the serializer field-by-field size/shape table,
including Pedersen keys and domain decoder, against the pinned dependencies.
Expected lengths must come from the actual circuit and full-verifier output
contract, not unauthenticated file prefixes. Golden byte fixtures and malicious
length-prefix tests are required. Until this table and memory budget are proven,
final-key cache implementation must not start. This is an explicit open safety
contract, not a detail to guess during coding.

## 7. Publication, concurrency and cleanup

This section specifies deferred D1 cache publication/locking. Existing public
artifact publication, cleanup and managed recovery remain current requirements.

Use one private lock per cache root for lookup/decode/publication/cleanup in the
first version. Do not hold it during expensive full computation. On a miss,
release it; calculate; reacquire and recheck before publishing. Duplicate cold
computation is acceptable; mixed or overwritten generations are not.

Writer builds an exclusively owned random staging directory. Write fixed result
files, flush each, write receipt last, flush it and the directory, then atomically
publish by no-replace rename. Flush the parent. Existing valid identical result
wins; never overwrite a generation in place. Different deterministic results for
the same input identity are a hard diagnostic conflict, not last-writer-wins.

Readers hold the private lock through selecting and decoding one generation.
Cleanup takes the same lock, so it cannot delete selected files mid-read. First
version has no automatic garbage collection. Explicit local cleanup may remove
unreferenced staging directories after proving no active writer owns them; age
alone is insufficient. A simpler safe default is to leave interrupted staging
for inspection until the cleanup command has exclusive ownership.

Crash expectations:

| Crash point | Required state |
| --- | --- |
| Before either key is complete | No visible hit |
| After PK, before VK | No visible hit |
| After both keys, before receipt | No visible hit |
| After receipt, before atomic rename | Staging remains unusable |
| After rename, before parent flush | On restart accept only fully valid entry; absence means miss |
| During public output publication | Cache may be valid; public operation still resumes under existing exact-output rules |

Never delete or modify public ceremony state while repairing cache data. Preserve
private failure evidence without exposing keys or full sensitive paths in public
logs. Resolve lock identity using the actual private directory, not spelling of
an alias. Symlink/cross-user cache-sharing is unsupported in the first version.

## 8. Recovery, role and schema compatibility

Current operation/publication recovery rules still apply. Cache authority, saved-key
hit behavior and cache receipt rules below are future D1 requirements only.

### Calculation record versus completion evidence

The private saved-result receipt certifies only a deterministic calculation.
Operation completion remains established by existing authenticated artifacts,
checks and publication state. Do not introduce a second cache receipt that can
claim an operation succeeded. A UI/journal status is a resumability hint, not
cryptographic authority. Revalidate required evidence when resuming.

| State after interruption | Retry behavior |
| --- | --- |
| Saved keys valid; no output yet | Reuse keys, run remaining operation checks and publish |
| Saved keys valid; proof invalid | Fail proof checks; do not publish or report success |
| Only unpublished staging exists | Ignore it as success evidence; reconstruct output using valid saved keys if available |
| Exact complete local output exists | Existing exact-output recovery rules apply; never infer validity from existence alone |
| Local output differs or is incomplete | Refuse conflict and preserve authoritative destination for inspection |
| Some remote artifacts uploaded | Authenticate checkpoint and resume immutable uploads under existing exact-version rules |
| Remote head write response lost | Reread authenticated storage; succeed only for the exact intended checkpoint/signature |
| A competing remote head won | Refuse stale advancement; synchronize and assess, never substitute a new predecessor automatically |

The local saved-key cache does not change remote upload memo authority. Those
are separate optimizations with different input and trust contracts. Retain
remote exact-head reconciliation after cancellation, even when calculation reuse
made the local part of the retry quick.


Existing output presence chooses a recovery route, not success. Continue to check
exact output inventories, signatures, stable timestamps, input predecessor and
no-overwrite publication. Never regenerate contribution randomness to guess a
lost output. Never convert a cache/read error into evidence for participant
rejection. A receipt does not authorize changing an existing frozen tool pin.

| Role/schema | Cache authority | Mathematical verification |
| --- | --- | --- |
| V5 coordinator allowlisted operations | Explicit local opt-in | Requested method on miss; only results of an allowed method reused on hit |
| Participant, both phases | None | Authenticate exact assigned input/history evidence; check own contribution only; trust prior coordinator acceptance mathematics |
| Auditor/public replay | None | Full independent reconstruction |
| G1/G2 release signer | None | Preserve existing protocol, do not invent V3 replay requirement |
| V3 release signer | None | Mandatory independent two-phase replay |
| V5 release reviewer/signer | None | Existing signed coordinator-replay review and output checks; preserve each decision schema |

## 9. Resource and progress contract

Keep the separate Relay resource-allocation design authoritative. Strict mode
counts bounded workloads, reserves headroom and refuses uncertain admission.
Hosts with unbounded external containers require explicit operator-budget mode
and acknowledgment; this coordinates Relay jobs but is not a host-wide memory
guarantee. New/replaced unknown workloads invalidate that acknowledgment.

Record allocation per operation before launch. Retries keep it; changed user caps
apply to new operations. Preserve conservative migration for legacy operations
without retained allocations. No live resizing. Cache hits have their own measured
memory needs, especially encoded buffers plus native keys.

Show stage start/end and elapsed time for authentication, calculation and
publication separately. Cache-result loading messages are deferred with D1; do
not show "reusing locally verified keys" in the current no-cache release. Log miss reasons
without secret material. Heartbeats establish liveness only.

## 10. Acceptance tests and evidence

Scope: T-series tests apply to current behavior, excluding their explicit cache-hit
clauses. Cache-specific A/K/C/O fixtures and cache clauses of R/P tests belong to
D1, while corresponding current file-integrity, public-publication and proof checks
remain mandatory. Do not require cache implementation to finish A–E.

The following are required tests to implement later, not tests run by this
documentation-only revision. Use real signed tiny fixtures with valid outer
signatures for mathematical negative cases; flipping an unsigned byte exercises
hash rejection, not detection of signed incorrect mathematics.

| ID | Required scenario and expected result |
| --- | --- |
| T1 | Wrong genesis bytes/hash, phase, ceremony, circuit digest/shape, nonzero initial challenge or Phase 1 seal linkage: reject before randomness in the participant path |
| T2 | Missing/mismatched acceptance evidence, false pass bit, unknown method, wrong participant/index/predecessor/order, earlier payload/attestation/erasure change: reject P1 reuse and P2 closure |
| T3 | Signed mathematically invalid earlier transition in either phase with consistent evidence: participant authentication may pass; final replay must reject. Invalid own transition must fail the participant self-check and coordinator acceptance |
| T4 | Altered raw beacon response, wrong round/network/challenge, wrong closure reference or incorrect beacon application with validly re-signed output: P1 reuse rejects; valid commons match independent replay byte for byte |
| T5 | Signed wrong P2 genesis with valid subsequent edges: default participant mode may pass by design, auditor/public full replay and final coordinator replay reject; label weaker assurance accurately |
| T6 | Signed invalid P1 or P2 mathematical history with syntactically consistent passing records: acceptance-based trust may not detect it, but final post-beacon reconstruction must reject and publish no successful final result/cache receipt |
| T7 | Missing participant, incomplete schedule, missing evidence, mismatched head or wrong current checkpoint: closure fails; preserve future-beacon lead time, distinct-round policy and exact retry behavior |
| T8 | Explicit coordinator full replay at closure/P1 preparation: execute all required checks, fail rather than downgrade; no ambient context leaks between roles |
| T9 | Participant contribution uses the single authenticated-assigned-input path in both phases with no independent-mode switch; retry retains exact attempt and all required checks; approved software binding remains enforced |
| T10 | Mismatched chain/allocation, replaced roots or wrong retry attempt: reject before entropy. Offline snapshot currentness is not globally provable; Relay rejects retired attempts at current-state upload/acceptance boundaries |
| T11 | Direct/allocated acceptance rejects invalid new transitions before creating passing receipts; generic checkpoint preparation rejects missing/unsigned/inconsistent acceptance evidence and never creates a passing receipt itself |
| T12 | Partial publication and complete-checkpoint recovery for both phases: exact attempt/timestamps/files retained; no existence-only acceptance; changed evidence never becomes a cache miss or candidate rejection |
| T13 | Call counters/typed-result tests: both participant paths do zero historical transition replay; Phase 2 does zero P1 replay and zero P2 initialization; Phase 1 retains one canonical-genesis check separately counted; each checks its own new transition; acceptance closure does no full replay; cold/full final reconstruction independently executes both phases and both beacons; key-cache hits prove provenance from that reconstruction and retain artifact/proof/publication checks |
| T15 | Wrong generated challenge rejected before verifier mutation; serialized input/output unchanged by self-check; shape/subgroup failures and entropy-before-preflight rejected in both phases |
| T16 | Raw/direct production invocation without authenticated allocation and phase-command/allocation mismatch rejected; retired offline attempt never silently retargeted or regenerated |
| T14 | For both phases, on valid fixtures the loaded assigned head equals the head from a test-only full replay; injected test-only identical entropy may compare outputs, but production contributions always use fresh randomness |

Final replay tests must exercise prepare, complete, final-candidate checkpoint and
all recovery/cache routes. A closure or acceptance receipt must never mint a
full-replay claim. Test final-key cache provenance separately from closure reuse.



| ID | Counterexample / required evidence |
| --- | --- |
| R1 | Replace a root after capture: result/receipt remains bound to captured bytes or fails; never mixed roots |
| R2 | Change native contribution/genesis/commons under unchanged roots: both paths reject |
| R3 | Alter attestations, cleanup, verification records or drand response: both paths reject |
| R4 | Valid newly signed roots: miss/full verification; signed mathematically invalid history never mints a full-replay receipt; independent lanes reject even if acceptance-based validation passes |
| A1 | Wrong local key, MAC, role, command, schema, executable or circuit: no hit |
| A2 | Participant/auditor/public/signer commands reject cache options and have no key mount |
| K1 | Hit keys exactly match full reconstruction and pass real proof verification |
| K2 | Mutate one decoded key pair: subsequent hit remains unchanged |
| K3 | Huge lengths, nested counts, unsupported encodings, malformed points, trailing bytes: bounded failure, no OOM |
| K4 | Mixed generations/replaced PK or VK: no hit |
| C1 | Two writers, reader during cleanup, lock alias, interrupted staging: no mixed result or destructive overwrite |
| C2 | Fault injection at each write/fsync/rename boundary: only absent or fully valid entries |
| O1 | Valid key cache plus invalid public proof/report/candidate/Phase2 seal: operation still fails |
| O2 | Changed public proof with same reconstruction inputs: keys reusable but all proof checks run again |
| O3 | Corrupt existing output or wrong predecessor on retry: refusal; no overwrite or false success |
| P1 | Before/after invocation counters establish actual initialization/replay counts for normal and recovery paths |
| P2 | Production-circuit cold/hit runs measure elapsed, CPU, peak RSS/cgroup memory and identical outputs |
| P3 | Relay consumes exact attested proof-tool release pins; resource/UI and diagnostic integration match that binary; no deferred cache arguments or mounts |
| P4 | Full fresh same-device ceremony completes contribution, cleanup, beacons, review, signing and public replay |

Tests must cover real signed tiny workflows and the exact production circuit.
Tiny fixtures prove behavior, not production runtime or memory. Existing benchmark
source is b0815c9, node component logs under
`/home/jason/ceremonies/phase2-resource-qualification-20260923/{2,4,6}cpu.log`.
Those results compare approximately 96/49/33-minute Phase 2 starting-parameter
reconstruction component totals at 2/4/6 CPUs with matching genesis. They are not
full participant timings. Remaining contribution and verification costs were not
separately measured; do not infer total participant time or a full cached-operation
speedup from them. Retain log hashes with the final
qualification report, exact source/binary/image identities and host settings.

## 11. Release sequencing and rollback

1. Finish design/preimplementation gates, implement and test the current no-cache
   proof-tool scope, then publish through the protected release process with both
   architecture checksums and attestations.
2. Update Relay to the exact verified released proof-tool assets and ship ONE
   Relay release containing the compatible resource/UI/integration changes.
   Qualify the full V5 workflow, required Tessera integration and release checks.
   A local binary or merged proof-tool commit is not a released pin.
3. Start a fresh definition and full ceremony with the released pairing. Do not
   replace approved binaries in an active operation or claim the stopped ceremony
   completed. There is no separate Relay-only/old-pin release in this sequence.

Exact version numbers remain subject to final scope and repository version policy;
previous provisional two-Relay-release numbers are superseded. Persistent cache
mounts/options/UI remain deferred. This describes ordering, not authorization to
merge, publish or deploy during documentation work.

Current scope has no persistent cache. Required mathematical work follows the
selected coordinator operation contract, and final reconstruction remains full.
A future D1 cache miss must preserve those obligations. Rollback does not authorize
replacing ceremony-approved software or weakening verification. Preserve supported
upgrade restrictions and fail closed on unknown public formats.
No public website activation before its separate readiness/catalogue/deployment
gates. No required review or protected release gate may be bypassed.

## 12. Current prerequisites and deferred follow-up

- Joint operator review of this documentation-only revision.
- Finish participant CLI/result reporting and exact retry handling;
  no new signed participant-policy schema or migration/consent gate is required.
- Retain regression coverage for the checked acceptance producer and generic
  checkpoint evidence consumer; no confirmed ordinary-path bypass was found.
- Qualify all acceptance/recovery routes against release binaries and Relay, not
  merely the inspected constructors; add adversarial signed-invalid histories.
- Apply the test-helper audit-count correction identified by the
  [final-review investigation](ceremony-final-review-investigation.md) and rerun repository full workflows.
  Determinism and checkpoint binding passed the diagnostic reproductions; the
  minimum audit threshold was incorrectly treated as an exact report count.
- Finish every loader/caller mapping, including initial preparation and all
  Relay-managed entry points and their underlying command paths; assign each expensive call a count and owner.
- Implement the reviewed CLI contract using existing structured output/error
  conventions, with tested diagnostic flag coverage.
- Obtain current full-operation memory evidence before recommending higher CPU
  limits or admitting operations under their recorded memory limits.

Deferred follow-up is tracked only as future scope in the
[deferred-task register](ceremony-optimization-deferred-tasks.md): D1 includes
MAC-key trust, private schema/domain constants, native cached-key bounds, exact
cross-command tuple equality, cache UI/permissions and cache-hit memory. D2 covers
standalone durable attempt tracking. Neither is a current implementation gate;
Relay recovery and memory requirements for current operations remain mandatory.

Independent adversarial review found the decoder, authority and read-chain gaps;
it also corrected final-seal circularity, recovery identity, miss/error handling,
concurrency and resource guarantees. They are addressed as contracts above where
possible, with unresolved blocking details named explicitly. Review is not a
security certification, and this draft does not claim exhaustive redundancy
elimination or release readiness.

Release-format decision: require only the full V5-definition ceremony workflow.
Remove historical V4-definition test cases, compatibility matrix entries and
fixture switches. Port shared invariant tests to V5 rather than losing coverage.
The current `UsesCoordinatorReplay()` predicate admits both V4 and V5; that is a
source observation, not a requirement to retain V4 workflow tests. V5 still uses
V4-named checkpoint APIs and wire formats; preserve their V5 coverage and assert
the actual signed definition is V5. Do not broadly delete tests by filename,
rename public schemas, or infer new-format authorization from a suffix.
Historical V4 investigation evidence is retained; release gates require V5 only.

### Adversarial review of this revision (2026-09-23)

A separate design reviewer traced acceptance, genesis loading, checkpoint
preparation and final replay. Findings were incorporated above:

- The initial review conflated authoring an acceptance checkpoint with creating
  the underlying acceptance receipt. Follow-up tracing found that generic
  preparation requires the existing coordinator-signed chain; normal receipt
  creation performs the mathematics first. Removed the claimed bypass/blocker
  and unnecessary duplicate-check requirement; retained regression coverage.
- Existing signatures bind genesis provenance. The original review proposed a
  new signed opt-in to preserve prior expectations; the operator clarified that
  this is the first real release, so that migration requirement is removed.
  The trust assumption remains explicit in setup/results. The operator subsequently
  removed the participant independent-verification option; final coordinator and
  auditor/public replay remain unchanged.
- A valid old signed chain can still be stale. Added initialization ancestry,
  current allocation/head and recovery binding requirements.
- Correct Phase 2 transitions can extend an incorrect starting state. Added a
  signed-wrong-genesis fixture and distinct method claims; final replay cannot
  retroactively give the participant independent starting-state assurance.
- No new participant-policy schema is required for the first-release default;
  coordinator cache permissions remain separately restricted. Final replay call
  counters apply to cold/full paths, while key-cache hits require full-replay provenance.
- Shared loaders can accidentally reintroduce expensive work or remove final
  checks. Added method-specific call-count tests, explicit closure context and
  full reconstruction isolation.

Review was source/design inspection, not execution of these new tests or security
certification. Participant CLI/retry handling, complete Relay
recovery qualification and applying the diagnosed full-workflow fixture correction remain pending.

Latest operator decision: participants in BOTH phases omit historical mathematical
replay and retain own-contribution checks. Updated T3/T13/T14 accordingly. Earlier
review statements requiring participant rejection of signed historical mathematical
faults are superseded; retained-file integrity failures must still be rejected.

Second design-review cycle: added explicit self-check mutation isolation, typed
assigned-input invariants, canonical Phase 1 genesis construction distinct from
historical replay, and an honest limit on offline assignment freshness. See the
[adversarial review log](ceremony-optimization-adversarial-review.md) for evidence,
preimplementation validation gates and remaining unresolved tests.

Exact role prompts, stage/result/error text and coordinator diagnostic options
are drafted in the [CLI contract](ceremony-optimization-cli-contract.md).
