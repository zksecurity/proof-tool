# Ceremony verification reuse

Historical source/implementation notes: this document includes decisions from
before the latest operator revision. For current requirements use the
[optimization specification](ceremony-optimization-specification.md),
[implementation plan](ceremony-optimization-implementation-plan.md) and
[deferred-task register](ceremony-optimization-deferred-tasks.md). In particular,
participants now omit historical mathematical replay in both phases, persistent
calculation caching is deferred, and only the full V5-definition workflow is a
release requirement. Historical V4 test logs and earlier runtime observations
remain evidence of those runs; they are not instructions to retain the old policy.


These changes are under validation. They require a new proof-tool release and a
subsequent Relay release pinned to its exact attested assets. They do not authorize
replacing the proof-tool approved by an already frozen ceremony.

## Changes within one command

- Phase 1 accepted-chain verification captures the chain and its exact signed
  references from one read. Previously it reopened the chain after authenticating
  its evidence and could pair the first chain with references to a different
  signed chain. This preserves the existing acceptance-evidence checks; it does
  not add or remove independent mathematical replay.

- Phase 2 initialization checkpoint recording builds its provisional projection
  from the authenticated zero-contribution chain. The authoritative checkpoint
  lifecycle verifier still proves deterministic genesis before signing. This
  avoids performing the same full verification twice during projection and
  preparation.
- Allocated candidate acceptance likewise constructs its provisional checkpoint
  from the exact signed accepted chain, checking phase and count before indexing
  it. Final checkpoint preparation still independently verifies the complete
  accepted chain, predecessor extension, allocation and candidate inventory.
  Post-acceptance failures remain operational errors, not evidence authorizing
  rejection of the candidate. Existing immutable artifacts remain recoverable.
- Zero-contribution genesis verification ends after checking deterministic
  initialization and authenticating the actual files. Replaying zero contributions
  would only derive the same genesis again.
- Accepted Phase 2 chain verification and Phase 2 file replay pass their freshly
  derived, verified genesis into the contribution-verification loop. Every edge is
  still checked; archived objects are cloned and are not mutated. Public replay
  APIs independently initialize their state. Sealing retains fresh evaluations
  for each key set, avoiding shared commitment arrays.
- The replay-time Phase 2 file loader checks the digest of the bytes it actually
  consumes against the signed chain and checks the predecessor challenge. An
  earlier authenticated read does not authorize a different file substituted
  before replay, even if the replacement is a valid contribution.

An independent design review required retaining all mathematical edge checks,
keeping initialization reuse private to one invocation, preserving evaluation
ownership, and checking replay-time file digests. That review also identified the
file-replacement gap. Review is not execution evidence or certification.

## Remaining audit and qualification

Phase 1 coordinator closure and sealing already support authenticated acceptance
evidence. The released code also has explicit full-replay options; the operator
now requires removal of that optional replay from sealing after the Phase 1
beacon. This is a planned change, not yet implemented. The separate pre-beacon
closure option is outside that decision. Phase 2 closure still verifies the
whole contribution chain. The changes above remove its duplicate initialization,
not its contribution verification.

Cross-command reuse of Phase 1 verification and seal processing remains a separate
design. A coordinator seal signature alone cannot replace mathematical checks.
Any local receipt would need independent local authority, exact input digests,
ceremony/circuit/verifier identity, stable-file handling, and a full-verification
fallback. Participants and auditors must retain independent verification.

Qualification must include signed workflow corruption tests, replay equivalence,
file substitution, archive immutability and independent key ownership. Retaining
genesis through file validation can increase peak memory; measure this on the
production circuit before claiming resource or runtime improvements. Small
synthetic circuits establish behavior, not production performance. Resource
benchmarks at 2, 4 and 6 CPUs and the fresh full production ceremony remain
separate requirements.

## Proposed local receipt for sealed Phase 1 (not implemented)

The first cross-command cache should certify one narrow result: successful full
local verification of a closed Phase 1 transcript and its derived sealed commons.
It must never be populated from the ordinary coordinator seal signature or the
acceptance-evidence-only sealing path. A cold invocation performs the existing
full verification. Only after all checks succeed can it publish a receipt.

Proposed authority and scope:

- Explicitly configured private cache outside the public artifact root. Relay
  mounts it only into the coordinator's approved proof-tool operations, never
  contributor containers, public exports, signing handoffs or website transport.
  Other roles continue their existing independent verification.
- A separate local random authentication key, private directory/file permissions,
  exclusive key creation, atomic durable receipt publication and a local lock.
  Receipt authentication uses a domain-separated MAC; the ceremony signing key
  provides no cache authority. This assumes the operator's local account and
  approved verifier process are trusted. It cannot protect against their compromise.
- Bind receipt schema and operation, exact verifier executable digest, ceremony
  definition/signature and trust-key digests, compiled circuit binding/R1CS digest,
  ordered Phase 1 chain and every consumed contribution/attestation/cleanup/
  verification artifact, closure/beacon/seal records and signatures, beacon evidence,
  and exact derived commons digest. Define the dependency inventory in code, rather
  than accepting an arbitrary list from a receipt.
- On reuse, authenticate the receipt, independently reconstruct the expected
  dependency inventory and rehash current inputs. Reject malformed, missing,
  additional or changed dependencies. Decode and hash the commons bytes actually
  consumed; do not hash one file and subsequently consume an unchecked reopening.
  A cache miss or incompatible receipt runs full verification. Unreadable or
  changing inputs remain errors, never successful cache hits.
- No metadata-only validity, global trust switch, public receipt import, or
  transfer of verification authority between participants. Changing verifier,
  circuit or any dependency invalidates reuse. Record hit/miss in local progress
  without changing signed ceremony formats.

Stable-file handling and the completeness of this inventory require independent
review before implementation. Hashing mutable inputs after verification alone
cannot establish what was verified: receipt creation must bind the bytes consumed
by verification, and reuse must bind the bytes consumed by the next operation.
Qualification needs forged/stale receipts, wrong local key, changed verifier,
dependency omission/substitution, concurrent mutation, crash/retry, cross-role
isolation and full-verification fallback, plus exact-circuit time/memory results.

Independent review rejected a thin cache around the current path readers:
before/after hashing permits verify-A/hash-B and hash-A/consume-B/restore-A races.
The implementation prerequisite is an exact-read context that records digests
from consumed bytes and rejects conflicting repeated reads. Alternatively,
fused operations can pass owned verified objects directly within one invocation.
A read-only bind mount, open descriptor or hard link is not an immutable snapshot.

The reader audit must cover these existing boundaries:

| Boundary | Inputs/result that must be bound |
| --- | --- |
| `LoadSignedDefinition` / `loadOperationalCeremony` | Exact definition/signature, decoded external trust key, running executable identity |
| `ValidateCircuitBinding` | Actual compiled R1CS binding, both digests, native size and shape |
| `LoadSignedChainExact` | Exact chain/signature bytes captured for the same parsed chain |
| `verifyChainFiles` | Genesis, native contributions, attestations/signatures, erasure records/signatures and verification records |
| `phase1FileLoader` | Digest of each contribution actually consumed by mathematical replay, agreeing with the authenticated chain |
| `loadCoordinatorSignedRecord` | Closure, beacon and seal bytes/signatures captured once |
| `VerifyBeaconRecordFiles` | Archived drand response, signed policy, round and randomness binding |
| `ReadCommonsFile` | The same decoding read supplies both returned commons and its digest |

Cold and hit paths need one dependency-discovery definition. Unexpected receipt
entries must fail; unrelated transcript files need not invalidate the cache.
Return owned decoded commons and metadata, never merely a supposedly verified
path that the caller reopens unchecked. Cache key exposure grants minting authority,
so its mount boundary also needs explicit implementation and isolation tests.

### Revised owned-input design (reviewed, not implemented)

A fixed tuple of captured signed roots can replace the proposed general read
ledger. A private owned-input loader would read and authenticate definition,
chain, closure, beacon and seal exactly once, retaining both decoded objects and
references derived from those same record/signature bytes. The tuple also binds
the decoded external trust key, approved running executable, actual validated
compiled circuit, operation/schema domain and exact commons digest.

Both cache paths must perform complete ordinary evidence validation against
these owned roots: native payloads and challenge links, participant attestations,
cleanup and verification records, closure-chain consistency, archived drand
cryptography, beacon-closure consistency and seal-beacon consistency. References
in the captured chain and beacon transitively bind their descendants; there is
no caller-supplied dependency inventory. Invalid ceremony evidence is an error,
not a cache miss that can bypass validation.

On a miss, replay uses the already-owned chain and the existing actual-read
native digest checks. It must not call a helper that reloads the chain. Derive
commons, compare its digest with the owned seal, and only then mint the local
MAC receipt with its verification method. Ordinary seal generation alone cannot
mint a verified-result receipt. The revised coordinator acceptance-history plus
independent beacon/output check may mint its own explicitly labelled method.
On a hit, skip only replay and deterministic commons derivation. Return the
owned commons object from the decoding read whose digest matched the seal;
downstream operations must not reopen a supposedly verified path.

Independent review accepted this object-consistency boundary in place of a
global filesystem snapshot: each consumed descendant must match an immutable
expected digest from a captured authenticated root. It did not certify the
implementation. Remaining prerequisites are a complete cold-path reader audit,
a shared private loader for seal verification and Phase 2 initialization,
precise running-executable identity, bounded/domain-separated receipt encoding,
atomic publication and coordinator-only key/mount isolation. Cache failures may
fall back to the explicitly requested verification method, never downgrade an
independent replay request; evidence failures never authorize a hit or mint.

Qualification must exercise changed signed roots, mixed individually valid
roots, changed descendants under unchanged roots, contribution replacement
during replay, commons replacement before decoding, wrong verifier/circuit/key,
forged receipts for mathematically invalid chains, failed cold verification,
interrupted publication and independent participant behavior. Root replacement
after capture must either fail or remain consistently bound to the captured
objects, never mix old verification with new references. No persistent cache
is enabled by this design document.

Reader-audit findings for the revised design:

- `loadOperationalCeremony` derives `RunningSoftware` from the kernel-held Linux
  `/proc/self/exe` and Go build metadata after checking the signed software
  policy. Reuse this process-derived identity; do not hash an operator-selected
  binary path to establish verifier authority.
- `validateCompiledCircuit` checks the private binder marker, field, counts and
  Phase 2 shape, but does not recompute the R1CS digest on every call. A receipt
  boundary must explicitly digest the actual owned R1CS and compare it with the
  signed binding; copying `circuit.Binding.R1CS.Digest` alone is insufficient.
  Keep that object private and unchanged throughout verification and use.
- `ReadR1CSFile` authenticates before decoding and then rebinds the decoded
  object. Retain its post-decode binding check; an open descriptor alone does
  not make the underlying bytes immutable.

Further within-call changes under validation: Phase 2 contributions replay from the freshly verified genesis and retain fresh entropy and all predecessor checks. First-contribution acceptance reuses that genesis as predecessor; later turns release it and load their authenticated head. Final replay now pairs genesis and fresh evaluations in a private single-use object and seals from that same initialization after genesis checks. Targeted deterministic-key equivalence, consumed-state rejection, archive immutability and independent evaluation-array tests pass. Full signed workflows and exact-circuit memory qualification remain required for these additions.

## Superseding coordinator Phase 1 design (2026-09-23)

The operator now explicitly authorizes prior coordinator acceptance checks as the
trust basis for a coordinator-only Phase 1 result, after exact history/file checks,
beacon cryptography, independent beacon application and output comparison. Earlier
full-replay-only minting requirements in this document are superseded for that
labelled method. They still apply to claims of independent full replay. The detailed
specification defines method isolation, role boundaries and mandatory negative tests.
The latest request retains an explicit troubleshooting replay option; the earlier
proposal to remove the seal CLI flag entirely is superseded. Implementation and
tests of this revised path are authorized, while releases remain gated.

V5 scope clarification: the coordinator acceptance-history method applies to both
V4 and V5. `UsesCoordinatorReplay()` is the existing closed predicate for these
two formats. The contribution checks and checkpoint lifecycle are shared; V5's
production-decision schema and release requirements remain unchanged. Public and
participant verification remain independent for both formats. The workflow test
helper's historical V4 name does not identify its schema: its current constructor
creates V5, so tests must assert the actual signed definition version.
