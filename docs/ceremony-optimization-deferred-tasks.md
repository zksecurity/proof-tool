# Deferred ceremony optimization tasks

Status: explicitly deferred by the operator. These tasks are outside the current
proof-tool → Relay release scope. This register controls scope; the detailed
[specification](ceremony-optimization-specification.md) retains future technical
contracts, and the [implementation plan](ceremony-optimization-implementation-plan.md)
contains current work. Deferral is not completion, validation or authorization to
enable an unfinished feature. Resume only after an explicit scope decision.

## D1. Persistent coordinator calculation caching

**Deferred:** saving/loading authenticated Phase 1 calculation receipts and final
proving/verifying key results across commands; private MAC keys, cache directories,
receipt formats, mount/permission integration, cleanup commands, cache options/UI,
cache-hit resource policies and automatic fallback behavior. Implementation-plan
package F and validation gate G7 belong here.

**Current behavior:** reuse owned results within one command; authenticate existing
signed acceptance history on each coordinator invocation and recompute Phase 1
beacon application as specified. No persistent calculation cache is created or
read. Existing normal output files and Relay's upload memo/journal are not this
cache and remain part of the supported workflow. Separate finalization commands
may still reconstruct keys. Do not claim three reconstructions reduced to one
across commands or display “Loading saved keys” in this release.

**Before resuming:**

- Confirm exact reconstruction-input equality across prepare, complete and
  final-candidate consumers, including actual executable/R1CS identity.
- Specify local key creation/permissions, allowed callers and trust boundaries.
- Finish native decoder/size/allocation bounds; measure peak memory including
  encoded buffers, decoded objects, cloning, live circuit data and concurrent work.
- Implement authenticated exact reads, independent key ownership, atomic PK/VK
  generations, receipt-last publication, locking and safe cleanup.
- Test interrupted writes, mixed generations, corrupt/missing receipts, altered
  evidence, invalid proofs with valid keys and cache hit/miss/error distinctions.
- Prove final-key entries originate only from mandatory full post-beacon replay
  of both phases. A hit never establishes proof validity or publication success.

**Future done criteria:** package F/G7, cache-specific specification tests and real
full-operation measurements pass on the exact approved build; the operator resumes
scope and release qualification covers the integrated cache paths. Existing local
preflight prototypes are unqualified and must not be connected implicitly.

**Does not block now:** participant/coordinator verification changes, within-command
reuse, resource UI and the no-cache V5 release. Memory validation of those CURRENT
operations, including new clones, is still required; deferral removes only
cache-specific work.

## D2. Standalone direct-CLI durable contribution-attempt tracking

**Deferred:** adding a shared durable started/completed-attempt mechanism to direct
CLI/API execution outside Relay's managed journal, including standalone locks,
recovery records and setup/migration integration. This is distinct from phase,
participant, allocation and exact-input checks, which remain current requirements.

**Current boundary:** the supported managed flow preserves Relay's durable
prepared → running-before-launch journal and existing inspection/recovery behavior.
Do not advertise equivalent crash-safe retry guarantees for arbitrary standalone
invocations. Missing output does not prove generation never started. Deferral does
not authorize same-attempt regeneration in the managed flow or weakening its
journal checks. Ordinary lower-level commands remain implementation components;
not every standalone recovery use is thereby qualified.

**Before resuming:**

- Define attempt identity, exact input/role binding and trusted state location.
- Persist started state durably before randomness and enforce one running process
  per attempt; specify locking, ownership and concurrent-invocation behavior.
- Bind completed state to exact output hashes and required inventory.
- Define recovery for active workloads, complete output, incomplete output and an
  ambiguous start. Use retirement/reallocation when generation may have occurred
  and no complete result is recoverable; never silently retarget an attempt.
- Fault-inject before/after start persistence, entropy, output directory creation,
  artifact writes and completion recording; prove no same-attempt regeneration.
- Define how the mechanism composes with Relay's journal without contradictory
  states or duplicated prompts. Do not introduce network access into offline work.

**Future done criteria:** standalone contract and failure tests pass and direct
recovery support is explicitly included in release qualification.

**Does not block now:** the Relay-managed scope, provided existing journal behavior
is preserved and its recovery tests pass. G6 still applies to Relay; it is not
wholly deferred. Phase/participant matching and stale-assignment handling remain
required for underlying commands used by Relay.

## Work that is NOT deferred

- Test-only final-review audit-count correction and full V5 workflow qualification.
- Removal of historical V4-definition test cases while retaining V5 coverage of
  V4-named components and checkpoint formats.
- Participant input authentication and own-contribution verification in both phases;
  coordinator verification before every new acceptance.
- Generated-challenge checks, safe object ownership, canonical Phase 1 genesis
  binding, command/assignment matching and complete call-path validation.
- Relay interrupted-generation, cleanup, upload and current-head recovery checks.
- Full final coordinator replay of both phases, beacon checks, proof/rejection
  tests, exact package/signature requirements and public/auditor verification.
- Resource admission, launch-time reservation, actual progress and current-operation
  memory/performance qualification; exact CLI contract implementation.
- Protected proof-tool release followed by one Relay release with verified updated
  pins and compatible resource/UI changes. No release is authorized by this file.

No other optimization is silently deferred by this register. Potential ideas such
as live resource resizing or reduced participant snapshots are not part of the
current design; they are not newly approved backlog tasks here.
