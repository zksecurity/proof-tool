# Ceremony optimization CLI contract

Status: proposed implementation acceptance criteria, 2026-09-23. Documentation
only; no commands, releases or pin changes are implemented by this document.
Implements the [design](ceremony-optimization-specification.md) and
[work packages](ceremony-optimization-implementation-plan.md). V5 ceremony
qualification only; V4-named commands/checkpoint formats still serve V5.

## Common presentation rules

Text below is the proposed operator-facing copy. Braced values are runtime values,
not literal text. Preserve existing command names and confirmation tokens unless
an entry below explicitly adds an option. Do not add confirmation prompts solely
to explain trust. Keep logs free of entropy, private keys and private credentials.

- Before computation: operation name, actual resource limits and verification basis.
- During work: actual stage plus periodically refreshed elapsed time; no invented
  percentage, speedup, remaining time or completion promise.
- Progress goes to stderr in machine-readable mode; stdout retains the existing
  structured result envelope. Keep existing output keys, exit-code conventions and
  parser compatibility. Diagnostic JSON fields require a separate schema review;
  this draft proposes text changes only, not a new JSON schema.
- Success describes the completed operation only. A local checkpoint is not a
  published checkpoint; checked keys do not mean proof tests or publication passed.
- No persistent-cache flags, cache status or “Loading saved keys” in current scope.
  Separate finalization commands may still reconstruct keys; do not promise one
  calculation across commands while persistent caching is deferred.

## Participant — Phase 1 and Phase 2

Setup/help copy, once in the existing contribution explanation (not a new consent):

> The coordinator checks earlier contributions. You authenticate your assigned
> input, add fresh randomness and check your own contribution.

Additional Phase 2 explanation:

> You rely on the coordinator to prepare the Phase 2 starting parameters correctly.

Keep the existing `CONTRIBUTE` confirmation token. Confirmation text:

> Authenticate this assigned input, create your contribution and check it.

Stages, emitted only when actually running:

1. `Checking assignment and signed records`
2. `Checking input files`
3. `Creating your contribution`
4. `Checking your contribution`
5. `Saving contribution and attestation`

Phase 1's retained canonical-genesis comparison belongs to input checking; it is
not replay of earlier contributions. Phase 2 must show no Phase 1 replay, no
starting-parameter derivation and no historical Phase 2 replay stage.

Local success: `Contribution saved. Assigned input authenticated and your contribution checked.`
Then retain the existing cleanup step. Cleanup and upload get their own success
messages only after validation; do not claim cleanup from a process exit alone.

No `--independent`, `--skip-verification`, participant `--full-replay` or hidden
environment mode selector is added. Both phase commands require their phase and
explicit participant ID to match the authenticated allocation before randomness.

Errors (existing error categories/exit codes retained):

| Condition | Text |
| --- | --- |
| Command phase differs from allocation | `This assignment is for {assigned_phase}, but the command requested {command_phase}. This invocation stopped before generating a contribution.` |
| Explicit participant differs from allocation | `The participant does not match this assignment. This invocation stopped before generating a contribution.` |
| Assigned input differs from signed reference | `The assigned input does not match its signed record. Stop and refresh the input through the normal workflow.` |
| Current delivery state retires the attempt | `This attempt has been retired. Keep its existing files and request a new assignment.` |
| Own check fails | `Your contribution failed verification. It cannot be submitted as a successful contribution.` |
| Relay journal says started, output incomplete | `This attempt started. Check whether its workload is still running and whether its existing output can be recovered. Do not rerun generation. If recovery cannot complete after the workload has stopped, ask the coordinator to retire this attempt and allocate a new one.` |

Offline checks validate the captured assignment, not continued global freshness.
Only use the retirement error after current authenticated delivery state establishes
retirement. Standalone direct-CLI durable tracking remains deferred; do not advertise
Relay's journal guarantees for arbitrary standalone invocations.

## Coordinator — acceptance, closure, beacons and preparation

Keep existing action names/tokens. Replace misleading “replay every contribution”
copy where the operation uses previous acceptance records.

| Operation | Existing confirmation/action description becomes | Stages / successful local result |
| --- | --- | --- |
| Accept either-phase contribution | `Check this contribution against the accepted input and record acceptance.` | `Checking candidate files` → `Checking the new contribution` → `Saving acceptance`; result `Contribution checked and acceptance recorded locally.` |
| Close Phase 1 | `Check accepted records and completion, then commit to the Phase 1 beacon round.` | `Checking accepted history and files` → `Checking completion requirements` → `Signing closure`; result `Phase 1 closure saved for beacon round {round}.` |
| Phase 1 beacon | `Fetch and verify the beacon round committed by the Phase 1 closure.` | Existing download, signature and committed-round checks; result `Committed Phase 1 beacon verified and saved.` |
| Seal Phase 1 | `Check accepted records, apply the committed beacon and save the Phase 1 result.` | `Checking accepted history and beacon` → `Applying beacon` → `Saving sealed Phase 1`; result `Phase 1 sealed using prior coordinator acceptance checks.` |
| Check sealed Phase 1 checkpoint | `Check the signed Phase 1 result against accepted history and beacon application.` | `Checking retained records and files` → `Recomputing beacon application` → `Comparing sealed output`; no claim of full historical replay. |
| Start Phase 2 | `Check sealed Phase 1 and derive the Phase 2 starting parameters.` | `Checking sealed Phase 1` → `Deriving Phase 2 starting parameters` → `Saving starting parameters and signed chain`; result `Phase 2 starting parameters saved.` |
| Close Phase 2 | `Check accepted records and completion, then commit to the Phase 2 beacon round.` | `Checking accepted history and files` → `Checking completion requirements` → `Signing closure`; result `Phase 2 closure saved for beacon round {round}.` |
| Phase 2 beacon | `Fetch and verify the beacon round committed by the Phase 2 closure.` | Existing download/verification; result `Committed Phase 2 beacon verified and saved.` Applying it belongs to final reconstruction. |

Checkpoint recording result: `Checkpoint prepared and signed locally. Publication is still required.`
Publish confirmation belongs to Relay's existing publication action; do not claim
publication from proof-tool success. No new record/signature format is proposed.

Errors: missing acceptance evidence → `Required acceptance evidence is missing or inconsistent. This invocation did not create a new closure.`
Wrong beacon/application → `The beacon or resulting files do not match the signed ceremony records.`
Expired future-round timing → `The selected beacon round no longer meets the required lead time. No new closure was published.`
Existing signed closure retries must preserve its exact round and existing recovery
rules; the timing message must never prompt replacing an already-signed closure.

## Coordinator diagnostic option contract

Use the existing spelling `--full-replay`; do not introduce `--full-verification`
as a competing synonym for the current no-cache scope.

| Command | Default | `--full-replay` behavior |
| --- | --- | --- |
| `phase1 close` | Authenticate acceptance history/completion | Replay Phase 1 before closure |
| `phase1 seal` | Authenticate history, verify/apply beacon | Replay Phase 1 before beacon application |
| `phase2 init` | Acceptance-based sealed Phase 1 validation | Fully replay Phase 1, verify its beacon/result, then derive Phase 2 |
| `phase2 close` | Authenticate acceptance history/completion | Fully replay Phase 1, reconstruct Phase 2 genesis and replay Phase 2 before closure |
| `checkpoint record-v4` | Operation-specific coordinator validation | Permit only Phase 1 closed/sealed, Phase 2 initialized/closed transitions; perform equivalent independent verification of their inputs before recording |

Exact checkpoint transition strings use existing constants. Implement and test the
above allowlist explicitly. For other transitions reject the flag before signing:
`--full-replay is not supported for this checkpoint transition.` Do not silently
ignore it. Public verification APIs retain full verification. Finalization always
requires full reconstruction, so it needs no “enable verification” flag.

Diagnostic heading: `Full replay requested. Checking the complete required contribution history.`
Failure is an error, never fallback to acceptance-based validation. Guided normal
menus do not add a verification choice; expose diagnostics through command help.

## Finalization, release signer, auditor and delivery

Coordinator final preparation/complete stages:
`Checking final transcript and beacons` → `Replaying Phase 1` →
`Deriving Phase 2 starting parameters` → `Replaying Phase 2 and reconstructing final keys`.
Emit later proof stages only in commands that actually perform them:
`Checking valid proof and rejection cases` → `Checking final output files` → `Saving final candidate`.
Preliminary-key command result: `Preliminary keys saved after full ceremony verification. Proof tests and final release checks are still required.`
Completed candidate result: `Final candidate saved after full ceremony and proof checks. Release review and signing are still required.`

V5 release reviewer/signer explanation (do not copy into signer help for a
protocol that requires independent signer replay):
`Check the exact final package and required evidence. This role relies on the coordinator's full mathematical verification.`
Review result: `Final package and required evidence checked. Release signature not yet created.`
Signing result: `Release package signed. Publication is still required.`
Preserve V5 decision/signature requirements; emit the last message only if publication
is in fact still required at that command boundary. No new signing option.

Auditor/public verifier: `Independently replaying the full ceremony` followed by
actual phase/beacon/output checks. Do not substitute acceptance-based results.

Delivery: `Checking signed checkpoint and required files` → `Publishing files` →
`Confirming the exact published checkpoint`. Retry starts with `Resuming publication
of the existing signed checkpoint`. Only confirmed current publication reports:
`The exact signed checkpoint is published.` Do not label upload-only success as
ceremony completion, or redo computation just to retry publication.

## Resource UI shared by computational roles

Use Relay's existing resource-policy commands and launch integration; add no new
resource flag spelling in this document. Honor admission rules and saved caps from
`docs/maintainer/resource-allocation-design.md` in Relay.

Display before a new operation:

```text
{Operation}
Docker capacity: {cpu_capacity} CPUs, {memory_capacity} GiB memory
Suggested allocation: {cpus} CPUs, {memory} GiB memory

1) Start with suggested resources
2) Adjust resource limits
3) Use conservative limits
```

Show suggestions after a capacity/policy assessment; they are not a reservation.
Revalidate and atomically reserve the required resources immediately before launch.
Do not hold a reservation across a user prompt. If capacity changed, stop before
starting and show an updated assessment. Total capacity is not available capacity.
Under operator-budget mode, label the calculation “Within your configured resource
budget”; do not describe budget headroom as measured free memory. “Conservative”
also requires admission and user-cap checks.
Display its actual values before launch; never silently exceed a saved cap.
Default policy values stay at the qualified conservative settings until measurements
approve alternatives. No hard-coded 6-CPU recommendation from component timings.
Save preferences through the existing policy mechanism; reprompt only when capacity
or requirements invalidate the saved choice. Running display:
`{stage} — elapsed {elapsed}; using {cpus} CPUs and {memory} GiB memory`.
Changed preference message:
`Updated resource preferences apply to new operations. This operation and its retries retain their recorded allocation.`
Insufficient admission:
`Cannot start within the saved resource limits and available capacity. Adjust limits or free capacity, then retry before starting.`
Do not turn an ambiguous started contribution into a new launch after resource changes.

## CLI acceptance checks

- Assert each stage corresponds to actual calls, with no hidden historical replay
  in participant sync/contribution or normal closure/checkpoint recording.
- Exercise help/parser support for every diagnostic allowlist entry and rejection
  elsewhere, including participant commands and unsupported checkpoint transitions.
- Cross-phase/participant mismatch must reject before entropy and produce no
  success result; successful phase labels come from authenticated output.
- Simulate missing evidence, bad beacon/application, phase mismatch, retired attempt,
  interrupted generation, partial publication and lost publication response.
- Test stderr progress versus unchanged stdout JSON envelope; preserve exit codes.
- No cache UI, participant mode selector, unsupported ETA or new consent screen.
- Run the full V5 ceremony workflow after integration. Proposed wording is not
  evidence that the currently released CLI already performs the new behavior.

## Independent design review disposition

One adversarial review was completed for this draft. It led to launch-time resource
revalidation/reservation (not a reservation while prompting), retry-aware failure
copy, running-workload checks before retirement guidance and V5-specific signer
wording. A suggestion to remove `phase1 seal --full-replay` relied on an older
superseded decision: the currently agreed design retains coordinator diagnostic
full replay. Therefore that existing option remains; participant replay options
remain excluded. These are document-review findings, not executed CLI tests.

Deferred scope and future resumption criteria are consolidated in the
[deferred-task register](ceremony-optimization-deferred-tasks.md). D1/G7 is cache-only; D2 is standalone
tracking only. Relay-managed recovery and current-operation memory checks remain.
