# Final-review test failure investigation

Date: 2026-09-23. This investigation changes documentation only in the working
repository. Diagnostic/test assertion changes were confined to a temporary
validation clone; production verification was not modified or released.

## Finding

The reported `final review is not deterministic or exactly bound` error is a
workflow test-helper assertion error, not an observed failure of production
review determinism, checkpoint binding or final-key reconstruction.

`testdata/workflowhelper/checkpoint_v4_review.go:runCheckpointV4Review` combines
three assertions under one message: repeated canonical review bytes match,
`ReviewCheckpoint` equals the expected checkpoint, and the number of returned
audits equals `PassingCeremonyAudits`.

The default checkpoint fixture has two auditors and requires a minimum of one
passing audit (`testdata/workflowhelper/main.go`). Its final workflow creates and
commits an audit from EVERY auditor when audits are enabled
(`checkpoint_v4_final.go`). The review correctly returns both audit references.
The test wrongly treats the minimum as an exact inventory count.

Production `audit.go:validateAuditCollectionCount` correctly rejects fewer than
the required minimum, permits additional valid audits when enabled and prohibits
audit artifacts when the policy disables audits. Signatures, uniqueness and
candidate binding are checked by the remaining collection verification.
Do not change production quorum semantics or omit valid audit evidence to make
this helper assertion pass.

## Reproduction and isolated validation

Both schema reproductions used the signed tiny workflow in a network-disabled,
read-only-root Linux container on `zksecurity-hetzner-node`, with a new investigation
workspace, synthetic fixture keys, 4 CPUs, 6 GiB memory/swap ceiling, Go memory target
4 GiB, GOGC 25 and unprivileged user 1000. No production ceremony was resumed.

Image: `ghcr.io/zksecurity/relay/relay-role-offline@sha256:15fa6612e449084cb707206b4dd648a1ffca3e46f699577f37dcae058fb89b62`.
Both local worktree and temporary validation clone start from
`b0815c943310a377c249eee83816a0af22ff621c` plus unpublished changes. This is not a
clean-release qualification. The V4-named helper creates V5 by default;
`MPC_WORKFLOW_HISTORICAL_V4=1` explicitly selects the historical fixture definition.

Node evidence directory:
`/home/jason/ceremonies/final-review-investigation-20260923/`.

| Run | Result |
| --- | --- |
| `diagnostic-v4.log` | Reproduced failure with `deterministic=true checkpoint_bound=true audits=2 required_minimum=1`, actual definition V4 |
| `diagnostic-v5.log` | Same failure and diagnostic values, actual definition V5 |
| `fixture-v4.log` | Test-only corrected assertion: complete tiny workflow exited 0, OOM false, including final review, release package/checkpoint and negative evidence checks |
| `fixture-v5.log` | Test-only corrected assertion: complete tiny workflow exited 0, OOM false, including final review, release package/checkpoint and negative evidence checks |

Diagnostic helper SHA-256:
`7e17a5322817a656f2a16030397566fc713379886c42e06146e843a1180a3774`.
Test-only corrected helper SHA-256:
`b09dd98f9d0f2767deae64490c151251d9ba83dfd3f1cf9082de26d1435883b3`.

The temporary correction splits the three assertions, checks the exact report count
this fixture intentionally produced (all configured auditors when enabled, otherwise
zero), and separately checks the minimum. It retains the canonical-byte equality
and exact checkpoint assertions. All subsequent tests still execute, including the
snapshot with only declared dependencies, corrupted/missing evidence rejection,
changed post-review evidence rejection, release creation and final checkpoint checks.

Existing local test also passed:
`go test -mod=vendor ./internal/mpcceremony -run '^TestCheckpointV4AuditCollectionPreservesQuorumAndBinding$' -count=1 -v`.
It covers partial collection, required minimum, duplicate auditors, wrong candidate,
disabled audits and bad signatures. It does not replace the signed Linux workflows.

## Proposed repository correction and remaining gates

At the next authorized implementation/test-maintenance step:

1. Give canonical determinism, checkpoint binding and audit inventory separate
   assertions/error messages.
2. Compare returned audit references against the exact reports committed by the
   fixture, independently of the required minimum. Do not merely weaken the test
   to `count >= minimum`, which would miss dropped optional reports.
3. Cover disabled audits, exact minimum, and more valid reports than the minimum;
   assert actual V5 definition schema in the fixture. Historical V4 workflow
   tests are to be removed under the later release-scope decision; the completed
   V4 runs above remain historical evidence only.
4. Keep under-minimum, duplicate/invalid-signature and wrong-candidate rejection.

The repository helper is still unchanged, so its affected configuration still
fails until this test correction is applied. The cause is now identified and
validated in isolation; it should no longer be described as an unexplained
production finalization defect. Tiny fixtures do not qualify production circuit
memory/runtime, new participant shortcuts or persistent key caching.

## Retained evidence hashes

Local copies of the four logs and the isolated fixture-only patch are retained at
`/tmp/final-review-investigation-20260923/`. Node logs remain in the directory above.
Comparison of production `internal/mpcceremony` Go sources found only a comment
difference (`coordinator V4` versus `coordinator V4/V5`); no executable-code
difference between the validation clone and working tree in that package.

| File | SHA-256 |
| --- | --- |
| `diagnostic-v4.log` | `e25df187276d6f45228a14c9821b6c8fba60162bf0945239edf6f52fad5a6f35` |
| `diagnostic-v5.log` | `c042c11ccbda98a52cba00d2180ac321c77f232178a30e04676063d1dbedf7f0` |
| `fixture-only-validation.patch` | `9669199647f53e4fa4f5d84fa40b4e67936f0a9e239201899278c3de97d78fc9` |
| `fixture-v4.log` | `ba23a63c309fbd2534879c3cb3721eab90dd8005e8d8307a953c8750bb5c81d0` |
| `fixture-v5.log` | `52b3304a8fa0d0f3f751600dc71b76bce5c112ddd6ea308593d6ca83cfc86ed4` |
