# Ceremony schema compatibility

## Released formats are frozen

Verified against released commit `47bec5663d04a4f8ac330fc38f126e6e7c1140f1`
(PR #31, September 15, 2026). Existing ceremonies keep their signed definition,
software allowlist and verification rules.

| Boundary | Released versions | Preserved meaning |
| --- | --- | --- |
| Ceremony definition | V1, V2, V3 | V1 single binary; V2 binary allowlist; V3 explicit assurance policy |
| Checkpoint | V1, V2, V3 | Existing storage-first lifecycle and custody/submission records |
| Operational bundle | V2, V3 | Existing custody, cleanup and enabled-assurance evidence |
| Final candidate/transcript | candidate V2; transcript V1, V2 | Existing coordinator replay and signer-replay requirements |
| Release manifest | key manifest V1 | Existing application bundle and setup-transcript binding |
| Production decision | V1, V2 | Existing evidence gates and signed decision meaning |

Coordinator `PrepareFinalization` and `Finalize` have required a complete
coordinator replay since commit `c1f177ee486fd555fac0dc4d9812b86737fccdfd`
(July 31, 2026). PR #31 additionally required the release signer to repeat that
replay for Definition V3. Neither rule may be weakened for V1–V3.

## Definition V4 is a replacement protocol

V4 is selected only by an explicitly signed V4 definition. It never upgrades an
existing ceremony and never changes the interpretation of a released record.

Its trust model is deliberately simple:

- the coordinator is trusted to choose legal ceremony actions and perform the
  mandatory full mathematical replay;
- the delivery service is trusted for availability and transport, while signed
  hashes still detect accidental or unauthorized byte changes;
- participants are trusted to follow the cleanup procedure they attest to;
- the release signer remains a required distinct signing role, but need not
  repeat the coordinator's mathematics;
- witnesses, mirrors, ceremony auditors and external audit signoffs are enabled
  only when their signed policy count is nonzero.

The normal participant turn is:

1. The coordinator signs a candidate allocation derived from the authenticated
   current checkpoint. Phase, index, participant and parent head are not caller
   choices.
2. The participant authenticates that allocation and its exact input snapshot in
   the same proof-tool process that generates contribution randomness.
3. The participant contributes, confirms cleanup and uploads the fixed five-file
   public candidate.
4. The coordinator verifies the candidate and contribution mathematics, writes
   the next immutable chain artifacts, and signs an acceptance checkpoint.
5. The delivery service conditionally advances the current-head pointer only if
   it still names the allocation checkpoint.

V4 has no custody handoff, custody receipt, participant transport envelope or
coordinator submission acknowledgement. An attempt ID identifies delivery and
retry state; it does not change the existing signed contribution statement.
Byte-identical retries are safe, conflicting outputs are retained for
investigation, and accepted/rejected/retired attempts remain in bounded history.

## Verification boundaries

- `checkpoint inspect-signed-v4` authenticates one checkpoint pair only for
  bounded dependency discovery. It does not validate ancestry or progress.
- `checkpoint verify-stored-v4` verifies complete signed ancestry and legal state
  transitions. It does not claim that the delivery-service head is globally
  current or replay contribution mathematics.
- `checkpoint allocate-v4` derives and signs the exact next allocation.
- `phase1 contribute` and `phase2 contribute`, when given a V4 allocation, verify
  the allocation and immutable input snapshot before generating randomness.
- `checkpoint accept-candidate-v4` verifies the active allocation, candidate and
  mathematics, then prepares and signs the descendant checkpoint.
- final-candidate preparation records the mandatory coordinator full replay and
  binds its exact executable and closed file inventory.
- release review verifies that replay binding, the exact final files, enabled
  assurance evidence and the required release signer. Independent signer or
  auditor replay is optional additional assurance in V4.
- each V4 phase retains the exact coordinator-signed beacon record and its one
  cryptographically verified drand response. A second endpoint may be tried as
  an availability fallback, but V4 does not create a separate multi-relay
  evidence record. Released V1-V3 verification rules remain unchanged.

Large contribution payloads are hashed and verified as streams. Canonical JSON
records and signatures retain strict small-file limits. Final reports have their
own explicit bounds and are not authority merely because they were generated.

## Compatibility gates

- Parsers dispatch by authenticated definition/schema, never by missing fields or
  a generic "latest" constant.
- Unknown versions fail closed.
- V1–V3 verification remains covered by compatibility tests.
- V4 uses final transcript V3 and production decision V3; the application key
  manifest stays V1 because its signed transcript hash binds the new transcript.
- Provider credentials, bucket names, object keys and upload manifests remain
  outside proof-tool's signed protocol types.
- Normal initialization must not emit V4 until the complete delivery-tool journey,
  live storage tests and released binary pairing have passed.

The V4 implementation has real Linux tiny-ceremony coverage for both phases,
coordinator replay, optional-assurance combinations, final signing, release
verification and negative cases. That evidence is not a production GO decision,
does not prove independent operators or physical erasure, and does not replace a
released end-to-end storage-backed rehearsal.
