# Optional ceremony controls (experimental)

Definition v3 signs one explicit assurance policy with four independent
minimums:

- public witnesses per phase;
- mirror receipts per accepted head;
- passing ceremony audits; and
- external security-audit signoffs.

Zero explicitly disables a control. Omitting the policy never means zero.
When ceremony audits are disabled, the signed auditor roster must also be
empty. Rehearsals must disable external security-audit signoffs because they
cannot satisfy a production review requirement honestly.

The policy is part of the ceremony ID. Checkpoints, operational evidence,
final transcripts, and production decisions repeat it and must match the
signed definition exactly. Evidence for a disabled control is rejected; an
enabled control must meet its signed minimum. A production decision displays a
disabled gate as `NOT_REQUIRED`, with no evidence, and may not use that status
for an enabled control.

Disabling witnesses does not disable the future drand beacon or its
verification. It does remove independent evidence that the coordinator
published the closure before learning the beacon value. The signed timestamps
remain operator claims, not trusted external time.

Definition v1/v2, operational-bundle v2, final-transcript v1, and
production-decision v1 keep their original one-or-more requirements. They are
not reinterpreted using the optional-role policy.

This work is experimental until the full Proof-tool release path, Relay role
journeys, storage backends, and Tessera contract are updated and tested as one
released pairing.
