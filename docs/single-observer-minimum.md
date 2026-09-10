# Single-observer minimums (unreleased)

Both rehearsal and production require at least one enrolled auditor, one public
witness per phase, and one mirror operator providing a signed receipt for every
accepted contribution. The same witness and mirror may serve both phases. A
higher explicitly selected witness quorum remains binding. Zero is rejected.

Release signing requires at least one verified passing transcript audit.
Production decisions also require at least one distinct external audit signoff;
this is a separate report requirement, not evidence supplied by a mirror or
witness. Every supplied report is still validated, including additional reports.

Production still requires at least two participants per phase, every scheduled
contribution, distinct signing identities and the existing independence checks.
Beacon lead times and multi-relay observation requirements are unchanged.

This policy changes verifier behavior and needs a new proof-tool release. Existing
ceremonies must continue using their approved proof-tool build. The companion CLI
must pin the new release and advertise the new `two-phase-v2` ruleset (version 2);
Tessera must provision that exact compatible CLI release before activating it.
Do not reinterpret old ceremonies using a newer verifier.
