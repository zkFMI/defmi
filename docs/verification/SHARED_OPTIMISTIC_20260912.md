# Shared optimistic assurance: observed integration

The accompanying JSON records real MPC, corporate outbox and five-validator native ledger observations on the isolated Softbank L40S research network on 2026-09-12. Assets, participants and collateral are synthetic development fixtures. The verdict is smoke_only, not a performance or production acceptance claim.

The observations used the integration working trees before publication. They do not establish that a later commit was deployed. The browser follow-up is documented separately in the QOMM and OCLOB repositories. Native finality, financial proofs and original application proof verification remain required on their respective paths. Unchallenged finality assumes an available honest challenger; it does not supply the skipped mathematical proof.

The shared state machine supports pending, challenged, proven, finalized and rejected claims. A valid matching defense transfers the challenger bond but still waits for the original window. A valid contradictory defense or an unanswered challenge rejects the claim and transfers collateral. Invalid proof bytes fail verification without silently settling or immediately resolving the claim.

Source ownership: concurrent proof-RPC parallelization and unrelated workflow changes are excluded from this publication. The proof coordinator retains its existing sequential RPC scheduling. The isolated owned zkPI source candidate was separately compiled and exercised through the protocol's state-machine and authorization checks on Softbank L40S.
