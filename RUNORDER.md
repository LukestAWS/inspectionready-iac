# InspectionReady — Module Run Order

Every engagement follows this sequence. Do not run a later stage
before the earlier stage is complete and outputs reviewed.

## Stage 1 — initial-state (mandatory, every engagement)
Path: modules/initial-state/
Purpose: Read-only baseline capture. No resources created.
Output: JSON snapshot of client environment before any changes.
Gate: Review outputs before proceeding. Confirm scope with client.

## Stage 2 — essential (every engagement)
Path: modules/essential/
Purpose: Core remediation — identity, data-protection, backup, monitoring.
Run order within essential: identity → data-protection → backup → monitoring
Gate: Confirm billing alarm is active before running.

## Stage 3 — professional (Professional Audit and above only)
Path: modules/professional/
Purpose: Advanced controls — GuardDuty, Security Hub, Macie.
Prerequisite: Stage 2 complete.
Gate: Confirm client has agreed Macie cost estimate before running.

## Stage 4 — bespoke (complex environments only)
Path: modules/bespoke/
Purpose: Environment-specific remediation surfaced by initial-state.
Prerequisite: Stages 2 and 3 complete.
Gate: Scope each bespoke module explicitly with client before running.

## The golden rule
initial-state runs first. Always. No exceptions.
