# Lab 4.4: Deterministic Quality Gates

## Goal

Validate the LLM generated proposal with controls that do not depend on another model judgment.

## Workbench steps

1. Stay in `Sigma Workbench`.
2. Run the deterministic gates.
3. Expand each result and repair all failures.
4. Run the gates again until every check passes.
5. Convert the rule with pySigma.
6. Confirm portable Sigma fields map to the intended ECS fields.

## Exit criteria

- Local metadata and safety gates pass.
- `sigma check` passes.
- pySigma conversion succeeds.
- The generated query matches the approved design.
- Quality and conversion evidence exists under `reports/`.

