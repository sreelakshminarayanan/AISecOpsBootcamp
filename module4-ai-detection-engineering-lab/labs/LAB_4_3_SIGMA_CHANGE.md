# Lab 4.3: LLM Assisted Sigma Proposal

## Goal

Use an approved design to create a portable Sigma proposal for human review.

## Workbench steps

1. Open `Sigma Workbench`.
2. Select the approved encoded PowerShell design.
3. Generate the Sigma proposal with Ollama.
4. Review every field, value, condition, exclusion, tag, and reference.
5. Confirm the rule uses portable Sigma fields, not ECS fields.
6. Confirm all logic is supported by the approved design.
7. Save the draft.

## Exit criteria

- The rule can be explained line by line.
- No unsupported field or behavior was added.
- The rule is saved as `workspace/encoded_powershell.yml`.
- The rule remains a proposal until deterministic gates and tests pass.

