# Lab 4.6: Evidence Based Tuning

## Goal

Repair a false positive with a narrow, testable exclusion while preserving malicious coverage.

## Workbench steps

1. Copy the Sigma rule to a new filename.
2. Remove the approved management tool filter.
3. Run regression fixtures in `Test and Tune`.
4. Identify the negative event that matches.
5. Inspect that event in `Telemetry Explorer`.
6. Add the narrowest exclusion supported by its fields and business context.
7. Run fixtures and complete dataset evaluation again.
8. Confirm both positive cases still match.

## Exit criteria

- The false positive was reproduced.
- The exclusion is based on observed evidence.
- Positive coverage remains intact.
- Regression evidence protects against future over tuning.

